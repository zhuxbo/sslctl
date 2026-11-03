package setup

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// certDeployPlan 单个证书的部署计划
type certDeployPlan struct {
	CertData       *fetcher.CertData
	ParsedCert     *x509.Certificate
	CertDomains    []string
	PrivateKey     string
	Bindings       []config.SiteBinding
	NeedSSLInstall []*matcher.ScannedSiteInfo

	// 部署阶段填充，供保存阶段使用
	SiteSuccess    int      // 本证书成功部署的站点数，保存门禁据此判定
	RetryableSites []string // 可重试失败的站点，写入 FailedBindings 交给 daemon
}

// siteCandidate 站点的候选证书信息（用于冲突解决）
type siteCandidate struct {
	planIndex    int              // certDeployPlan 索引
	matchType    config.MatchType // 匹配类型
	matchedCount int              // 匹配域名数
	orderID      int              // 订单 ID（越大越新）
}

// runBatch 批量部署（query 为逗号分隔的订单 ID，形态已在入口校验）
func runBatch(p *setupParams, query string) {
	// 1/7: 检测 Web 服务并扫描站点（宿主机 + Docker）
	fmt.Println("步骤 1/7: 检测 Web 服务并扫描站点...")
	scanResult := scanWebServersAndSites(p.log)
	if len(scanResult.ServerTypes) == 0 {
		fmt.Fprintln(os.Stderr, webServersNotFoundMessage())
		os.Exit(1)
	}
	fmt.Printf("  ✓ 检测到 Web 服务: %s\n", strings.Join(scanResult.ServerTypes, ", "))
	if len(scanResult.Sites) == 0 {
		fmt.Fprintln(os.Stderr, deployableSitesNotFoundMessage())
		os.Exit(1)
	}
	sites := scanResult.Sites
	environment, _ := summarizeScannedSites(sites)
	fmt.Printf("  ✓ 发现 %d 个可部署站点\n", len(sites))
	fmt.Printf("  环境: %s\n", environment)

	// 2/7: 查询证书
	fmt.Println("\n步骤 2/7: 查询证书...")
	f := fetcher.New()
	certList, renewBeforeDays, err := f.QueryBatch(p.ctx, p.apiURL, p.token, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询证书失败: %v\n", err)
		os.Exit(1)
	}
	applyRenewBeforeDays(p.cfgManager, p.log, renewBeforeDays)

	if len(certList) == 0 {
		fmt.Fprintln(os.Stderr, "未查询到证书")
		os.Exit(1)
	}
	fmt.Printf("  查询到 %d 个证书\n", len(certList))
	// 不存在的 ID 被服务端静默跳过（deploy-spec §2.3），条数少于请求数时如实提示
	if requested := len(strings.Split(query, ",")); len(certList) < requested {
		fmt.Printf("  提示: 请求 %d 个订单，%d 个未命中（不存在或不在当前 Token 可见范围）\n",
			requested, requested-len(certList))
	}

	// 过滤并验证证书
	certValidator := validator.New("")
	var plans []*certDeployPlan
	for i := range certList {
		cd := &certList[i]
		if cd.Status != config.OrderStatusActive || cd.Cert == "" {
			fmt.Printf("  ⚠ 订单 %d: 证书未就绪 (status=%s)，跳过\n", cd.OrderID, cd.Status)
			continue
		}
		if cd.IntermediateCert == "" {
			fmt.Printf("  ⚠ 订单 %d: 中间证书为空，跳过\n", cd.OrderID)
			continue
		}
		parsedCert, err := certValidator.ValidateCert(cd.Cert)
		if err != nil {
			fmt.Printf("  ⚠ 订单 %d: 证书验证失败: %v，跳过\n", cd.OrderID, err)
			continue
		}
		domains := extractDomainsFromCert(parsedCert)
		if len(domains) == 0 {
			fmt.Printf("  ⚠ 订单 %d: 证书缺少域名信息，跳过\n", cd.OrderID)
			continue
		}
		// 验证 API 返回的私钥
		if cd.PrivateKey != "" {
			if err := certValidator.ValidateCertKeyPair(cd.Cert, cd.PrivateKey); err != nil {
				fmt.Printf("  ⚠ 订单 %d: API 私钥与证书不匹配，跳过\n", cd.OrderID)
				continue
			}
		}
		plans = append(plans, &certDeployPlan{
			CertData:    cd,
			ParsedCert:  parsedCert,
			CertDomains: domains,
		})
		fmt.Printf("  ✓ 订单 %d: %s\n", cd.OrderID, strings.Join(domains, ", "))
	}

	if len(plans) == 0 {
		fmt.Fprintln(os.Stderr, "\n没有可部署的证书")
		os.Exit(1)
	}
	fmt.Printf("\n  共 %d 个证书可部署\n", len(plans))

	// 3/7: 匹配站点 + 冲突解决
	fmt.Println("\n步骤 3/7: 匹配证书与站点...")
	resolveSiteConflicts(plans, sites, p.cfgManager)

	// 统计有绑定的计划
	var activePlans int
	var totalBindings int
	for _, plan := range plans {
		if len(plan.Bindings) > 0 {
			activePlans++
			totalBindings += len(plan.Bindings)
		}
	}

	if totalBindings == 0 {
		fmt.Fprintln(os.Stderr, "\n未找到可绑定的站点")
		os.Exit(1)
	}

	// 4/7: 确认部署计划
	fmt.Println("\n步骤 4/7: 确认部署计划...")
	printDeployPlan(plans)
	fmt.Printf("\n  共 %d 个证书，%d 个站点\n", activePlans, totalBindings)

	if !p.yes {
		if !confirm("\n确认部署?") {
			fmt.Println("已取消")
			os.Exit(0)
		}
	}

	// 5/7: 验证私钥 + 部署
	fmt.Println("\n步骤 5/7: 部署证书...")
	var certSuccess, certFail int
	var totalSiteSuccess, totalSiteFail int
	var needKeyNames []string

	for _, plan := range plans {
		if len(plan.Bindings) == 0 {
			continue
		}

		_, fileValidation := deriveRenewPolicy(plan.CertDomains, p.localKey, p.fileValidation)
		unsupported := false
		for i := range plan.Bindings {
			if fileValidation && config.IsDockerCopyBinding(&plan.Bindings[i]) {
				unsupported = true
			}
		}
		if unsupported {
			fmt.Fprintln(os.Stderr, "Docker copy 暂不支持文件验证，跳过该证书")
			certFail++
			continue
		}

		certName := buildCertName(plan.CertDomains[0], plan.CertData.OrderID)
		fmt.Printf("\n  证书 %s:\n", certName)

		// 获取私钥（批量模式不交互，缺私钥的最后汇总提示）
		privateKey, err := getAndValidatePrivateKey(p.keyFile, plan.Bindings, plan.CertData, certValidator, false)
		if err != nil {
			if errors.Is(err, errNeedPrivateKey) {
				fmt.Fprintf(os.Stderr, "    缺少私钥，跳过\n")
				needKeyNames = append(needKeyNames, certName)
			} else {
				fmt.Fprintf(os.Stderr, "    私钥验证失败: %v，跳过\n", err)
				certFail++
			}
			continue
		}
		plan.PrivateKey = privateKey

		// SSL 安装
		for _, site := range plan.NeedSSLInstall {
			installSSLForBatch(site, plan, p)
		}

		// 部署到每个绑定
		siteSuccess, failedSites, retryableSites := deployPlanBindings(p, plan)
		siteFail := len(failedSites) + len(retryableSites)
		plan.RetryableSites = retryableSites
		plan.SiteSuccess = siteSuccess
		totalSiteSuccess += siteSuccess
		totalSiteFail += siteFail

		// 上报该证书的部署结果（deploy-spec §5.1 步骤 6）。必须留在部署循环内：
		// 后面既有全失败 os.Exit(1)，保存循环又会跳过没有成功绑定的证书，
		// 放到那里会正好丢掉最该上报的那批。
		// 三条 continue（无绑定、缺私钥、私钥验证失败）都未发生部署，不上报——
		// deploy-spec §5.3 把"需要私钥"单列为区别于"失败"的第三类。
		sendBatchDeployCallback(p, f, plan.CertData.OrderID, siteSuccess, siteFail)

		if siteSuccess > 0 {
			certSuccess++
		} else {
			certFail++
		}
	}

	if certSuccess == 0 && (certFail > 0 || len(needKeyNames) > 0) {
		fmt.Fprintln(os.Stderr, "\n批量部署失败! 所有证书部署均失败")
		if len(needKeyNames) > 0 {
			fmt.Fprintf(os.Stderr, "  需要私钥的证书: %s\n", strings.Join(needKeyNames, ", "))
		}
		exitSetup(1)
	}

	// 6/7: 保存配置
	fmt.Println("\n步骤 6/7: 保存配置...")
	for _, plan := range plans {
		if len(plan.Bindings) == 0 {
			continue
		}
		// 必须按"有没有成功部署"判定，不能看"有没有启用的绑定"。
		// 二者此前等价，仅仅因为部署失败一律置 Enabled=false；P1-2 保留可重试绑定后
		// 该等价被打破，全失败的证书会被写入配置，进而由 AddCert 摘除其它证书的同名绑定。
		if plan.SiteSuccess == 0 {
			continue
		}

		certConfig := &config.CertConfig{
			CertName: buildCertName(plan.CertDomains[0], plan.CertData.OrderID),
			OrderID:  plan.CertData.OrderID,
			Enabled:  true,
			Domains:  plan.CertDomains,
			API: config.APIConfig{
				URL:   p.apiURL,
				Token: p.token,
			},
			Bindings: plan.Bindings,
		}
		certConfig.Metadata.CertExpiresAt = plan.ParsedCert.NotAfter
		certConfig.Metadata.CertSerial = fmt.Sprintf("%X", plan.ParsedCert.SerialNumber)
		certConfig.Metadata.LastDeployAt = time.Now()
		// 可重试失败的站点交给 daemon 自愈
		if len(plan.RetryableSites) > 0 {
			certConfig.Metadata.FailedBindings = plan.RetryableSites
			certConfig.Metadata.FailedBindingsAt = time.Now()
		}

		// 逐证书派生续签模式：SAN 含 IP 的证书强制 local + file（deploy-spec §5.2），
		// DNS 证书按命令行参数派生，混合批次下 DNS 证书不受 IP 证书影响。
		useLocalKey, useFileValidation := deriveRenewPolicy(plan.CertDomains, p.localKey, p.fileValidation)
		if config.ContainsIPDomain(plan.CertDomains) {
			fmt.Printf("  证书 %s 含 IP，自动启用 local/file\n", certConfig.CertName)
		}

		if useLocalKey {
			certConfig.RenewMode = config.RenewModeLocal
		}

		if useFileValidation {
			// 校验：通配符域名不支持文件验证
			skipCert := false
			for _, domain := range plan.CertDomains {
				if errMsg := config.ValidateValidationMethod(domain, config.ValidationMethodFile); errMsg != "" {
					fmt.Fprintf(os.Stderr, "  ⚠ 证书 %s 域名 %s: %s，跳过\n", certConfig.CertName, domain, errMsg)
					skipCert = true
					break
				}
			}
			if skipCert {
				continue
			}
			certConfig.ValidationMethod = config.ValidationMethodFile
			if p.webroot != "" {
				for i := range certConfig.Bindings {
					certConfig.Bindings[i].Paths.Webroot = p.webroot
				}
			} else {
				// 检查至少一个绑定有扫描到的 webroot
				hasWebroot := false
				for _, b := range certConfig.Bindings {
					if b.Paths.Webroot != "" {
						hasWebroot = true
						break
					}
				}
				if !hasWebroot {
					fmt.Fprintf(os.Stderr, "  ⚠ 证书 %s 未扫描到 webroot，跳过\n", certConfig.CertName)
					continue
				}
			}
		} else if useLocalKey {
			certConfig.ValidationMethod = config.ValidationMethodDelegation
		}

		if err := p.cfgManager.AddCert(certConfig); err != nil {
			fmt.Fprintf(os.Stderr, "  保存 %s 失败: %v\n", certConfig.CertName, err)
			continue
		}
		fmt.Printf("  ✓ %s 配置已保存\n", certConfig.CertName)

		// 通知服务端是否自动续签（非关键路径，失败仅记录警告）
		notifyAutoReissue(p, f, certConfig.OrderID, certConfig.RenewMode)
	}

	// 7/7: 安装守护服务
	if !p.noService {
		fmt.Println("\n步骤 7/7: 安装守护服务...")
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "  安装服务失败: %v\n", err)
			fmt.Println("  可稍后使用 'sslctl service repair' 修复")
		} else {
			fmt.Println("  ✓ 服务已安装并启动")
		}
	} else {
		fmt.Println("\n步骤 7/7: 跳过服务安装 (--no-service)")
	}

	// 汇总
	fmt.Println("\n========================================")
	if certFail > 0 || totalSiteFail > 0 || len(needKeyNames) > 0 {
		fmt.Printf("批量部署部分完成! 证书: 成功 %d 个，失败 %d 个; 站点: 成功 %d 个，失败 %d 个\n",
			certSuccess, certFail, totalSiteSuccess, totalSiteFail)
		if len(needKeyNames) > 0 {
			fmt.Printf("\n需要私钥（请使用 sslctl setup --order <id> 逐个部署）:\n")
			for _, name := range needKeyNames {
				fmt.Printf("  - %s\n", name)
			}
		}
	} else {
		fmt.Printf("批量部署完成! 共 %d 个证书，%d 个站点\n", certSuccess, totalSiteSuccess)
	}
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", p.cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", p.cfgManager.GetCertsDir())

	fmt.Print(deploymentStatusHint())

	p.reportNonCriticalSkips()

	// 检查 Docker 非卷挂载站点
	if totalSiteSuccess > 0 {
		for _, site := range sites {
			if site.ContainerID != "" && !site.VolumeMode {
				fmt.Println("\n[!] 检测到 Docker 容器站点的证书路径未挂载为卷")
				fmt.Println("    重建容器后需要重新部署证书")
				break
			}
		}
	}

	// 存在失败/未完成（含需私钥而跳过）时非零退出（部分失败也算失败），便于脚本调用方感知
	if hasDeployFailures(totalSiteFail, certFail, len(needKeyNames)) {
		os.Exit(1)
	}
}

// resolveSiteConflicts 为每个证书匹配站点，解决多证书匹配同一站点的冲突
func resolveSiteConflicts(plans []*certDeployPlan, sites []*matcher.ScannedSiteInfo, cm *config.ConfigManager) {
	// 第一步：每个证书独立匹配所有站点
	// 站点 → 所有候选
	candidateMap := make(map[string][]siteCandidate)

	for i, plan := range plans {
		m := matcher.New(plan.CertDomains)
		fullMatch, partialMatch, _ := m.MatchSites(sites)

		for _, smr := range fullMatch {
			name := smr.Site.ServerName
			candidateMap[name] = append(candidateMap[name], siteCandidate{
				planIndex:    i,
				matchType:    config.MatchTypeFull,
				matchedCount: len(smr.Result.MatchedDomains),
				orderID:      plan.CertData.OrderID,
			})
		}
		for _, smr := range partialMatch {
			name := smr.Site.ServerName
			candidateMap[name] = append(candidateMap[name], siteCandidate{
				planIndex:    i,
				matchType:    config.MatchTypePartial,
				matchedCount: len(smr.Result.MatchedDomains),
				orderID:      plan.CertData.OrderID,
			})
		}
	}

	// 第二步：冲突解决 - 每个站点选一个最优证书
	// 站点名 → 分配的 planIndex
	siteAssignment := make(map[string]int)
	for siteName, candidates := range candidateMap {
		best := candidates[0]
		for _, c := range candidates[1:] {
			if betterCandidate(c, best) {
				best = c
			}
		}
		siteAssignment[siteName] = best.planIndex

		if len(candidates) > 1 {
			bestPlan := plans[best.planIndex]
			fmt.Printf("  站点 %s 有 %d 个证书匹配，选择 %s\n",
				siteName, len(candidates), buildCertName(bestPlan.CertDomains[0], bestPlan.CertData.OrderID))
		}
	}

	// 第三步：构建站点名到站点信息的映射
	siteInfoMap := make(map[string]*matcher.ScannedSiteInfo)
	for _, site := range sites {
		siteInfoMap[site.ServerName] = site
	}

	// 第四步：为每个计划创建绑定
	for siteName, planIdx := range siteAssignment {
		site := siteInfoMap[siteName]
		if site == nil {
			continue
		}

		plan := plans[planIdx]
		binding := createBinding(site, cm)
		plan.Bindings = append(plan.Bindings, binding)

		if !site.HasSSL {
			plan.NeedSSLInstall = append(plan.NeedSSLInstall, site)
		}
	}
}

// betterCandidate 判断 a 是否比 b 更优
func betterCandidate(a, b siteCandidate) bool {
	// 完全匹配优先于部分匹配
	if a.matchType == config.MatchTypeFull && b.matchType != config.MatchTypeFull {
		return true
	}
	if a.matchType != config.MatchTypeFull && b.matchType == config.MatchTypeFull {
		return false
	}
	// 同级别：匹配域名数多的优先
	if a.matchedCount != b.matchedCount {
		return a.matchedCount > b.matchedCount
	}
	// 仍然相同：OrderID 更大的优先（更新的证书）
	return a.orderID > b.orderID
}

// printDeployPlan 展示部署计划
func printDeployPlan(plans []*certDeployPlan) {
	for _, plan := range plans {
		if len(plan.Bindings) == 0 {
			continue
		}
		fmt.Printf("\n  证书 %s:\n", buildCertName(plan.CertDomains[0], plan.CertData.OrderID))
		for _, b := range plan.Bindings {
			sslTag := ""
			if !fileExists(b.Paths.Certificate) {
				sslTag = " [需安装 SSL]"
			}
			fmt.Printf("    → %s (%s)%s\n", b.ServerName, b.ServerType, sslTag)
		}
	}
}

// installSSLForBatch 批量模式下为站点安装 SSL 配置
func installSSLForBatch(site *matcher.ScannedSiteInfo, plan *certDeployPlan, p *setupParams) {
	var binding *config.SiteBinding
	for i := range plan.Bindings {
		if plan.Bindings[i].ServerName == site.ServerName {
			binding = &plan.Bindings[i]
			break
		}
	}
	if binding == nil || !binding.Enabled {
		return
	}

	if config.IsDockerCopyBinding(binding) {
		fmt.Fprintf(os.Stderr, "    %s: Docker copy 仅支持已有 HTTPS 配置的站点\n", site.ServerName)
		binding.Enabled = false
		return
	}

	// 写入证书和私钥文件
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "    %s: 创建目录失败: %v\n", site.ServerName, err)
		binding.Enabled = false
		return
	}

	fullchain := plan.CertData.Cert
	if plan.CertData.IntermediateCert != "" {
		fullchain += "\n" + plan.CertData.IntermediateCert
	}
	if err := util.AtomicWrite(binding.Paths.Certificate, []byte(fullchain), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "    %s: 写入证书失败: %v\n", site.ServerName, err)
		binding.Enabled = false
		return
	}
	if err := util.AtomicWrite(binding.Paths.PrivateKey, []byte(plan.PrivateKey), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "    %s: 写入私钥失败: %v\n", site.ServerName, err)
		binding.Enabled = false
		return
	}

	result, err := installSSLConfig(site, p.cfgManager)
	if err != nil {
		fmt.Fprintf(os.Stderr, "    %s: 安装 SSL 配置失败: %v\n", site.ServerName, err)
		binding.Enabled = false
		return
	}
	if result.Modified {
		fmt.Printf("    ✓ %s: SSL 配置已安装（备份: %s）\n", site.ServerName, result.BackupPath)
		updateSiteAfterInstall(site, p.cfgManager)
	}
}

// sendBatchDeployCallback 上报单张证书的 setup 部署结果（deploy-spec §5.1 步骤 6）。
// 非关键路径，失败仅记日志。
func sendBatchDeployCallback(p *setupParams, f *fetcher.Fetcher, orderID, successCount, failCount int) {
	if p.nonCriticalTripped() {
		return
	}

	req := &fetcher.CallbackRequest{
		OrderID:    orderID,
		Status:     "success",
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	if failCount > 0 {
		req.Status = "failure"
		req.Message = certops.CallbackMessage(
			fmt.Errorf("%d 个站点部署失败，%d 个成功", failCount, successCount))
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), certops.CallbackFallbackBudget)
	defer cancel()

	renewBeforeDays, err := f.CallbackNew(ctx, p.apiURL, p.token, req)
	p.recordNonCritical(err)
	if err != nil {
		p.log.Warn("上报证书 order_id=%d 的部署结果失败（不影响部署结果）: %v", orderID, err)
		return
	}
	applyRenewBeforeDays(p.cfgManager, p.log, renewBeforeDays)
}

// deployPlanBindings 部署证书计划中的所有绑定。
// 与 deploySingleBindings 同一分流规则：failedSites 的绑定已禁用，
// retryableSites 的绑定保持启用并写入 FailedBindings 交给 daemon 重试，两者不重叠。
func deployPlanBindings(p *setupParams, plan *certDeployPlan) (success int, failedSites, retryableSites []string) {
	svc := certops.NewService(p.cfgManager, p.log)
	for i := range plan.Bindings {
		binding := &plan.Bindings[i]
		if !binding.Enabled {
			failedSites = append(failedSites, binding.ServerName)
			continue
		}
		fmt.Printf("    部署到: %s\n", binding.ServerName)

		if err := deployToSiteBinding(p.ctx, svc, binding, plan.CertData, plan.PrivateKey); err != nil {
			if sslerrors.IsPermanentDeployError(err) {
				fmt.Fprintf(os.Stderr, "      部署失败（需修正该站点配置后重新 setup）: %v\n", err)
				binding.Enabled = false
				failedSites = append(failedSites, binding.ServerName)
				continue
			}
			fmt.Fprintf(os.Stderr, "      部署失败（保留绑定，将由守护进程重试）: %v\n", err)
			retryableSites = append(retryableSites, binding.ServerName)
			continue
		}
		fmt.Printf("      ✓ 部署成功\n")
		success++
	}
	return
}

// fileExists 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
