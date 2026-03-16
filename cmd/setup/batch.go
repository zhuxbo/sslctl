package setup

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// certDeployPlan 单个证书的部署计划
type certDeployPlan struct {
	CertData       *fetcher.CertData
	ParsedCert     *x509.Certificate
	CertDomains    []string
	PrivateKey     string
	Bindings       []config.SiteBinding
	NeedSSLInstall []*matcher.ScannedSiteInfo
}

// siteCandidate 站点的候选证书信息（用于冲突解决）
type siteCandidate struct {
	planIndex    int                // certDeployPlan 索引
	matchType    config.MatchType   // 匹配类型
	matchedCount int                // 匹配域名数
	orderID      int                // 订单 ID（越大越新）
}

// runBatch 批量部署
func runBatch(p *setupParams, query string) {
	// 1/8: 检测 Web 服务器
	fmt.Println("步骤 1/8: 检测 Web 服务器...")
	serverType := webserver.DetectWebServerType()
	if serverType == "" {
		fmt.Fprintln(os.Stderr, "未检测到 Nginx 或 Apache 服务")
		os.Exit(1)
	}
	fmt.Printf("  检测到: %s\n", serverType)

	// 2/8: 查询证书
	fmt.Println("\n步骤 2/8: 查询证书...")
	f := fetcher.New(30 * time.Second)
	certList, err := f.QueryBatch(p.ctx, p.apiURL, p.token, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询证书失败: %v\n", err)
		os.Exit(1)
	}

	if len(certList) == 0 {
		fmt.Fprintln(os.Stderr, "未查询到证书")
		os.Exit(1)
	}
	fmt.Printf("  查询到 %d 个证书\n", len(certList))

	// 过滤并验证证书
	certValidator := validator.New("")
	var plans []*certDeployPlan
	for i := range certList {
		cd := &certList[i]
		if cd.Status != "active" || cd.Cert == "" {
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
		domains := parsedCert.DNSNames
		if len(domains) == 0 {
			fmt.Printf("  ⚠ 订单 %d: 证书缺少 SAN，跳过\n", cd.OrderID)
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

	// 3/8: 扫描站点
	fmt.Println("\n步骤 3/8: 扫描站点...")
	sites := scanSites(serverType, p.log)
	if len(sites) == 0 {
		fmt.Fprintln(os.Stderr, "未发现站点配置")
		os.Exit(1)
	}
	fmt.Printf("  发现 %d 个站点\n", len(sites))

	// 4/8: 匹配站点 + 冲突解决
	fmt.Println("\n步骤 4/8: 匹配站点...")
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

	// 5/8: 确认部署计划
	fmt.Println("\n步骤 5/8: 确认部署计划...")
	printDeployPlan(plans)
	fmt.Printf("\n  共 %d 个证书，%d 个站点\n", activePlans, totalBindings)

	if !p.yes {
		if !confirm("\n确认部署?") {
			fmt.Println("已取消")
			os.Exit(0)
		}
	}

	// 6/8: 验证私钥 + 部署
	fmt.Println("\n步骤 6/8: 部署证书...")
	var certSuccess, certFail int
	var totalSiteSuccess, totalSiteFail int

	for _, plan := range plans {
		if len(plan.Bindings) == 0 {
			continue
		}

		fmt.Printf("\n  证书 %s:\n", buildCertName(plan.CertDomains[0], plan.CertData.OrderID))

		// 获取私钥
		privateKey, err := getAndValidatePrivateKey(plan.Bindings, plan.CertData, certValidator)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    私钥验证失败: %v，跳过此证书\n", err)
			certFail++
			continue
		}
		plan.PrivateKey = privateKey

		// SSL 安装
		for _, site := range plan.NeedSSLInstall {
			installSSLForBatch(site, plan, p)
		}

		// 部署到每个绑定
		siteSuccess, siteFail := deployPlanBindings(p, plan)
		totalSiteSuccess += siteSuccess
		totalSiteFail += siteFail

		if siteSuccess > 0 {
			certSuccess++
		} else {
			certFail++
		}
	}

	if certSuccess == 0 && certFail > 0 {
		fmt.Fprintln(os.Stderr, "\n批量部署失败! 所有证书部署均失败")
		os.Exit(1)
	}

	// 7/8: 保存配置
	fmt.Println("\n步骤 7/8: 保存配置...")
	for _, plan := range plans {
		if len(plan.Bindings) == 0 {
			continue
		}
		// 检查是否有成功的绑定
		hasEnabled := false
		for _, b := range plan.Bindings {
			if b.Enabled {
				hasEnabled = true
				break
			}
		}
		if !hasEnabled {
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

		if p.localKey {
			certConfig.RenewMode = config.RenewModeLocal
		}

		if err := p.cfgManager.AddCert(certConfig); err != nil {
			fmt.Fprintf(os.Stderr, "  保存 %s 失败: %v\n", certConfig.CertName, err)
			continue
		}
		fmt.Printf("  ✓ %s 配置已保存\n", certConfig.CertName)
	}

	// 8/8: 安装守护服务
	if !p.noService {
		fmt.Println("\n步骤 8/8: 安装守护服务...")
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "  安装服务失败: %v\n", err)
			fmt.Println("  可稍后使用 'sslctl service repair' 修复")
		} else {
			fmt.Println("  ✓ 服务已安装并启动")
		}
	} else {
		fmt.Println("\n步骤 8/8: 跳过服务安装 (--no-service)")
	}

	// 汇总
	fmt.Println("\n========================================")
	if certFail > 0 || totalSiteFail > 0 {
		fmt.Printf("批量部署部分完成! 证书: 成功 %d 个，失败 %d 个; 站点: 成功 %d 个，失败 %d 个\n",
			certSuccess, certFail, totalSiteSuccess, totalSiteFail)
	} else {
		fmt.Printf("批量部署完成! 共 %d 个证书，%d 个站点\n", certSuccess, totalSiteSuccess)
	}
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", p.cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", p.cfgManager.GetCertsDir())

	if !p.noService {
		fmt.Println("\n守护服务命令:")
		fmt.Println("  systemctl status sslctl    # 查看状态")
		fmt.Println("  journalctl -u sslctl -f    # 查看日志")
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

// deployPlanBindings 部署证书计划中的所有绑定，返回成功和失败数
func deployPlanBindings(p *setupParams, plan *certDeployPlan) (success, fail int) {
	for i := range plan.Bindings {
		binding := &plan.Bindings[i]
		if !binding.Enabled {
			fail++
			continue
		}
		fmt.Printf("    部署到: %s\n", binding.ServerName)

		if err := deployToSiteBinding(p.ctx, binding, plan.CertData, plan.PrivateKey, p.log); err != nil {
			fmt.Fprintf(os.Stderr, "      部署失败: %v\n", err)
			fail++
			binding.Enabled = false
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
