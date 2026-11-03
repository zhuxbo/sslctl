// Package setup 一键部署命令
package setup

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	apacheScanner "github.com/zhuxbo/sslctl/internal/apache/scanner"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// setupParams 保存 setup 命令的通用参数
type setupParams struct {
	apiURL         string
	token          string
	localKey       bool
	keyFile        string // --key 指定的私钥文件路径
	fileValidation bool   // --file-validation 启用文件验证
	webroot        string // --webroot 指定的 Web 根目录
	yes            bool
	noService      bool
	ctx            context.Context
	cfgManager     *config.ConfigManager
	log            *logger.Logger

	// nonCriticalFails 非关键上报（部署结果回调 / toggleAutoReissue）的连续失败次数
	nonCriticalFails int
	// nonCriticalSkipped 熔断后跳过的非关键上报次数，结束时汇总
	nonCriticalSkipped int
	// nonCriticalTripReason 因服务端明确拒绝而熔断时的 error_code，仅用于汇总文案
	nonCriticalTripReason string
	// nonCriticalRetryAfter 睡满即可重试的保守秒数，仅用于汇总文案（不据它定时重试）
	nonCriticalRetryAfter int
}

// exitSetup 保留部署预检失败的进程边界，测试可观察退出码。
var exitSetup = os.Exit

// orderPattern --order 参数形态（deploy-spec §2.3）：仅订单 ID，单个或英文逗号分隔多个
var orderPattern = regexp.MustCompile(`^\d+(,\d+)*$`)

// nonCriticalFailureCap 非关键上报连续失败上限：达到即熔断，跳过本次 setup 剩余同类调用。
//
// 每个调用各有超时预算并不等于整体有边界：批量部署逐证书各调一次部署结果回调与
// toggleAutoReissue，API 不可达时最坏耗时随证书数线性放大到数小时。而第一张证书失败时
// 答案就已经确定，让后续每张证书各自重复一遍完整超时预算没有任何收益。
const nonCriticalFailureCap = 3

// nonCriticalTripped 判断是否已熔断；已熔断时顺带累计跳过次数
func (p *setupParams) nonCriticalTripped() bool {
	if p.nonCriticalFails < nonCriticalFailureCap {
		return false
	}
	p.nonCriticalSkipped++
	return true
}

// recordNonCritical 记录一次非关键上报结果。
//
// 成功即清零而非累计：间歇性故障不该攒够次数后熔断，只有持续不可达才熔断。
//
// 整批共通的 error_code（限流 / token 失效 / 账号或 IP 被禁）直接熔断，不等攒满次数——
// 这类失败由认证与限流中间件下发，对本批每一张证书都会以同样方式失败，逐张重试纯属浪费。
// 单条目 error_code（order_not_found 等）与未分类失败一律按普通失败计数：前者只说明这一张
// 证书的订单有问题，后者结果不确定，同批其他证书仍可能上报成功，攒满上限才熔断。
func (p *setupParams) recordNonCritical(err error) {
	if err == nil {
		p.nonCriticalFails = 0
		return
	}
	if code := sslerrors.ErrorCodeOf(err); fetcher.IsAuthBlockErrorCode(code) {
		p.nonCriticalFails = nonCriticalFailureCap
		p.nonCriticalTripReason = code
		// retry_after 只入日志文案供运维判断「大约多久后不再限流」，刻意不据它 sleep 重试。
		// 服务端下发的是「睡满即可重试的保守秒数」（已跨过下一个整窗口，spec §2.2），据它
		// sleep 属合法用法；但这里走的是 spec 推荐的另一种：本轮停止、下个调度周期自然重来。
		// 批量部署里睡几十秒只为补一条状态上报，代价远大于收益；且 sleep 期间同一 token 上
		// 的其他调用会继续累积计数，让这个值不再成立。
		p.nonCriticalRetryAfter = sslerrors.RetryAfterOf(err)
		return
	}
	p.nonCriticalFails++
}

// reportNonCriticalSkips 汇总熔断跳过情况（部署结果不受影响，但服务端状态会滞后）
func (p *setupParams) reportNonCriticalSkips() {
	if p.nonCriticalSkipped == 0 {
		return
	}
	cause := fmt.Sprintf("连续失败 %d 次", nonCriticalFailureCap)
	if p.nonCriticalTripReason != "" {
		cause = fmt.Sprintf("服务端明确拒绝（%s）", p.nonCriticalTripReason)
		if p.nonCriticalRetryAfter > 0 {
			cause += fmt.Sprintf("，约 %d 秒后可重试", p.nonCriticalRetryAfter)
		}
	}
	msg := fmt.Sprintf("非关键上报因%s已熔断，跳过 %d 次上报；部署结果不受影响，但服务端状态可能滞后",
		cause, p.nonCriticalSkipped)
	fmt.Fprintf(os.Stderr, "\n[!] %s\n", msg)
	p.log.Warn("%s", msg)
}

// Run 运行 setup 命令
func Run(args []string, debug bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	apiURL := fs.String("url", "", "证书 API 基础地址")
	token := fs.String("token", "", "API 认证 Token")
	order := fs.String("order", "", "订单 ID（必填），单个或英文逗号分隔多个（最多 100）")
	localKey := fs.Bool("local-key", false, "使用本机提交")
	keyFile := fs.String("key", "", "私钥文件路径（隐含 --local-key）")
	fileValidation := fs.Bool("file-validation", false, "启用文件验证（隐含 --local-key）")
	webroot := fs.String("webroot", "", "文件验证的 Web 根目录（隐含 --file-validation）")
	yes := fs.Bool("yes", false, "跳过确认提示")
	noService := fs.Bool("no-service", false, "不安装守护服务")
	nginxPrefix := fs.String("nginx-prefix", "", "显式指定 nginx 普通相对路径的 prefix（不影响证书路径，仅本次生效）")
	apachePrefix := fs.String("apache-prefix", "", "显式指定 Apache ServerRoot 解析基准（仅本次生效，不写入配置）")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --url <base_url> --token <token> --order <order_id>          # 单证书部署\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --url <base_url> --token <token> --order \"123,456\"           # 批量部署（订单 ID，逗号分隔）\n")
		fmt.Fprintf(os.Stderr, "  sslctl setup --key /path/key.pem --webroot /var/www/html --url <url> ...  # 指定私钥+文件验证\n")
		fmt.Fprintf(os.Stderr, "\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 隐含关系推导：--webroot → --file-validation → --local-key，--key → --local-key
	if *webroot != "" {
		*fileValidation = true
	}
	if *fileValidation || *keyFile != "" {
		*localKey = true
	}

	// 校验 --webroot 路径
	if *webroot != "" {
		if fi, err := os.Stat(*webroot); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--webroot 路径不存在或不是目录: %s\n", *webroot)
			os.Exit(1)
		}
	}

	if *apiURL == "" || *token == "" {
		fs.Usage()
		os.Exit(1)
	}

	// --order 必填且只接受订单 ID（deploy-spec §2.3）：域名与空参数形态已从协议移除
	orderStr := strings.TrimSpace(*order)
	if orderStr == "" {
		fmt.Fprintln(os.Stderr, "--order 必填（订单 ID，多个用英文逗号分隔）")
		fs.Usage()
		os.Exit(1)
	}
	if !orderPattern.MatchString(orderStr) {
		fmt.Fprintf(os.Stderr, "--order 只接受订单 ID（纯数字，英文逗号分隔）: %s\n", orderStr)
		os.Exit(1)
	}

	// --nginx-prefix / --apache-prefix 仅在本次进程内生效，影响扫描器的相对路径解析
	if *nginxPrefix != "" {
		nginxScanner.SetPrefixOverride(*nginxPrefix)
	}
	if *apachePrefix != "" {
		apacheScanner.SetPrefixOverride(*apachePrefix)
	}

	if err := util.CheckRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 创建配置管理器
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 检查是否已有配置（重复运行时保留 Schedule 等用户自定义设置）
	if existingCfg, loadErr := cfgManager.Load(); loadErr == nil && len(existingCfg.Certificates) > 0 {
		fmt.Println("检测到已有配置，将更新证书配置（保留 Schedule 等设置）")
	}

	// 初始化日志
	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}
	log, err := logger.New(logDir, "setup")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	// 与守护进程共享续签互斥锁，避免 setup 与自动续签并发操作同一证书目录与配置
	release, acquired, lockErr := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if lockErr != nil {
		log.Warn("%v，继续执行", lockErr)
	} else if !acquired {
		fmt.Fprintln(os.Stderr, "守护进程正在续签（或另一部署进程正在运行），请稍后再试")
		os.Exit(1)
	} else {
		defer release()
	}

	params := &setupParams{
		apiURL:         *apiURL,
		token:          *token,
		localKey:       *localKey,
		keyFile:        *keyFile,
		fileValidation: *fileValidation,
		webroot:        *webroot,
		yes:            *yes,
		noService:      *noService,
		ctx:            context.Background(),
		cfgManager:     cfgManager,
		log:            log,
	}

	// 路由：单个 ID 走单订单路径，逗号分隔多 ID 走批量（形态已在入口校验）
	if orderID, err := strconv.Atoi(orderStr); err == nil && orderID > 0 {
		runSingle(params, orderID)
	} else {
		runBatch(params, orderStr)
	}
}

// runSingle 单证书部署（保持原有 7 步流程）
func runSingle(p *setupParams, orderID int) {
	p.log.Info("开始 setup: order_id=%d, api_url=%s", orderID, p.apiURL)

	// 1. 检测 Web 服务并扫描站点（宿主机 + Docker）
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

	// 2. 获取证书信息
	fmt.Println("\n步骤 2/7: 获取证书信息...")
	f := fetcher.New()
	certData, renewBeforeDays, err := f.QueryOrder(p.ctx, p.apiURL, p.token, orderID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询订单失败: %v\n", err)
		os.Exit(1)
	}
	applyRenewBeforeDays(p.cfgManager, p.log, renewBeforeDays)

	// 订单续费后 API 返回新订单号
	if certData.OrderID > 0 && certData.OrderID != orderID {
		fmt.Printf("  订单已续费，使用新订单号: %d -> %d\n", orderID, certData.OrderID)
		orderID = certData.OrderID
	}

	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		fmt.Fprintf(os.Stderr, "证书未就绪: status=%s\n", certData.Status)
		os.Exit(1)
	}

	// 从证书中解析域名（比 API 返回的域名更准确）
	certValidator := validator.New("")
	parsedCert, err := certValidator.ValidateCert(certData.Cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "证书验证失败: %v\n", err)
		os.Exit(1)
	}

	// 从证书提取域名：合并 CN + SAN（DNSNames + IPAddresses），去重
	certDomains := extractDomainsFromCert(parsedCert)
	if len(certDomains) == 0 {
		fmt.Fprintln(os.Stderr, "证书缺少域名信息（CN 和 SAN 均为空）")
		os.Exit(1)
	}

	// SAN 含 IP 的证书强制 local + file（deploy-spec §5.2）；DNS 证书按命令行参数派生
	useLocalKey, useFileValidation := deriveRenewPolicy(certDomains, p.localKey, p.fileValidation)
	if config.ContainsIPDomain(certDomains) {
		fmt.Println("  检测到 IP 证书，自动启用本机提交 + 文件验证（local/file）")
	}

	// 如果 API 返回了私钥，立即验证匹配
	if certData.PrivateKey != "" {
		if err := certValidator.ValidateCertKeyPair(certData.Cert, certData.PrivateKey); err != nil {
			fmt.Fprintf(os.Stderr, "  API 返回的私钥与证书不匹配: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("  ✓ API 私钥验证通过")
	}

	fmt.Printf("  订单 ID: %d\n", certData.OrderID)
	fmt.Printf("  证书域名: %s\n", strings.Join(certDomains, ", "))

	// 3. 匹配证书与站点
	fmt.Println("\n步骤 3/7: 匹配证书与站点...")
	m := matcher.New(certDomains)
	fullMatch, partialMatch, _ := m.MatchSites(sites)

	var bindings []config.SiteBinding
	var needSSLInstall []*matcher.ScannedSiteInfo
	hasDockerNonVolume := false

	// 处理完全匹配
	for _, smr := range fullMatch {
		site := smr.Site
		fmt.Printf("\n  ✓ 完全匹配: %s\n", site.ServerName)
		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL，部署时将安装 HTTPS 配置\n")
			if !p.yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			needSSLInstall = append(needSSLInstall, site)
		}
		if site.ContainerID != "" && !site.VolumeMode {
			hasDockerNonVolume = true
		}
		bindings = append(bindings, createBinding(site, p.cfgManager))
	}

	// 处理部分匹配
	for _, smr := range partialMatch {
		site := smr.Site
		fmt.Printf("\n  ~ 部分匹配: %s\n", site.ServerName)
		fmt.Printf("    匹配域名: %s\n", strings.Join(smr.Result.MatchedDomains, ", "))
		fmt.Printf("    未覆盖域名: %s\n", strings.Join(smr.Result.MissedDomains, ", "))

		if !p.yes {
			if !confirm("    是否绑定此站点?") {
				continue
			}
		}

		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL，部署时将安装 HTTPS 配置\n")
			if !p.yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			needSSLInstall = append(needSSLInstall, site)
		}
		if site.ContainerID != "" && !site.VolumeMode {
			hasDockerNonVolume = true
		}
		bindings = append(bindings, createBinding(site, p.cfgManager))
	}

	if len(bindings) == 0 {
		fmt.Fprintln(os.Stderr, "\n未找到可绑定的站点")
		os.Exit(1)
	}

	// 校验验证方式与域名兼容性（在部署前检查，避免部署后配置保存失败导致状态不一致）
	if useFileValidation {
		for i := range bindings {
			if config.IsDockerCopyBinding(&bindings[i]) {
				fmt.Fprintln(os.Stderr, "Docker copy 暂不支持文件验证，请使用 DNS 委托验证")
				exitSetup(1)
			}
		}

		for _, domain := range certDomains {
			if errMsg := config.ValidateValidationMethod(domain, config.ValidationMethodFile); errMsg != "" {
				fmt.Fprintf(os.Stderr, "域名 %s: %s\n", domain, errMsg)
				os.Exit(1)
			}
		}
		// 文件验证无 --webroot 时，检查至少一个绑定有扫描到的 webroot
		if p.webroot == "" {
			hasWebroot := false
			for _, b := range bindings {
				if b.Paths.Webroot != "" {
					hasWebroot = true
					break
				}
			}
			if !hasWebroot {
				fmt.Fprintln(os.Stderr, "未扫描到 webroot，请使用 --webroot 指定")
				os.Exit(1)
			}
		}
	}

	// 4. 验证私钥
	fmt.Println("\n步骤 4/7: 验证私钥...")
	privateKey, err := getAndValidatePrivateKey(p.keyFile, bindings, certData, certValidator, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ✓ 私钥验证通过")

	// 验证中间证书
	if certData.IntermediateCert == "" {
		fmt.Fprintln(os.Stderr, "中间证书为空，无法部署")
		os.Exit(1)
	}

	// 确认部署
	if !p.yes {
		fmt.Printf("\n将部署证书到 %d 个站点:\n", len(bindings))
		for _, b := range bindings {
			fmt.Printf("  - %s (%s)\n", b.ServerName, b.ServerType)
		}
		// Windows 非服务模式提示：部署过程需要重启进程，会短暂中断服务
		if runtime.GOOS == "windows" {
			if name := processRestartServerName(bindings); name != "" {
				fmt.Printf("\n  ⚠ %s 未注册为系统服务，部署过程将通过重启进程重载配置，服务会短暂中断数秒\n", name)
			}
		}
		if !confirm("\n确认部署?") {
			fmt.Println("已取消")
			os.Exit(0)
		}
	}

	// 5. 部署证书
	fmt.Println("\n步骤 5/7: 部署证书...")
	certName := buildCertName(certDomains[0], orderID)

	// 创建证书配置（API 配置写入证书级别）
	certConfig := &config.CertConfig{
		CertName: certName,
		OrderID:  orderID,
		Enabled:  true,
		Domains:  certDomains,
		API: config.APIConfig{
			URL:   p.apiURL,
			Token: p.token,
		},
		Bindings: bindings,
	}

	// 为未启用 SSL 的站点安装 HTTPS 配置（先写入证书文件，再安装配置，避免 nginx -t 失败）
	for _, site := range needSSLInstall {
		var binding *config.SiteBinding
		for i := range bindings {
			if bindings[i].ServerName == site.ServerName {
				binding = &bindings[i]
				break
			}
		}
		if binding == nil || !binding.Enabled {
			continue
		}

		if config.IsDockerCopyBinding(binding) {
			fmt.Fprintf(os.Stderr, "    %s: Docker copy 仅支持已有 HTTPS 配置的站点\n", site.ServerName)
			binding.Enabled = false
			continue
		}

		// 先写入证书和私钥文件
		certDir := filepath.Dir(binding.Paths.Certificate)
		if err := util.EnsureDir(certDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 创建目录失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}

		fullchain := certData.Cert
		if certData.IntermediateCert != "" {
			fullchain += "\n" + certData.IntermediateCert
		}
		if err := prewriteKeyThenCert(binding.Paths.Certificate, binding.Paths.PrivateKey, fullchain, privateKey); err != nil {
			fmt.Fprintf(os.Stderr, "    %s: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}

		// 安装 SSL 配置（此时 nginx -t 可以加载已写入的证书文件）
		result, err := installSSLConfig(site, p.cfgManager)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    %s: 安装 SSL 配置失败: %v\n", site.ServerName, err)
			binding.Enabled = false
			continue
		}
		if result.Modified {
			fmt.Printf("    ✓ %s: SSL 配置已安装（备份: %s）\n", site.ServerName, result.BackupPath)
			updateSiteAfterInstall(site, p.cfgManager)
		}
	}

	// 部署到每个绑定（跳过因 SSL 配置安装失败而被禁用的绑定，计为失败而非误报成功）
	svc := certops.NewService(p.cfgManager, p.log)
	successCount, failedSites, retryableSites := deploySingleBindings(p.ctx, svc, bindings, certData, privateKey)
	failCount := len(failedSites) + len(retryableSites)

	// 上报部署结果（deploy-spec §5.1 步骤 6）。必须在全失败退出之前——
	// 全失败恰是服务端最需要知道的情形，放到保存之后会被 os.Exit(1) 整个跳过。
	sendSetupDeployCallback(p, f, orderID, successCount, failCount)

	// 全部失败时退出
	if successCount == 0 && failCount > 0 {
		p.log.Error("setup 失败: 所有 %d 个站点部署均失败", failCount)
		fmt.Fprintln(os.Stderr, "\n一键部署失败! 所有站点部署均失败")
		exitSetup(1)
	}

	p.log.Info("setup 部署完成: 成功=%d, 失败=%d", successCount, failCount)

	// 保存配置
	fmt.Println("\n步骤 6/7: 保存配置...")

	// 使用步骤 2 已解析的证书设置元数据
	certConfig.Metadata.CertExpiresAt = parsedCert.NotAfter
	certConfig.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
	certConfig.Metadata.LastDeployAt = time.Now()
	// 可重试失败的站点交给 daemon 自愈：不写入就没人接手，绑定虽启用却永远不会被重试
	if len(retryableSites) > 0 {
		certConfig.Metadata.FailedBindings = retryableSites
		certConfig.Metadata.FailedBindingsAt = time.Now()
	}

	if useLocalKey {
		certConfig.RenewMode = config.RenewModeLocal
	}

	// 验证方式和 webroot（域名兼容性已在部署前校验；IP 证书已强制 file）
	if useFileValidation {
		certConfig.ValidationMethod = config.ValidationMethodFile
		if p.webroot != "" {
			for i := range certConfig.Bindings {
				certConfig.Bindings[i].Paths.Webroot = p.webroot
			}
		}
	} else if useLocalKey {
		certConfig.ValidationMethod = config.ValidationMethodDelegation
	}

	if err := p.cfgManager.AddCert(certConfig); err != nil {
		fmt.Fprintf(os.Stderr, "保存证书配置失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  配置已保存: %s\n", p.cfgManager.GetConfigPath())

	// 通知服务端是否自动续签（非关键路径，失败仅记录警告）
	notifyAutoReissue(p, f, orderID, certConfig.RenewMode)

	// 7. 安装守护服务
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

	fmt.Println("\n========================================")
	if failCount > 0 {
		fmt.Printf("一键部署部分完成! 成功 %d 个，失败 %d 个\n", successCount, failCount)
		if len(failedSites) > 0 {
			fmt.Printf("失败站点（已禁用，需修正配置后重新 setup）: %s\n", strings.Join(failedSites, ", "))
		}
		if len(retryableSites) > 0 {
			fmt.Printf("失败站点（保留绑定，守护进程将自动重试）: %s\n", strings.Join(retryableSites, ", "))
		}
	} else {
		fmt.Printf("一键部署完成! 共 %d 个站点\n", successCount)
	}
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", p.cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", p.cfgManager.GetCertsDir())

	fmt.Print(deploymentStatusHint())

	if hasDockerNonVolume && successCount > 0 {
		fmt.Println("\n[!] 检测到 Docker 容器站点的证书路径未挂载为卷")
		fmt.Println("    重建容器后需要重新部署证书")
	}

	// 存在部署失败的站点时非零退出（部分失败也算失败），便于脚本调用方感知
	if hasDeployFailures(failCount, 0, 0) {
		os.Exit(1)
	}
}

// deriveRenewPolicy 按证书域名与命令行参数逐证书派生续签策略（deploy-spec §5.2）。
// SAN 含 IP 的证书强制 local + file；DNS 证书按命令行参数透传。
// 逐证书独立派生，混合批次下 IP 证书不影响 DNS 证书。
// 返回 (useLocalKey, useFileValidation)。
func deriveRenewPolicy(certDomains []string, localKey, fileValidation bool) (useLocalKey, useFileValidation bool) {
	if config.ContainsIPDomain(certDomains) {
		return true, true
	}
	return localKey, fileValidation
}

func scanSitesWithFactory(log *logger.Logger, newScanner func(webserver.ServerType) (webserver.Scanner, error)) []*matcher.ScannedSiteInfo {
	return scanWebServersAndSitesWithFactory(log, newScanner).Sites
}

type webServerSiteScanResult struct {
	ServerTypes []string
	Sites       []*matcher.ScannedSiteInfo
}

func scanWebServersAndSites(log *logger.Logger) webServerSiteScanResult {
	return scanWebServersAndSitesWithFactory(log, webserver.NewScanner)
}

func scanWebServersAndSitesWithFactory(log *logger.Logger, newScanner func(webserver.ServerType) (webserver.Scanner, error)) webServerSiteScanResult {
	var sites []*matcher.ScannedSiteInfo
	var serverTypes []string
	seenServerTypes := make(map[string]struct{})
	addServerType := func(serverType string) {
		if serverType == "" {
			return
		}
		if _, exists := seenServerTypes[serverType]; exists {
			return
		}
		serverTypes = append(serverTypes, serverType)
		seenServerTypes[serverType] = struct{}{}
	}

	for _, wsType := range []webserver.ServerType{webserver.TypeNginx, webserver.TypeApache} {
		scanner, err := newScanner(wsType)
		if err != nil {
			log.Error("创建 %s 扫描器失败: %v", wsType, err)
			continue
		}

		allSites, err := scanner.Scan()
		if err != nil {
			// Prefix 未知是阻塞性错误：打印修复指引并中止，避免写入错误位置
			var prefixErr *sslerrors.PrefixUnknownError
			if errors.As(err, &prefixErr) {
				log.Error("%s prefix 未知，部署中止", wsType)
				fmt.Fprint(os.Stderr, prefixErr.RenderHint())
				os.Exit(1)
			}
			continue
		}
		if len(allSites) == 0 {
			addServerType(string(wsType))
		}

		for _, site := range allSites {
			addServerType(string(site.ServerType))
			sites = append(sites, &matcher.ScannedSiteInfo{
				ServerName:     site.ServerName,
				ServerAlias:    site.ServerAlias,
				ConfigFile:     site.ConfigFile,
				HasSSL:         site.CertificatePath != "",
				CertPath:       site.CertificatePath,
				KeyPath:        site.PrivateKeyPath,
				ChainPath:      site.ChainFile,
				ServerType:     string(site.ServerType),
				ContainerID:    site.ContainerID,
				ContainerName:  site.ContainerName,
				HostCertPath:   site.HostCertPath,
				HostKeyPath:    site.HostKeyPath,
				HostChainPath:  site.HostChainPath,
				VolumeMode:     site.VolumeMode,
				ExecutablePath: site.ExecutablePath,
			})
		}
	}

	// 合并同域名站点（处理 80/443 分开的 server block）
	sites = mergeSameNameSites(sites)

	return webServerSiteScanResult{
		ServerTypes: serverTypes,
		Sites:       sites,
	}
}

func summarizeScannedSites(sites []*matcher.ScannedSiteInfo) (string, []string) {
	var hasLocal, hasDocker bool
	var serverTypes []string
	seenTypes := make(map[string]struct{})

	for _, site := range sites {
		if config.IsDockerType(site.ServerType) || site.ContainerID != "" || site.ContainerName != "" {
			hasDocker = true
		} else {
			hasLocal = true
		}
		if _, exists := seenTypes[site.ServerType]; !exists && site.ServerType != "" {
			serverTypes = append(serverTypes, site.ServerType)
			seenTypes[site.ServerType] = struct{}{}
		}
	}

	environment := "宿主机"
	switch {
	case hasLocal && hasDocker:
		environment = "宿主机 + Docker"
	case hasDocker:
		environment = "Docker"
	}
	return environment, serverTypes
}

func deploymentStatusHint() string {
	return "\n查看部署状态:\n  sslctl status\n"
}

func webServersNotFoundMessage() string {
	return "Nginx 和 Apache 服务均未检测到（已检查宿主机和 Docker）"
}

func deployableSitesNotFoundMessage() string {
	return "未发现可部署站点"
}

// mergeSameNameSites 合并同域名的站点
// 同一域名有多个 server block 时（如 80 和 443 分开），合并为一条，优先保留 SSL 条目的信息
func mergeSameNameSites(sites []*matcher.ScannedSiteInfo) []*matcher.ScannedSiteInfo {
	seen := make(map[string]int) // 服务器实例 + ServerName -> result 中的索引
	var result []*matcher.ScannedSiteInfo

	for _, site := range sites {
		mergeKey := siteMergeKey(site)
		if idx, exists := seen[mergeKey]; exists {
			existing := result[idx]
			if site.HasSSL && !existing.HasSSL {
				// 当前条目有 SSL，替换已有的非 SSL 条目
				// 继承非 SSL 条目的 Webroot（HTTP block 通常有 root 指令）
				if site.Webroot == "" && existing.Webroot != "" {
					site.Webroot = existing.Webroot
				}
				result[idx] = site
			} else if !existing.HasSSL || !site.HasSSL {
				// 已有条目有 SSL、当前没有：仅继承 Webroot
				if existing.Webroot == "" && site.Webroot != "" {
					existing.Webroot = site.Webroot
				}
			}
			// 两个都有 SSL：保持已有条目（先出现的优先）
		} else {
			seen[mergeKey] = len(result)
			result = append(result, site)
		}
	}

	return result
}

func siteMergeKey(site *matcher.ScannedSiteInfo) string {
	container := site.ContainerID
	if container == "" {
		container = site.ContainerName
	}
	return site.ServerType + "\x00" + container + "\x00" + site.ServerName
}

// createBinding 创建站点绑定
func createBinding(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) config.SiteBinding {
	isDocker := config.IsDockerType(site.ServerType)

	// 确定证书路径
	certPath := site.CertPath
	keyPath := site.KeyPath

	// Docker 站点：证书写入宿主机侧挂载路径（容器内路径不能直接写）
	if isDocker && site.VolumeMode {
		if site.HostCertPath != "" {
			certPath = site.HostCertPath
		}
		if site.HostKeyPath != "" {
			keyPath = site.HostKeyPath
		}
	}

	// 本地站点无 SSL 配置时使用默认路径；Docker 站点缺挂载路径由部署层报错，不落默认路径
	if certPath == "" && !isDocker {
		certDir, _ := cm.EnsureSiteCertsDir(site.ServerName)
		certPath = filepath.Join(certDir, "cert.pem")
		keyPath = filepath.Join(certDir, "key.pem")
	}

	binding := config.SiteBinding{
		ServerName: site.ServerName,
		ServerType: site.ServerType,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ConfigFile:  site.ConfigFile,
			Webroot:     site.Webroot,
		},
	}

	// Apache：保留扫描到的 ChainFile 路径（已有 SSLCertificateChainFile 的站点）
	// 新安装 SSL 的站点 ChainPath 为空，使用 fullchain 模式。
	// Docker 卷模式必须用宿主机链路径，否则会把证书链写到容器内路径（宿主机错误位置）。
	if site.VolumeMode && site.HostChainPath != "" {
		binding.Paths.ChainFile = site.HostChainPath
	} else if site.ChainPath != "" {
		binding.Paths.ChainFile = site.ChainPath
	}

	// 设置重载命令（根据系统环境动态检测）
	var cmds webserver.ServerCommands
	switch {
	case isDocker:
		// Docker 站点：容器化 test/reload 命令 + Docker 元信息
		cmds = webserver.DetectDockerCommands(webserver.ServerType(site.ServerType), site.ContainerName)
		deployMode := "copy"
		if site.VolumeMode && site.HostCertPath != "" {
			deployMode = "volume"
		}
		binding.Docker = &config.DockerInfo{
			ContainerName: site.ContainerName,
			DeployMode:    deployMode,
		}
	case site.ServerType == config.ServerTypeNginx:
		cmds = webserver.DetectNginxCommandsFor(site.ExecutablePath)
	case site.ServerType == config.ServerTypeApache:
		cmds = webserver.DetectApacheCommands()
	}
	if cmds.TestCmd != "" {
		binding.Reload = config.ReloadConfig{
			TestCommand:   cmds.TestCmd,
			ReloadCommand: cmds.ReloadCmd,
		}
	}

	return binding
}

// processRestartServerName 检测是否需要进程重启，返回服务器名称（如 "Apache"/"Nginx"），无需则返回空
func processRestartServerName(bindings []config.SiteBinding) string {
	for _, b := range bindings {
		cmd := b.Reload.ReloadCommand
		if strings.Contains(cmd, "-k ") {
			return "Apache"
		}
		if strings.Contains(cmd, "-s reload") {
			return "Nginx"
		}
	}
	return ""
}

// deployToSiteBinding 部署证书到单个站点绑定
// 复用 certops 的部署路径（证书校验 + 现有证书备份 + 失败自动回滚），与 deploy/续签路径一致
func deployToSiteBinding(ctx context.Context, svc *certops.Service, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string) error {
	return svc.DeployToBinding(ctx, binding, certData, privateKey)
}

// deploySingleBindings 部署单证书模式的所有绑定，返回成功数、失败数和失败站点列表。
// 返回值中 failedSites 与 retryableSites 不重叠，失败总数为二者之和：
//   - failedSites：绑定已被禁用（SSL 配置安装失败、或永久性部署错误），daemon 不再接手
//   - retryableSites：绑定保持启用，写入 FailedBindings 交给 daemon 每日重试
//
// 此前所有部署失败一律 Enabled=false，而 nginx -t 失败恰恰是最典型的可修复情形——
// 被禁用后 daemon 永不接手，站点一路静默到真实过期。
func deploySingleBindings(ctx context.Context, svc *certops.Service, bindings []config.SiteBinding, certData *fetcher.CertData, privateKey string) (success int, failedSites, retryableSites []string) {
	for i := range bindings {
		binding := &bindings[i]
		if !binding.Enabled {
			// SSL 配置安装失败等已禁用该绑定：计为失败，避免误报部署成功
			fmt.Fprintf(os.Stderr, "    %s: 跳过部署（SSL 配置安装失败）\n", binding.ServerName)
			failedSites = append(failedSites, binding.ServerName)
			continue
		}
		fmt.Printf("  部署到: %s\n", binding.ServerName)

		if err := deployToSiteBinding(ctx, svc, binding, certData, privateKey); err != nil {
			if sslerrors.IsPermanentDeployError(err) {
				fmt.Fprintf(os.Stderr, "    部署失败（需修正该站点配置后重新 setup）: %v\n", err)
				binding.Enabled = false
				failedSites = append(failedSites, binding.ServerName)
				continue
			}
			fmt.Fprintf(os.Stderr, "    部署失败（保留绑定，将由守护进程重试）: %v\n", err)
			retryableSites = append(retryableSites, binding.ServerName)
			continue
		}
		fmt.Printf("    ✓ 部署成功\n")
		success++
	}
	return
}

// hasDeployFailures 判断本次部署是否存在失败/未完成（用于决定进程退出码）。
// 任一站点部署失败、任一证书失败、或存在需人工提供私钥而跳过的证书，均视为失败。
// 部分失败也算失败，便于脚本调用方通过退出码感知，而非误判为全部成功。
func hasDeployFailures(siteFail, certFail, needKey int) bool {
	return siteFail > 0 || certFail > 0 || needKey > 0
}

// installService 安装守护服务
func installService() error {
	svcMgr, err := service.New(nil)
	if err != nil {
		return err
	}

	// 停止现有服务（忽略错误，可能不存在）
	_ = svcMgr.Stop()

	// 安装服务（已存在时自动删除重建）
	if err := svcMgr.Install(); err != nil {
		return err
	}

	// 启用开机启动
	if err := svcMgr.Enable(); err != nil {
		return err
	}

	// 启动服务
	return svcMgr.Start()
}

// prewriteKeyThenCert 为待安装 SSL 的站点预写证书文件：先写私钥后写证书，
// 与全项目"先写私钥后写证书"原则一致，中途失败不留下"新证书 + 旧私钥"的错配状态。
// 注意：两文件各自原子写，但两者之间尚未事务化（TODO：needSSLInstall 预写整体事务化）。
func prewriteKeyThenCert(certPath, keyPath, fullchain, privateKey string) error {
	if err := util.AtomicWrite(keyPath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}
	if err := util.AtomicWrite(certPath, []byte(fullchain), 0644); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	return nil
}

// installSSLConfig 为未启用 SSL 的站点安装 HTTPS 配置
func installSSLConfig(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) (*webserver.InstallResult, error) {
	// 确定证书路径
	certDir, err := cm.EnsureSiteCertsDir(site.ServerName)
	if err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")

	// Apache 新安装使用 fullchain 模式（cert.pem 包含 cert+intermediate），不生成 SSLCertificateChainFile
	// Nginx 本身就是 fullchain 模式，chainPath 无意义
	chainPath := ""

	// 确定 testCmd（根据站点类型动态检测）
	var testCmd string
	if site.ServerType == config.ServerTypeApache {
		testCmd = webserver.DetectApacheCommands().TestCmd
	} else {
		testCmd = webserver.DetectNginxCommandsFor(site.ExecutablePath).TestCmd
	}

	// 创建安装器
	wsType := webserver.ServerType(site.ServerType)
	installer, err := webserver.NewInstaller(wsType, site.ConfigFile, certPath, keyPath, chainPath, site.ServerName, testCmd)
	if err != nil {
		return nil, fmt.Errorf("创建安装器失败: %w", err)
	}

	// 执行安装
	return installer.Install()
}

// updateSiteAfterInstall 安装 SSL 配置后更新站点信息
func updateSiteAfterInstall(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) {
	certDir, err := cm.EnsureSiteCertsDir(site.ServerName)
	if err != nil {
		// EnsureSiteCertsDir 在 installSSLConfig 中已成功调用过，这里不应失败
		return
	}
	site.HasSSL = true
	site.CertPath = filepath.Join(certDir, "cert.pem")
	site.KeyPath = filepath.Join(certDir, "key.pem")
}

// errNeedPrivateKey 表示前 3 个来源均无可用私钥，需要用户提供
var errNeedPrivateKey = errors.New("需要用户提供私钥")

// getAndValidatePrivateKey 获取并验证私钥与证书匹配
// 优先级: 1. API 返回 → 2. --key 指定路径 → 3. 默认路径 → 4. 交互输入路径
// interactive=false 时跳过第 4 步，返回 errNeedPrivateKey
func getAndValidatePrivateKey(keyFile string, bindings []config.SiteBinding, certData *fetcher.CertData, v *validator.Validator, interactive bool) (string, error) {
	// 1. API 返回了私钥
	if certData.PrivateKey != "" {
		if err := v.ValidateCertKeyPair(certData.Cert, certData.PrivateKey); err != nil {
			return "", fmt.Errorf("API 返回的私钥与证书不匹配: %v", err)
		}
		return certData.PrivateKey, nil
	}

	fmt.Println("  API 未返回私钥，检查本地私钥...")

	// 2. --key 指定了私钥路径
	if keyFile != "" {
		privateKey, err := readAndValidateKeyFile(keyFile, certData.Cert, v)
		if err != nil {
			return "", fmt.Errorf("--key 指定的私钥无效: %v", err)
		}
		return privateKey, nil
	}

	// 获取默认私钥路径（从 binding）
	defaultKeyPath := ""
	for _, b := range bindings {
		if b.Enabled && b.Paths.PrivateKey != "" {
			defaultKeyPath = b.Paths.PrivateKey
			break
		}
	}
	if defaultKeyPath == "" && len(bindings) > 0 {
		defaultKeyPath = bindings[0].Paths.PrivateKey
	}

	// 3. 从绑定的实际位置读取默认私钥（包含 Docker copy）。
	if key, err := certops.GetPrivateKey(context.Background(), &config.CertConfig{Bindings: bindings}, "", nil); err == nil {
		if err := v.ValidateCertKeyPair(certData.Cert, key); err == nil {
			return key, nil
		}
	}
	for i := range bindings {
		if config.IsDockerCopyBinding(&bindings[i]) {
			defaultKeyPath = ""
			break
		}
	}

	// 4. 交互终端：提示用户输入私钥文件路径
	if !interactive || !isInteractiveTerminal() {
		return "", errNeedPrivateKey
	}

	absKeyPath := defaultKeyPath
	if absKeyPath != "" {
		absKeyPath, _ = filepath.Abs(absKeyPath)
		fmt.Printf("  私钥文件不存在: %s\n", absKeyPath)
		fmt.Println("  请输入私钥文件绝对路径（或将私钥放到上述路径后直接按回车）:")
	} else {
		fmt.Println("  请输入私钥文件绝对路径:")
	}
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("读取输入失败: %v", err)
	}
	input = strings.TrimSpace(input)

	// 用户直接按回车：重新检查默认路径
	if input == "" {
		if defaultKeyPath == "" {
			return "", fmt.Errorf("缺少私钥路径")
		}
		privateKey, err := readAndValidateKeyFile(defaultKeyPath, certData.Cert, v)
		if err != nil {
			return "", fmt.Errorf("私钥文件仍不可用: %v", err)
		}
		return privateKey, nil
	}

	// 用户输入了路径
	privateKey, err := readAndValidateKeyFile(input, certData.Cert, v)
	if err != nil {
		return "", fmt.Errorf("私钥文件无效: %v", err)
	}
	return privateKey, nil
}

// readAndValidateKeyFile 读取私钥文件并验证与证书匹配
func readAndValidateKeyFile(keyPath, certPEM string, v *validator.Validator) (string, error) {
	keyData, err := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", fmt.Errorf("读取私钥失败: %v", err)
	}
	privateKey := string(keyData)
	clear(keyData)
	if err := v.ValidateCertKeyPair(certPEM, privateKey); err != nil {
		return "", fmt.Errorf("私钥与证书不匹配: %v", err)
	}
	return privateKey, nil
}

// isInteractiveTerminal 检查 stdin 是否为交互终端
func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// confirm 确认提示
// 非终端环境（如 CI）读取失败时返回 false，需使用 --yes 参数
func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [Y/n]: ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no"
}

// buildCertName 根据域名和订单ID生成证书名称
// 通配符 *.example.com → WILDCARD.example.com-12345
func buildCertName(domain string, orderID int) string {
	name := strings.Replace(domain, "*.", "WILDCARD.", 1)
	return fmt.Sprintf("%s-%d", name, orderID)
}

// extractDomainsFromCert 从证书中提取所有域名：合并 CN + SAN（DNSNames + IPAddresses），去重
func extractDomainsFromCert(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var domains []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	// SAN 优先
	for _, d := range cert.DNSNames {
		add(d)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	// CN 补充（可能不在 SAN 中）
	add(cert.Subject.CommonName)
	return domains
}

// notifyAutoReissue 通知服务端是否自动续签（非关键路径，失败仅记录警告）
// pull 模式 → autoReissue=true；local 模式 → autoReissue=false
// sendSetupDeployCallback 上报一次 setup 的部署结果（deploy-spec §5.1 步骤 6）。
// 非关键路径，失败仅记日志。CLI 无 deadline，显式限定兜底预算，
// 避免部署已完成却让命令再挂几分钟。
//
// 调用位置有硬性要求：必须紧跟部署循环，早于任何 os.Exit 与保存门禁。
// 放到保存阶段会同时被两道关卡吃掉——全失败时 os.Exit(1) 直接结束，
// 保存门禁又会跳过没有成功绑定的证书，而这两类恰恰是最该上报的。
func sendSetupDeployCallback(p *setupParams, f *fetcher.Fetcher, orderID, successCount, failCount int) {
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
		p.log.Warn("上报 setup 部署结果失败（不影响部署结果）: %v", err)
		return
	}
	applyRenewBeforeDays(p.cfgManager, p.log, renewBeforeDays)
}

func notifyAutoReissue(p *setupParams, f *fetcher.Fetcher, orderID int, renewMode string) {
	if p.nonCriticalTripped() {
		return
	}

	autoReissue := renewMode != config.RenewModeLocal

	// CLI ctx 无 deadline，显式限定预算，与其余非关键上报一致；此前裸用 p.ctx，
	// 上界只剩传输层的 4 次尝试 × 60s POST 超时，是同类调用的 2.7 倍。
	// 不同于部署结果回调：本调用不是结果的唯一出口，无需 WithoutCancel 脱离取消传播。
	ctx, cancel := context.WithTimeout(p.ctx, certops.CallbackFallbackBudget)
	defer cancel()

	renewBeforeDays, err := f.ToggleAutoReissue(ctx, p.apiURL, p.token, orderID, autoReissue)
	p.recordNonCritical(err)
	if err != nil {
		p.log.Warn("toggleAutoReissue 失败 (order_id=%d, auto_reissue=%v): %v", orderID, autoReissue, err)
		return
	}
	applyRenewBeforeDays(p.cfgManager, p.log, renewBeforeDays)
}

func applyRenewBeforeDays(cm *config.ConfigManager, log *logger.Logger, value int) {
	if value > config.MaxRenewBeforeDays {
		log.Warn("服务端返回的 renew_before_days=%d 超过上限 %d，保留本地配置", value, config.MaxRenewBeforeDays)
		return
	}
	if _, err := cm.UpdateRenewBeforeDays(value); err != nil {
		log.Warn("更新 renew_before_days 失败: %v", err)
	}
}
