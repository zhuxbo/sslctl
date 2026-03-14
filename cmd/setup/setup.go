// Package setup 一键部署命令
package setup

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/service"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// Run 运行 setup 命令
func Run(args []string, version, buildTime string, debug bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	apiURL := fs.String("url", "", "证书 API 基础地址")
	token := fs.String("token", "", "API 认证 Token")
	orderID := fs.Int("order", 0, "订单 ID")
	localKey := fs.Bool("local-key", false, "使用本地私钥模式")
	yes := fs.Bool("yes", false, "跳过确认提示")
	noService := fs.Bool("no-service", false, "不安装守护服务")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl setup --url <base_url> --token <token> --order <order_id>\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *apiURL == "" || *token == "" || *orderID == 0 {
		fs.Usage()
		os.Exit(1)
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
	if existingCfg, loadErr := cfgManager.Load(); loadErr == nil && existingCfg.API.URL != "" {
		fmt.Println("检测到已有配置，将更新 API 和证书配置（保留 Schedule 等设置）")
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

	ctx := context.Background()

	// 1. 检测 Web 服务器
	fmt.Println("步骤 1/6: 检测 Web 服务器...")
	serverType := webserver.DetectWebServerType()
	if serverType == "" {
		fmt.Fprintln(os.Stderr, "未检测到 Nginx 或 Apache 服务")
		os.Exit(1)
	}
	fmt.Printf("  检测到: %s\n", serverType)

	// 2. 获取证书信息
	fmt.Println("\n步骤 2/6: 获取证书信息...")
	f := fetcher.New(30 * time.Second)
	certData, err := f.QueryOrder(ctx, *apiURL, *token, *orderID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询订单失败: %v\n", err)
		os.Exit(1)
	}

	if certData.Status != "active" || certData.Cert == "" {
		fmt.Fprintf(os.Stderr, "证书未就绪: status=%s\n", certData.Status)
		os.Exit(1)
	}

	// 解析域名列表
	certDomains := parseDomains(certData.Domains)
	if len(certDomains) == 0 && certData.Domain != "" {
		certDomains = []string{certData.Domain}
	}
	if len(certDomains) == 0 && certData.CommonName != "" {
		certDomains = []string{certData.CommonName}
	}
	fmt.Printf("  订单 ID: %d\n", certData.OrderID)
	fmt.Printf("  证书域名: %s\n", strings.Join(certDomains, ", "))

	// 3. 扫描站点并匹配
	fmt.Println("\n步骤 3/6: 扫描站点...")
	sites := scanSites(serverType, log)
	if len(sites) == 0 {
		fmt.Fprintln(os.Stderr, "未发现站点配置")
		os.Exit(1)
	}
	fmt.Printf("  发现 %d 个站点\n", len(sites))

	// 匹配域名
	m := matcher.New(certDomains)
	fullMatch, partialMatch, _ := m.MatchSites(sites)

	var bindings []config.SiteBinding

	// 处理完全匹配
	for _, smr := range fullMatch {
		site := smr.Site
		fmt.Printf("\n  ✓ 完全匹配: %s\n", site.ServerName)
		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL\n")
			if !*yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			result, err := installSSLConfig(site, cfgManager)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    安装 SSL 配置失败: %v\n", err)
				continue
			}
			if result.Modified {
				fmt.Printf("    ✓ SSL 配置已安装（备份: %s）\n", result.BackupPath)
				updateSiteAfterInstall(site, cfgManager)
			}
		}
		bindings = append(bindings, createBinding(site, cfgManager))
	}

	// 处理部分匹配
	for _, smr := range partialMatch {
		site := smr.Site
		fmt.Printf("\n  ~ 部分匹配: %s\n", site.ServerName)
		fmt.Printf("    匹配域名: %s\n", strings.Join(smr.Result.MatchedDomains, ", "))
		fmt.Printf("    未覆盖域名: %s\n", strings.Join(smr.Result.MissedDomains, ", "))

		if !*yes {
			if !confirm("    是否绑定此站点?") {
				continue
			}
		}

		if !site.HasSSL {
			fmt.Printf("    站点未启用 SSL\n")
			if !*yes {
				if !confirm("    是否安装 HTTPS 配置?") {
					continue
				}
			}
			result, err := installSSLConfig(site, cfgManager)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    安装 SSL 配置失败: %v\n", err)
				continue
			}
			if result.Modified {
				fmt.Printf("    ✓ SSL 配置已安装（备份: %s）\n", result.BackupPath)
				updateSiteAfterInstall(site, cfgManager)
			}
		}
		bindings = append(bindings, createBinding(site, cfgManager))
	}

	if len(bindings) == 0 {
		fmt.Fprintln(os.Stderr, "\n未找到可绑定的站点")
		os.Exit(1)
	}

	// 4. 确认部署
	if !*yes {
		fmt.Printf("\n将部署证书到 %d 个站点:\n", len(bindings))
		for _, b := range bindings {
			fmt.Printf("  - %s (%s)\n", b.SiteName, b.ServerType)
		}
		if !confirm("\n确认部署?") {
			fmt.Println("已取消")
			os.Exit(0)
		}
	}

	// 5. 部署证书
	fmt.Println("\n步骤 4/6: 部署证书...")
	certName := fmt.Sprintf("order-%d", *orderID)

	// 创建证书配置
	certConfig := &config.CertConfig{
		CertName: certName,
		OrderID:  *orderID,
		Enabled:  true,
		Domains:  certDomains,
		Bindings: bindings,
	}

	// 获取私钥：优先使用 API 返回，否则从站点现有路径读取
	privateKey, err := certops.GetPrivateKeyFromBindings(bindings, certData.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取私钥失败: %v\n", err)
		os.Exit(1)
	}
	if certData.PrivateKey == "" && len(bindings) > 0 && bindings[0].Paths.PrivateKey != "" {
		fmt.Printf("  使用本地私钥: %s\n", bindings[0].Paths.PrivateKey)
	}

	// 验证私钥与证书匹配
	v := validator.New("")
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "私钥与证书不匹配: %v\n", err)
		os.Exit(1)
	}

	// 验证中间证书
	if certData.IntermediateCert == "" {
		fmt.Fprintln(os.Stderr, "中间证书为空，无法部署")
		os.Exit(1)
	}

	// 部署到每个绑定
	var successCount, failCount int
	var failedSites []string
	for i := range bindings {
		binding := &bindings[i]
		fmt.Printf("  部署到: %s\n", binding.SiteName)

		if err := deployToSiteBinding(ctx, binding, certData, privateKey, log); err != nil {
			fmt.Fprintf(os.Stderr, "    部署失败: %v\n", err)
			failCount++
			failedSites = append(failedSites, binding.SiteName)
			binding.Enabled = false // 标记失败绑定为禁用，避免守护进程持续重试
			continue
		}
		fmt.Printf("    ✓ 部署成功\n")
		successCount++
	}

	// 全部失败时退出
	if successCount == 0 && failCount > 0 {
		fmt.Fprintln(os.Stderr, "\n一键部署失败! 所有站点部署均失败")
		os.Exit(1)
	}

	// 保存配置
	fmt.Println("\n步骤 5/6: 保存配置...")

	// 验证证书获取过期时间
	cert, err := v.ValidateCert(certData.Cert)
	if err == nil {
		certConfig.Metadata.CertExpiresAt = cert.NotAfter
		certConfig.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	}
	certConfig.Metadata.LastDeployAt = time.Now()

	// 初始化或更新配置
	// 先保存 API 配置（Load 返回副本，直接修改不会持久化）
	if err := cfgManager.SetAPI(config.APIConfig{
		URL:   *apiURL,
		Token: *token,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "保存 API 配置失败: %v\n", err)
		os.Exit(1)
	}

	if *localKey {
		certConfig.RenewMode = config.RenewModeLocal
	}

	if err := cfgManager.AddCert(certConfig); err != nil {
		fmt.Fprintf(os.Stderr, "保存证书配置失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  配置已保存: %s\n", cfgManager.GetConfigPath())

	// 6. 安装守护服务
	if !*noService {
		fmt.Println("\n步骤 6/6: 安装守护服务...")
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "  安装服务失败: %v\n", err)
			fmt.Println("  可稍后使用 'sslctl service repair' 修复")
		} else {
			fmt.Println("  ✓ 服务已安装并启动")
		}
	} else {
		fmt.Println("\n步骤 6/6: 跳过服务安装 (--no-service)")
	}

	fmt.Println("\n========================================")
	if failCount > 0 {
		fmt.Printf("一键部署部分完成! 成功 %d 个，失败 %d 个\n", successCount, failCount)
		fmt.Printf("失败站点: %s\n", strings.Join(failedSites, ", "))
	} else {
		fmt.Printf("一键部署完成! 共 %d 个站点\n", successCount)
	}
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", cfgManager.GetCertsDir())

	if !*noService {
		fmt.Println("\n守护服务命令:")
		fmt.Println("  systemctl status sslctl    # 查看状态")
		fmt.Println("  journalctl -u sslctl -f    # 查看日志")
	}
}

// scanSites 扫描站点（使用 webserver 抽象层）
func scanSites(serverType string, log *logger.Logger) []*matcher.ScannedSiteInfo {
	var sites []*matcher.ScannedSiteInfo

	// 确定服务器类型
	wsType := webserver.TypeNginx
	if serverType == "apache" {
		wsType = webserver.TypeApache
	}

	// 使用抽象层创建扫描器
	scanner, err := webserver.NewScanner(wsType)
	if err != nil {
		log.Error("创建扫描器失败: %v", err)
		return sites
	}

	// 扫描站点
	allSites, err := scanner.Scan()
	if err != nil {
		log.Error("扫描 %s 失败: %v", serverType, err)
		return sites
	}

	// 转换为 matcher.ScannedSiteInfo
	for _, site := range allSites {
		sites = append(sites, &matcher.ScannedSiteInfo{
			ServerName:  site.ServerName,
			ServerAlias: site.ServerAlias,
			ConfigFile:  site.ConfigFile,
			HasSSL:      site.CertificatePath != "",
			CertPath:    site.CertificatePath,
			KeyPath:     site.PrivateKeyPath,
			ServerType:  string(site.ServerType),
		})
	}

	return sites
}

// createBinding 创建站点绑定
func createBinding(site *matcher.ScannedSiteInfo, cm *config.ConfigManager) config.SiteBinding {
	// 确定证书路径
	certPath := site.CertPath
	keyPath := site.KeyPath

	// 如果站点没有 SSL 配置，使用默认路径
	if certPath == "" {
		certDir, _ := cm.EnsureSiteCertsDir(site.ServerName)
		certPath = filepath.Join(certDir, "cert.pem")
		keyPath = filepath.Join(certDir, "key.pem")
	}

	binding := config.SiteBinding{
		SiteName:   site.ServerName,
		ServerType: site.ServerType,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ConfigFile:  site.ConfigFile,
		},
	}

	// Apache 需要设置证书链路径
	if site.ServerType == config.ServerTypeApache {
		if binding.Paths.ChainFile == "" {
			certDir, _ := cm.EnsureSiteCertsDir(site.ServerName)
			binding.Paths.ChainFile = filepath.Join(certDir, "chain.pem")
		}
	}

	// 设置重载命令
	if site.ServerType == config.ServerTypeNginx {
		binding.Reload = config.ReloadConfig{
			TestCommand:   "nginx -t",
			ReloadCommand: "nginx -s reload",
		}
	} else {
		binding.Reload = config.ReloadConfig{
			TestCommand:   "apache2ctl -t",
			ReloadCommand: "systemctl reload apache2",
		}
	}

	return binding
}

// deployToSiteBinding 部署证书到单个站点绑定
func deployToSiteBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 使用 webserver 抽象层创建部署器
	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return fmt.Errorf("创建部署器失败: %w", err)
	}

	return deployer.Deploy(certData.Cert, certData.IntermediateCert, privateKey)
}

// installService 安装守护服务
func installService() error {
	svcMgr, err := service.New(nil)
	if err != nil {
		return err
	}

	// 停止现有服务
	_ = svcMgr.Stop()

	// 安装服务
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

// parseDomains 解析域名列表
func parseDomains(domainsStr string) []string {
	if domainsStr == "" {
		return nil
	}
	var domains []string
	for _, d := range strings.Split(domainsStr, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			domains = append(domains, d)
		}
	}
	return domains
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
	chainPath := filepath.Join(certDir, "chain.pem")

	// 确定 testCmd（根据站点类型而非全局检测类型）
	testCmd := "nginx -t"
	if site.ServerType == config.ServerTypeApache {
		testCmd = "apache2ctl -t"
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

// confirm 确认提示
func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [Y/n]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no"
}
