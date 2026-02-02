// Package setup 一键部署命令
package setup

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	apacheDeployer "github.com/zhuxbo/cert-deploy/internal/apache/deployer"
	apacheScanner "github.com/zhuxbo/cert-deploy/internal/apache/scanner"
	nginxDeployer "github.com/zhuxbo/cert-deploy/internal/nginx/deployer"
	nginxScanner "github.com/zhuxbo/cert-deploy/internal/nginx/scanner"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
	"github.com/zhuxbo/cert-deploy/pkg/matcher"
	"github.com/zhuxbo/cert-deploy/pkg/service"
	"github.com/zhuxbo/cert-deploy/pkg/validator"
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
		fmt.Fprintf(os.Stderr, "用法: cert-deploy setup --url <base_url> --token <token> --order <order_id>\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *apiURL == "" || *token == "" || *orderID == 0 {
		fs.Usage()
		os.Exit(1)
	}

	// 检查权限
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "请使用 root 权限运行此命令")
		os.Exit(1)
	}

	// 创建配置管理器
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
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
	serverType := detectWebServer()
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
			fmt.Printf("    警告: 站点未启用 SSL，需要先安装 HTTPS 配置\n")
			continue
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
			fmt.Printf("    警告: 站点未启用 SSL，需要先安装 HTTPS 配置\n")
			continue
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
	privateKey := certData.PrivateKey
	if privateKey == "" && len(bindings) > 0 {
		// 本地私钥模式：尝试从第一个绑定的私钥路径读取
		keyPath := bindings[0].Paths.PrivateKey
		if keyPath != "" {
			keyData, err := os.ReadFile(keyPath)
			if err == nil {
				privateKey = string(keyData)
				fmt.Printf("  使用本地私钥: %s\n", keyPath)
			}
		}
	}

	if privateKey == "" {
		fmt.Fprintln(os.Stderr, "缺少私钥（API 未返回且本地不存在）")
		os.Exit(1)
	}

	// 验证私钥与证书匹配
	v := validator.New("")
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "私钥与证书不匹配: %v\n", err)
		os.Exit(1)
	}

	// 部署到每个绑定
	for i := range bindings {
		binding := &bindings[i]
		fmt.Printf("  部署到: %s\n", binding.SiteName)

		if err := deployCert(ctx, binding, certData, privateKey, log); err != nil {
			fmt.Fprintf(os.Stderr, "    部署失败: %v\n", err)
			continue
		}
		fmt.Printf("    ✓ 部署成功\n")
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
	cfg, err := cfgManager.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	cfg.API = config.APIConfig{
		URL:   *apiURL,
		Token: *token,
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
			fmt.Println("  可稍后使用 'cert-deploy service repair' 修复")
		} else {
			fmt.Println("  ✓ 服务已安装并启动")
		}
	} else {
		fmt.Println("\n步骤 6/6: 跳过服务安装 (--no-service)")
	}

	fmt.Println("\n========================================")
	fmt.Println("一键部署完成!")
	fmt.Println("========================================")
	fmt.Printf("\n配置文件: %s\n", cfgManager.GetConfigPath())
	fmt.Printf("证书目录: %s\n", cfgManager.GetCertsDir())

	if !*noService {
		fmt.Println("\n守护服务命令:")
		fmt.Println("  systemctl status cert-deploy    # 查看状态")
		fmt.Println("  journalctl -u cert-deploy -f    # 查看日志")
	}
}

// detectWebServer 检测 Web 服务器类型
func detectWebServer() string {
	if _, err := exec.LookPath("nginx"); err == nil {
		if _, err := nginxScanner.DetectNginx(); err == nil {
			return "nginx"
		}
	}

	if _, err := exec.LookPath("apache2ctl"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}
	if _, err := exec.LookPath("apachectl"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}
	if _, err := exec.LookPath("httpd"); err == nil {
		if _, _, err := apacheScanner.DetectApache(); err == nil {
			return "apache"
		}
	}

	return ""
}

// scanSites 扫描站点
func scanSites(serverType string, log *logger.Logger) []*matcher.ScannedSiteInfo {
	var sites []*matcher.ScannedSiteInfo

	if serverType == "nginx" {
		s := nginxScanner.New()
		allSites, err := s.ScanAll()
		if err != nil {
			log.Error("扫描 Nginx 失败: %v", err)
			return sites
		}

		for _, site := range allSites {
			sites = append(sites, &matcher.ScannedSiteInfo{
				ServerName:  site.ServerName,
				ServerAlias: site.ServerAlias,
				ConfigFile:  site.ConfigFile,
				HasSSL:      site.HasSSL,
				CertPath:    site.CertificatePath,
				KeyPath:     site.PrivateKeyPath,
				Webroot:     site.Webroot,
				ServerType:  config.ServerTypeNginx,
			})
		}
	} else {
		s := apacheScanner.New()
		allSites, err := s.ScanAll()
		if err != nil {
			log.Error("扫描 Apache 失败: %v", err)
			return sites
		}

		for _, site := range allSites {
			sites = append(sites, &matcher.ScannedSiteInfo{
				ServerName:  site.ServerName,
				ServerAlias: site.ServerAlias,
				ConfigFile:  site.ConfigFile,
				HasSSL:      site.HasSSL,
				CertPath:    site.CertificatePath,
				KeyPath:     site.PrivateKeyPath,
				Webroot:     site.Webroot,
				ServerType:  config.ServerTypeApache,
			})
		}
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

// deployCert 部署证书
func deployCert(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	if binding.ServerType == config.ServerTypeNginx || binding.ServerType == config.ServerTypeDockerNginx {
		d := nginxDeployer.NewNginxDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		return d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)
	}

	d := apacheDeployer.NewApacheDeployer(
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	return d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)
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

// confirm 确认提示
func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
