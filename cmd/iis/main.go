// IIS 证书部署客户端
// 扫描 IIS SSL 站点，自动部署证书
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cnssl/cert-deploy/internal/iis/deployer"
	"github.com/cnssl/cert-deploy/internal/iis/installer"
	"github.com/cnssl/cert-deploy/internal/iis/scanner"
	"github.com/cnssl/cert-deploy/pkg/config"
	"github.com/cnssl/cert-deploy/pkg/fetcher"
	"github.com/cnssl/cert-deploy/pkg/issuer"
	"github.com/cnssl/cert-deploy/pkg/logger"
	"github.com/cnssl/cert-deploy/pkg/prompt"
	"github.com/cnssl/cert-deploy/pkg/util"
	"github.com/cnssl/cert-deploy/pkg/validator"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// 命令行参数
	var (
		showVersion  = flag.Bool("version", false, "显示版本信息")
		scanOnly     = flag.Bool("scan", false, "仅扫描显示 IIS SSL 站点")
		siteName     = flag.String("site", "", "部署指定站点")
		issueMode    = flag.Bool("issue", false, "发起证书签发（用于 file 验证）")
		installHTTPS = flag.Bool("install-https", false, "为 HTTP 站点安装 HTTPS 绑定")
		daemon       = flag.Bool("daemon", false, "守护进程模式")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-deploy-iis %s (built at %s)\n", version, buildTime)
		os.Exit(0)
	}

	// 验证 IIS 模块
	s := scanner.New()
	if err := s.ValidateIIS(); err != nil {
		fmt.Fprintf(os.Stderr, "IIS 模块验证失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化配置管理器
	cfgManager, err := config.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	log, err := logger.New(cfgManager.GetLogsDir(), "iis")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if *scanOnly {
		runScan(log)
	} else if *daemon {
		runDaemon(cfgManager, log)
	} else if *siteName != "" && *issueMode {
		if err := issueSite(cfgManager, *siteName, log); err != nil {
			log.Error("签发失败: %v", err)
			os.Exit(1)
		}
	} else if *installHTTPS && *siteName == "" {
		// 交互式安装 HTTPS 绑定模式
		if err := interactiveInstallHTTPS(cfgManager, log); err != nil {
			log.Error("安装 HTTPS 绑定失败: %v", err)
			os.Exit(1)
		}
	} else if *siteName != "" && *installHTTPS {
		if err := installHTTPSSite(cfgManager, *siteName, log); err != nil {
			log.Error("安装 HTTPS 绑定失败: %v", err)
			os.Exit(1)
		}
	} else if *siteName != "" {
		if err := deploySite(cfgManager, *siteName, log); err != nil {
			log.Error("部署失败: %v", err)
			os.Exit(1)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
}

// runScan 扫描并显示所有 IIS SSL 站点
func runScan(log *logger.Logger) {
	s := scanner.New()
	sites, err := s.Scan()
	if err != nil {
		log.Error("扫描失败: %v", err)
		fmt.Printf("扫描失败: %v\n", err)
		return
	}

	log.LogScan("IIS", len(sites))

	if len(sites) == 0 {
		fmt.Println("未发现 IIS SSL 站点")
		return
	}

	fmt.Printf("发现 %d 个 IIS SSL 站点:\n\n", len(sites))
	for i, site := range sites {
		fmt.Printf("%d. %s\n", i+1, site.SiteName)
		fmt.Printf("   主机名:   %s\n", site.HostName)
		fmt.Printf("   端口:     %s\n", site.Port)
		fmt.Printf("   证书指纹: %s\n", site.CertThumbprint)
		if !site.CertExpires.IsZero() {
			fmt.Printf("   证书到期: %s\n", site.CertExpires.Format("2006-01-02"))
		}
		fmt.Printf("   证书主题: %s\n", site.CertSubject)
		if site.PhysicalPath != "" {
			fmt.Printf("   物理路径: %s\n", site.PhysicalPath)
		}
		fmt.Println()
	}
}

// runDaemon 守护进程模式
func runDaemon(cfgManager *config.Manager, log *logger.Logger) {
	log.Info("启动守护进程模式")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 立即执行一次
	checkAndDeploy(ctx, cfgManager, log)

	for {
		select {
		case <-ticker.C:
			checkAndDeploy(ctx, cfgManager, log)
		case sig := <-sigCh:
			log.Info("收到信号 %v，正在退出", sig)
			return
		}
	}
}

// checkAndDeploy 检查并部署证书
func checkAndDeploy(ctx context.Context, cfgManager *config.Manager, log *logger.Logger) {
	log.Info("开始检查证书...")

	// 1. 扫描 IIS 站点
	s := scanner.New()
	scannedSites, err := s.Scan()
	if err != nil {
		log.Warn("扫描 IIS 站点失败: %v", err)
	} else {
		log.LogScan("IIS", len(scannedSites))
	}

	// 2. 构建站点名称到扫描站点的映射
	scannedMap := make(map[string]*scanner.SSLSite)
	for _, site := range scannedSites {
		scannedMap[site.SiteName] = site
		// 同时按主机名映射
		if site.HostName != "" {
			scannedMap[site.HostName] = site
		}
	}

	// 3. 加载站点配置
	sites, err := cfgManager.ListSites()
	if err != nil {
		log.Error("加载站点配置失败: %v", err)
		return
	}

	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		// 只处理 iis 类型的站点
		if site.ServerType != "iis" {
			continue
		}

		// 检查是否需要续期
		if !site.NeedsRenewal() {
			log.Debug("站点 %s 证书有效，跳过", site.SiteName)
			continue
		}

		// 匹配扫描到的站点
		var scanned *scanner.SSLSite
		if s, ok := scannedMap[site.SiteName]; ok {
			scanned = s
		} else {
			for _, domain := range site.Domains {
				if s, ok := scannedMap[domain]; ok {
					scanned = s
					break
				}
			}
		}

		if err := deploySiteConfig(ctx, cfgManager, site, scanned, log); err != nil {
			log.Error("部署站点 %s 失败: %v", site.SiteName, err)
		}
	}

	log.Info("检查完成")
}

// deploySite 部署指定站点
func deploySite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	// 扫描获取当前站点信息
	s := scanner.New()
	scanned, _ := s.FindBySiteName(siteName)
	if scanned == nil {
		// 尝试通过域名查找
		for _, domain := range site.Domains {
			scanned, _ = s.FindByHostName(domain)
			if scanned != nil {
				break
			}
		}
	}

	// 如果没有找到 SSL 站点，检查是否有 HTTP 站点并提示安装
	if scanned == nil {
		// 尝试查找 HTTP 站点
		httpSites, _ := s.ScanHTTPSites()
		var httpSite *scanner.HTTPSite
		for _, hs := range httpSites {
			if hs.SiteName == siteName {
				httpSite = hs
				break
			}
			for _, domain := range site.Domains {
				if hs.HostName == domain {
					httpSite = hs
					break
				}
			}
			if httpSite != nil {
				break
			}
		}

		if httpSite != nil {
			fmt.Printf("检测到站点 %s 尚未配置 HTTPS 绑定\n", siteName)

			if prompt.IsInteractive() && prompt.Confirm("是否现在安装 HTTPS 绑定?") {
				// 输入证书指纹
				thumbprint := prompt.InputRequired("证书指纹 (Thumbprint)")

				// 确定主机名
				hostname := httpSite.HostName
				if hostname == "" && len(site.Domains) > 0 {
					hostname = site.Domains[0]
				}

				// 安装 HTTPS 绑定
				inst := installer.NewIISInstaller(
					httpSite.SiteName,
					hostname,
					443,
					thumbprint,
				)

				result, err := inst.Install()
				if err != nil {
					return fmt.Errorf("安装 HTTPS 绑定失败: %w", err)
				}

				if result.BindingCreated {
					log.Info("HTTPS 绑定安装成功: %s", httpSite.SiteName)
					fmt.Printf("✓ HTTPS 绑定安装成功\n")
					fmt.Printf("%s\n", result.Message)
				}

				// 重新扫描获取 scanned
				scanned, _ = s.FindBySiteName(httpSite.SiteName)
			} else {
				return fmt.Errorf("站点 %s 未配置 HTTPS 绑定，请先使用 -install-https 安装", siteName)
			}
		}
	}

	ctx := context.Background()
	return deploySiteConfig(ctx, cfgManager, site, scanned, log)
}

// issueSite 签发并部署证书
func issueSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	// 扫描获取当前站点信息
	s := scanner.New()
	scanned, _ := s.FindBySiteName(siteName)
	if scanned == nil {
		for _, domain := range site.Domains {
			scanned, _ = s.FindByHostName(domain)
			if scanned != nil {
				break
			}
		}
	}

	// 获取 webroot
	webroot := site.Paths.Webroot
	if webroot == "" && scanned != nil {
		webroot = scanned.PhysicalPath
	}

	// 使用 issuer 模块签发证书
	iss := issuer.New(log)
	opts := issuer.IssueOptions{
		Webroot:          webroot,
		ValidationMethod: "file",
	}

	log.Info("开始签发证书: %s", site.SiteName)

	result, err := iss.Issue(context.Background(), site, opts)
	if err != nil {
		return fmt.Errorf("证书签发失败: %w", err)
	}

	// 更新元数据
	site.Metadata.CSRSubmittedAt = time.Now()
	site.Metadata.LastCSRHash = result.CSRHash
	site.Metadata.LastIssueState = result.CertData.Status

	// 构造 certData 用于部署
	certData := result.CertData

	// 使用签发返回的私钥
	privateKey := result.PrivateKey
	if certData.PrivateKey != "" {
		privateKey = certData.PrivateKey
	}

	// 部署证书
	return deployWithCertData(cfgManager, site, scanned, certData, privateKey, log)
}

// deployWithCertData 使用已获取的证书数据部署
func deployWithCertData(cfgManager *config.Manager, site *config.SiteConfig, scanned *scanner.SSLSite, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	// 验证证书
	v := validator.New("")
	cert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	// 验证域名覆盖
	dv := validator.NewDomainValidator(site.Domains, site.Validation.IgnoreDomainMismatch)
	if err := dv.ValidateDomainCoverage(cert); err != nil {
		return fmt.Errorf("域名验证失败: %w", err)
	}

	// 验证证书和私钥配对
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("证书私钥配对验证失败: %w", err)
	}

	// 确定 IIS 站点名称和端口
	iisSiteName := site.SiteName
	hostname := ""
	port := 443

	if len(site.Domains) > 0 {
		hostname = site.Domains[0]
	}

	if scanned != nil {
		iisSiteName = scanned.SiteName
		if scanned.HostName != "" {
			hostname = scanned.HostName
		}
		if scanned.Port != "" {
			_, _ = fmt.Sscanf(scanned.Port, "%d", &port)
		}
	}

	// 部署证书到 IIS
	d := deployer.NewIISDeployer(iisSiteName, hostname, port, cfgManager.GetSiteCertsDir(site.SiteName))

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, "", "", false, err)
		return fmt.Errorf("IIS 部署失败: %w", err)
	}

	log.LogDeployment(site.SiteName, "IIS Certificate Store", "", true, nil)

	// 更新元数据
	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		log.Warn("保存站点元数据失败: %v", err)
	}

	// 发送部署回调
	if site.API.CallbackURL != "" {
		f := fetcher.New(30 * time.Second)
		callbackReq := &fetcher.CallbackRequest{
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "iis",
		}
		ctx := context.Background()
		if err := f.Callback(ctx, site.API.CallbackURL, site.API.ReferID, callbackReq); err != nil {
			log.Warn("发送部署回调失败: %v", err)
		} else {
			log.Info("部署回调发送成功")
		}
	}

	log.Info("站点 %s 部署成功，证书有效期至 %s", site.SiteName, cert.NotAfter.Format("2006-01-02"))
	return nil
}

// deploySiteConfig 部署站点配置
func deploySiteConfig(ctx context.Context, cfgManager *config.Manager, site *config.SiteConfig, scanned *scanner.SSLSite, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	// 1. 获取证书
	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, site.API.URL, site.API.ReferID)
	if err != nil {
		return fmt.Errorf("获取证书失败: %w", err)
	}

	// 1.1 处理文件验证 (status=processing 且返回 file 数据)
	if certData.Status == "processing" && certData.File != nil {
		// 获取 webroot：优先使用配置，其次使用扫描到的 PhysicalPath
		webroot := site.Paths.Webroot
		if webroot == "" && scanned != nil {
			webroot = scanned.PhysicalPath
		}
		if webroot == "" {
			return fmt.Errorf("证书需要文件验证，但未配置 webroot 路径")
		}

		// 写入验证文件
		validationPath, err := util.JoinUnderDir(webroot, certData.File.Path)
		if err != nil {
			return fmt.Errorf("验证文件路径无效: %w", err)
		}
		validationDir := filepath.Dir(validationPath)

		if err := os.MkdirAll(validationDir, 0755); err != nil {
			return fmt.Errorf("创建验证文件目录失败: %w", err)
		}

		if err := os.WriteFile(validationPath, []byte(certData.File.Content), 0644); err != nil {
			return fmt.Errorf("写入验证文件失败: %w", err)
		}

		log.Info("验证文件已放置: %s", validationPath)

		// 等待证书签发完成 (最多等待 5 分钟，每 10 秒检查一次)
		maxWait := 5 * time.Minute
		checkInterval := 10 * time.Second
		deadline := time.Now().Add(maxWait)

		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(checkInterval):
				certData, err = f.Info(ctx, site.API.URL, site.API.ReferID)
				if err != nil {
					log.Warn("检查证书状态失败: %v", err)
					continue
				}

				if certData.Status == "active" && certData.Cert != "" {
					log.Info("证书签发完成")
					// 清理验证文件
					os.Remove(validationPath)
					goto deploy
				}

				log.Debug("证书状态: %s，继续等待...", certData.Status)
			}
		}

		// 超时清理验证文件
		os.Remove(validationPath)
		return fmt.Errorf("等待证书签发超时: status=%s", certData.Status)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return fmt.Errorf("证书未就绪: status=%s", certData.Status)
	}

deploy:

	// 2. 验证证书
	v := validator.New("")
	cert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	// 3. 验证域名覆盖
	dv := validator.NewDomainValidator(site.Domains, site.Validation.IgnoreDomainMismatch)
	if err := dv.ValidateDomainCoverage(cert); err != nil {
		return fmt.Errorf("域名验证失败: %w", err)
	}

	// 4. 获取私钥
	privateKey := certData.PrivateKey
	if privateKey == "" {
		return fmt.Errorf("API 未返回私钥，IIS 部署需要私钥")
	}

	// 4.1 验证证书和私钥配对
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("证书私钥配对验证失败: %w", err)
	}

	// 5. 确定 IIS 站点名称和端口
	iisSiteName := site.SiteName
	hostname := ""
	port := 443

	if len(site.Domains) > 0 {
		hostname = site.Domains[0]
	}

	// 如果扫描到了站点，使用扫描的站点名称
	if scanned != nil {
		iisSiteName = scanned.SiteName
		if scanned.HostName != "" {
			hostname = scanned.HostName
		}
		if scanned.Port != "" {
			_, _ = fmt.Sscanf(scanned.Port, "%d", &port)
		}
	}

	// 6. 部署证书到 IIS
	d := deployer.NewIISDeployer(iisSiteName, hostname, port, cfgManager.GetSiteCertsDir(site.SiteName))

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, "", "", false, err)
		return fmt.Errorf("IIS 部署失败: %w", err)
	}

	log.LogDeployment(site.SiteName, "IIS Certificate Store", "", true, nil)

	// 7. 更新元数据
	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		log.Warn("保存站点元数据失败: %v", err)
	}

	// 8. 发送部署回调
	if site.API.CallbackURL != "" {
		callbackReq := &fetcher.CallbackRequest{
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "iis",
		}
		if err := f.Callback(ctx, site.API.CallbackURL, site.API.ReferID, callbackReq); err != nil {
			log.Warn("发送部署回调失败: %v", err)
		} else {
			log.Info("部署回调发送成功")
		}
	}

	log.Info("站点 %s 部署成功，证书有效期至 %s", site.SiteName, cert.NotAfter.Format("2006-01-02"))
	return nil
}

// installHTTPSSite 为站点安装 HTTPS 绑定
func installHTTPSSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	// 扫描获取当前站点信息
	s := scanner.New()
	scanned, _ := s.FindBySiteName(siteName)
	if scanned == nil {
		// 尝试通过域名查找
		for _, domain := range site.Domains {
			scanned, _ = s.FindByHostName(domain)
			if scanned != nil {
				break
			}
		}
	}

	// 确定 IIS 站点名称和证书指纹
	iisSiteName := site.SiteName
	hostname := ""
	port := 443
	thumbprint := ""

	if len(site.Domains) > 0 {
		hostname = site.Domains[0]
	}

	if scanned != nil {
		iisSiteName = scanned.SiteName
		if scanned.HostName != "" {
			hostname = scanned.HostName
		}
		thumbprint = scanned.CertThumbprint
	}

	if thumbprint == "" {
		return fmt.Errorf("未找到证书指纹，请先部署证书或通过扫描确认证书已安装")
	}

	// 创建安装器
	inst := installer.NewIISInstaller(iisSiteName, hostname, port, thumbprint)

	log.Info("开始为站点 %s 安装 HTTPS 绑定", site.SiteName)

	result, err := inst.Install()
	if err != nil {
		return fmt.Errorf("安装 HTTPS 绑定失败: %w", err)
	}

	if !result.BindingCreated {
		log.Info("站点 %s: %s", site.SiteName, result.Message)
		fmt.Printf("站点 %s: %s\n", site.SiteName, result.Message)
		return nil
	}

	log.Info("站点 %s HTTPS 绑定安装成功", site.SiteName)
	fmt.Printf("站点 %s HTTPS 绑定安装成功\n", site.SiteName)
	fmt.Printf("%s\n", result.Message)

	return nil
}

// interactiveInstallHTTPS 交互式安装 HTTPS 绑定
func interactiveInstallHTTPS(cfgManager *config.Manager, log *logger.Logger) error {
	if !prompt.IsInteractive() {
		return fmt.Errorf("需要交互式终端，请使用 -site 参数指定站点")
	}

	fmt.Println("正在扫描 IIS 站点...")

	// 扫描 HTTP 站点
	s := scanner.New()
	httpSites, err := s.ScanHTTPSites()
	if err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}

	if len(httpSites) == 0 {
		fmt.Println("未发现仅有 HTTP 绑定的站点")
		return nil
	}

	// 显示站点列表
	fmt.Printf("\n发现 %d 个仅有 HTTP 绑定的站点:\n", len(httpSites))
	options := make([]string, len(httpSites))
	for i, site := range httpSites {
		hostInfo := site.SiteName
		if site.HostName != "" {
			hostInfo = fmt.Sprintf("%s (%s)", site.SiteName, site.HostName)
		}
		options[i] = hostInfo
	}

	// 选择站点
	idx := prompt.SelectWithCancel("请选择要安装 HTTPS 绑定的站点", options)
	if idx < 0 {
		fmt.Println("已取消")
		return nil
	}

	selectedSite := httpSites[idx]
	fmt.Printf("\n已选择: %s\n", selectedSite.SiteName)

	// 输入证书指纹
	thumbprint := prompt.InputRequired("证书指纹 (Thumbprint)")

	// 输入主机名
	hostname := selectedSite.HostName
	if hostname == "" {
		hostname = prompt.Input("主机名 (可选)", "")
	}

	// 输入端口
	port := 443

	// 确认安装
	fmt.Printf("\n站点名称: %s\n", selectedSite.SiteName)
	fmt.Printf("证书指纹: %s\n", thumbprint)
	if hostname != "" {
		fmt.Printf("主机名: %s\n", hostname)
	}
	fmt.Printf("端口: %d\n", port)

	if !prompt.Confirm("\n确认安装 HTTPS 绑定?") {
		fmt.Println("已取消")
		return nil
	}

	// 创建安装器
	inst := installer.NewIISInstaller(selectedSite.SiteName, hostname, port, thumbprint)

	log.Info("开始为站点 %s 安装 HTTPS 绑定", selectedSite.SiteName)

	result, err := inst.Install()
	if err != nil {
		return fmt.Errorf("安装 HTTPS 绑定失败: %w", err)
	}

	if !result.BindingCreated {
		fmt.Printf("站点 %s: %s\n", selectedSite.SiteName, result.Message)
		return nil
	}

	log.Info("站点 %s HTTPS 绑定安装成功", selectedSite.SiteName)
	fmt.Printf("\n✓ HTTPS 绑定安装成功\n")
	fmt.Printf("%s\n", result.Message)

	return nil
}
