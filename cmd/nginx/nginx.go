// Package nginx Nginx 证书部署客户端
// 自动扫描 Nginx 配置文件，提取 SSL 站点，自动部署证书
package nginx

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cnssl/cert-deploy/internal/nginx/deployer"
	"github.com/cnssl/cert-deploy/internal/nginx/docker"
	"github.com/cnssl/cert-deploy/internal/nginx/installer"
	"github.com/cnssl/cert-deploy/internal/nginx/scanner"
	"github.com/cnssl/cert-deploy/pkg/backup"
	"github.com/cnssl/cert-deploy/pkg/config"
	"github.com/cnssl/cert-deploy/pkg/fetcher"
	"github.com/cnssl/cert-deploy/pkg/issuer"
	"github.com/cnssl/cert-deploy/pkg/logger"
	"github.com/cnssl/cert-deploy/pkg/prompt"
	"github.com/cnssl/cert-deploy/pkg/util"
	"github.com/cnssl/cert-deploy/pkg/validator"
)

// Run 运行 nginx 命令
func Run(args []string, version, buildTime string, debug bool) {
	fs := flag.NewFlagSet("nginx", flag.ExitOnError)

	var (
		showVersion  = fs.Bool("version", false, "显示版本信息")
		scanOnly     = fs.Bool("scan", false, "仅扫描显示 SSL 站点")
		siteName     = fs.String("site", "", "部署指定站点")
		issueMode    = fs.Bool("issue", false, "发起证书签发（用于 file 验证）")
		installHTTPS = fs.Bool("install-https", false, "为 HTTP 站点安装 HTTPS 配置")
		daemon       = fs.Bool("daemon", false, "守护进程模式")
		initConfig   = fs.Bool("init", false, "根据扫描结果生成站点配置")
		apiURL       = fs.String("url", "", "证书 API 地址")
		referID      = fs.String("refer_id", "", "API 认证 ID")
		domains      = fs.String("domains", "", "域名列表（逗号分隔）")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy nginx [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	// 处理子命令
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			args = append([]string{"-scan"}, args[1:]...)
		case "deploy":
			// 保持原样，通过 -site 参数处理
		case "issue":
			args = append([]string{"-issue"}, args[1:]...)
		case "install-https":
			args = append([]string{"-install-https"}, args[1:]...)
		case "init":
			args = append([]string{"-init"}, args[1:]...)
		case "daemon":
			args = append([]string{"-daemon"}, args[1:]...)
		case "version":
			fmt.Printf("cert-deploy-nginx %s (built at %s)\n", version, buildTime)
			return
		case "help":
			fs.Usage()
			return
		}
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("cert-deploy-nginx %s (built at %s)\n", version, buildTime)
		return
	}

	// 初始化配置管理器
	cfgManager, err := config.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logDir := cfgManager.GetLogsDir()
	if debug {
		// debug 模式使用专门的日志目录
		logDir = filepath.Join(cfgManager.GetLogsDir(), "debug")
	}

	log, err := logger.New(logDir, "nginx")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if debug {
		log.SetLevel(logger.LevelDebug)
		log.Debug("调试模式已启用")
	}

	if *scanOnly {
		runScan(log)
	} else if *initConfig {
		if err := runInit(*apiURL, *referID, *domains, fs.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
			os.Exit(1)
		}
	} else if *daemon {
		runDaemon(cfgManager, log)
	} else if *siteName != "" && *issueMode {
		if err := issueSite(cfgManager, *siteName, log); err != nil {
			log.Error("签发失败: %v", err)
			os.Exit(1)
		}
	} else if *installHTTPS && *siteName == "" {
		if err := interactiveInstallHTTPS(cfgManager, log); err != nil {
			log.Error("安装 HTTPS 配置失败: %v", err)
			os.Exit(1)
		}
	} else if *siteName != "" && *installHTTPS {
		if err := installHTTPSSite(cfgManager, *siteName, log); err != nil {
			log.Error("安装 HTTPS 配置失败: %v", err)
			os.Exit(1)
		}
	} else if *siteName != "" {
		if err := deploySite(cfgManager, *siteName, log); err != nil {
			log.Error("部署失败: %v", err)
			os.Exit(1)
		}
	} else {
		fs.Usage()
		os.Exit(1)
	}
}

// detectEnvironment 检测运行环境
func detectEnvironment() string {
	if _, err := exec.LookPath("nginx"); err == nil {
		if _, err := scanner.DetectNginx(); err == nil {
			return "local"
		}
	}

	if docker.CheckDockerAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if docker.HasNginxContainers(ctx) {
			return "docker"
		}
	}

	return "none"
}

// runScan 扫描并显示所有 SSL 站点
func runScan(log *logger.Logger) {
	env := detectEnvironment()
	result := &config.ScanResult{
		Environment: env,
		Sites:       []config.ScannedSite{},
	}

	switch env {
	case "local":
		sites := runLocalScan(log)
		result.Sites = append(result.Sites, sites...)
	case "docker":
		sites := runDockerScan(log)
		result.Sites = append(result.Sites, sites...)
	case "none":
		fmt.Println("未检测到本地 Nginx 或 Docker 容器中的 Nginx")
		log.Error("未检测到 Nginx 环境")
		return
	}

	if len(result.Sites) > 0 {
		if err := config.SaveScanResult(result); err != nil {
			log.Error("保存扫描结果失败: %v", err)
		} else {
			fmt.Printf("\n扫描结果已保存: %s\n", config.GetScanResultPath())
		}
	}
}

// runLocalScan 扫描本地 Nginx
func runLocalScan(log *logger.Logger) []config.ScannedSite {
	var result []config.ScannedSite

	s := scanner.New()
	sites, err := s.Scan()
	if err != nil {
		log.Error("扫描失败: %v", err)
		fmt.Printf("扫描失败: %v\n", err)
		return result
	}

	configPath := s.GetConfigPath()
	fmt.Printf("检测到 Nginx 配置: %s\n\n", configPath)
	log.LogScan(configPath, len(sites))

	if len(sites) == 0 {
		fmt.Println("未发现 SSL 站点")
		return result
	}

	fmt.Printf("发现 %d 个 SSL 站点:\n\n", len(sites))
	for i, site := range sites {
		allDomains := site.ServerName
		if len(site.ServerAlias) > 0 {
			allDomains += ", " + strings.Join(site.ServerAlias, ", ")
		}
		fmt.Printf("%d. %s\n", i+1, allDomains)
		fmt.Printf("   配置文件: %s\n", site.ConfigFile)
		fmt.Printf("   证书路径: %s\n", site.CertificatePath)
		fmt.Printf("   私钥路径: %s\n", site.PrivateKeyPath)
		fmt.Printf("   监听端口: %v\n", site.ListenPorts)
		if site.Webroot != "" {
			fmt.Printf("   Web 根目录: %s\n", site.Webroot)
		}
		fmt.Println()

		result = append(result, config.ScannedSite{
			ID:              site.ServerName,
			Name:            "本地",
			Source:          "local",
			ConfigFile:      site.ConfigFile,
			ServerName:      site.ServerName,
			ServerAlias:     site.ServerAlias,
			ListenPorts:     site.ListenPorts,
			Webroot:         site.Webroot,
			CertificatePath: site.CertificatePath,
			PrivateKeyPath:  site.PrivateKeyPath,
		})
	}

	return result
}

// runDockerScan 扫描 Docker 容器中的 Nginx
func runDockerScan(log *logger.Logger) []config.ScannedSite {
	var result []config.ScannedSite

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	containers, err := docker.DiscoverNginxContainers(ctx)
	if err != nil {
		log.Error("发现 Docker 容器失败: %v", err)
		fmt.Printf("发现 Docker 容器失败: %v\n", err)
		return result
	}

	if len(containers) == 0 {
		fmt.Println("未发现运行中的 Nginx 容器")
		return result
	}

	fmt.Printf("发现 %d 个 Nginx 容器:\n\n", len(containers))

	totalSites := 0
	for _, container := range containers {
		composeInfo := ""
		if container.IsCompose {
			composeInfo = fmt.Sprintf(" (compose: %s)", container.ServiceName)
		}
		fmt.Printf("容器: %s (%s)%s\n", container.Name, container.ID[:12], composeInfo)

		var client *docker.Client
		if container.IsCompose && container.ComposeFile != "" {
			client = docker.NewComposeClient(container.ComposeFile, container.ServiceName)
		} else {
			client = docker.NewClient(container.ID)
		}

		dockerScanner := docker.NewScanner(client)
		sites, err := dockerScanner.Scan(ctx)
		if err != nil {
			fmt.Printf("   扫描失败: %v\n\n", err)
			continue
		}

		log.LogScan(fmt.Sprintf("Docker:%s", container.Name), len(sites))

		if len(sites) == 0 {
			fmt.Println("   未发现 SSL 站点")
			continue
		}

		totalSites += len(sites)
		for i, site := range sites {
			allDomains := site.ServerName
			if len(site.ServerAlias) > 0 {
				allDomains += ", " + strings.Join(site.ServerAlias, ", ")
			}

			mode := "copy"
			if site.VolumeMode {
				mode = "volume"
			}

			fmt.Printf("   %d. %s [%s]\n", i+1, allDomains, mode)
			fmt.Printf("      容器内配置: %s\n", site.ConfigFile)
			fmt.Printf("      容器内证书: %s\n", site.CertificatePath)
			fmt.Printf("      容器内私钥: %s\n", site.PrivateKeyPath)
			if site.HostCertPath != "" {
				fmt.Printf("      宿主机证书: %s\n", site.HostCertPath)
			}
			if site.HostKeyPath != "" {
				fmt.Printf("      宿主机私钥: %s\n", site.HostKeyPath)
			}
			fmt.Printf("      监听端口: %v\n", site.ListenPorts)
			if site.Webroot != "" {
				fmt.Printf("      Web 根目录: %s\n", site.Webroot)
			}

			result = append(result, config.ScannedSite{
				ID:              site.ServerName,
				Name:            container.Name,
				Source:          "docker",
				ContainerID:     site.ContainerID,
				ContainerName:   site.ContainerName,
				ComposeService:  container.ServiceName,
				ConfigFile:      site.ConfigFile,
				ServerName:      site.ServerName,
				ServerAlias:     site.ServerAlias,
				ListenPorts:     site.ListenPorts,
				Webroot:         site.Webroot,
				CertificatePath: site.CertificatePath,
				PrivateKeyPath:  site.PrivateKeyPath,
				HostCertPath:    site.HostCertPath,
				HostKeyPath:     site.HostKeyPath,
				VolumeMode:      site.VolumeMode,
			})
		}
		fmt.Println()
	}

	fmt.Printf("共发现 %d 个 SSL 站点\n", totalSites)
	return result
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

	s := scanner.New()
	scannedSites, err := s.Scan()
	if err != nil {
		log.Error("扫描 Nginx 配置失败: %v", err)
		return
	}
	log.LogScan("Nginx 配置", len(scannedSites))

	siteConfigs, err := cfgManager.ListSites()
	if err != nil {
		log.Error("加载站点配置失败: %v", err)
		return
	}

	scannedMap := make(map[string]*scanner.SSLSite)
	for _, site := range scannedSites {
		scannedMap[site.ServerName] = site
		for _, alias := range site.ServerAlias {
			scannedMap[alias] = site
		}
	}

	for _, siteCfg := range siteConfigs {
		if !siteCfg.Enabled {
			continue
		}
		if siteCfg.ServerType != "" && siteCfg.ServerType != "nginx" {
			continue
		}

		if !siteCfg.NeedsRenewal() {
			log.Debug("站点 %s 证书有效，跳过", siteCfg.SiteName)
			continue
		}

		var certPath, keyPath, webroot string
		for _, domain := range siteCfg.Domains {
			if scanned, ok := scannedMap[domain]; ok {
				certPath = scanned.CertificatePath
				keyPath = scanned.PrivateKeyPath
				webroot = scanned.Webroot
				break
			}
		}

		if siteCfg.Paths.Certificate != "" {
			certPath = siteCfg.Paths.Certificate
		}
		if siteCfg.Paths.PrivateKey != "" {
			keyPath = siteCfg.Paths.PrivateKey
		}
		if siteCfg.Paths.Webroot != "" {
			webroot = siteCfg.Paths.Webroot
		}

		if certPath == "" || keyPath == "" {
			log.Warn("站点 %s 未找到证书路径", siteCfg.SiteName)
			continue
		}

		if err := deploySiteConfig(ctx, cfgManager, siteCfg, certPath, keyPath, webroot, log); err != nil {
			log.Error("部署站点 %s 失败: %v", siteCfg.SiteName, err)
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

	s := scanner.New()
	var certPath, keyPath, webroot string
	var foundSSL bool

	for _, domain := range site.Domains {
		if scanned, err := s.FindByDomain(domain); err == nil && scanned != nil {
			certPath = scanned.CertificatePath
			keyPath = scanned.PrivateKeyPath
			webroot = scanned.Webroot
			foundSSL = true
			break
		}
	}

	if site.Paths.Certificate != "" {
		certPath = site.Paths.Certificate
	}
	if site.Paths.PrivateKey != "" {
		keyPath = site.Paths.PrivateKey
	}
	if site.Paths.Webroot != "" {
		webroot = site.Paths.Webroot
	}

	if !foundSSL && certPath == "" && keyPath == "" {
		httpSites, _ := s.ScanHTTPSites()
		var httpSite *scanner.HTTPSite
		for _, hs := range httpSites {
			for _, domain := range site.Domains {
				if hs.ServerName == domain {
					httpSite = hs
					break
				}
			}
			if httpSite != nil {
				break
			}
		}

		if httpSite != nil {
			fmt.Printf("检测到站点 %s 尚未配置 HTTPS\n", siteName)

			if prompt.IsInteractive() && prompt.Confirm("是否现在安装 HTTPS 配置?") {
				defaultCertPath := fmt.Sprintf("/etc/ssl/certs/%s.pem", httpSite.ServerName)
				certPath = prompt.InputPath("证书路径", defaultCertPath, false)

				defaultKeyPath := fmt.Sprintf("/etc/ssl/private/%s.key", httpSite.ServerName)
				keyPath = prompt.InputPath("私钥路径", defaultKeyPath, false)

				testCommand := site.Reload.TestCommand
				if testCommand == "" {
					testCommand = "nginx -t"
				}

				inst := installer.NewNginxInstaller(
					httpSite.ConfigFile,
					certPath,
					keyPath,
					httpSite.ServerName,
					testCommand,
				)

				result, err := inst.Install()
				if err != nil {
					return fmt.Errorf("安装 HTTPS 配置失败: %w", err)
				}

				if result.Modified {
					log.Info("HTTPS 配置安装成功: %s", httpSite.ServerName)
					fmt.Printf("✓ HTTPS 配置安装成功\n")
					fmt.Printf("✓ 备份文件: %s\n", result.BackupPath)
				}

				webroot = httpSite.Webroot
			} else {
				return fmt.Errorf("站点 %s 未配置 HTTPS，请先使用 -install-https 安装", siteName)
			}
		} else {
			return fmt.Errorf("未找到证书路径，请检查站点配置或 Nginx 配置")
		}
	}

	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未找到证书路径，请检查站点配置或 Nginx 配置")
	}

	ctx := context.Background()
	return deploySiteConfig(ctx, cfgManager, site, certPath, keyPath, webroot, log)
}

// issueSite 签发并部署证书
func issueSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	s := scanner.New()
	var certPath, keyPath, webroot string

	for _, domain := range site.Domains {
		if scanned, err := s.FindByDomain(domain); err == nil && scanned != nil {
			certPath = scanned.CertificatePath
			keyPath = scanned.PrivateKeyPath
			webroot = scanned.Webroot
			break
		}
	}

	if site.Paths.Certificate != "" {
		certPath = site.Paths.Certificate
	}
	if site.Paths.PrivateKey != "" {
		keyPath = site.Paths.PrivateKey
	}
	if site.Paths.Webroot != "" {
		webroot = site.Paths.Webroot
	}

	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未找到证书路径，请检查站点配置或 Nginx 配置")
	}

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

	site.Metadata.CSRSubmittedAt = time.Now()
	site.Metadata.LastCSRHash = result.CSRHash
	site.Metadata.LastIssueState = result.CertData.Status

	certData := result.CertData

	privateKey := result.PrivateKey
	if certData.PrivateKey != "" {
		privateKey = certData.PrivateKey
	}

	return deployWithCertData(cfgManager, site, certPath, keyPath, certData, privateKey, log)
}

// deployWithCertData 使用已获取的证书数据部署
func deployWithCertData(cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath string, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	v := validator.New("")
	cert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	if site.Validation.VerifyDomain {
		dv := validator.NewDomainValidator(site.Domains, site.Validation.IgnoreDomainMismatch)
		if err := dv.ValidateDomainCoverage(cert); err != nil {
			return fmt.Errorf("域名验证失败: %w", err)
		}
	}

	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("证书私钥配对验证失败: %w", err)
	}

	var backupPath string
	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), site.Backup.KeepVersions)
	if site.Backup.Enabled {
		if _, err := os.Stat(certPath); err == nil {
			result, err := backupMgr.Backup(site.SiteName, certPath, keyPath, nil)
			if err != nil {
				log.Warn("备份失败: %v", err)
				log.LogBackup(certPath, "", false, err)
			} else {
				backupPath = result.BackupPath
				log.LogBackup(certPath, backupPath, true, nil)
				if result.CleanupError != nil {
					log.Warn("备份清理失败: %v", result.CleanupError)
				}
			}
		}
	}

	d := deployer.NewNginxDeployer(
		certPath,
		keyPath,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

		if backupPath != "" {
			backupCertPath, backupKeyPath := backupMgr.GetBackupPaths(backupPath)
			if rollbackErr := d.Rollback(backupCertPath, backupKeyPath); rollbackErr != nil {
				log.Error("回滚失败: %v", rollbackErr)
			} else {
				log.Info("已回滚到备份证书")
			}
		}

		return fmt.Errorf("部署失败: %w", err)
	}

	log.LogDeployment(site.SiteName, certPath, keyPath, true, nil)

	if site.Reload.ReloadCommand != "" {
		log.LogReload(site.Reload.ReloadCommand, true, "", nil)
	}

	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		log.Warn("保存站点元数据失败: %v", err)
	}

	if site.API.CallbackURL != "" {
		f := fetcher.New(30 * time.Second)
		callbackReq := &fetcher.CallbackRequest{
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "nginx",
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
func deploySiteConfig(ctx context.Context, cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath, webroot string, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, site.API.URL, site.API.ReferID)
	if err != nil {
		return fmt.Errorf("获取证书失败: %w", err)
	}

	if certData.Status == "processing" && certData.File != nil {
		if webroot == "" {
			return fmt.Errorf("证书需要文件验证，但未配置 webroot 路径")
		}

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
					os.Remove(validationPath)
					goto deploy
				}

				log.Debug("证书状态: %s，继续等待...", certData.Status)
			}
		}

		os.Remove(validationPath)
		return fmt.Errorf("等待证书签发超时: status=%s", certData.Status)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return fmt.Errorf("证书未就绪: status=%s", certData.Status)
	}

deploy:

	v := validator.New("")
	cert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	if site.Validation.VerifyDomain {
		dv := validator.NewDomainValidator(site.Domains, site.Validation.IgnoreDomainMismatch)
		if err := dv.ValidateDomainCoverage(cert); err != nil {
			return fmt.Errorf("域名验证失败: %w", err)
		}
	}

	var privateKey string
	if certData.PrivateKey != "" {
		privateKey = certData.PrivateKey
	} else {
		keyBytes, err := os.ReadFile(keyPath)
		if err == nil {
			privateKey = string(keyBytes)
			if pairErr := v.ValidateCertKeyPair(certData.Cert, privateKey); pairErr != nil {
				log.Warn("本地私钥与证书不匹配: %v", pairErr)
				privateKey = ""
			}
		} else {
			log.Warn("读取本地私钥失败: %v", err)
		}

		if privateKey == "" {
			if prompt.IsInteractive() {
				fmt.Println("无法获取有效私钥：API 未返回且本地私钥不存在或不匹配")
				inputKeyPath := prompt.InputPath("请输入私钥文件路径", keyPath, true)
				keyBytes, err := os.ReadFile(inputKeyPath)
				if err != nil {
					return fmt.Errorf("读取私钥失败: %w", err)
				}
				privateKey = string(keyBytes)
			} else {
				return fmt.Errorf("无法获取私钥：API 未返回且本地私钥不存在或不匹配")
			}
		}
	}

	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("证书私钥配对验证失败: %w", err)
	}

	var backupPath string
	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), site.Backup.KeepVersions)
	if site.Backup.Enabled && !site.Docker.Enabled {
		if _, err := os.Stat(certPath); err == nil {
			result, err := backupMgr.Backup(site.SiteName, certPath, keyPath, nil)
			if err != nil {
				log.Warn("备份失败: %v", err)
				log.LogBackup(certPath, "", false, err)
			} else {
				backupPath = result.BackupPath
				log.LogBackup(certPath, backupPath, true, nil)
				if result.CleanupError != nil {
					log.Warn("备份清理失败: %v", result.CleanupError)
				}
			}
		}
	}

	if site.Docker.Enabled {
		if err := deployDockerSite(ctx, site, certData.Cert, certData.IntermediateCert, privateKey, log); err != nil {
			log.LogDeployment(site.SiteName, certPath, keyPath, false, err)
			return fmt.Errorf("Docker 部署失败: %w", err)
		}
		log.LogDeployment(site.SiteName, fmt.Sprintf("Docker:%s", site.Docker.ContainerName), "", true, nil)
	} else {
		d := deployer.NewNginxDeployer(
			certPath,
			keyPath,
			site.Reload.TestCommand,
			site.Reload.ReloadCommand,
		)

		if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
			log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

			if backupPath != "" {
				backupCertPath, backupKeyPath := backupMgr.GetBackupPaths(backupPath)
				if rollbackErr := d.Rollback(backupCertPath, backupKeyPath); rollbackErr != nil {
					log.Error("回滚失败: %v", rollbackErr)
				} else {
					log.Info("已回滚到备份证书")
				}
			}

			return fmt.Errorf("部署失败: %w", err)
		}
		log.LogDeployment(site.SiteName, certPath, keyPath, true, nil)
	}

	if site.Reload.ReloadCommand != "" {
		log.LogReload(site.Reload.ReloadCommand, true, "", nil)
	}

	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		log.Warn("保存站点元数据失败: %v", err)
	}

	if site.API.CallbackURL != "" {
		callbackReq := &fetcher.CallbackRequest{
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "nginx",
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

// installHTTPSSite 为站点安装 HTTPS 配置
func installHTTPSSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	var certPath, keyPath, configFile string

	if site.Paths.Certificate != "" {
		certPath = site.Paths.Certificate
	}
	if site.Paths.PrivateKey != "" {
		keyPath = site.Paths.PrivateKey
	}
	if site.Paths.ConfigFile != "" {
		configFile = site.Paths.ConfigFile
	}

	if configFile == "" {
		s := scanner.New()
		for _, domain := range site.Domains {
			if found, err := s.FindByDomain(domain); err == nil && found != nil {
				configFile = found.ConfigFile
				if certPath == "" {
					certPath = found.CertificatePath
				}
				if keyPath == "" {
					keyPath = found.PrivateKeyPath
				}
				break
			}
		}
	}

	if configFile == "" {
		s := scanner.New()
		for _, domain := range site.Domains {
			if found, err := installer.FindHTTPServerBlock(s.GetConfigPath(), domain); err == nil && found != "" {
				configFile = found
				break
			}
		}
	}

	if configFile == "" {
		return fmt.Errorf("未找到配置文件路径，请在站点配置中指定 paths.config_file")
	}

	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未找到证书路径，请确保证书已部署或在配置中指定路径")
	}

	serverName := site.SiteName
	if len(site.Domains) > 0 {
		serverName = site.Domains[0]
	}

	testCommand := site.Reload.TestCommand
	if testCommand == "" {
		testCommand = "nginx -t"
	}

	inst := installer.NewNginxInstaller(configFile, certPath, keyPath, serverName, testCommand)

	log.Info("开始为站点 %s 安装 HTTPS 配置", site.SiteName)

	result, err := inst.Install()
	if err != nil {
		return fmt.Errorf("安装 HTTPS 配置失败: %w", err)
	}

	if !result.Modified {
		log.Info("站点 %s 已有 SSL 配置，跳过", site.SiteName)
		fmt.Printf("站点 %s 已有 SSL 配置，无需修改\n", site.SiteName)
		return nil
	}

	log.Info("站点 %s HTTPS 配置安装成功，备份文件: %s", site.SiteName, result.BackupPath)
	fmt.Printf("站点 %s HTTPS 配置安装成功\n", site.SiteName)
	fmt.Printf("备份文件: %s\n", result.BackupPath)
	fmt.Printf("请执行 '%s' 重载配置\n", site.Reload.ReloadCommand)

	return nil
}

// interactiveInstallHTTPS 交互式安装 HTTPS 配置
func interactiveInstallHTTPS(cfgManager *config.Manager, log *logger.Logger) error {
	if !prompt.IsInteractive() {
		return fmt.Errorf("需要交互式终端，请使用 -site 参数指定站点")
	}

	fmt.Println("正在扫描 Nginx 配置...")

	s := scanner.New()
	httpSites, err := s.ScanHTTPSites()
	if err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}

	if len(httpSites) == 0 {
		fmt.Println("未发现未启用 HTTPS 的站点")
		return nil
	}

	fmt.Printf("\n发现 %d 个未启用 HTTPS 的站点:\n", len(httpSites))
	options := make([]string, len(httpSites))
	for i, site := range httpSites {
		options[i] = fmt.Sprintf("%s (%s)", site.ServerName, site.ConfigFile)
	}

	idx := prompt.SelectWithCancel("请选择要安装 HTTPS 的站点", options)
	if idx < 0 {
		fmt.Println("已取消")
		return nil
	}

	selectedSite := httpSites[idx]
	fmt.Printf("\n已选择: %s\n", selectedSite.ServerName)

	defaultCertPath := fmt.Sprintf("/etc/ssl/certs/%s.pem", selectedSite.ServerName)
	certPath := prompt.InputPath("证书路径", defaultCertPath, false)

	defaultKeyPath := fmt.Sprintf("/etc/ssl/private/%s.key", selectedSite.ServerName)
	keyPath := prompt.InputPath("私钥路径", defaultKeyPath, false)

	fmt.Printf("\n配置文件: %s\n", selectedSite.ConfigFile)
	fmt.Printf("证书路径: %s\n", certPath)
	fmt.Printf("私钥路径: %s\n", keyPath)

	if !prompt.Confirm("\n确认安装 HTTPS 配置?") {
		fmt.Println("已取消")
		return nil
	}

	inst := installer.NewNginxInstaller(
		selectedSite.ConfigFile,
		certPath,
		keyPath,
		selectedSite.ServerName,
		"nginx -t",
	)

	log.Info("开始为站点 %s 安装 HTTPS 配置", selectedSite.ServerName)

	result, err := inst.Install()
	if err != nil {
		return fmt.Errorf("安装 HTTPS 配置失败: %w", err)
	}

	if !result.Modified {
		fmt.Printf("站点 %s 已有 SSL 配置，无需修改\n", selectedSite.ServerName)
		return nil
	}

	log.Info("站点 %s HTTPS 配置安装成功", selectedSite.ServerName)
	fmt.Printf("\n✓ 备份原配置: %s\n", result.BackupPath)
	fmt.Printf("✓ 添加 SSL 配置\n")
	fmt.Printf("✓ 测试配置通过\n")
	fmt.Printf("\n安装完成! 请执行 'systemctl reload nginx' 重载配置\n")

	return nil
}

// deployDockerSite Docker 模式部署证书
func deployDockerSite(ctx context.Context, site *config.SiteConfig, cert, intermediate, privateKey string, log *logger.Logger) error {
	var client *docker.Client
	if site.Docker.ComposeFile != "" && site.Docker.ServiceName != "" {
		client = docker.NewComposeClient(site.Docker.ComposeFile, site.Docker.ServiceName)
		log.Info("使用 docker-compose 模式: %s", site.Docker.ServiceName)
	} else if site.Docker.ContainerID != "" {
		client = docker.NewClient(site.Docker.ContainerID)
		log.Info("使用 docker 模式: %s", site.Docker.ContainerID)
	} else if site.Docker.ContainerName != "" {
		client = docker.NewClient(site.Docker.ContainerName)
		log.Info("使用 docker 模式: %s", site.Docker.ContainerName)
	} else if site.Docker.AutoDiscover {
		containers, err := docker.DiscoverNginxContainers(ctx)
		if err != nil {
			return fmt.Errorf("自动发现容器失败: %w", err)
		}
		if len(containers) == 0 {
			return fmt.Errorf("未发现 Nginx 容器")
		}
		container := containers[0]
		if container.IsCompose && container.ComposeFile != "" {
			client = docker.NewComposeClient(container.ComposeFile, container.ServiceName)
		} else {
			client = docker.NewClient(container.ID)
		}
		log.Info("自动发现容器: %s", container.Name)
	} else {
		return fmt.Errorf("未配置 Docker 容器信息")
	}

	certPath := site.Docker.ContainerPaths.Certificate
	keyPath := site.Docker.ContainerPaths.PrivateKey
	if certPath == "" {
		certPath = site.Paths.Certificate
	}
	if keyPath == "" {
		keyPath = site.Paths.PrivateKey
	}
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未配置证书路径")
	}

	opts := docker.DeployerOptions{
		CertPath:      certPath,
		KeyPath:       keyPath,
		DeployMode:    site.Docker.DeployMode,
		TestCommand:   "nginx -t",
		ReloadCommand: "nginx -s reload",
	}

	if site.Paths.Certificate != "" && site.Docker.DeployMode == "volume" {
		opts.HostCertPath = site.Paths.Certificate
		opts.HostKeyPath = site.Paths.PrivateKey
	}

	d := docker.NewDeployer(client, opts)

	log.Info("开始部署证书到 Docker 容器...")
	if err := d.Deploy(ctx, cert, intermediate, privateKey); err != nil {
		return err
	}

	mode := d.GetDeployMode()
	log.Info("部署完成，模式: %s", mode)

	return nil
}

// runInit 根据扫描结果生成站点配置
func runInit(apiURL, referID, domainsStr, siteID string) error {
	if apiURL == "" {
		return fmt.Errorf("缺少 -url 参数")
	}
	if referID == "" {
		return fmt.Errorf("缺少 -refer_id 参数")
	}

	scanResult, err := config.LoadScanResult()
	if err != nil {
		return fmt.Errorf("加载扫描结果失败: %v\n请先执行 -scan 扫描站点", err)
	}

	if len(scanResult.Sites) == 0 {
		return fmt.Errorf("扫描结果为空，请先执行 -scan 扫描站点")
	}

	var site *config.ScannedSite
	if siteID != "" {
		site = scanResult.FindSiteByID(siteID)
		if site == nil {
			return fmt.Errorf("未找到站点: %s", siteID)
		}
	} else {
		fmt.Printf("扫描结果 (%s):\n", scanResult.ScanTime.Format("2006-01-02 15:04:05"))
		for i, s := range scanResult.Sites {
			source := "local"
			if s.Source == "docker" {
				mode := "copy"
				if s.VolumeMode {
					mode = "volume"
				}
				source = fmt.Sprintf("docker/%s", mode)
			}
			name := s.Name
			if name == "" {
				name = "本地"
			}
			fmt.Printf("  %d. %s (%s) [%s]\n", i+1, s.ID, name, source)
		}
		fmt.Print("\n请选择站点 [1-")
		fmt.Printf("%d]: ", len(scanResult.Sites))

		var choice int
		if _, err := fmt.Scanf("%d", &choice); err != nil {
			return fmt.Errorf("无效的选择")
		}

		site = scanResult.FindSiteByIndex(choice)
		if site == nil {
			return fmt.Errorf("无效的选择: %d", choice)
		}
	}

	var domains []string
	if domainsStr != "" {
		for _, d := range strings.Split(domainsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}

	cfg := generateSiteConfig(site, apiURL, referID, domains)

	cfgManager, err := config.NewManager()
	if err != nil {
		return fmt.Errorf("初始化配置管理器失败: %v", err)
	}

	if err := cfgManager.SaveSite(cfg); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	configPath := filepath.Join(cfgManager.GetSitesDir(), site.ID+".json")
	fmt.Printf("\n已生成配置文件: %s\n", configPath)
	fmt.Printf("\n下一步:\n")
	fmt.Printf("  cert-deploy nginx deploy --site %s    # 部署证书\n", site.ID)

	return nil
}

// generateSiteConfig 生成站点配置
func generateSiteConfig(site *config.ScannedSite, apiURL, referID string, domains []string) *config.SiteConfig {
	cfg := &config.SiteConfig{
		Version:    "1.0",
		SiteName:   site.ID,
		Enabled:    true,
		ServerType: "nginx",
		API: config.APIConfig{
			URL:     apiURL,
			ReferID: referID,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "nginx -t",
			ReloadCommand: "nginx -s reload",
		},
		Backup: config.BackupConfig{
			Enabled:      true,
			KeepVersions: 3,
		},
		Schedule: config.ScheduleConfig{
			CheckIntervalHours: 12,
			RenewBeforeDays:    30,
		},
	}

	if len(domains) > 0 {
		cfg.Domains = domains
	} else if site.ServerName != "" {
		cfg.Domains = append([]string{site.ServerName}, site.ServerAlias...)
	}

	if site.Source == "docker" {
		cfg.Docker = config.DockerConfig{
			Enabled:       true,
			ContainerID:   site.ContainerID,
			ContainerName: site.ContainerName,
			DeployMode:    "auto",
			ContainerPaths: config.ContainerPathsConfig{
				Certificate: site.CertificatePath,
				PrivateKey:  site.PrivateKeyPath,
			},
		}
		if site.VolumeMode && site.HostCertPath != "" {
			cfg.Paths = config.PathsConfig{
				Certificate: site.HostCertPath,
				PrivateKey:  site.HostKeyPath,
				ConfigFile:  site.ConfigFile,
				Webroot:     site.Webroot,
			}
			cfg.Docker.DeployMode = "volume"
		}
	} else {
		cfg.Paths = config.PathsConfig{
			Certificate: site.CertificatePath,
			PrivateKey:  site.PrivateKeyPath,
			ConfigFile:  site.ConfigFile,
			Webroot:     site.Webroot,
		}
	}

	return cfg
}
