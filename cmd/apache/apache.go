// Package apache Apache 证书部署客户端
// 自动扫描 Apache 配置文件，提取 SSL 站点，自动部署证书
package apache

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zhuxbo/cert-deploy/internal/apache/deployer"
	"github.com/zhuxbo/cert-deploy/internal/apache/installer"
	"github.com/zhuxbo/cert-deploy/internal/apache/scanner"
	"github.com/zhuxbo/cert-deploy/pkg/backup"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/issuer"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
	"github.com/zhuxbo/cert-deploy/pkg/prompt"
	"github.com/zhuxbo/cert-deploy/pkg/util"
	"github.com/zhuxbo/cert-deploy/pkg/validator"
)

// Run 运行 apache 命令
func Run(args []string, version, buildTime string, debug bool) {
	fs := flag.NewFlagSet("apache", flag.ExitOnError)

	var (
		showVersion  = fs.Bool("version", false, "显示版本信息")
		scanOnly     = fs.Bool("scan", false, "扫描显示站点")
		sslOnly      = fs.Bool("ssl-only", false, "仅扫描 SSL 站点（与 scan 配合使用）")
		siteName     = fs.String("site", "", "部署指定站点")
		issueMode    = fs.Bool("issue", false, "发起证书签发（用于 file 验证）")
		installHTTPS = fs.Bool("install-https", false, "为 HTTP 站点安装 HTTPS 配置")
		daemon       = fs.Bool("daemon", false, "守护进程模式")
		initConfig   = fs.Bool("init", false, "根据扫描结果生成站点配置")
		apiURL       = fs.String("url", "", "证书 API 地址")
		token        = fs.String("token", "", "API 认证 Token")
		domains      = fs.String("domains", "", "域名列表（逗号分隔）")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy apache [选项]\n\n选项:\n")
		fs.PrintDefaults()
	}

	// 处理子命令
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			args = append([]string{"-scan"}, args[1:]...)
		case "deploy":
			// 移除 "deploy" 子命令，保留后续参数
			args = args[1:]
		case "issue":
			args = append([]string{"-issue"}, args[1:]...)
		case "install-https":
			args = append([]string{"-install-https"}, args[1:]...)
		case "init":
			args = append([]string{"-init"}, args[1:]...)
		case "daemon":
			args = append([]string{"-daemon"}, args[1:]...)
		case "version":
			fmt.Printf("cert-deploy-apache %s (built at %s)\n", version, buildTime)
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
		fmt.Printf("cert-deploy-apache %s (built at %s)\n", version, buildTime)
		return
	}

	cfgManager, err := config.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(cfgManager.GetLogsDir(), "debug")
	}

	log, err := logger.New(logDir, "apache")
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
		runScan(log, *sslOnly)
	} else if *initConfig {
		if err := runInit(*apiURL, *token, *domains, fs.Arg(0)); err != nil {
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

// runScan 扫描并显示站点（sslOnly=true 时仅显示 SSL 站点）
func runScan(log *logger.Logger, sslOnly bool) {
	s := scanner.New()

	// 启用 debug 日志
	if os.Getenv("CERT_DEPLOY_DEBUG") == "1" {
		s.SetDebug(true, func(format string, args ...interface{}) {
			log.Debug(format, args...)
		})
	}

	configPath := s.GetConfigPath()
	serverRoot := s.GetServerRoot()
	if configPath == "" {
		if cp, sr, err := scanner.DetectApache(); err == nil {
			configPath = cp
			serverRoot = sr
		}
	}
	fmt.Printf("检测到 Apache 配置: %s\n", configPath)
	fmt.Printf("ServerRoot: %s\n\n", serverRoot)

	result := &config.ScanResult{
		Environment: "local",
		Sites:       []config.ScannedSite{},
	}

	if sslOnly {
		// 仅扫描 SSL 站点（兼容旧行为）
		sites, err := s.Scan()
		if err != nil {
			log.Error("扫描失败: %v", err)
			fmt.Printf("扫描失败: %v\n", err)
			return
		}
		log.LogScan(configPath, len(sites))

		if len(sites) == 0 {
			fmt.Println("未发现 SSL 站点")
			return
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
			if site.ChainPath != "" {
				fmt.Printf("   证书链:   %s\n", site.ChainPath)
			}
			fmt.Printf("   监听端口: %s\n", site.ListenPort)
			if site.Webroot != "" {
				fmt.Printf("   Web 根目录: %s\n", site.Webroot)
			}
			fmt.Println()

			result.Sites = append(result.Sites, config.ScannedSite{
				ID:              site.ServerName,
				Name:            "本地",
				Source:          "local",
				ConfigFile:      site.ConfigFile,
				ServerName:      site.ServerName,
				ServerAlias:     site.ServerAlias,
				ListenPorts:     []string{site.ListenPort},
				Webroot:         site.Webroot,
				CertificatePath: site.CertificatePath,
				PrivateKeyPath:  site.PrivateKeyPath,
			})
		}
	} else {
		// 扫描所有站点（新默认行为）
		sites, err := s.ScanAll()
		if err != nil {
			log.Error("扫描失败: %v", err)
			fmt.Printf("扫描失败: %v\n", err)
			return
		}
		log.LogScan(configPath, len(sites))

		if len(sites) == 0 {
			fmt.Println("未发现站点")
			return
		}

		fmt.Printf("发现 %d 个站点:\n\n", len(sites))
		for i, site := range sites {
			allDomains := site.ServerName
			if len(site.ServerAlias) > 0 {
				allDomains += ", " + strings.Join(site.ServerAlias, ", ")
			}
			sslStatus := "HTTP"
			if site.HasSSL {
				sslStatus = "HTTPS"
			}
			fmt.Printf("%d. %s [%s]\n", i+1, allDomains, sslStatus)
			fmt.Printf("   配置文件: %s\n", site.ConfigFile)
			if site.HasSSL {
				fmt.Printf("   证书路径: %s\n", site.CertificatePath)
				fmt.Printf("   私钥路径: %s\n", site.PrivateKeyPath)
				if site.ChainPath != "" {
					fmt.Printf("   证书链:   %s\n", site.ChainPath)
				}
			}
			fmt.Printf("   监听端口: %v\n", site.ListenPorts)
			if site.Webroot != "" {
				fmt.Printf("   Web 根目录: %s\n", site.Webroot)
			}
			fmt.Println()

			result.Sites = append(result.Sites, config.ScannedSite{
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
	}

	if len(result.Sites) > 0 {
		if err := config.SaveScanResult(result); err != nil {
			log.Error("保存扫描结果失败: %v", err)
		} else {
			fmt.Printf("\n扫描结果已保存: %s\n", config.GetScanResultPath())
		}
	}
}

func runDaemon(cfgManager *config.Manager, log *logger.Logger) {
	log.Info("启动守护进程模式")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 检查间隔（默认 10 分钟）
	interval := 10 * time.Minute
	log.Info("检查间隔: %v", interval)

	ticker := time.NewTicker(interval)
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

func checkAndDeploy(ctx context.Context, cfgManager *config.Manager, log *logger.Logger) {
	log.Info("开始检查证书...")

	s := scanner.New()
	scannedSites, err := s.Scan()
	if err != nil {
		log.Warn("扫描 Apache 配置失败: %v", err)
	} else {
		log.LogScan(s.GetConfigPath(), len(scannedSites))
	}

	scannedMap := make(map[string]*scanner.SSLSite)
	for _, site := range scannedSites {
		scannedMap[site.ServerName] = site
		for _, alias := range site.ServerAlias {
			scannedMap[alias] = site
		}
	}

	sites, err := cfgManager.ListSites()
	if err != nil {
		log.Error("加载站点配置失败: %v", err)
		return
	}

	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		if site.ServerType != "apache" {
			continue
		}

		if !site.NeedsRenewal() {
			log.Debug("站点 %s 证书有效，跳过", site.SiteName)
			continue
		}

		var certPath, keyPath, chainPath, webroot string
		for _, domain := range site.Domains {
			if scanned, ok := scannedMap[domain]; ok {
				certPath = scanned.CertificatePath
				keyPath = scanned.PrivateKeyPath
				chainPath = scanned.ChainPath
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
		if site.Paths.ChainFile != "" {
			chainPath = site.Paths.ChainFile
		}
		if site.Paths.Webroot != "" {
			webroot = site.Paths.Webroot
		}

		if certPath == "" || keyPath == "" {
			log.Warn("站点 %s 未找到证书路径", site.SiteName)
			continue
		}

		if err := deploySiteConfig(ctx, cfgManager, site, certPath, keyPath, chainPath, webroot, log); err != nil {
			log.Error("部署站点 %s 失败: %v", site.SiteName, err)
		}
	}

	log.Info("检查完成")
}

func deploySite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	s := scanner.New()
	var certPath, keyPath, chainPath, webroot string
	var foundSSL bool

	for _, domain := range site.Domains {
		if scanned, err := s.FindByDomain(domain); err == nil && scanned != nil {
			certPath = scanned.CertificatePath
			keyPath = scanned.PrivateKeyPath
			chainPath = scanned.ChainPath
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
	if site.Paths.ChainFile != "" {
		chainPath = site.Paths.ChainFile
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

				defaultChainPath := fmt.Sprintf("/etc/ssl/certs/%s-chain.pem", httpSite.ServerName)
				chainPath = prompt.Input("证书链路径 (可选)", defaultChainPath)

				testCommand := site.Reload.TestCommand
				if testCommand == "" {
					testCommand = "apache2ctl -t"
				}

				inst := installer.NewApacheInstaller(
					httpSite.ConfigFile,
					certPath,
					keyPath,
					chainPath,
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
			return fmt.Errorf("未找到证书路径，请检查站点配置或 Apache 配置")
		}
	}

	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未找到证书路径，请检查站点配置或 Apache 配置")
	}

	ctx := context.Background()
	return deploySiteConfig(ctx, cfgManager, site, certPath, keyPath, chainPath, webroot, log)
}

func issueSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	s := scanner.New()
	var certPath, keyPath, chainPath, webroot string

	for _, domain := range site.Domains {
		if scanned, err := s.FindByDomain(domain); err == nil && scanned != nil {
			certPath = scanned.CertificatePath
			keyPath = scanned.PrivateKeyPath
			chainPath = scanned.ChainPath
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
	if site.Paths.ChainFile != "" {
		chainPath = site.Paths.ChainFile
	}
	if site.Paths.Webroot != "" {
		webroot = site.Paths.Webroot
	}

	if certPath == "" || keyPath == "" {
		return fmt.Errorf("未找到证书路径，请检查站点配置或 Apache 配置")
	}

	iss := issuer.New(log)

	// 确定验证方式
	method := site.Validation.Method
	if method == "" {
		method = "file" // 默认
	}
	// 通配符域名强制使用 delegation（不支持 file 验证）
	for _, d := range site.Domains {
		if strings.HasPrefix(d, "*") {
			method = "delegation"
			break
		}
	}

	opts := issuer.IssueOptions{
		Webroot:          webroot,
		ValidationMethod: method,
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

	return deployWithCertData(cfgManager, site, certPath, keyPath, chainPath, certData, privateKey, log)
}

func deployWithCertData(cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath, chainPath string, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
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

	d := deployer.NewApacheDeployer(
		certPath,
		keyPath,
		chainPath,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

		if backupPath != "" {
			backupCertPath, backupKeyPath := backupMgr.GetBackupPaths(backupPath)
			if rollbackErr := d.Rollback(backupCertPath, backupKeyPath, ""); rollbackErr != nil {
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
			OrderID:       certData.OrderID,
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "apache",
		}
		ctx := context.Background()
		if err := f.Callback(ctx, site.API.CallbackURL, site.API.Token, callbackReq); err != nil {
			log.Warn("发送部署回调失败: %v", err)
		} else {
			log.Info("部署回调发送成功")
		}
	}

	log.Info("站点 %s 部署成功，证书有效期至 %s", site.SiteName, cert.NotAfter.Format("2006-01-02"))
	return nil
}

func deploySiteConfig(ctx context.Context, cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath, chainPath, webroot string, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, site.API.URL, site.API.Token)
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
				certData, err = f.Info(ctx, site.API.URL, site.API.Token)
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
		if err != nil {
			return fmt.Errorf("读取私钥失败: %w", err)
		}
		privateKey = string(keyBytes)
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

	d := deployer.NewApacheDeployer(
		certPath,
		keyPath,
		chainPath,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

		if backupPath != "" {
			backupCertPath, backupKeyPath := backupMgr.GetBackupPaths(backupPath)
			if rollbackErr := d.Rollback(backupCertPath, backupKeyPath, ""); rollbackErr != nil {
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
		callbackReq := &fetcher.CallbackRequest{
			OrderID:       certData.OrderID,
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "apache",
		}
		if err := f.Callback(ctx, site.API.CallbackURL, site.API.Token, callbackReq); err != nil {
			log.Warn("发送部署回调失败: %v", err)
		} else {
			log.Info("部署回调发送成功")
		}
	}

	log.Info("站点 %s 部署成功，证书有效期至 %s", site.SiteName, cert.NotAfter.Format("2006-01-02"))
	return nil
}

func installHTTPSSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	var certPath, keyPath, chainPath, configFile string

	if site.Paths.Certificate != "" {
		certPath = site.Paths.Certificate
	}
	if site.Paths.PrivateKey != "" {
		keyPath = site.Paths.PrivateKey
	}
	if site.Paths.ChainFile != "" {
		chainPath = site.Paths.ChainFile
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
				if chainPath == "" {
					chainPath = found.ChainPath
				}
				break
			}
		}
	}

	if configFile == "" {
		s := scanner.New()
		for _, domain := range site.Domains {
			if found, err := installer.FindHTTPVirtualHost(s.GetConfigPath(), domain); err == nil && found != "" {
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
		testCommand = "apache2ctl -t"
	}

	inst := installer.NewApacheInstaller(configFile, certPath, keyPath, chainPath, serverName, testCommand)

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

func interactiveInstallHTTPS(cfgManager *config.Manager, log *logger.Logger) error {
	if !prompt.IsInteractive() {
		return fmt.Errorf("需要交互式终端，请使用 -site 参数指定站点")
	}

	fmt.Println("正在扫描 Apache 配置...")

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

	defaultChainPath := fmt.Sprintf("/etc/ssl/certs/%s-chain.pem", selectedSite.ServerName)
	chainPath := prompt.Input("证书链路径 (可选)", defaultChainPath)

	fmt.Printf("\n配置文件: %s\n", selectedSite.ConfigFile)
	fmt.Printf("证书路径: %s\n", certPath)
	fmt.Printf("私钥路径: %s\n", keyPath)
	if chainPath != "" {
		fmt.Printf("证书链路径: %s\n", chainPath)
	}

	if !prompt.Confirm("\n确认安装 HTTPS 配置?") {
		fmt.Println("已取消")
		return nil
	}

	inst := installer.NewApacheInstaller(
		selectedSite.ConfigFile,
		certPath,
		keyPath,
		chainPath,
		selectedSite.ServerName,
		"apache2ctl -t",
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
	fmt.Printf("\n安装完成! 请执行 'systemctl reload apache2' 重载配置\n")

	return nil
}

func runInit(apiURL, token, domainsStr, siteID string) error {
	if apiURL == "" {
		return fmt.Errorf("缺少 -url 参数")
	}
	if token == "" {
		return fmt.Errorf("缺少 -token 参数")
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
			name := s.Name
			if name == "" {
				name = "本地"
			}
			fmt.Printf("  %d. %s (%s) [%s]\n", i+1, s.ID, name, s.Source)
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

	cfg := generateSiteConfig(site, apiURL, token, domains)

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
	fmt.Printf("  cert-deploy apache deploy --site %s    # 部署证书\n", site.ID)

	return nil
}

func generateSiteConfig(site *config.ScannedSite, apiURL, token string, domains []string) *config.SiteConfig {
	cfg := &config.SiteConfig{
		Version:    "1.0",
		SiteName:   site.ID,
		Enabled:    true,
		ServerType: "apache",
		API: config.APIConfig{
			URL:     apiURL,
			Token: token,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "apache2ctl -t",
			ReloadCommand: "systemctl reload apache2",
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

	cfg.Paths = config.PathsConfig{
		Certificate: site.CertificatePath,
		PrivateKey:  site.PrivateKeyPath,
		ConfigFile:  site.ConfigFile,
		Webroot:     site.Webroot,
	}

	return cfg
}
