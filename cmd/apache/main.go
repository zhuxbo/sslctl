// Apache 证书部署客户端
// 自动扫描 Apache 配置文件，提取 SSL 站点，自动部署证书
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

	"github.com/cnssl/cert-deploy/internal/apache/deployer"
	"github.com/cnssl/cert-deploy/internal/apache/installer"
	"github.com/cnssl/cert-deploy/internal/apache/scanner"
	"github.com/cnssl/cert-deploy/pkg/backup"
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
		scanOnly     = flag.Bool("scan", false, "仅扫描显示 SSL 站点")
		siteName     = flag.String("site", "", "部署指定站点")
		issueMode    = flag.Bool("issue", false, "发起证书签发（用于 file 验证）")
		installHTTPS = flag.Bool("install-https", false, "为 HTTP 站点安装 HTTPS 配置")
		daemon       = flag.Bool("daemon", false, "守护进程模式")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-deploy-apache %s (built at %s)\n", version, buildTime)
		os.Exit(0)
	}

	// 初始化配置管理器（复用 nginx 的配置结构）
	cfgManager, err := config.NewManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	log, err := logger.New(cfgManager.GetLogsDir(), "apache")
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
		// 交互式安装 HTTPS 配置模式
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
		flag.Usage()
		os.Exit(1)
	}
}

// runScan 扫描并显示所有 SSL 站点
func runScan(log *logger.Logger) {
	s := scanner.New()
	sites, err := s.Scan()
	if err != nil {
		log.Error("扫描失败: %v", err)
		fmt.Printf("扫描失败: %v\n", err)
		return
	}

	// 显示检测到的配置路径
	configPath := s.GetConfigPath()
	serverRoot := s.GetServerRoot()
	fmt.Printf("检测到 Apache 配置: %s\n", configPath)
	fmt.Printf("ServerRoot: %s\n\n", serverRoot)
	log.LogScan(configPath, len(sites))

	if len(sites) == 0 {
		fmt.Println("未发现 SSL 站点")
		return
	}

	fmt.Printf("发现 %d 个 SSL 站点:\n\n", len(sites))
	for i, site := range sites {
		fmt.Printf("%d. %s\n", i+1, site.ServerName)
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
	}
}

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

func checkAndDeploy(ctx context.Context, cfgManager *config.Manager, log *logger.Logger) {
	log.Info("开始检查证书...")

	// 1. 扫描 Apache 配置
	s := scanner.New()
	scannedSites, err := s.Scan()
	if err != nil {
		log.Warn("扫描 Apache 配置失败: %v", err)
	} else {
		log.LogScan(s.GetConfigPath(), len(scannedSites))
	}

	// 2. 构建域名到扫描站点的映射
	scannedMap := make(map[string]*scanner.SSLSite)
	for _, site := range scannedSites {
		scannedMap[site.ServerName] = site
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
		// 只处理 apache 类型的站点
		if site.ServerType != "apache" {
			continue
		}

		// 检查是否需要续期
		if !site.NeedsRenewal() {
			log.Debug("站点 %s 证书有效，跳过", site.SiteName)
			continue
		}

		// 匹配扫描到的站点
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

		// 使用配置中的路径（优先级更高）
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

	// 扫描获取实际路径
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

	// 使用配置中的路径（优先级更高）
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

	// 如果没有找到 SSL 配置，检查是否有 HTTP 站点并提示安装
	if !foundSSL && certPath == "" && keyPath == "" {
		// 尝试查找 HTTP 站点
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
				// 输入证书路径
				defaultCertPath := fmt.Sprintf("/etc/ssl/certs/%s.pem", httpSite.ServerName)
				certPath = prompt.InputPath("证书路径", defaultCertPath, false)

				defaultKeyPath := fmt.Sprintf("/etc/ssl/private/%s.key", httpSite.ServerName)
				keyPath = prompt.InputPath("私钥路径", defaultKeyPath, false)

				defaultChainPath := fmt.Sprintf("/etc/ssl/certs/%s-chain.pem", httpSite.ServerName)
				chainPath = prompt.Input("证书链路径 (可选)", defaultChainPath)

				// 安装 HTTPS 配置
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

// issueSite 签发并部署证书
func issueSite(cfgManager *config.Manager, siteName string, log *logger.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("加载站点配置失败: %w", err)
	}

	// 扫描获取实际路径
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

	// 使用配置中的路径（优先级更高）
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
	return deployWithCertData(cfgManager, site, certPath, keyPath, chainPath, certData, privateKey, log)
}

// deployWithCertData 使用已获取的证书数据部署
func deployWithCertData(cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath, chainPath string, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
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

	// 备份旧证书
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

	// 部署证书
	d := deployer.NewApacheDeployer(
		certPath,
		keyPath,
		chainPath,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

		// 尝试回滚
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

	// 重载服务日志
	if site.Reload.ReloadCommand != "" {
		log.LogReload(site.Reload.ReloadCommand, true, "", nil)
	}

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
			ServerType:    "apache",
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

func deploySiteConfig(ctx context.Context, cfgManager *config.Manager, site *config.SiteConfig, certPath, keyPath, chainPath, webroot string, log *logger.Logger) error {
	log.Info("开始部署站点: %s", site.SiteName)

	// 1. 获取证书
	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, site.API.URL, site.API.ReferID)
	if err != nil {
		return fmt.Errorf("获取证书失败: %w", err)
	}

	// 1.1 处理文件验证 (status=processing 且返回 file 数据)
	if certData.Status == "processing" && certData.File != nil {
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

	// 4. 获取私钥（优先 API，否则读取本地）
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

	// 4.1 验证证书和私钥配对
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("证书私钥配对验证失败: %w", err)
	}

	// 5. 备份旧证书
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

	// 6. 部署证书（Apache 使用分离的证书和链文件）
	d := deployer.NewApacheDeployer(
		certPath,
		keyPath,
		chainPath,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, privateKey); err != nil {
		log.LogDeployment(site.SiteName, certPath, keyPath, false, err)

		// 尝试回滚
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

	// 7. 重载服务日志
	if site.Reload.ReloadCommand != "" {
		log.LogReload(site.Reload.ReloadCommand, true, "", nil)
	}

	// 8. 更新元数据
	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		log.Warn("保存站点元数据失败: %v", err)
	}

	// 9. 发送部署回调
	if site.API.CallbackURL != "" {
		callbackReq := &fetcher.CallbackRequest{
			Domain:        site.SiteName,
			Status:        "success",
			DeployedAt:    time.Now().Format(time.RFC3339),
			CertExpiresAt: cert.NotAfter.Format(time.RFC3339),
			CertSerial:    fmt.Sprintf("%X", cert.SerialNumber),
			ServerType:    "apache",
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

	// 获取证书路径
	var certPath, keyPath, chainPath, configFile string

	// 首先检查配置中是否有路径
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

	// 如果没有配置文件路径，尝试从扫描器查找
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

	// 如果还是没找到配置文件，尝试查找 HTTP VirtualHost
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

	// 创建安装器
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

// interactiveInstallHTTPS 交互式安装 HTTPS 配置
func interactiveInstallHTTPS(cfgManager *config.Manager, log *logger.Logger) error {
	if !prompt.IsInteractive() {
		return fmt.Errorf("需要交互式终端，请使用 -site 参数指定站点")
	}

	fmt.Println("正在扫描 Apache 配置...")

	// 扫描 HTTP 站点
	s := scanner.New()
	httpSites, err := s.ScanHTTPSites()
	if err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}

	if len(httpSites) == 0 {
		fmt.Println("未发现未启用 HTTPS 的站点")
		return nil
	}

	// 显示站点列表
	fmt.Printf("\n发现 %d 个未启用 HTTPS 的站点:\n", len(httpSites))
	options := make([]string, len(httpSites))
	for i, site := range httpSites {
		options[i] = fmt.Sprintf("%s (%s)", site.ServerName, site.ConfigFile)
	}

	// 选择站点
	idx := prompt.SelectWithCancel("请选择要安装 HTTPS 的站点", options)
	if idx < 0 {
		fmt.Println("已取消")
		return nil
	}

	selectedSite := httpSites[idx]
	fmt.Printf("\n已选择: %s\n", selectedSite.ServerName)

	// 输入证书路径
	defaultCertPath := fmt.Sprintf("/etc/ssl/certs/%s.pem", selectedSite.ServerName)
	certPath := prompt.InputPath("证书路径", defaultCertPath, false)

	defaultKeyPath := fmt.Sprintf("/etc/ssl/private/%s.key", selectedSite.ServerName)
	keyPath := prompt.InputPath("私钥路径", defaultKeyPath, false)

	defaultChainPath := fmt.Sprintf("/etc/ssl/certs/%s-chain.pem", selectedSite.ServerName)
	chainPath := prompt.Input("证书链路径 (可选)", defaultChainPath)

	// 确认安装
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

	// 创建安装器
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
