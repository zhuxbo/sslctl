// Package deploy 证书部署命令
package deploy

import (
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
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// Run 运行 deploy 命令
func Run(args []string, version, buildTime string, debug bool) {
	// 检查是否为 local 子命令
	if len(args) > 0 && args[0] == "local" {
		runLocal(args[1:], debug)
		return
	}

	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	certName := fs.String("cert", "", "证书名称")
	all := fs.Bool("all", false, "部署所有证书")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl deploy --cert <name>\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy --all\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy local --cert <file> --key <file> --site <name>\n\n选项:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *certName == "" && !*all {
		fs.Usage()
		os.Exit(1)
	}

	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}

	log, err := logger.New(logDir, "deploy")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	cfg, err := cfgManager.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	if cfg.API.URL == "" || cfg.API.Token == "" {
		fmt.Fprintln(os.Stderr, "API 配置不完整，请先运行 setup 命令")
		os.Exit(1)
	}

	ctx := context.Background()
	f := fetcher.New(30 * time.Second)

	if *all {
		// 部署所有证书
		for i := range cfg.Certificates {
			cert := &cfg.Certificates[i]
			if !cert.Enabled {
				continue
			}
			if err := fetchAndDeployCert(ctx, cfgManager, cert, cfg.API, f, log); err != nil {
				log.Error("部署证书 %s 失败: %v", cert.CertName, err)
			}
		}
	} else {
		// 部署指定证书
		cert, err := cfgManager.GetCert(*certName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "证书不存在: %s\n", *certName)
			os.Exit(1)
		}
		if err := fetchAndDeployCert(ctx, cfgManager, cert, cfg.API, f, log); err != nil {
			fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("部署完成")
}

// fetchAndDeployCert 从 API 获取并部署单个证书到所有绑定
func fetchAndDeployCert(ctx context.Context, cfgManager *config.ConfigManager, cert *config.CertConfig, api config.APIConfig, f *fetcher.Fetcher, log *logger.Logger) error {
	fmt.Printf("部署证书: %s\n", cert.CertName)

	// 查询证书
	certData, err := f.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return fmt.Errorf("查询证书失败: %w", err)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return fmt.Errorf("证书未就绪: status=%s", certData.Status)
	}

	// 验证证书
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取
	privateKey, err := certops.GetPrivateKeyFromBindings(cert.Bindings, certData.PrivateKey)
	if err != nil {
		return err
	}
	if certData.PrivateKey == "" && len(cert.Bindings) > 0 && cert.Bindings[0].Paths.PrivateKey != "" {
		fmt.Printf("  使用本地私钥: %s\n", cert.Bindings[0].Paths.PrivateKey)
	}

	// 验证私钥与证书匹配
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("私钥与证书不匹配: %w", err)
	}

	// 部署到所有绑定
	for i := range cert.Bindings {
		binding := &cert.Bindings[i]
		if !binding.Enabled {
			continue
		}

		fmt.Printf("  部署到: %s\n", binding.SiteName)

		if err := deployToBinding(binding, certData, privateKey, log); err != nil {
			fmt.Printf("    失败: %v\n", err)
			continue
		}
		fmt.Printf("    成功\n")
	}

	// 更新元数据
	cert.Metadata.LastDeployAt = time.Now()
	cert.Metadata.CertExpiresAt = parsedCert.NotAfter
	cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)

	return cfgManager.UpdateCert(cert)
}

// deployToBinding 部署到绑定
// 错误处理设计说明：
// - 目录创建和部署器创建使用 fmt.Errorf（环境/配置错误，非部署阶段）
// - deployer.Deploy() 返回 StructuredDeployError（部署阶段错误），直接透传保留错误类型
// - 这种分层设计使调用方可以区分错误来源和阶段
func deployToBinding(binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

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

	// 直接返回 deployer.Deploy 的结果，保留 StructuredDeployError 类型
	return deployer.Deploy(certData.Cert, certData.IntermediateCert, privateKey)
}

// runLocal 运行本地证书部署子命令
func runLocal(args []string, debug bool) {
	fs := flag.NewFlagSet("deploy local", flag.ExitOnError)
	certFile := fs.String("cert", "", "证书文件路径")
	keyFile := fs.String("key", "", "私钥文件路径")
	caFile := fs.String("ca", "", "CA 证书链文件路径（Apache 需要）")
	siteName := fs.String("site", "", "目标站点名称")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: sslctl deploy local --cert <file> --key <file> --site <name>\n")
		fmt.Fprintf(os.Stderr, "      sslctl deploy local --cert <file> --key <file> --ca <file> --site <name>\n\n")
		fmt.Fprintf(os.Stderr, "从本地文件部署证书到指定站点。\n\n")
		fmt.Fprintf(os.Stderr, "选项:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  sslctl deploy local --cert cert.pem --key key.pem --site example.com\n")
		fmt.Fprintf(os.Stderr, "  sslctl deploy local --cert cert.pem --key key.pem --ca chain.pem --site apache-site.com\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// 验证必需参数
	if *certFile == "" || *keyFile == "" || *siteName == "" {
		fmt.Fprintln(os.Stderr, "错误: --cert, --key, --site 参数是必需的")
		fs.Usage()
		os.Exit(1)
	}

	// 初始化配置管理器
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

	log, err := logger.New(logDir, "deploy-local")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	// 验证并读取证书文件（使用 SafeReadFile 防止 TOCTOU 攻击）
	const maxCertFileSize = 1 << 20 // 1MB
	certData, err := util.SafeReadFile(*certFile, maxCertFileSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取证书文件失败: %v\n", err)
		os.Exit(1)
	}

	// 验证并读取私钥文件
	keyData, err := util.SafeReadFile(*keyFile, maxCertFileSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取私钥文件失败: %v\n", err)
		os.Exit(1)
	}

	// 读取 CA 证书文件（可选）
	var caData string
	if *caFile != "" {
		ca, err := util.SafeReadFile(*caFile, maxCertFileSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 CA 证书文件失败: %v\n", err)
			os.Exit(1)
		}
		caData = string(ca)
	}

	certPEM := string(certData)
	keyPEM := string(keyData)

	// 验证证书
	v := validator.New("")
	if _, err := v.ValidateCert(certPEM); err != nil {
		fmt.Fprintf(os.Stderr, "证书验证失败: %v\n", err)
		os.Exit(1)
	}

	// 验证私钥
	if err := v.ValidateKey(keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "私钥验证失败: %v\n", err)
		os.Exit(1)
	}

	// 验证证书和私钥匹配
	if err := v.ValidateCertKeyPair(certPEM, keyPEM); err != nil {
		fmt.Fprintf(os.Stderr, "证书和私钥不匹配: %v\n", err)
		os.Exit(1)
	}

	// 验证 CA 证书（如果提供）
	if caData != "" {
		if err := v.ValidateCA(caData); err != nil {
			fmt.Fprintf(os.Stderr, "CA 证书验证失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 从配置获取站点绑定（优先从 config.json，回退到 scan-result.json）
	binding, err := getSiteBindingForLocal(cfgManager, *siteName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取站点配置失败: %v\n", err)
		fmt.Fprintf(os.Stderr, "提示: 请先运行 'sslctl scan' 扫描站点\n")
		os.Exit(1)
	}

	// 检查站点是否启用
	if !binding.Enabled {
		fmt.Fprintf(os.Stderr, "错误: 站点 %s 已被禁用\n", binding.SiteName)
		os.Exit(1)
	}

	// 检查 Apache 是否需要 CA 证书（仅当配置了 ChainFile 时才要求）
	if isApacheType(binding.ServerType) && binding.Paths.ChainFile != "" && caData == "" {
		fmt.Fprintf(os.Stderr, "错误: Apache 站点已配置证书链路径，需要提供 --ca 参数\n")
		os.Exit(1)
	}

	fmt.Printf("部署本地证书到站点: %s (%s)\n", binding.SiteName, binding.ServerType)

	// 构造 CertData 并部署
	certDataStruct := &fetcher.CertData{
		Cert:             certPEM,
		IntermediateCert: caData,
	}

	if err := deployToBinding(binding, certDataStruct, keyPEM, log); err != nil {
		fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("部署成功")
}

// isApacheType 判断是否为 Apache 类型服务器
func isApacheType(serverType string) bool {
	return strings.HasPrefix(serverType, "apache") || strings.HasSuffix(serverType, "-apache")
}

// getSiteBindingForLocal 获取站点绑定（用于 deploy local）
// 优先从 config.json 的证书绑定中查找，回退到 scan-result.json
func getSiteBindingForLocal(cfgManager *config.ConfigManager, siteName string) (*config.SiteBinding, error) {
	// 1. 优先从 config.json 的证书绑定中查找
	binding, err := cfgManager.GetSiteBinding(siteName)
	if err == nil {
		return binding, nil
	}

	// 2. 回退到 scan-result.json
	scanResult, err := config.LoadScanResult()
	if err != nil {
		return nil, fmt.Errorf("站点未找到，且无法加载扫描结果: %w", err)
	}

	site := scanResult.FindSiteByID(siteName)
	if site == nil {
		return nil, fmt.Errorf("站点 %s 不存在于配置或扫描结果中", siteName)
	}

	// 3. 从扫描结果构造绑定
	return buildBindingFromScanResult(site, cfgManager), nil
}

// validateFilePath 验证文件路径安全性（已废弃，使用 util.SafeReadFile 代替）
// 保留此函数用于兼容，但建议直接使用 SafeReadFile 进行原子性的验证和读取
func validateFilePath(path string) error {
	// 检查路径遍历
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains traversal sequence")
	}

	// 获取文件信息（不跟随符号链接）
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}

	// 必须是常规文件
	if !info.Mode().IsRegular() {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links not allowed for security")
		}
		return fmt.Errorf("not a regular file")
	}

	// 检查文件大小（防止读取超大文件导致内存耗尽）
	const maxFileSize = 1 << 20 // 1MB，足够容纳证书和私钥
	if info.Size() > maxFileSize {
		return fmt.Errorf("file too large (max %d bytes)", maxFileSize)
	}

	return nil
}

// buildBindingFromScanResult 从扫描结果构造站点绑定
func buildBindingFromScanResult(site *config.ScannedSite, cfgManager *config.ConfigManager) *config.SiteBinding {
	// 确定服务器类型（多重判断提高准确性）
	serverType := detectServerType(site)

	// 确定证书路径
	certPath := site.CertificatePath
	keyPath := site.PrivateKeyPath
	if site.HostCertPath != "" {
		certPath = site.HostCertPath
	}
	if site.HostKeyPath != "" {
		keyPath = site.HostKeyPath
	}

	// 如果扫描结果没有证书路径，使用默认路径
	if certPath == "" {
		certPath = config.GetDefaultCertPath(site.ServerName)
	}
	if keyPath == "" {
		keyPath = config.GetDefaultKeyPath(site.ServerName)
	}

	binding := &config.SiteBinding{
		SiteName:   site.ServerName,
		ServerType: serverType,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ConfigFile:  site.ConfigFile,
		},
	}

	// 注意：不自动填充 Apache ChainFile，允许 fullchain 单文件部署
	// 用户如需分离 chain file，可通过 --ca 参数指定

	// Docker 站点添加信息
	if site.Source == "docker" {
		binding.Docker = &config.DockerInfo{
			ContainerName: site.ContainerName,
		}
		if site.VolumeMode {
			binding.Docker.DeployMode = "volume"
		} else {
			binding.Docker.DeployMode = "copy"
		}
	}

	// 添加默认重载命令
	if serverType == config.ServerTypeNginx {
		binding.Reload = config.ReloadConfig{
			TestCommand:   "nginx -t",
			ReloadCommand: "systemctl reload nginx",
		}
	} else if serverType == config.ServerTypeApache {
		binding.Reload = config.ReloadConfig{
			TestCommand:   "apachectl -t",
			ReloadCommand: "systemctl reload apache2 || systemctl reload httpd",
		}
	}

	return binding
}

// detectServerType 检测服务器类型（多重判断提高准确性）
func detectServerType(site *config.ScannedSite) string {
	isDocker := site.Source == "docker"

	// 1. 通过配置文件内容特征判断（如果可读）
	if site.ConfigFile != "" {
		if content, err := os.ReadFile(site.ConfigFile); err == nil {
			contentStr := string(content)
			// Apache 特征指令
			if strings.Contains(contentStr, "<VirtualHost") ||
				strings.Contains(contentStr, "SSLCertificateFile") ||
				strings.Contains(contentStr, "SSLCertificateKeyFile") {
				if isDocker {
					return config.ServerTypeDockerApache
				}
				return config.ServerTypeApache
			}
			// Nginx 特征指令
			if strings.Contains(contentStr, "server {") ||
				strings.Contains(contentStr, "ssl_certificate") ||
				strings.Contains(contentStr, "ssl_certificate_key") {
				if isDocker {
					return config.ServerTypeDockerNginx
				}
				return config.ServerTypeNginx
			}
		}
	}

	// 2. 回退到路径关键词判断
	configPath := strings.ToLower(site.ConfigFile)
	if strings.Contains(configPath, "apache") || strings.Contains(configPath, "httpd") {
		if isDocker {
			return config.ServerTypeDockerApache
		}
		return config.ServerTypeApache
	}

	// 3. 默认为 Nginx
	if isDocker {
		return config.ServerTypeDockerNginx
	}
	return config.ServerTypeNginx
}
