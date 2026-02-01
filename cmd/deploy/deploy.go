// Package deploy 证书部署命令
package deploy

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apacheDeployer "github.com/zhuxbo/cert-deploy/internal/apache/deployer"
	nginxDeployer "github.com/zhuxbo/cert-deploy/internal/nginx/deployer"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
	"github.com/zhuxbo/cert-deploy/pkg/validator"
)

// Run 运行 deploy 命令
func Run(args []string, version, buildTime string, debug bool) {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	certName := fs.String("cert", "", "证书名称")
	all := fs.Bool("all", false, "部署所有证书")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: cert-deploy deploy --cert <name>\n")
		fmt.Fprintf(os.Stderr, "      cert-deploy deploy --all\n\n选项:\n")
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
			if err := deployCert(ctx, cfgManager, cert, cfg.API, f, log); err != nil {
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
		if err := deployCert(ctx, cfgManager, cert, cfg.API, f, log); err != nil {
			fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("部署完成")
}

// deployCert 部署单个证书
func deployCert(ctx context.Context, cfgManager *config.ConfigManager, cert *config.CertConfig, api config.APIConfig, f *fetcher.Fetcher, log *logger.Logger) error {
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
	privateKey := certData.PrivateKey
	if privateKey == "" {
		// 本地私钥模式或 API 未返回私钥，尝试从第一个绑定的私钥路径读取
		if len(cert.Bindings) > 0 {
			keyPath := cert.Bindings[0].Paths.PrivateKey
			if keyPath != "" {
				keyData, err := os.ReadFile(keyPath)
				if err != nil {
					return fmt.Errorf("读取本地私钥失败: %w", err)
				}
				privateKey = string(keyData)
				fmt.Printf("  使用本地私钥: %s\n", keyPath)
			}
		}
	}

	if privateKey == "" {
		return fmt.Errorf("缺少私钥（API 未返回且本地不存在）")
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
func deployToBinding(binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, log *logger.Logger) error {
	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	switch binding.ServerType {
	case config.ServerTypeNginx, config.ServerTypeDockerNginx:
		d := nginxDeployer.NewNginxDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		return d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)

	case config.ServerTypeApache, config.ServerTypeDockerApache:
		d := apacheDeployer.NewApacheDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Paths.ChainFile,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		return d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)

	default:
		return fmt.Errorf("不支持的服务器类型: %s", binding.ServerType)
	}
}
