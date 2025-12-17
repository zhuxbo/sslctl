// Apache 证书部署客户端
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cnssl/cert-deploy/internal/apache/deployer"
	"github.com/cnssl/cert-deploy/internal/nginx/config"
	"github.com/cnssl/cert-deploy/pkg/fetcher"
	"github.com/cnssl/cert-deploy/pkg/validator"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// 命令行参数
	var (
		showVersion = flag.Bool("version", false, "显示版本信息")
		siteName    = flag.String("site", "", "站点名称")
		daemon      = flag.Bool("daemon", false, "守护进程模式")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-deploy-apache %s (built at %s)\n", version, buildTime)
		os.Exit(0)
	}

	// 初始化日志
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 获取可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("failed to get executable path", "error", err)
		os.Exit(1)
	}

	// 初始化配置管理器（复用 nginx 的配置结构）
	cfgManager, err := config.NewManager(execPath)
	if err != nil {
		logger.Error("failed to create config manager", "error", err)
		os.Exit(1)
	}

	if *daemon {
		runDaemon(cfgManager, logger)
	} else if *siteName != "" {
		if err := deploySite(cfgManager, *siteName, logger); err != nil {
			logger.Error("deployment failed", "error", err)
			os.Exit(1)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
}

func runDaemon(cfgManager *config.Manager, logger *slog.Logger) {
	logger.Info("starting daemon mode")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 立即执行一次
	checkAndDeploy(ctx, cfgManager, logger)

	for {
		select {
		case <-ticker.C:
			checkAndDeploy(ctx, cfgManager, logger)
		case sig := <-sigCh:
			logger.Info("received signal, shutting down", "signal", sig)
			return
		}
	}
}

func checkAndDeploy(ctx context.Context, cfgManager *config.Manager, logger *slog.Logger) {
	sites, err := cfgManager.ListSites()
	if err != nil {
		logger.Error("failed to list sites", "error", err)
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
		if site.NeedsRenewal() {
			if err := deploySiteConfig(ctx, cfgManager, site, logger); err != nil {
				logger.Error("failed to deploy site", "site", site.SiteName, "error", err)
			}
		}
	}
}

func deploySite(cfgManager *config.Manager, siteName string, logger *slog.Logger) error {
	site, err := cfgManager.LoadSite(siteName)
	if err != nil {
		return fmt.Errorf("failed to load site config: %w", err)
	}

	ctx := context.Background()
	return deploySiteConfig(ctx, cfgManager, site, logger)
}

func deploySiteConfig(ctx context.Context, cfgManager *config.Manager, site *config.SiteConfig, logger *slog.Logger) error {
	logger.Info("deploying certificate", "site", site.SiteName)

	// 1. 获取证书
	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, site.API.URL, site.API.ReferID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return fmt.Errorf("certificate not ready: status=%s", certData.Status)
	}

	// 2. 验证证书
	v := validator.New("")
	cert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// 3. 验证域名覆盖
	dv := validator.NewDomainValidator(site.Domains, site.Validation.IgnoreDomainMismatch)
	if err := dv.ValidateDomainCoverage(cert); err != nil {
		return fmt.Errorf("domain validation failed: %w", err)
	}

	// 4. 读取本地私钥
	keyBytes, err := os.ReadFile(site.Paths.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// 5. 部署证书（Apache 使用分离的证书和链文件）
	d := deployer.NewApacheDeployer(
		site.Paths.Certificate,
		site.Paths.PrivateKey,
		site.Paths.ChainFile,
		site.Reload.TestCommand,
		site.Reload.ReloadCommand,
	)

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, string(keyBytes)); err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	// 6. 更新元数据
	site.Metadata.CertExpiresAt = cert.NotAfter
	site.Metadata.CertSerial = fmt.Sprintf("%X", cert.SerialNumber)
	site.Metadata.LastDeployAt = time.Now()
	site.Metadata.LastCheckAt = time.Now()

	if err := cfgManager.SaveSite(site); err != nil {
		logger.Warn("failed to save site metadata", "error", err)
	}

	logger.Info("certificate deployed successfully", "site", site.SiteName, "expires", cert.NotAfter)
	return nil
}
