// IIS 证书部署客户端
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

	"github.com/cnssl/cert-deploy/internal/iis/deployer"
	"github.com/cnssl/cert-deploy/pkg/fetcher"
	"github.com/cnssl/cert-deploy/pkg/validator"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

// Config IIS 部署配置
type Config struct {
	APIURL    string
	ReferID   string
	SiteName  string
	Hostname  string
	Port      int
	TempDir   string
	LogLevel  string
}

func main() {
	// 命令行参数
	var (
		showVersion = flag.Bool("version", false, "显示版本信息")
		daemon      = flag.Bool("daemon", false, "守护进程模式")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-deploy-iis %s (built at %s)\n", version, buildTime)
		os.Exit(0)
	}

	// 初始化日志
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 从环境变量加载配置
	cfg := loadConfig()
	if err := validateConfig(cfg); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// 验证 IIS 模块
	d := deployer.NewIISDeployer(cfg.SiteName, cfg.Hostname, cfg.Port, cfg.TempDir)
	if err := d.ValidateIISModule(); err != nil {
		logger.Error("IIS module validation failed", "error", err)
		os.Exit(1)
	}

	if *daemon {
		runDaemon(cfg, logger)
	} else {
		if err := deploy(cfg, logger); err != nil {
			logger.Error("deployment failed", "error", err)
			os.Exit(1)
		}
	}
}

func loadConfig() *Config {
	port := 443
	if p := os.Getenv("IIS_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	tempDir := os.Getenv("TEMP_DIR")
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	return &Config{
		APIURL:   os.Getenv("CERT_API_URL"),
		ReferID:  os.Getenv("CERT_REFER_ID"),
		SiteName: os.Getenv("IIS_SITE_NAME"),
		Hostname: os.Getenv("IIS_HOSTNAME"),
		Port:     port,
		TempDir:  tempDir,
		LogLevel: getEnvDefault("LOG_LEVEL", "info"),
	}
}

func validateConfig(cfg *Config) error {
	if cfg.APIURL == "" {
		return fmt.Errorf("CERT_API_URL is required")
	}
	if cfg.ReferID == "" {
		return fmt.Errorf("CERT_REFER_ID is required")
	}
	if cfg.SiteName == "" {
		return fmt.Errorf("IIS_SITE_NAME is required")
	}
	return nil
}

func runDaemon(cfg *Config, logger *slog.Logger) {
	logger.Info("starting daemon mode")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	// 立即执行一次
	if err := deploy(cfg, logger); err != nil {
		logger.Error("initial deployment failed", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := deploy(cfg, logger); err != nil {
				logger.Error("deployment failed", "error", err)
			}
		case sig := <-sigCh:
			logger.Info("received signal, shutting down", "signal", sig)
			return
		}
	}
}

func deploy(cfg *Config, logger *slog.Logger) error {
	ctx := context.Background()
	logger.Info("deploying certificate", "site", cfg.SiteName)

	// 1. 获取证书
	f := fetcher.New(30 * time.Second)
	certData, err := f.Info(ctx, cfg.APIURL, cfg.ReferID)
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

	// 3. 验证域名
	if cfg.Hostname != "" {
		dv := validator.NewDomainValidator([]string{cfg.Hostname}, false)
		if err := dv.ValidateDomainCoverage(cert); err != nil {
			logger.Warn("domain validation warning", "error", err)
		}
	}

	// 4. 部署证书到 IIS
	d := deployer.NewIISDeployer(cfg.SiteName, cfg.Hostname, cfg.Port, cfg.TempDir)

	// IIS 需要私钥，从 API 获取或本地文件读取
	// 这里假设私钥需要另外获取（通过环境变量指定路径）
	keyPath := os.Getenv("CERT_KEY_PATH")
	if keyPath == "" {
		return fmt.Errorf("CERT_KEY_PATH is required for IIS deployment")
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	if err := d.Deploy(certData.Cert, certData.IntermediateCert, string(keyBytes)); err != nil {
		return fmt.Errorf("IIS deployment failed: %w", err)
	}

	logger.Info("certificate deployed successfully", "site", cfg.SiteName, "expires", cert.NotAfter)
	return nil
}

func getEnvDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
