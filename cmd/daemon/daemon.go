// Package daemon 守护进程模式
package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/certops"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
)

// Run 运行守护进程
func Run(args []string, version, buildTime string, debug bool) {
	cfgManager, err := config.NewConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}

	logDir := cfgManager.GetLogsDir()
	if debug {
		logDir = filepath.Join(logDir, "debug")
	}

	log, err := logger.New(logDir, "daemon")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建日志失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	log.Info("cert-deploy daemon 启动 (version: %s)", version)

	// 加载配置
	cfg, err := cfgManager.Load()
	if err != nil {
		log.Error("加载配置失败: %v", err)
		os.Exit(1)
	}

	// 检查间隔
	interval := time.Duration(cfg.Schedule.CheckIntervalHours) * time.Hour
	if interval == 0 {
		interval = time.Duration(config.DefaultCheckIntervalHours) * time.Hour
	}
	log.Info("检查间隔: %v", interval)

	// 创建证书服务
	svc := certops.NewService(cfgManager, log)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动时立即检查一次
	checkAndDeploy(ctx, svc, log)

	for {
		select {
		case <-ticker.C:
			checkAndDeploy(ctx, svc, log)
		case sig := <-sigCh:
			log.Info("收到信号 %v，正在退出", sig)
			return
		}
	}
}

// checkAndDeploy 检查并部署证书
func checkAndDeploy(ctx context.Context, svc *certops.Service, log *logger.Logger) {
	log.Info("开始检查证书...")

	results, err := svc.CheckAndRenewAll(ctx)
	if err != nil {
		log.Error("检查证书失败: %v", err)
		return
	}

	// 输出结果统计
	var successCount, failedCount, pendingCount int
	for _, r := range results {
		switch r.Status {
		case "success":
			successCount++
			log.Info("证书 %s 续签成功，部署到 %d 个站点", r.CertName, r.DeployCount)
		case "failed":
			failedCount++
			log.Warn("证书 %s 续签失败: %v", r.CertName, r.Error)
		case "pending":
			pendingCount++
			log.Debug("证书 %s 等待签发中", r.CertName)
		}
	}

	if len(results) > 0 {
		log.Info("检查完成: 成功 %d, 失败 %d, 等待中 %d", successCount, failedCount, pendingCount)
	} else {
		log.Info("检查完成: 无需续签的证书")
	}
}
