// Package daemon 守护进程模式
package daemon

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/zhuxbo/sslctl/pkg/certops"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
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
	defer func() { _ = log.Close() }()

	if debug {
		log.SetLevel(logger.LevelDebug)
	}

	log.Info("sslctl daemon 启动 (version: %s)", version)

	// 加载配置
	cfg, err := cfgManager.Load()
	if err != nil {
		log.Error("加载配置失败: %v", err)
		os.Exit(1)
	}

	log.Info("检查频率: 每天一次（随机时间）")

	// 关闭超时
	shutdownTimeout := time.Duration(cfg.Schedule.ShutdownTimeoutSeconds) * time.Second
	if shutdownTimeout == 0 {
		shutdownTimeout = time.Duration(config.DefaultShutdownTimeoutSeconds) * time.Second
	}

	// 创建证书服务
	svc := certops.NewService(cfgManager, log)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 用于等待正在运行的任务完成
	var wg sync.WaitGroup
	taskRunning := make(chan struct{}, 1) // 防止任务重叠

	// 启动时立即检查一次（占用 taskRunning 防止与 ticker 重叠）
	taskRunning <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-taskRunning }()
		checkAndDeploy(ctx, svc, cfgManager, log)
	}()

	for {
		delay := nextRandomDaily()
		log.Info("下次检查: %v 后", delay.Round(time.Minute))
		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			// 检查是否有任务正在运行，防止重叠
			select {
			case taskRunning <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-taskRunning }()
					checkAndDeploy(ctx, svc, cfgManager, log)
				}()
			default:
				log.Debug("上一次检查任务仍在运行，跳过本次检查")
			}
		case sig := <-sigCh:
			timer.Stop()
			log.Info("收到信号 %v，正在退出...", sig)
			// 取消 context，通知正在运行的任务停止
			cancel()

			// 等待任务完成
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				log.Info("所有任务已完成，退出")
			case <-time.After(shutdownTimeout):
				log.Warn("等待任务完成超时（%v），强制退出", shutdownTimeout)
			}
			return
		}
	}
}

// nextRandomDaily 计算到明天随机时刻的延迟
// 在明天 00:00~23:59 之间随机选择一个时间点，最短不低于 1 小时
func nextRandomDaily() time.Duration {
	now := time.Now()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1,
		rand.IntN(24), rand.IntN(60), 0, 0, now.Location())
	delay := tomorrow.Sub(now)
	if delay < time.Hour {
		delay += 24 * time.Hour
	}
	return delay
}

// calcCheckTimeout 根据证书数量动态计算检查超时
// 最小 30 分钟，每个证书 2 分钟，上限 4 小时
func calcCheckTimeout(certCount int) time.Duration {
	count := certCount
	if count > 100 {
		count = 100
	}
	timeout := time.Duration(count) * 2 * time.Minute
	if timeout < 30*time.Minute {
		timeout = 30 * time.Minute
	}
	if timeout > 4*time.Hour {
		timeout = 4 * time.Hour
	}
	return timeout
}

// checkAndDeploy 检查并部署证书
func checkAndDeploy(parentCtx context.Context, svc *certops.Service, cfgManager *config.ConfigManager, log *logger.Logger) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("检查任务 panic: %v", r)
		}
	}()

	// 动态计算超时：根据证书数量调整，防止大量证书场景超时
	certCount := 0
	if cfg, err := cfgManager.Load(); err == nil {
		certCount = len(cfg.Certificates)
	}
	timeout := calcCheckTimeout(certCount)
	log.Debug("检查超时: %v（证书数: %d）", timeout.Round(time.Minute), certCount)
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

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
		case "failure":
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

	// 检查证书过期告警
	svc.CheckExpiry()
}
