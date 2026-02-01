// Package daemon 守护进程模式
package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	apacheDeployer "github.com/zhuxbo/cert-deploy/internal/apache/deployer"
	nginxDeployer "github.com/zhuxbo/cert-deploy/internal/nginx/deployer"
	"github.com/zhuxbo/cert-deploy/pkg/backup"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/csr"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
	"github.com/zhuxbo/cert-deploy/pkg/util"
	"github.com/zhuxbo/cert-deploy/pkg/validator"
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

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动时立即检查一次
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
func checkAndDeploy(ctx context.Context, cfgManager *config.ConfigManager, log *logger.Logger) {
	log.Info("开始检查证书...")

	// 重新加载配置
	cfg, err := cfgManager.Reload()
	if err != nil {
		log.Error("加载配置失败: %v", err)
		return
	}

	if cfg.API.URL == "" || cfg.API.Token == "" {
		log.Warn("API 配置不完整，跳过检查")
		return
	}

	f := fetcher.New(30 * time.Second)
	backupMgr := backup.NewManager(cfgManager.GetBackupDir(), 5)

	for i := range cfg.Certificates {
		cert := &cfg.Certificates[i]
		if !cert.Enabled {
			continue
		}

		// 检查是否需要续期
		if !cert.NeedsRenewal(&cfg.Schedule) {
			log.Debug("证书 %s 有效期充足，跳过", cert.CertName)
			continue
		}

		log.Info("证书 %s 需要续期，开始处理...", cert.CertName)

		mode := getRenewMode(&cfg.Schedule)

		var (
			certData   *fetcher.CertData
			privateKey string
		)

		if mode == config.RenewModeLocal {
			certData, privateKey, err = prepareLocalRenew(ctx, cert, cfg.API, f, log, cfgManager.GetWorkDir())
			if err != nil {
				log.Warn("证书 %s 本地续签失败: %v", cert.CertName, err)
				continue
			}
			if certData == nil {
				continue
			}
		} else {
			certData, privateKey, err = preparePullRenew(ctx, cert, cfg.API, f, log)
			if err != nil {
				log.Warn("证书 %s 拉取失败: %v", cert.CertName, err)
				continue
			}
			if certData == nil {
				continue
			}
		}

		deploySuccess, err := deployCertToBindings(ctx, cert, certData, privateKey, backupMgr, log)
		if err != nil {
			log.Warn("证书 %s 部署失败: %v", cert.CertName, err)
			continue
		}
		if deploySuccess {
			if err := cfgManager.UpdateCert(cert); err != nil {
				log.Warn("更新证书元数据失败: %v", err)
			}
		}
	}

	// 更新检查时间
	cfg.Metadata.LastCheckAt = time.Now()
	cfgManager.Save(cfg)

	log.Info("检查完成")
}

// deployToBinding 部署证书到绑定（带备份和回滚）
func deployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string, backupMgr *backup.Manager, log *logger.Logger) error {
	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 1. 备份现有证书（如果存在）
	var backupPath string
	if util.FileExists(binding.Paths.Certificate) && util.FileExists(binding.Paths.PrivateKey) {
		result, err := backupMgr.Backup(binding.SiteName, binding.Paths.Certificate, binding.Paths.PrivateKey, nil, binding.Paths.ChainFile)
		if err != nil {
			log.Warn("备份证书失败（继续部署）: %v", err)
		} else if result != nil {
			backupPath = result.BackupPath
			log.Debug("已备份证书到: %s", backupPath)
		}
	}

	// 2. 部署
	var deployErr error
	switch binding.ServerType {
	case config.ServerTypeNginx, config.ServerTypeDockerNginx:
		d := nginxDeployer.NewNginxDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		deployErr = d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)

	case config.ServerTypeApache, config.ServerTypeDockerApache:
		d := apacheDeployer.NewApacheDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Paths.ChainFile,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		deployErr = d.Deploy(certData.Cert, certData.IntermediateCert, privateKey)

	default:
		return fmt.Errorf("不支持的服务器类型: %s", binding.ServerType)
	}

	// 3. 部署失败时回滚
	if deployErr != nil && backupPath != "" {
		log.Warn("部署失败，尝试回滚: %v", deployErr)
		if rollbackErr := rollbackFromBackup(binding, backupPath, backupMgr, log); rollbackErr != nil {
			log.Error("回滚失败: %v", rollbackErr)
		} else {
			log.Info("已回滚到备份: %s", backupPath)
		}
		return fmt.Errorf("部署失败（已回滚）: %w", deployErr)
	}

	return deployErr
}

// rollbackFromBackup 从备份回滚证书
func rollbackFromBackup(binding *config.SiteBinding, backupPath string, backupMgr *backup.Manager, log *logger.Logger) error {
	certPath, keyPath, chainPath := backupMgr.GetBackupPathsWithChain(backupPath)

	// 恢复证书文件
	if err := util.CopyFile(certPath, binding.Paths.Certificate); err != nil {
		return fmt.Errorf("恢复证书失败: %w", err)
	}

	// 恢复私钥文件
	if err := util.CopyFile(keyPath, binding.Paths.PrivateKey); err != nil {
		return fmt.Errorf("恢复私钥失败: %w", err)
	}

	// 恢复证书链文件（如果有）
	if binding.Paths.ChainFile != "" && util.FileExists(chainPath) {
		if err := util.CopyFile(chainPath, binding.Paths.ChainFile); err != nil {
			log.Warn("恢复证书链失败: %v", err)
		}
	}

	// 重载服务
	switch binding.ServerType {
	case config.ServerTypeNginx, config.ServerTypeDockerNginx:
		d := nginxDeployer.NewNginxDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		return d.Reload()

	case config.ServerTypeApache, config.ServerTypeDockerApache:
		d := apacheDeployer.NewApacheDeployer(
			binding.Paths.Certificate,
			binding.Paths.PrivateKey,
			binding.Paths.ChainFile,
			binding.Reload.TestCommand,
			binding.Reload.ReloadCommand,
		)
		return d.Reload()
	}

	return nil
}

// csrPendingTimeout CSR 处于 processing 状态的最大等待时间
const csrPendingTimeout = 24 * time.Hour

// getRenewMode 获取续签模式（带默认值）
func getRenewMode(schedule *config.ScheduleConfig) string {
	mode := schedule.RenewMode
	if mode == "" {
		return config.RenewModePull
	}
	return mode
}

// pickKeyPath 选择一个可用的私钥路径（优先启用的绑定）
func pickKeyPath(cert *config.CertConfig) string {
	for i := range cert.Bindings {
		if cert.Bindings[i].Enabled && cert.Bindings[i].Paths.PrivateKey != "" {
			return cert.Bindings[i].Paths.PrivateKey
		}
	}
	if len(cert.Bindings) > 0 {
		return cert.Bindings[0].Paths.PrivateKey
	}
	return ""
}

// readPrivateKey 读取本地私钥内容
func readPrivateKey(keyPath string) (string, error) {
	if keyPath == "" {
		return "", fmt.Errorf("private key path is empty")
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	return string(keyData), nil
}

// savePrivateKey 保存本地私钥（0600）
func savePrivateKey(keyPath string, keyPEM string) error {
	if keyPath == "" {
		return fmt.Errorf("private key path is empty")
	}
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}
	return os.WriteFile(keyPath, []byte(keyPEM), 0600)
}

// preparePullRenew 拉取模式：等待服务端续签完成后拉取证书
func preparePullRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig, f *fetcher.Fetcher, log *logger.Logger) (*fetcher.CertData, string, error) {
	certData, err := f.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, "", err
	}
	if certData.Status != "active" || certData.Cert == "" {
		log.Debug("证书 %s 状态: %s，跳过", cert.CertName, certData.Status)
		return nil, "", nil
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取
	privateKey := certData.PrivateKey
	if privateKey == "" {
		keyPath := pickKeyPath(cert)
		if keyPath == "" {
			return nil, "", fmt.Errorf("missing local private key path")
		}
		keyData, err := readPrivateKey(keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("读取本地私钥失败: %w", err)
		}
		privateKey = keyData
		log.Debug("证书 %s 使用本地私钥: %s", cert.CertName, keyPath)
	}

	if privateKey == "" {
		return nil, "", fmt.Errorf("缺少私钥（API 未返回且本地不存在）")
	}
	return certData, privateKey, nil
}

// pendingKeyDir 待确认私钥目录
const pendingKeyDir = "pending-keys"

// getPendingKeyPath 获取待确认私钥路径
func getPendingKeyPath(workDir, certName string) string {
	return filepath.Join(workDir, pendingKeyDir, certName, "pending-key.pem")
}

// savePendingKey 保存待确认私钥到临时位置
func savePendingKey(workDir, certName, keyPEM string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	pendingDir := filepath.Dir(pendingPath)
	if err := os.MkdirAll(pendingDir, 0700); err != nil {
		return err
	}
	return os.WriteFile(pendingPath, []byte(keyPEM), 0600)
}

// readPendingKey 读取待确认私钥
func readPendingKey(workDir, certName string) (string, error) {
	pendingPath := getPendingKeyPath(workDir, certName)
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// commitPendingKey 签发成功后将待确认私钥移动到正式位置
func commitPendingKey(workDir, certName, targetPath string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		return nil // 不存在则跳过
	}
	// 确保目标目录存在
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return err
	}
	// 移动文件
	if err := os.Rename(pendingPath, targetPath); err != nil {
		// 如果跨文件系统，使用复制+删除
		data, err := os.ReadFile(pendingPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, data, 0600); err != nil {
			return err
		}
		os.Remove(pendingPath)
	}
	// 清理待确认目录
	os.Remove(filepath.Dir(pendingPath))
	return nil
}

// cleanupPendingKey 清理待确认私钥
func cleanupPendingKey(workDir, certName string) {
	pendingPath := getPendingKeyPath(workDir, certName)
	os.Remove(pendingPath)
	os.Remove(filepath.Dir(pendingPath))
}

// prepareLocalRenew 本地私钥模式：生成 CSR 并通过 API 触发续签
func prepareLocalRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig, f *fetcher.Fetcher, log *logger.Logger, workDir string) (*fetcher.CertData, string, error) {
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return nil, "", fmt.Errorf("missing local private key path")
	}

	// 如果上次提交仍在处理中，先查询状态
	if cert.Metadata.LastIssueState == "processing" {
		if !cert.Metadata.CSRSubmittedAt.IsZero() && time.Since(cert.Metadata.CSRSubmittedAt) > csrPendingTimeout {
			log.Warn("证书 %s CSR 已提交超过 %s，尝试重新提交", cert.CertName, csrPendingTimeout)
			cert.Metadata.LastIssueState = ""
			cleanupPendingKey(workDir, cert.CertName)
		} else {
			certData, err := f.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
			if err != nil {
				return nil, "", fmt.Errorf("查询订单失败: %w", err)
			}
			if certData.Status == "processing" {
				log.Debug("证书 %s CSR 正在处理，跳过", cert.CertName)
				return nil, "", nil
			}
			if certData.Status != "active" || certData.Cert == "" {
				log.Warn("证书 %s 状态异常: %s，将重新提交 CSR", cert.CertName, certData.Status)
				cert.Metadata.IssueRetryCount++
				cert.Metadata.LastIssueState = ""
				cleanupPendingKey(workDir, cert.CertName)
				return nil, "", nil
			}

			// 签发成功，尝试读取待确认私钥
			privateKey, err := readPendingKey(workDir, cert.CertName)
			if err != nil {
				// 回退到正式私钥
				privateKey, err = readPrivateKey(keyPath)
				if err != nil {
					return nil, "", fmt.Errorf("读取私钥失败: %w", err)
				}
			} else {
				// 将待确认私钥提交为正式私钥
				if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
					log.Warn("提交待确认私钥失败: %v", err)
				}
			}
			return certData, privateKey, nil
		}
	}

	// 生成新的私钥与 CSR
	// 标记进入续签重试状态，避免 14 天阈值后停止检查
	if cert.Metadata.IssueRetryCount == 0 {
		cert.Metadata.IssueRetryCount = 1
	} else {
		cert.Metadata.IssueRetryCount++
	}

	commonName := ""
	if len(cert.Domains) > 0 {
		commonName = cert.Domains[0]
	}
	if commonName == "" {
		return nil, "", fmt.Errorf("缺少域名，无法生成 CSR")
	}

	privateKey, csrPEM, csrHash, err := csr.GenerateKeyAndCSR(csr.KeyOptions{}, csr.CSROptions{
		CommonName: commonName,
	})
	if err != nil {
		return nil, "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// 新私钥保存到待确认目录（不覆盖正式私钥）
	if err := savePendingKey(workDir, cert.CertName, privateKey); err != nil {
		return nil, "", fmt.Errorf("保存待确认私钥失败: %w", err)
	}

	certData, err := f.Update(ctx, api.URL, api.Token, cert.OrderID, csrPEM, strings.Join(cert.Domains, ","), "")
	if err != nil {
		// 提交失败，清理待确认私钥
		cleanupPendingKey(workDir, cert.CertName)
		return nil, "", fmt.Errorf("提交 CSR 失败: %w", err)
	}

	if certData.OrderID > 0 {
		cert.OrderID = certData.OrderID
	}

	cert.Metadata.CSRSubmittedAt = time.Now()
	cert.Metadata.LastCSRHash = csrHash
	cert.Metadata.LastIssueState = certData.Status

	if certData.Status != "active" || certData.Cert == "" {
		log.Info("证书 %s CSR 已提交，等待签发 (status=%s)", cert.CertName, certData.Status)
		return nil, "", nil
	}

	// 签发成功，将待确认私钥提交为正式私钥
	if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
		log.Warn("提交待确认私钥失败: %v", err)
	}

	return certData, privateKey, nil
}

// deployCertToBindings 验证并部署证书到所有绑定
func deployCertToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string, backupMgr *backup.Manager, log *logger.Logger) (bool, error) {
	// 验证证书与私钥
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return false, fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return false, fmt.Errorf("私钥不匹配: %w", err)
	}

	// 部署到所有绑定
	deploySuccess := true
	for j := range cert.Bindings {
		binding := &cert.Bindings[j]
		if !binding.Enabled {
			continue
		}

		if err := deployToBinding(ctx, binding, certData, privateKey, backupMgr, log); err != nil {
			log.Error("部署到 %s 失败: %v", binding.SiteName, err)
			deploySuccess = false
			continue
		}
		log.Info("证书已部署到 %s", binding.SiteName)
	}

	// 更新元数据
	if deploySuccess {
		cert.Metadata.LastDeployAt = time.Now()
		cert.Metadata.CertExpiresAt = parsedCert.NotAfter
		cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		// 成功后清理本地续签状态
		cert.Metadata.CSRSubmittedAt = time.Time{}
		cert.Metadata.LastCSRHash = ""
		cert.Metadata.LastIssueState = ""
		cert.Metadata.IssueRetryCount = 0
	}
	return deploySuccess, nil
}
