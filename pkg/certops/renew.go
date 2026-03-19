// Package certops 证书续签逻辑
package certops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// csrPendingTimeout CSR 处于 processing 状态的最大等待时间
const csrPendingTimeout = 24 * time.Hour

// pendingKeyDir 待确认私钥目录
const pendingKeyDir = "pending-keys"

// MaxIssueRetryCount 最大重试次数
const MaxIssueRetryCount = 10

// CheckAndRenewAll 检查并续签所有证书
func (s *Service) CheckAndRenewAll(ctx context.Context) ([]*RenewResult, error) {
	cfg, err := s.cfgManager.Load()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	var results []*RenewResult

	for i := range cfg.Certificates {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		cert := cfg.Certificates[i]
		if !cert.Enabled {
			continue
		}

		// 逐证书检查 API 配置
		api := cert.GetAPI()
		if api.URL == "" || api.Token == "" {
			s.log.Warn("证书 %s 的 API 配置不完整，跳过续签", cert.CertName)
			continue
		}

		// 检查是否需要续期
		if !cert.NeedsRenewal(&cfg.Schedule) {
			s.log.Debug("证书 %s 有效期充足，跳过", cert.CertName)
			continue
		}

		s.log.Info("证书 %s 需要续期，开始处理...", cert.CertName)

		mode := cert.GetRenewMode(&cfg.Schedule)
		result := &RenewResult{
			CertName: cert.CertName,
			Mode:     mode,
		}

		var (
			certData   *fetcher.CertData
			privateKey string
		)

		if mode == config.RenewModeLocal {
			certData, privateKey, err = s.prepareLocalRenew(ctx, &cert, api)
		} else {
			certData, privateKey, err = s.preparePullRenew(ctx, &cert, api)
		}

		if err != nil {
			result.Status = "failure"
			result.Error = err
			s.log.Warn("证书 %s 续签失败: %v", cert.CertName, err)
			results = append(results, result)
			continue
		}

		if certData == nil {
			result.Status = "pending"
			results = append(results, result)
			continue
		}

		// 部署证书
		deployCount, deployErr := s.deployCertToBindings(ctx, &cert, certData, privateKey)
		result.DeployCount = deployCount
		if deployErr != nil {
			result.Status = "failure"
			result.Error = deployErr
		} else {
			result.Status = "success"
		}

		// 部分成功时也需持久化元数据（deployCertToBindings 内部已更新 cert 的过期时间等）
		if deployCount > 0 {
			if err := s.cfgManager.UpdateCert(&cert); err != nil {
				s.log.Warn("更新证书元数据失败: %v", err)
			}
		}

		// 发送续签回调（仅在有明确结果时）
		if result.Status == "success" || result.Status == "failure" {
			s.sendRenewCallback(ctx, &cert, result)
		}

		results = append(results, result)
	}

	// 更新检查时间（使用原子更新避免覆盖其他并发修改）
	_ = s.cfgManager.UpdateMetadata(func(m *config.ConfigMetadata) {
		m.LastCheckAt = time.Now()
	})

	return results, nil
}

// sendRenewCallback 向 API 发送续签结果回调
// 非关键路径，失败仅记录日志
func (s *Service) sendRenewCallback(ctx context.Context, cert *config.CertConfig, result *RenewResult) {
	msg := ""
	if result.Error != nil {
		msg = result.Error.Error()
	}

	callbackReq := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Domain:     strings.Join(cert.Domains, ","),
		Status:     result.Status,
		DeployedAt: time.Now().Format(time.RFC3339),
		Message:    msg,
	}

	fillCertMetadata(callbackReq, cert)
	s.sendCallback(ctx, cert.GetAPI(), callbackReq)
}

// getRenewMode 获取续签模式（带默认值）
func getRenewMode(schedule *config.ScheduleConfig) string {
	mode := schedule.RenewMode
	if mode == "" {
		return config.RenewModePull
	}
	return mode
}

// preparePullRenew 自动签发：等待服务端续签完成后拉取证书
func (s *Service) preparePullRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	certData, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, "", err
	}
	if certData.Status != "active" || certData.Cert == "" {
		s.log.Debug("证书 %s 状态: %s，跳过", cert.CertName, certData.Status)
		return nil, "", nil
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取
	privateKey, err := GetPrivateKey(cert, certData.PrivateKey, s.log)
	if err != nil {
		return nil, "", err
	}
	return certData, privateKey, nil
}

// prepareLocalRenew 本机提交：生成 CSR 并通过 API 触发续签
func (s *Service) prepareLocalRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	// 自动重置过期的重试计数（CSR 提交超过 7 天则重置）
	if cert.Metadata.IssueRetryCount > 0 && !cert.Metadata.CSRSubmittedAt.IsZero() &&
		time.Since(cert.Metadata.CSRSubmittedAt) > 7*24*time.Hour {
		s.log.Info("证书 %s 重试计数已过期（超过 7 天），重置为 0", cert.CertName)
		cert.Metadata.IssueRetryCount = 0
		cert.Metadata.LastIssueState = ""
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("重置重试计数失败: %v", err)
		}
	}

	// 检查重试次数是否超限
	if cert.Metadata.IssueRetryCount >= MaxIssueRetryCount {
		s.log.Error("证书 %s 重试次数已达上限 (%d)，跳过", cert.CertName, MaxIssueRetryCount)
		return nil, "", fmt.Errorf("exceeded max retry count (%d)", MaxIssueRetryCount)
	}

	workDir := s.cfgManager.GetWorkDir()
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return nil, "", fmt.Errorf("missing local private key path")
	}

	// 如果上次提交仍在处理中，先查询状态
	if cert.Metadata.LastIssueState == "processing" {
		if !cert.Metadata.CSRSubmittedAt.IsZero() && time.Since(cert.Metadata.CSRSubmittedAt) > csrPendingTimeout {
			s.log.Warn("证书 %s CSR 已提交超过 %s，尝试重新提交", cert.CertName, csrPendingTimeout)
			// 注意：不在这里递增 IssueRetryCount，后面生成新 CSR 时会递增
			cert.Metadata.LastIssueState = ""
			if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
				s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
			}
			if err := s.cfgManager.UpdateCert(cert); err != nil {
				s.log.Warn("更新证书元数据失败: %v", err)
			}
		} else {
			certData, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
			if err != nil {
				return nil, "", fmt.Errorf("查询订单失败: %w", err)
			}
			if certData.Status == "processing" {
				s.log.Debug("证书 %s CSR 正在处理，跳过", cert.CertName)
				return nil, "", nil
			}
			if certData.Status != "active" || certData.Cert == "" {
				s.log.Warn("证书 %s 状态异常: %s，将重新提交 CSR", cert.CertName, certData.Status)
				// 注意：不在这里递增 IssueRetryCount，下次生成新 CSR 时会递增
				// 清空状态，下次检查将进入生成新 CSR 分支
				cert.Metadata.LastIssueState = ""
				if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
					s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
				}
				_ = s.cfgManager.UpdateCert(cert)
				return nil, "", nil
			}

			// 签发成功，尝试读取待确认私钥
			privateKey, err := readPendingKey(workDir, cert.CertName)
			if err != nil {
				// 回退到正式私钥，使用安全读取函数
				keyData, readErr := util.SafeReadFile(keyPath, config.MaxPrivateKeySize)
				if readErr != nil {
					return nil, "", fmt.Errorf("读取私钥失败: %w", readErr)
				}
				privateKey = string(keyData)
			} else {
				// 将待确认私钥提交为正式私钥
				if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
					return nil, "", fmt.Errorf("提交待确认私钥失败: %w", err)
				}
			}

			if certData.IntermediateCert == "" {
				return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
			}
			return certData, privateKey, nil
		}
	}

	// 生成新的私钥与 CSR
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

	// CSR 成功提交前先递增并持久化重试计数（确保计数不会丢失）
	cert.Metadata.IssueRetryCount++
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		// 持久化失败时回滚内存中的计数，避免不一致
		cert.Metadata.IssueRetryCount--
		if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
			s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
		}
		return nil, "", fmt.Errorf("持久化重试计数失败: %w", err)
	}

	certData, err := s.fetcher.Update(ctx, api.URL, api.Token, cert.OrderID, csrPEM, strings.Join(cert.Domains, ","), "")
	if err != nil {
		// 提交失败，清理待确认私钥（重试计数已持久化，下次重试会使用）
		if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
			s.log.Warn("清理待确认私钥失败: %v", cleanupErr)
		}
		return nil, "", fmt.Errorf("提交 CSR 失败: %w", err)
	}

	if certData.OrderID > 0 {
		cert.OrderID = certData.OrderID
	}

	cert.Metadata.CSRSubmittedAt = time.Now()
	cert.Metadata.LastCSRHash = csrHash
	cert.Metadata.LastIssueState = certData.Status

	if certData.Status != "active" || certData.Cert == "" {
		// 保存元数据变更（OrderID、CSRSubmittedAt 等）
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("保存证书元数据失败: %v", err)
		}
		s.log.Info("证书 %s CSR 已提交，等待签发 (status=%s)", cert.CertName, certData.Status)
		return nil, "", nil
	}

	// 签发成功，将待确认私钥提交为正式私钥
	if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
		return nil, "", fmt.Errorf("提交待确认私钥失败: %w", err)
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	return certData, privateKey, nil
}

// deployCertToBindings 部署证书到所有绑定
func (s *Service) deployCertToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string) (int, error) {
	// 验证证书与私钥
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil || parsedCert == nil {
		return 0, fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return 0, fmt.Errorf("私钥不匹配: %w", err)
	}

	// 部署到所有绑定
	deployCount := 0
	var lastErr error
	for j := range cert.Bindings {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		binding := cert.Bindings[j]
		if !binding.Enabled {
			continue
		}

		if err := s.deployToBinding(ctx, &binding, certData, privateKey); err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.ServerName, err)
			lastErr = err
			continue
		}
		s.log.Info("证书已部署到 %s", binding.ServerName)
		deployCount++
	}

	// 更新元数据
	if deployCount > 0 {
		cert.Metadata.LastDeployAt = time.Now()
		cert.Metadata.CertExpiresAt = parsedCert.NotAfter
		cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		// 成功后清理本地续签状态
		cert.Metadata.CSRSubmittedAt = time.Time{}
		cert.Metadata.LastCSRHash = ""
		cert.Metadata.LastIssueState = ""
		cert.Metadata.IssueRetryCount = 0
	}

	return deployCount, lastErr
}

// getPendingKeyPath 获取待确认私钥路径
func getPendingKeyPath(workDir, certName string) string {
	return filepath.Join(workDir, pendingKeyDir, certName, "pending-key.pem")
}

// savePendingKey 保存待确认私钥到临时位置
func savePendingKey(workDir, certName, keyPEM string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	pendingDir := filepath.Dir(pendingPath)
	if err := util.EnsureDir(pendingDir, 0700); err != nil {
		return err
	}
	return util.AtomicWrite(pendingPath, []byte(keyPEM), 0600)
}

// readPendingKey 读取待确认私钥
// 使用 SafeReadFile 进行安全读取：大小限制 + 符号链接防护 + TOCTOU 保护
func readPendingKey(workDir, certName string) (string, error) {
	pendingPath := getPendingKeyPath(workDir, certName)
	data, err := util.SafeReadFile(pendingPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// commitPendingKey 签发成功后将待确认私钥移动到正式位置
// 失败时错误信息包含相对路径（脱敏），便于手动恢复
func commitPendingKey(workDir, certName, targetPath string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		return nil // 不存在则跳过
	}
	// 相对路径用于错误消息（脱敏）
	pendingRelPath := filepath.Join(pendingKeyDir, certName, "pending-key.pem")

	// 确保目标目录存在
	targetDir := filepath.Dir(targetPath)
	if err := util.EnsureDir(targetDir, 0700); err != nil {
		return fmt.Errorf("创建目标目录失败: %w (pending 私钥保留在: %s，请手动恢复)", err, pendingRelPath)
	}
	// 移动文件
	if err := os.Rename(pendingPath, targetPath); err != nil {
		// 如果跨文件系统，使用原子写入：先写临时文件，再重命名
		data, readErr := os.ReadFile(pendingPath)
		if readErr != nil {
			// 读取失败，保留 pending 私钥以便手动恢复
			return fmt.Errorf("读取待确认私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", readErr, pendingRelPath)
		}
		// 使用 AtomicWrite 安全写入（带符号链接防护）
		if writeErr := util.AtomicWrite(targetPath, data, 0600); writeErr != nil {
			// 清零内存中的私钥材料
			for i := range data {
				data[i] = 0
			}
			return fmt.Errorf("写入目标私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", writeErr, pendingRelPath)
		}
		// 清零内存中的私钥材料
		for i := range data {
			data[i] = 0
		}
		// 成功后才清理 pending 私钥
		_ = os.Remove(pendingPath)
	}
	// 清理待确认目录
	_ = os.Remove(filepath.Dir(pendingPath))
	return nil
}

// cleanupPendingKey 清理待确认私钥，返回清理过程中遇到的第一个错误
func cleanupPendingKey(workDir, certName string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	var firstErr error
	if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		firstErr = err
	}
	if err := os.Remove(filepath.Dir(pendingPath)); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

