// Package certops 证书续签逻辑
package certops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/csr"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/validator"
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

	if cfg.API.URL == "" || cfg.API.Token == "" {
		return nil, fmt.Errorf("API 配置不完整")
	}

	var results []*RenewResult

	for i := range cfg.Certificates {
		cert := &cfg.Certificates[i]
		if !cert.Enabled {
			continue
		}

		// 检查是否需要续期
		if !cert.NeedsRenewal(&cfg.Schedule) {
			s.log.Debug("证书 %s 有效期充足，跳过", cert.CertName)
			continue
		}

		s.log.Info("证书 %s 需要续期，开始处理...", cert.CertName)

		mode := getRenewMode(&cfg.Schedule)
		result := &RenewResult{
			CertName: cert.CertName,
			Mode:     mode,
		}

		var (
			certData   *fetcher.CertData
			privateKey string
		)

		if mode == config.RenewModeLocal {
			certData, privateKey, err = s.prepareLocalRenew(ctx, cert, cfg.API)
		} else {
			certData, privateKey, err = s.preparePullRenew(ctx, cert, cfg.API)
		}

		if err != nil {
			result.Status = "failed"
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
		deployCount, deployErr := s.deployCertToBindings(ctx, cert, certData, privateKey)
		if deployErr != nil {
			result.Status = "failed"
			result.Error = deployErr
		} else {
			result.Status = "success"
			result.DeployCount = deployCount
		}

		// 更新配置
		if result.Status == "success" {
			if err := s.cfgManager.UpdateCert(cert); err != nil {
				s.log.Warn("更新证书元数据失败: %v", err)
			}
		}

		results = append(results, result)
	}

	// 更新检查时间
	cfg.Metadata.LastCheckAt = time.Now()
	s.cfgManager.Save(cfg)

	return results, nil
}

// getRenewMode 获取续签模式（带默认值）
func getRenewMode(schedule *config.ScheduleConfig) string {
	mode := schedule.RenewMode
	if mode == "" {
		return config.RenewModePull
	}
	return mode
}

// preparePullRenew 拉取模式：等待服务端续签完成后拉取证书
func (s *Service) preparePullRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	certData, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, "", err
	}
	if certData.Status != "active" || certData.Cert == "" {
		s.log.Debug("证书 %s 状态: %s，跳过", cert.CertName, certData.Status)
		return nil, "", nil
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取
	privateKey := certData.PrivateKey
	if privateKey == "" {
		keyPath := pickKeyPath(cert)
		if keyPath == "" {
			return nil, "", fmt.Errorf("missing local private key path")
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("读取本地私钥失败: %w", err)
		}
		privateKey = string(keyData)
		s.log.Debug("证书 %s 使用本地私钥: %s", cert.CertName, keyPath)
	}

	if privateKey == "" {
		return nil, "", fmt.Errorf("缺少私钥（API 未返回且本地不存在）")
	}
	return certData, privateKey, nil
}

// prepareLocalRenew 本地私钥模式：生成 CSR 并通过 API 触发续签
func (s *Service) prepareLocalRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
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
			cert.Metadata.IssueRetryCount++
			cert.Metadata.LastIssueState = ""
			cleanupPendingKey(workDir, cert.CertName)
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
				cert.Metadata.IssueRetryCount++
				// 立即持久化 IssueRetryCount
				s.cfgManager.UpdateCert(cert)
				cert.Metadata.LastIssueState = ""
				cleanupPendingKey(workDir, cert.CertName)
				return nil, "", nil
			}

			// 签发成功，尝试读取待确认私钥
			privateKey, err := readPendingKey(workDir, cert.CertName)
			if err != nil {
				// 回退到正式私钥
				keyData, err := os.ReadFile(keyPath)
				if err != nil {
					return nil, "", fmt.Errorf("读取私钥失败: %w", err)
				}
				privateKey = string(keyData)
			} else {
				// 将待确认私钥提交为正式私钥
				if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
					s.log.Warn("提交待确认私钥失败: %v", err)
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
	// 立即持久化 IssueRetryCount
	s.cfgManager.UpdateCert(cert)

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

	certData, err := s.fetcher.Update(ctx, api.URL, api.Token, cert.OrderID, csrPEM, strings.Join(cert.Domains, ","), "")
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
		s.log.Info("证书 %s CSR 已提交，等待签发 (status=%s)", cert.CertName, certData.Status)
		return nil, "", nil
	}

	// 签发成功，将待确认私钥提交为正式私钥
	if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil {
		s.log.Warn("提交待确认私钥失败: %v", err)
	}

	return certData, privateKey, nil
}

// deployCertToBindings 部署证书到所有绑定
func (s *Service) deployCertToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string) (int, error) {
	// 验证证书与私钥
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil {
		return 0, fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return 0, fmt.Errorf("私钥不匹配: %w", err)
	}

	// 部署到所有绑定
	deployCount := 0
	var lastErr error
	for j := range cert.Bindings {
		binding := &cert.Bindings[j]
		if !binding.Enabled {
			continue
		}

		if err := s.deployToBinding(ctx, binding, certData, privateKey); err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.SiteName, err)
			lastErr = err
			continue
		}
		s.log.Info("证书已部署到 %s", binding.SiteName)
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
		data, readErr := os.ReadFile(pendingPath)
		if readErr != nil {
			cleanupPendingKey(workDir, certName) // 确保清理
			return readErr
		}
		if writeErr := os.WriteFile(targetPath, data, 0600); writeErr != nil {
			cleanupPendingKey(workDir, certName) // 确保清理
			return writeErr
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
