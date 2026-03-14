// Package certops 证书部署逻辑
package certops

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// DeployOne 部署指定证书
// 注意：部分绑定失败时返回 nil error，调用方必须检查 result.Success 和 result.Error。
// 仅当所有启用的绑定均部署失败时，才同时返回非 nil error。
func (s *Service) DeployOne(ctx context.Context, certName string) (*DeployResult, error) {
	cert, err := s.cfgManager.GetCert(certName)
	if err != nil {
		return nil, fmt.Errorf("获取证书配置失败: %w", err)
	}

	api := cert.GetAPI()
	if api.URL == "" || api.Token == "" {
		return nil, fmt.Errorf("证书 %s 的 API 配置不完整", certName)
	}

	// 从 API 获取证书
	certData, err := s.fetcher.QueryOrder(ctx, api.URL, api.Token, cert.OrderID)
	if err != nil {
		return nil, fmt.Errorf("获取证书失败: %w", err)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return nil, fmt.Errorf("证书未就绪 (status=%s)", certData.Status)
	}

	if certData.IntermediateCert == "" {
		return nil, fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取
	privateKey, err := GetPrivateKey(cert, certData.PrivateKey, s.log)
	if err != nil {
		return nil, err
	}

	// 部署到所有绑定
	result := &DeployResult{
		CertName: certName,
		Success:  true,
	}

	enabledCount := 0
	successCount := 0
	for i := range cert.Bindings {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		binding := cert.Bindings[i]
		if !binding.Enabled {
			continue
		}
		enabledCount++

		err := s.deployToBinding(ctx, &binding, certData, privateKey)
		if err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.SiteName, err)
			result.Success = false
			result.Error = err
		} else {
			s.log.Info("证书已部署到 %s", binding.SiteName)
			successCount++
		}
	}

	// 发送部署回调（非关键路径，失败仅记录日志）
	s.sendDeployCallback(ctx, cert, result)

	// 如果所有绑定都部署失败，返回错误
	if enabledCount > 0 && successCount == 0 && result.Error != nil {
		return result, result.Error
	}

	return result, nil
}

// DeployAllCerts 部署所有启用的证书
func (s *Service) DeployAllCerts(ctx context.Context) ([]*DeployResult, error) {
	certs, err := s.cfgManager.ListEnabledCerts()
	if err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %w", err)
	}

	var results []*DeployResult
	for _, cert := range certs {
		result, err := s.DeployOne(ctx, cert.CertName)
		if err != nil {
			results = append(results, &DeployResult{
				CertName: cert.CertName,
				Success:  false,
				Error:    err,
			})
		} else {
			results = append(results, result)
		}
	}

	return results, nil
}

// sendDeployCallback 向 API 发送部署结果回调
// 非关键路径，失败仅记录日志不影响部署结果
func (s *Service) sendDeployCallback(ctx context.Context, cert *config.CertConfig, result *DeployResult) {
	status := "success"
	msg := ""
	if !result.Success {
		status = "failure"
		if result.Error != nil {
			msg = result.Error.Error()
		}
	}

	// 收集绑定的服务器类型
	var serverTypes []string
	for _, b := range cert.Bindings {
		if b.Enabled && b.ServerType != "" {
			serverTypes = append(serverTypes, b.ServerType)
		}
	}

	callbackReq := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Domain:     strings.Join(cert.Domains, ","),
		Status:     status,
		DeployedAt: time.Now().Format(time.RFC3339),
		ServerType: strings.Join(serverTypes, ","),
		Message:    msg,
	}

	fillCertMetadata(callbackReq, cert)
	s.sendCallback(ctx, cert.GetAPI(), callbackReq)
}

// deployToBinding 部署证书到绑定（带备份和回滚）
func (s *Service) deployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string) error {
	// 验证证书与私钥
	v := validator.New("")
	if _, err := v.ValidateCert(certData.Cert); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "证书验证失败", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "私钥不匹配", err)
	}

	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := util.EnsureDir(certDir, 0700); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseWriteCert, "创建证书目录失败", err)
	}

	// 1. 备份现有证书（如果存在）
	var backupPath string
	if util.FileExists(binding.Paths.Certificate) && util.FileExists(binding.Paths.PrivateKey) {
		result, err := s.backupMgr.Backup(binding.SiteName, binding.Paths.Certificate, binding.Paths.PrivateKey, nil, binding.Paths.ChainFile)
		if err != nil {
			s.log.Warn("备份证书失败（继续部署）: %v", err)
		} else if result != nil {
			backupPath = result.BackupPath
			s.log.Debug("已备份证书到: %s", backupPath)
		}
	}

	// 2. 部署（使用 webserver 抽象层）
	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseWriteCert, "创建部署器失败", err)
	}
	deployErr := deployer.Deploy(certData.Cert, certData.IntermediateCert, privateKey)

	// 3. 部署失败时回滚
	if deployErr != nil && backupPath != "" {
		s.log.Warn("部署失败，尝试回滚: %v", deployErr)
		if rollbackErr := s.rollbackFromBackup(binding, backupPath); rollbackErr != nil {
			s.log.Error("回滚失败: %v", rollbackErr)
			// 构造手动恢复指引
			recoveryCmd := fmt.Sprintf("cp %s %s && cp %s %s",
				util.ShellQuote(backupPath+"/cert.pem"), util.ShellQuote(binding.Paths.Certificate),
				util.ShellQuote(backupPath+"/key.pem"), util.ShellQuote(binding.Paths.PrivateKey))
			if binding.Reload.TestCommand != "" {
				recoveryCmd += " && " + binding.Reload.TestCommand
			}
			if binding.Reload.ReloadCommand != "" {
				recoveryCmd += " && " + binding.Reload.ReloadCommand
			}
			return errors.NewStructuredDeployError(errors.DeployErrorUnknown, errors.PhaseRollback,
				fmt.Sprintf("部署失败且回滚失败（服务可能不可用）: deploy=%v, rollback=%v\n手动恢复: %s", deployErr, rollbackErr, recoveryCmd), nil)
		}
		s.log.Info("已回滚到备份: %s", backupPath)
		return errors.NewStructuredDeployError(errors.DeployErrorReload, errors.PhaseReload, "部署失败（已回滚）", deployErr)
	}

	return deployErr
}

// rollbackFromBackup 从备份回滚证书
// 直接调用 Deployer.Rollback()，包含完整回滚逻辑（文件恢复 + 测试 + 重载）
func (s *Service) rollbackFromBackup(binding *config.SiteBinding, backupPath string) error {
	certPath, keyPath, chainPath := s.backupMgr.GetBackupPathsWithChain(backupPath)

	// 使用 webserver 抽象层创建部署器
	deployer, err := webserver.NewDeployer(
		webserver.ServerType(binding.ServerType),
		binding.Paths.Certificate,
		binding.Paths.PrivateKey,
		binding.Paths.ChainFile,
		binding.Reload.TestCommand,
		binding.Reload.ReloadCommand,
	)
	if err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseRollback, "创建部署器失败", err)
	}

	// 直接调用 Deployer.Rollback，包含完整回滚逻辑
	if err := deployer.Rollback(certPath, keyPath, chainPath); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseRollback, "回滚失败", err)
	}
	return nil
}

// pickKeyPath 选择一个可用的私钥路径（优先启用的绑定）
func pickKeyPath(cert *config.CertConfig) string {
	for i := range cert.Bindings {
		// 使用值拷贝而非指针，与 DeployOne 保持一致
		binding := cert.Bindings[i]
		if binding.Enabled && binding.Paths.PrivateKey != "" {
			return binding.Paths.PrivateKey
		}
	}
	if len(cert.Bindings) > 0 {
		return cert.Bindings[0].Paths.PrivateKey
	}
	return ""
}
