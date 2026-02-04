// Package certops 证书部署逻辑
package certops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	apacheDeployer "github.com/zhuxbo/sslctl/internal/apache/deployer"
	nginxDeployer "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// DeployOne 部署指定证书
func (s *Service) DeployOne(ctx context.Context, certName string) (*DeployResult, error) {
	cert, err := s.cfgManager.GetCert(certName)
	if err != nil {
		return nil, fmt.Errorf("获取证书配置失败: %w", err)
	}

	cfg, err := s.cfgManager.Load()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 从 API 获取证书
	certData, err := s.fetcher.QueryOrder(ctx, cfg.API.URL, cfg.API.Token, cert.OrderID)
	if err != nil {
		return nil, fmt.Errorf("获取证书失败: %w", err)
	}

	if certData.Status != "active" || certData.Cert == "" {
		return nil, fmt.Errorf("证书未就绪 (status=%s)", certData.Status)
	}

	// 获取私钥
	privateKey := certData.PrivateKey
	if privateKey == "" {
		keyPath := pickKeyPath(cert)
		if keyPath == "" {
			return nil, fmt.Errorf("缺少私钥路径")
		}
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取本地私钥失败: %w", err)
		}
		privateKey = string(keyData)
	}

	// 部署到所有绑定
	result := &DeployResult{
		CertName: certName,
		Success:  true,
	}

	enabledCount := 0
	successCount := 0
	for i := range cert.Bindings {
		binding := &cert.Bindings[i]
		if !binding.Enabled {
			continue
		}
		enabledCount++

		err := s.deployToBinding(ctx, binding, certData, privateKey)
		if err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.SiteName, err)
			result.Success = false
			result.Error = err
		} else {
			s.log.Info("证书已部署到 %s", binding.SiteName)
			successCount++
		}
	}

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

// deployToBinding 部署证书到绑定（带备份和回滚）
func (s *Service) deployToBinding(ctx context.Context, binding *config.SiteBinding, certData *fetcher.CertData, privateKey string) error {
	// 验证证书与私钥
	v := validator.New("")
	if _, err := v.ValidateCert(certData.Cert); err != nil {
		return fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return fmt.Errorf("私钥不匹配: %w", err)
	}

	// 确保目录存在
	certDir := filepath.Dir(binding.Paths.Certificate)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
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
		s.log.Warn("部署失败，尝试回滚: %v", deployErr)
		if rollbackErr := s.rollbackFromBackup(binding, backupPath); rollbackErr != nil {
			s.log.Error("回滚失败: %v", rollbackErr)
		} else {
			s.log.Info("已回滚到备份: %s", backupPath)
		}
		return fmt.Errorf("部署失败（已回滚）: %w", deployErr)
	}

	return deployErr
}

// rollbackFromBackup 从备份回滚证书
func (s *Service) rollbackFromBackup(binding *config.SiteBinding, backupPath string) error {
	certPath, keyPath, chainPath := s.backupMgr.GetBackupPathsWithChain(backupPath)

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
			s.log.Warn("恢复证书链失败: %v", err)
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
