// Package deployer Nginx 证书部署器
package deployer

import (
	"fmt"
	"path/filepath"

	baseDeployer "github.com/zhuxbo/sslctl/internal/deployer"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// NginxDeployer Nginx 部署器
type NginxDeployer struct {
	baseDeployer.Base        // 嵌入公共功能
	certPath          string // fullchain.pem 路径
	keyPath           string // 私钥路径
}

// NewNginxDeployer 创建 Nginx 部署器
func NewNginxDeployer(cfg baseDeployer.Config) *NginxDeployer {
	return &NginxDeployer{
		Base: baseDeployer.Base{
			TestCommand:   cfg.TestCommand,
			ReloadCommand: cfg.ReloadCommand,
		},
		certPath: cfg.CertPath,
		keyPath:  cfg.KeyPath,
	}
}

// Deploy 部署证书（cert=服务器证书, intermediate=中间证书, key=私钥）
func (d *NginxDeployer) Deploy(cert, intermediate, key string) error {
	fullchain := cert + "\n" + intermediate

	if err := util.EnsureDir(filepath.Dir(d.certPath), 0700); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to create certificate directory: %s", filepath.Dir(d.certPath)), err,
		)
	}
	if err := util.EnsureDir(filepath.Dir(d.keyPath), 0700); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to create key directory: %s", filepath.Dir(d.keyPath)), err,
		)
	}

	if err := util.AtomicWrite(d.certPath, []byte(fullchain), 0644); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to write certificate file: %s", d.certPath), err,
		)
	}

	if err := util.AtomicWrite(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to write private key file: %s", d.keyPath), err,
		)
	}

	return d.TestAndReload()
}

// Reload 重载 Nginx 服务
func (d *NginxDeployer) Reload() error {
	return d.ReloadService()
}

// Test 测试 Nginx 配置
func (d *NginxDeployer) Test() error {
	return d.TestConfig()
}

// Rollback 回滚到备份的证书
func (d *NginxDeployer) Rollback(backupCertPath, backupKeyPath string) error {
	if err := baseDeployer.RestoreFile(backupCertPath, d.certPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore certificate", err,
		)
	}

	if err := baseDeployer.RestoreFile(backupKeyPath, d.keyPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore private key", err,
		)
	}

	return d.TestAndReloadForRollback()
}
