// Package deployer Nginx 证书部署器
package deployer

import (
	"context"
	"fmt"
	"os"

	baseDeployer "github.com/zhuxbo/sslctl/internal/deployer"
	"github.com/zhuxbo/sslctl/pkg/errors"
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
func (d *NginxDeployer) Deploy(ctx context.Context, cert, intermediate, key string) error {
	if err := d.Prepare(); err != nil {
		return err
	}
	fullchain := cert
	if intermediate != "" {
		fullchain = cert + "\n" + intermediate
	}

	// 先写私钥再写证书：中途失败时不会留下"新证书 + 旧私钥"的错配状态
	if err := d.WriteCertificate(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to write private key file: %s", d.keyPath), err,
		)
	}

	if err := d.WriteCertificate(d.certPath, []byte(fullchain), 0644); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to write certificate file: %s", d.certPath), err,
		)
	}

	// 恢复 SELinux 安全上下文（非 Enforcing 或无 SELinux 时静默跳过，失败仅警告）
	if err := d.RestoreCertificateContext(d.certPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] SELinux context restore failed for %s: %v\n", d.certPath, err)
	}
	if err := d.RestoreCertificateContext(d.keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] SELinux context restore failed for %s: %v\n", d.keyPath, err)
	}

	return d.TestAndReload(ctx)
}

// Reload 重载 Nginx 服务
func (d *NginxDeployer) Reload(ctx context.Context) error {
	return d.ReloadService(ctx)
}

// Test 测试 Nginx 配置
func (d *NginxDeployer) Test(ctx context.Context) error {
	return d.TestConfig(ctx)
}

// Rollback 回滚到备份的证书
func (d *NginxDeployer) Rollback(ctx context.Context, backupCertPath, backupKeyPath string) error {
	if err := d.Prepare(); err != nil {
		return err
	}
	if err := d.RestoreCertificate(backupCertPath, d.certPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore certificate", err,
		)
	}

	if err := d.RestoreCertificate(backupKeyPath, d.keyPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore private key", err,
		)
	}

	return d.TestAndReloadForRollback(ctx)
}

// Prepare 固定本次部署和回滚的文件目标。
func (d *NginxDeployer) Prepare() error { return d.PrepareFiles(d.certPath, d.keyPath) }
