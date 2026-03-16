// Package deployer Apache 证书部署器
package deployer

import (
	"fmt"
	"os"
	"path/filepath"

	baseDeployer "github.com/zhuxbo/sslctl/internal/deployer"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// ApacheDeployer Apache 部署器
type ApacheDeployer struct {
	baseDeployer.Base        // 嵌入公共功能
	certPath          string // 服务器证书路径
	keyPath           string // 私钥路径
	chainPath         string // 中间证书链路径
}

// NewApacheDeployer 创建 Apache 部署器
func NewApacheDeployer(cfg baseDeployer.Config) *ApacheDeployer {
	return &ApacheDeployer{
		Base: baseDeployer.Base{
			TestCommand:   cfg.TestCommand,
			ReloadCommand: cfg.ReloadCommand,
		},
		certPath:  cfg.CertPath,
		keyPath:   cfg.KeyPath,
		chainPath: cfg.ChainPath,
	}
}

// Deploy 部署证书（cert=服务器证书, intermediate=中间证书, key=私钥）
func (d *ApacheDeployer) Deploy(cert, intermediate, key string) error {
	// 确保目录存在（0700 权限保护敏感文件）
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
	if d.chainPath != "" {
		if err := util.EnsureDir(filepath.Dir(d.chainPath), 0700); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorPermission, errors.PhaseWriteChain,
				fmt.Sprintf("failed to create chain directory: %s", filepath.Dir(d.chainPath)), err,
			)
		}
	}

	// 写入证书：有 chainPath 时分离写入，无 chainPath 时合并为 fullchain
	certContent := cert
	if d.chainPath == "" && intermediate != "" {
		// 无 SSLCertificateChainFile 指令，将中间证书合并到证书文件
		certContent = cert + "\n" + intermediate
	}
	if err := util.AtomicWrite(d.certPath, []byte(certContent), 0644); err != nil {
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

	// 有 chainPath 时，中间证书写入独立文件
	if d.chainPath != "" && intermediate != "" {
		if err := util.AtomicWrite(d.chainPath, []byte(intermediate), 0644); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorPermission, errors.PhaseWriteChain,
				fmt.Sprintf("failed to write chain file: %s", d.chainPath), err,
			)
		}
	}

	// 恢复 SELinux 安全上下文（非 Enforcing 或无 SELinux 时静默跳过，失败仅警告）
	if err := util.RestoreFileContext(d.certPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] SELinux context restore failed for %s: %v\n", d.certPath, err)
	}
	if err := util.RestoreFileContext(d.keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] SELinux context restore failed for %s: %v\n", d.keyPath, err)
	}
	if d.chainPath != "" {
		if err := util.RestoreFileContext(d.chainPath); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] SELinux context restore failed for %s: %v\n", d.chainPath, err)
		}
	}

	return d.TestAndReload()
}

// Reload 重载 Apache 服务
func (d *ApacheDeployer) Reload() error {
	return d.ReloadService()
}

// Test 测试 Apache 配置
func (d *ApacheDeployer) Test() error {
	return d.TestConfig()
}

// Rollback 回滚到备份的证书
func (d *ApacheDeployer) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error {
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

	if d.chainPath != "" && backupChainPath != "" {
		if err := baseDeployer.RestoreFile(backupChainPath, d.chainPath); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorPermission, errors.PhaseRollback,
				"failed to restore chain file", err,
			)
		}
	}

	return d.TestAndReloadForRollback()
}
