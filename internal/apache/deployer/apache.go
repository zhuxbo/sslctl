// Package deployer Apache 证书部署器
package deployer

import (
	"fmt"
	"path/filepath"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// ApacheDeployer Apache 部署器
type ApacheDeployer struct {
	certPath      string // 服务器证书路径
	keyPath       string // 私钥路径
	chainPath     string // 中间证书链路径
	testCommand   string // 测试命令
	reloadCommand string // 重载命令
}

// NewApacheDeployer 创建 Apache 部署器
func NewApacheDeployer(certPath, keyPath, chainPath, testCmd, reloadCmd string) *ApacheDeployer {
	return &ApacheDeployer{
		certPath:      certPath,
		keyPath:       keyPath,
		chainPath:     chainPath,
		testCommand:   testCmd,
		reloadCommand: reloadCmd,
	}
}

// Deploy 部署证书
// cert: 服务器证书
// intermediate: 中间证书
// key: 私钥
func (d *ApacheDeployer) Deploy(cert, intermediate, key string) error {
	// 1. 确保目录存在（统一使用 0700 权限保护敏感文件）
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

	// 2. 原子写入服务器证书
	if err := util.AtomicWrite(d.certPath, []byte(cert), 0644); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to write certificate file: %s", d.certPath), err,
		)
	}

	// 3. 原子写入私钥文件（0600）
	if err := util.AtomicWrite(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to write private key file: %s", d.keyPath), err,
		)
	}

	// 4. 原子写入中间证书链（Apache 需要分离的 chain 文件）
	if d.chainPath != "" && intermediate != "" {
		if err := util.AtomicWrite(d.chainPath, []byte(intermediate), 0644); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorPermission, errors.PhaseWriteChain,
				fmt.Sprintf("failed to write chain file: %s", d.chainPath), err,
			)
		}
	}

	// 5. 测试配置
	if d.testCommand != "" {
		if err := d.runCommand(d.testCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorConfig, errors.PhaseTest,
				fmt.Sprintf("config test failed: %s", d.testCommand), err,
			)
		}
	}

	// 6. 重载服务
	if d.reloadCommand != "" {
		if err := d.runCommand(d.reloadCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorReload, errors.PhaseReload,
				fmt.Sprintf("reload failed: %s", d.reloadCommand), err,
			)
		}
	}

	return nil
}

// runCommand 执行命令（使用统一的 executor 包）
func (d *ApacheDeployer) runCommand(cmdStr string) error {
	return executor.Run(cmdStr)
}

// Reload 重载 Apache 服务
func (d *ApacheDeployer) Reload() error {
	if d.reloadCommand == "" {
		return nil
	}
	return d.runCommand(d.reloadCommand)
}

// Test 测试 Apache 配置
func (d *ApacheDeployer) Test() error {
	if d.testCommand == "" {
		return nil
	}
	return d.runCommand(d.testCommand)
}

// Rollback 回滚到备份的证书
func (d *ApacheDeployer) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error {
	// 1. 复制备份文件
	if err := util.CopyFile(backupCertPath, d.certPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore certificate", err,
		)
	}

	if err := util.CopyFile(backupKeyPath, d.keyPath); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseRollback,
			"failed to restore private key", err,
		)
	}

	if d.chainPath != "" && backupChainPath != "" {
		if err := util.CopyFile(backupChainPath, d.chainPath); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorPermission, errors.PhaseRollback,
				"failed to restore chain file", err,
			)
		}
	}

	// 2. 测试配置
	if d.testCommand != "" {
		if err := d.runCommand(d.testCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorConfig, errors.PhaseRollback,
				"config test failed after rollback", err,
			)
		}
	}

	// 3. 重载服务
	if d.reloadCommand != "" {
		if err := d.runCommand(d.reloadCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorReload, errors.PhaseRollback,
				"reload failed after rollback", err,
			)
		}
	}

	return nil
}
