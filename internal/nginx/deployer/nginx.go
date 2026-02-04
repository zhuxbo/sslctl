// Package deployer Nginx 证书部署器
package deployer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// NginxDeployer Nginx 部署器
type NginxDeployer struct {
	certPath      string // fullchain.pem 路径
	keyPath       string // 私钥路径
	testCommand   string // 测试命令
	reloadCommand string // 重载命令
}

// NewNginxDeployer 创建 Nginx 部署器
func NewNginxDeployer(certPath, keyPath, testCmd, reloadCmd string) *NginxDeployer {
	return &NginxDeployer{
		certPath:      certPath,
		keyPath:       keyPath,
		testCommand:   testCmd,
		reloadCommand: reloadCmd,
	}
}

// Deploy 部署证书
// cert: 服务器证书
// intermediate: 中间证书
// key: 私钥
func (d *NginxDeployer) Deploy(cert, intermediate, key string) error {
	// 1. 组合证书 (服务器证书 + 中间证书)
	fullchain := cert + "\n" + intermediate

	// 2. 确保证书与私钥目录存在
	if err := os.MkdirAll(filepath.Dir(d.certPath), 0755); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to create certificate directory: %s", filepath.Dir(d.certPath)), err,
		)
	}
	if err := os.MkdirAll(filepath.Dir(d.keyPath), 0700); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to create key directory: %s", filepath.Dir(d.keyPath)), err,
		)
	}

	// 3. 原子写入证书文件
	if err := util.AtomicWrite(d.certPath, []byte(fullchain), 0644); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteCert,
			fmt.Sprintf("failed to write certificate file: %s", d.certPath), err,
		)
	}

	// 4. 原子写入私钥文件（0600）
	if err := util.AtomicWrite(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorPermission, errors.PhaseWriteKey,
			fmt.Sprintf("failed to write private key file: %s", d.keyPath), err,
		)
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
func (d *NginxDeployer) runCommand(cmdStr string) error {
	return executor.Run(cmdStr)
}

// Reload 重载 Nginx 服务
func (d *NginxDeployer) Reload() error {
	if d.reloadCommand == "" {
		return nil
	}
	return d.runCommand(d.reloadCommand)
}

// Test 测试 Nginx 配置
func (d *NginxDeployer) Test() error {
	if d.testCommand == "" {
		return nil
	}
	return d.runCommand(d.testCommand)
}

// Rollback 回滚到备份的证书
func (d *NginxDeployer) Rollback(backupCertPath, backupKeyPath string) error {
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
