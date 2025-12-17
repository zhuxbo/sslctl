// Package deployer Nginx 证书部署器
package deployer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cnssl/cert-deploy/pkg/errors"
	"github.com/cnssl/cert-deploy/pkg/util"
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
		return errors.NewDeployError("failed to create certificate directory", err)
	}
	if err := os.MkdirAll(filepath.Dir(d.keyPath), 0700); err != nil {
		return errors.NewDeployError("failed to create key directory", err)
	}

	// 3. 原子写入证书文件
	if err := util.AtomicWrite(d.certPath, []byte(fullchain), 0644); err != nil {
		return errors.NewDeployError(
			fmt.Sprintf("failed to write certificate file: %s", d.certPath),
			err,
		)
	}

	// 4. 原子写入私钥文件（0600）
	if err := util.AtomicWrite(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewDeployError(
			fmt.Sprintf("failed to write private key file: %s", d.keyPath),
			err,
		)
	}

	// 5. 测试配置
	if d.testCommand != "" {
		if err := d.runCommand(d.testCommand); err != nil {
			return errors.NewDeployError(
				fmt.Sprintf("config test failed: %s", d.testCommand),
				err,
			)
		}
	}

	// 6. 重载服务
	if d.reloadCommand != "" {
		if err := d.runCommand(d.reloadCommand); err != nil {
			return errors.NewDeployError(
				fmt.Sprintf("reload failed: %s", d.reloadCommand),
				err,
			)
		}
	}

	return nil
}

// runCommand 执行命令
func (d *NginxDeployer) runCommand(cmdStr string) error {
	// 允许的命令白名单
	allowed := map[string]bool{
		"nginx -t":               true,
		"nginx -s reload":        true,
		"systemctl reload nginx": true,
		"service nginx reload":   true,
	}
	if !allowed[cmdStr] {
		return fmt.Errorf("command not in whitelist: %s", cmdStr)
	}
	var cmd *exec.Cmd

	// 根据操作系统选择 shell
	if _, err := os.Stat("/bin/sh"); err == nil {
		cmd = exec.Command("/bin/sh", "-c", cmdStr)
	} else {
		cmd = exec.Command("cmd", "/C", cmdStr)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}

	return nil
}

// Rollback 回滚到备份的证书
func (d *NginxDeployer) Rollback(backupCertPath, backupKeyPath string) error {
	// 1. 复制备份文件
	if err := util.CopyFile(backupCertPath, d.certPath); err != nil {
		return errors.NewDeployError("failed to restore certificate", err)
	}

	if err := util.CopyFile(backupKeyPath, d.keyPath); err != nil {
		return errors.NewDeployError("failed to restore private key", err)
	}

	// 2. 测试配置
	if d.testCommand != "" {
		if err := d.runCommand(d.testCommand); err != nil {
			return errors.NewDeployError("config test failed after rollback", err)
		}
	}

	// 3. 重载服务
	if d.reloadCommand != "" {
		if err := d.runCommand(d.reloadCommand); err != nil {
			return errors.NewDeployError("reload failed after rollback", err)
		}
	}

	return nil
}
