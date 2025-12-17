// Package deployer Apache 证书部署器
package deployer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cnssl/cert-deploy/pkg/errors"
	"github.com/cnssl/cert-deploy/pkg/util"
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
	// 1. 确保目录存在
	if err := os.MkdirAll(filepath.Dir(d.certPath), 0755); err != nil {
		return errors.NewDeployError("failed to create certificate directory", err)
	}
	if err := os.MkdirAll(filepath.Dir(d.keyPath), 0700); err != nil {
		return errors.NewDeployError("failed to create key directory", err)
	}
	if d.chainPath != "" {
		if err := os.MkdirAll(filepath.Dir(d.chainPath), 0755); err != nil {
			return errors.NewDeployError("failed to create chain directory", err)
		}
	}

	// 2. 原子写入服务器证书
	if err := util.AtomicWrite(d.certPath, []byte(cert), 0644); err != nil {
		return errors.NewDeployError(
			fmt.Sprintf("failed to write certificate file: %s", d.certPath),
			err,
		)
	}

	// 3. 原子写入私钥文件（0600）
	if err := util.AtomicWrite(d.keyPath, []byte(key), 0600); err != nil {
		return errors.NewDeployError(
			fmt.Sprintf("failed to write private key file: %s", d.keyPath),
			err,
		)
	}

	// 4. 原子写入中间证书链（Apache 需要分离的 chain 文件）
	if d.chainPath != "" && intermediate != "" {
		if err := util.AtomicWrite(d.chainPath, []byte(intermediate), 0644); err != nil {
			return errors.NewDeployError(
				fmt.Sprintf("failed to write chain file: %s", d.chainPath),
				err,
			)
		}
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
func (d *ApacheDeployer) runCommand(cmdStr string) error {
	// 允许的命令白名单
	allowed := map[string]bool{
		"apachectl -t":             true,
		"apachectl graceful":       true,
		"apache2ctl -t":            true,
		"apache2ctl graceful":      true,
		"httpd -t":                 true,
		"systemctl reload apache2": true,
		"systemctl reload httpd":   true,
		"service apache2 reload":   true,
		"service httpd reload":     true,
	}
	if !allowed[cmdStr] {
		return fmt.Errorf("command not in whitelist: %s", cmdStr)
	}

	var cmd *exec.Cmd
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
func (d *ApacheDeployer) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error {
	// 1. 复制备份文件
	if err := util.CopyFile(backupCertPath, d.certPath); err != nil {
		return errors.NewDeployError("failed to restore certificate", err)
	}

	if err := util.CopyFile(backupKeyPath, d.keyPath); err != nil {
		return errors.NewDeployError("failed to restore private key", err)
	}

	if d.chainPath != "" && backupChainPath != "" {
		if err := util.CopyFile(backupChainPath, d.chainPath); err != nil {
			return errors.NewDeployError("failed to restore chain file", err)
		}
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
