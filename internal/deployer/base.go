// Package deployer 提供部署器公共功能
package deployer

import (
	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// Config 部署器配置
type Config struct {
	CertPath      string // 证书文件路径
	KeyPath       string // 私钥文件路径
	ChainPath     string // 中间证书链路径（仅 Apache）
	TestCommand   string // 配置测试命令
	ReloadCommand string // 服务重载命令
}

// Base 部署器基础功能
type Base struct {
	TestCommand   string
	ReloadCommand string
}

// TestConfig 测试配置
func (b *Base) TestConfig() error {
	if b.TestCommand == "" {
		return nil
	}
	return executor.Run(b.TestCommand)
}

// ReloadService 重载服务
func (b *Base) ReloadService() error {
	if b.ReloadCommand == "" {
		return nil
	}
	return executor.Run(b.ReloadCommand)
}

// TestAndReload 测试配置并重载服务
func (b *Base) TestAndReload() error {
	if err := b.TestConfig(); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorConfig, errors.PhaseTest,
			"config test failed", err,
		)
	}
	if err := b.ReloadService(); err != nil {
		return errors.NewStructuredDeployError(
			errors.DeployErrorReload, errors.PhaseReload,
			"reload failed", err,
		)
	}
	return nil
}

// TestAndReloadForRollback 回滚后测试配置并重载服务
func (b *Base) TestAndReloadForRollback() error {
	if b.TestCommand != "" {
		if err := executor.Run(b.TestCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorConfig, errors.PhaseRollback,
				"config test failed after rollback", err,
			)
		}
	}
	if b.ReloadCommand != "" {
		if err := executor.Run(b.ReloadCommand); err != nil {
			return errors.NewStructuredDeployError(
				errors.DeployErrorReload, errors.PhaseRollback,
				"reload failed after rollback", err,
			)
		}
	}
	return nil
}

// RestoreFile 恢复单个文件
func RestoreFile(backupPath, targetPath string) error {
	return util.CopyFile(backupPath, targetPath)
}
