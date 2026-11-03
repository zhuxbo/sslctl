package certops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zhuxbo/sslctl/internal/nginx/docker"
	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// 文件系统边界集中保留，便于验证快照失败时必须停止部署。
var (
	containerWriteFile = os.WriteFile
	containerChmod     = os.Chmod
	containerStat      = os.Stat
)

// DeployDockerCopy 使用容器路径完成备份、部署及失败恢复，供 CLI 和自动续签共用。
func DeployDockerCopy(ctx context.Context, binding *config.SiteBinding, data *fetcher.CertData, key string, manager *backup.Manager, log *logger.Logger) error {
	return deployDockerCopy(ctx, binding, data, key, manager, log, nil)
}

func deployDockerCopy(ctx context.Context, binding *config.SiteBinding, data *fetcher.CertData, key string, manager *backup.Manager, log *logger.Logger, restore *[2]docker.ContainerFile) error {
	if err := config.ValidateDockerBinding(binding); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorConfig, errors.PhaseWriteCert, "容器绑定无效", err)
	}
	v := validator.New("")
	if _, err := v.ValidateCert(data.Cert); err != nil && restore == nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "证书验证失败", err)
	}
	if err := v.ValidateCertKeyPair(data.Cert, key); err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorValidation, errors.PhaseValidate, "私钥不匹配", err)
	}
	client, err := docker.NewRunningClient(ctx, binding.Docker.ContainerName)
	if err != nil {
		return err
	}
	if err := client.CheckCopyPaths(ctx, binding.Paths.Certificate, binding.Paths.PrivateKey); err != nil {
		return err
	}
	oldCert, err := client.ReadRegularFile(ctx, binding.Paths.Certificate, config.MaxCertFileSize)
	if err != nil {
		return fmt.Errorf("读取容器现有证书失败: %w", err)
	}
	oldKey, err := client.ReadRegularFile(ctx, binding.Paths.PrivateKey, config.MaxPrivateKeySize)
	if err != nil {
		return fmt.Errorf("读取容器现有私钥失败: %w", err)
	}
	defer clear(oldKey.Data)
	dir, err := os.MkdirTemp("", "sslctl-container-backup-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for file, snapshot := range map[string]docker.ContainerFile{certFile: oldCert, keyFile: oldKey} {
		if err := containerWriteFile(file, snapshot.Data, snapshot.Mode); err != nil {
			return err
		}
		if err := containerChmod(file, snapshot.Mode); err != nil {
			return err
		}
	}
	result, err := manager.BackupContainer(binding.ServerName, binding.Docker.ContainerName, binding.Paths.Certificate, binding.Paths.PrivateKey, certFile, keyFile)
	if err != nil {
		return errors.NewStructuredDeployError(errors.DeployErrorPermission, errors.PhaseBackup, "备份容器证书失败，中止部署", err)
	}
	if result.CleanupError != nil && log != nil {
		log.Warn("清理旧容器备份失败: %v", result.CleanupError)
	}
	deployer := docker.NewDeployer(client, docker.DeployerOptions{CertPath: binding.Paths.Certificate, KeyPath: binding.Paths.PrivateKey, DeployMode: "copy"})
	apply := func() error { return deployer.Deploy(ctx, data.Cert, data.IntermediateCert, key) }
	if restore != nil {
		restoreCert, restoreKey := filepath.Join(dir, "restore-cert.pem"), filepath.Join(dir, "restore-key.pem")
		for file, snapshot := range map[string]docker.ContainerFile{restoreCert: restore[0], restoreKey: restore[1]} {
			if err := containerWriteFile(file, snapshot.Data, snapshot.Mode); err != nil {
				return err
			}
			if err := containerChmod(file, snapshot.Mode); err != nil {
				return err
			}
		}
		apply = func() error { return deployer.Rollback(ctx, restoreCert, restoreKey) }
	}
	if deployErr := apply(); deployErr != nil {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackBudget)
		defer cancel()
		if err := deployer.Rollback(rbCtx, certFile, keyFile); err != nil {
			return errors.NewStructuredDeployError(errors.DeployErrorUnknown, errors.PhaseRollback, fmt.Sprintf("部署失败且回滚失败，持久备份: %s；部署: %v；回滚: %v", result.BackupPath, deployErr, err), nil)
		}
		return fmt.Errorf("部署失败（已回滚）: %w", deployErr)
	}
	return nil
}

// RestoreDockerBackup 恢复容器备份，先备份当前文件；验证或重载失败则恢复当前状态。
func RestoreDockerBackup(ctx context.Context, manager *backup.Manager, backupPath string, meta *backup.Metadata) error {
	var files [2]docker.ContainerFile
	for i, name := range []string{"cert.pem", "key.pem"} {
		file := filepath.Join(backupPath, name)
		content, err := util.SafeReadFile(file, config.MaxCertFileSize)
		if err != nil {
			return err
		}
		info, err := containerStat(file)
		if err != nil {
			return err
		}
		files[i] = docker.ContainerFile{Data: content, Mode: info.Mode().Perm()}
	}
	defer clearDockerSnapshots(&files)
	binding := &config.SiteBinding{
		ServerName: meta.ServerName, ServerType: config.ServerTypeDockerNginx,
		Docker: &config.DockerInfo{ContainerName: meta.ContainerName, DeployMode: "copy"},
		Paths:  config.BindingPaths{Certificate: meta.CertPath, PrivateKey: meta.KeyPath},
		Reload: config.ReloadConfig{TestCommand: "docker exec " + meta.ContainerName + " nginx -t", ReloadCommand: "docker exec " + meta.ContainerName + " nginx -s reload"},
	}
	return deployDockerCopy(ctx, binding, &fetcher.CertData{Cert: string(files[0].Data)}, string(files[1].Data), manager, nil, &files)
}

// 回滚结束后清除已读取的快照，避免私钥缓冲区残留。
func clearDockerSnapshots(files *[2]docker.ContainerFile) {
	for i := range files {
		clear(files[i].Data)
	}
}
