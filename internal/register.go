// Package internal 内部实现
// 此文件负责向 pkg/webserver 注册各种 Web 服务器的实现
package internal

import (
	"context"
	"errors"
	"fmt"

	apacheDeployer "github.com/zhuxbo/sslctl/internal/apache/deployer"
	apacheDocker "github.com/zhuxbo/sslctl/internal/apache/docker"
	apacheInstaller "github.com/zhuxbo/sslctl/internal/apache/installer"
	apacheScanner "github.com/zhuxbo/sslctl/internal/apache/scanner"
	baseDeployer "github.com/zhuxbo/sslctl/internal/deployer"
	nginxDeployer "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	nginxDocker "github.com/zhuxbo/sslctl/internal/nginx/docker"
	nginxInstaller "github.com/zhuxbo/sslctl/internal/nginx/installer"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

func init() {
	// 注册 Nginx 扫描器
	webserver.RegisterScanner(webserver.TypeNginx, func() webserver.Scanner {
		return &nginxScannerAdapter{scanner: nginxScanner.New()}
	})

	// 注册 Apache 扫描器
	webserver.RegisterScanner(webserver.TypeApache, func() webserver.Scanner {
		return &apacheScannerAdapter{scanner: apacheScanner.New()}
	})

	// 注册 Nginx 部署器
	webserver.RegisterDeployer(webserver.TypeNginx, func(certPath, keyPath, _, testCmd, reloadCmd string) webserver.Deployer {
		return &nginxDeployerAdapter{
			deployer: nginxDeployer.NewNginxDeployer(baseDeployer.Config{
				CertPath:      certPath,
				KeyPath:       keyPath,
				TestCommand:   testCmd,
				ReloadCommand: reloadCmd,
			}),
		}
	})

	// 注册 Apache 部署器
	webserver.RegisterDeployer(webserver.TypeApache, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) webserver.Deployer {
		return &apacheDeployerAdapter{
			deployer: apacheDeployer.NewApacheDeployer(baseDeployer.Config{
				CertPath:      certPath,
				KeyPath:       keyPath,
				ChainPath:     chainPath,
				TestCommand:   testCmd,
				ReloadCommand: reloadCmd,
			}),
		}
	})

	// 注册 Nginx 安装器
	webserver.RegisterInstaller(webserver.TypeNginx, func(configPath, certPath, keyPath, _, serverName, testCmd string) webserver.Installer {
		// Nginx 安装器不需要 chainPath 参数
		return &nginxInstallerAdapter{
			installer: nginxInstaller.NewNginxInstaller(configPath, certPath, keyPath, serverName, testCmd),
		}
	})

	// 注册 Apache 安装器
	webserver.RegisterInstaller(webserver.TypeApache, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) webserver.Installer {
		return &apacheInstallerAdapter{
			installer: apacheInstaller.NewApacheInstaller(configPath, certPath, keyPath, chainPath, serverName, testCmd),
		}
	})
}

// nginxScannerAdapter Nginx 扫描器适配器
type nginxScannerAdapter struct {
	scanner *nginxScanner.Scanner
}

func (a *nginxScannerAdapter) Scan() ([]webserver.Site, error) {
	// 统一扫描入口：本地和 Docker 独立扫描，互不阻塞
	localSites, localErr := a.ScanLocal()

	// PrefixUnknownError 是阻塞性错误：相对路径写错位置会导致静默失败，
	// 必须直接传递到 CLI 层渲染修复指引，不能被 Docker 成功结果掩盖
	var prefixErr *sslerrors.PrefixUnknownError
	if errors.As(localErr, &prefixErr) {
		return nil, localErr
	}

	dockerSites, dockerErr := a.ScanDocker()

	// 合并结果
	var allSites []webserver.Site
	if localErr == nil {
		allSites = append(allSites, localSites...)
	}
	allSites = append(allSites, dockerSites...)

	// 无站点时保留两侧错误；已扫描到的站点不因其他容器失败而丢失。
	if len(allSites) == 0 {
		return nil, errors.Join(localErr, dockerErr)
	}

	return allSites, nil
}

func (a *nginxScannerAdapter) ScanLocal() ([]webserver.Site, error) {
	sites, err := a.scanner.ScanAll()
	if err != nil {
		return nil, err
	}

	var result []webserver.Site
	for _, s := range sites {
		result = append(result, webserver.Site{
			ServerName:      s.ServerName,
			ServerAlias:     s.ServerAlias,
			ConfigFile:      s.ConfigFile,
			ListenPorts:     s.ListenPorts,
			CertificatePath: s.CertificatePath,
			PrivateKeyPath:  s.PrivateKeyPath,
			ServerType:      webserver.TypeNginx,
			ExecutablePath:  a.scanner.ExecutablePath(),
		})
	}
	return result, nil
}

func (a *nginxScannerAdapter) ScanDocker() ([]webserver.Site, error) {
	if !nginxDocker.CheckDockerAvailable() {
		return nil, nil
	}

	ctx := context.Background()
	containers, err := nginxDocker.DiscoverNginxContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("发现 Docker Nginx 容器失败: %w", err)
	}

	var sites []webserver.Site
	var scanErrors []error
	for _, container := range containers {
		// 已发现具体容器，直接执行以避免依赖 Compose 命令和原始编排文件。
		client := nginxDocker.NewClient(container.ID)

		scanner := nginxDocker.NewScanner(client)
		dockerSites, err := scanner.Scan(ctx)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("扫描 Docker Nginx 容器 %s 失败: %w", container.Name, err))
			continue
		}

		for _, ds := range dockerSites {
			sites = append(sites, webserver.Site{
				ServerName:      ds.ServerName,
				ServerAlias:     ds.ServerAlias,
				ConfigFile:      ds.ConfigFile,
				ListenPorts:     ds.ListenPorts,
				CertificatePath: ds.CertificatePath,
				PrivateKeyPath:  ds.PrivateKeyPath,
				ServerType:      webserver.TypeDockerNginx,
				ContainerID:     ds.ContainerID,
				ContainerName:   ds.ContainerName,
				HostCertPath:    ds.HostCertPath,
				HostKeyPath:     ds.HostKeyPath,
				VolumeMode:      ds.VolumeMode,
			})
		}
	}

	return sites, errors.Join(scanErrors...)
}

func (a *nginxScannerAdapter) ServerType() webserver.ServerType {
	return webserver.TypeNginx
}

// nginxDeployerAdapter Nginx 部署器适配器
type nginxDeployerAdapter struct {
	deployer *nginxDeployer.NginxDeployer
}

func (a *nginxDeployerAdapter) Deploy(ctx context.Context, cert, chain, key string) error {
	return a.deployer.Deploy(ctx, cert, chain, key)
}

func (a *nginxDeployerAdapter) Reload(ctx context.Context) error {
	return a.deployer.Reload(ctx)
}

func (a *nginxDeployerAdapter) Test(ctx context.Context) error {
	return a.deployer.Test(ctx)
}

func (a *nginxDeployerAdapter) Rollback(ctx context.Context, backupCertPath, backupKeyPath, _ string) error {
	// Nginx 不需要 chainPath，忽略第三个参数
	return a.deployer.Rollback(ctx, backupCertPath, backupKeyPath)
}

// apacheDeployerAdapter Apache 部署器适配器
type apacheDeployerAdapter struct {
	deployer *apacheDeployer.ApacheDeployer
}

func (a *apacheDeployerAdapter) Deploy(ctx context.Context, cert, chain, key string) error {
	return a.deployer.Deploy(ctx, cert, chain, key)
}

func (a *apacheDeployerAdapter) Reload(ctx context.Context) error {
	return a.deployer.Reload(ctx)
}

func (a *apacheDeployerAdapter) Test(ctx context.Context) error {
	return a.deployer.Test(ctx)
}

func (a *apacheDeployerAdapter) Rollback(ctx context.Context, backupCertPath, backupKeyPath, backupChainPath string) error {
	return a.deployer.Rollback(ctx, backupCertPath, backupKeyPath, backupChainPath)
}

// apacheScannerAdapter Apache 扫描器适配器
// 命名映射说明：
// - internal 包使用 ScanAll()，webserver 接口使用 Scan() - 适配器统一为 Scan
// - internal 包使用 ChainPath，webserver 使用 ChainFile - 适配器映射字段名
// 这种设计允许 internal 包保持自己的命名约定，同时对外提供统一的接口
type apacheScannerAdapter struct {
	scanner *apacheScanner.Scanner
}

func (a *apacheScannerAdapter) Scan() ([]webserver.Site, error) {
	localSites, localErr := a.ScanLocal()

	// PrefixUnknownError 是阻塞性错误，需穿透到 CLI 层渲染修复指引
	var prefixErr *sslerrors.PrefixUnknownError
	if errors.As(localErr, &prefixErr) {
		return nil, localErr
	}

	dockerSites, _ := a.ScanDocker()

	var allSites []webserver.Site
	if localErr == nil {
		allSites = append(allSites, localSites...)
	}
	allSites = append(allSites, dockerSites...)

	if localErr != nil && len(dockerSites) == 0 {
		return nil, localErr
	}

	return allSites, nil
}

func (a *apacheScannerAdapter) ScanLocal() ([]webserver.Site, error) {
	sites, err := a.scanner.ScanAll() // ScanAll -> Scan 方法名映射
	if err != nil {
		return nil, err
	}

	var result []webserver.Site
	for _, s := range sites {
		result = append(result, webserver.Site{
			ServerName:      s.ServerName,
			ServerAlias:     s.ServerAlias,
			ConfigFile:      s.ConfigFile,
			ListenPorts:     s.ListenPorts,
			CertificatePath: s.CertificatePath,
			PrivateKeyPath:  s.PrivateKeyPath,
			ChainFile:       s.ChainPath, // ChainPath -> ChainFile 字段名映射
			ServerType:      webserver.TypeApache,
		})
	}
	return result, nil
}

func (a *apacheScannerAdapter) ScanDocker() ([]webserver.Site, error) {
	if !apacheDocker.CheckDockerAvailable() {
		return nil, nil
	}

	ctx := context.Background()
	containers, err := apacheDocker.DiscoverApacheContainers(ctx)
	if err != nil || len(containers) == 0 {
		return nil, nil
	}

	var sites []webserver.Site
	for _, container := range containers {
		client := apacheDocker.NewClient(container.ID)
		if container.IsCompose {
			client = apacheDocker.NewComposeClient(container.ComposeFile, container.ServiceName)
			client.SetContainer(container.ID)
		}

		scanner := apacheDocker.NewScanner(client)
		dockerSites, err := scanner.Scan(ctx)
		if err != nil {
			continue
		}

		for _, ds := range dockerSites {
			sites = append(sites, webserver.Site{
				ServerName:      ds.ServerName,
				ServerAlias:     ds.ServerAlias,
				ConfigFile:      ds.ConfigFile,
				ListenPorts:     []string{ds.ListenPort},
				CertificatePath: ds.CertificatePath,
				PrivateKeyPath:  ds.PrivateKeyPath,
				ChainFile:       ds.ChainPath,
				ServerType:      webserver.TypeDockerApache,
				ContainerID:     ds.ContainerID,
				ContainerName:   ds.ContainerName,
				HostCertPath:    ds.HostCertPath,
				HostKeyPath:     ds.HostKeyPath,
				HostChainPath:   ds.HostChainPath,
				VolumeMode:      ds.VolumeMode,
			})
		}
	}

	return sites, nil
}

func (a *apacheScannerAdapter) ServerType() webserver.ServerType {
	return webserver.TypeApache
}

// nginxInstallerAdapter Nginx 安装器适配器
type nginxInstallerAdapter struct {
	installer *nginxInstaller.NginxInstaller
}

func (a *nginxInstallerAdapter) Install() (*webserver.InstallResult, error) {
	result, err := a.installer.Install()
	if err != nil {
		return nil, err
	}
	return &webserver.InstallResult{
		BackupPath: result.BackupPath,
		Modified:   result.Modified,
	}, nil
}

func (a *nginxInstallerAdapter) Rollback(backupPath string) error {
	return a.installer.Rollback(backupPath)
}

// apacheInstallerAdapter Apache 安装器适配器
type apacheInstallerAdapter struct {
	installer *apacheInstaller.ApacheInstaller
}

func (a *apacheInstallerAdapter) Install() (*webserver.InstallResult, error) {
	result, err := a.installer.Install()
	if err != nil {
		return nil, err
	}
	return &webserver.InstallResult{
		BackupPath: result.BackupPath,
		Modified:   result.Modified,
	}, nil
}

func (a *apacheInstallerAdapter) Rollback(backupPath string) error {
	return a.installer.Rollback(backupPath)
}

func (a *nginxDeployerAdapter) Prepare() error  { return a.deployer.Prepare() }
func (a *apacheDeployerAdapter) Prepare() error { return a.deployer.Prepare() }
