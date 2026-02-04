// Package internal 内部实现
// 此文件负责向 pkg/webserver 注册各种 Web 服务器的实现
package internal

import (
	apacheDeployer "github.com/zhuxbo/sslctl/internal/apache/deployer"
	apacheScanner "github.com/zhuxbo/sslctl/internal/apache/scanner"
	baseDeployer "github.com/zhuxbo/sslctl/internal/deployer"
	nginxDeployer "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
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
}

// nginxScannerAdapter Nginx 扫描器适配器
type nginxScannerAdapter struct {
	scanner *nginxScanner.Scanner
}

func (a *nginxScannerAdapter) Scan() ([]webserver.Site, error) {
	// 统一扫描入口：先扫描本地，再扫描 Docker
	localSites, err := a.ScanLocal()
	if err != nil {
		return nil, err
	}

	dockerSites, err := a.ScanDocker()
	if err != nil {
		// Docker 扫描失败不影响本地结果
		return localSites, nil
	}

	return append(localSites, dockerSites...), nil
}

func (a *nginxScannerAdapter) ScanLocal() ([]webserver.Site, error) {
	sites, err := a.scanner.ScanAll()
	if err != nil {
		return nil, err
	}

	var result []webserver.Site
	for _, s := range sites {
		result = append(result, webserver.Site{
			Name:            s.ServerName,
			ServerName:      s.ServerName,
			ServerAlias:     s.ServerAlias,
			ConfigFile:      s.ConfigFile,
			ListenPorts:     s.ListenPorts,
			CertificatePath: s.CertificatePath,
			PrivateKeyPath:  s.PrivateKeyPath,
			ServerType:      webserver.TypeNginx,
		})
	}
	return result, nil
}

func (a *nginxScannerAdapter) ScanDocker() ([]webserver.Site, error) {
	// Docker 扫描暂不支持
	return nil, nil
}

func (a *nginxScannerAdapter) ServerType() webserver.ServerType {
	return webserver.TypeNginx
}

// nginxDeployerAdapter Nginx 部署器适配器
type nginxDeployerAdapter struct {
	deployer *nginxDeployer.NginxDeployer
}

func (a *nginxDeployerAdapter) Deploy(cert, chain, key string) error {
	return a.deployer.Deploy(cert, chain, key)
}

func (a *nginxDeployerAdapter) Reload() error {
	return a.deployer.Reload()
}

func (a *nginxDeployerAdapter) Test() error {
	return a.deployer.Test()
}

func (a *nginxDeployerAdapter) Rollback(backupCertPath, backupKeyPath, _ string) error {
	// Nginx 不需要 chainPath，忽略第三个参数
	return a.deployer.Rollback(backupCertPath, backupKeyPath)
}

// apacheDeployerAdapter Apache 部署器适配器
type apacheDeployerAdapter struct {
	deployer *apacheDeployer.ApacheDeployer
}

func (a *apacheDeployerAdapter) Deploy(cert, chain, key string) error {
	return a.deployer.Deploy(cert, chain, key)
}

func (a *apacheDeployerAdapter) Reload() error {
	return a.deployer.Reload()
}

func (a *apacheDeployerAdapter) Test() error {
	return a.deployer.Test()
}

func (a *apacheDeployerAdapter) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error {
	return a.deployer.Rollback(backupCertPath, backupKeyPath, backupChainPath)
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
	return a.ScanLocal()
}

func (a *apacheScannerAdapter) ScanLocal() ([]webserver.Site, error) {
	sites, err := a.scanner.ScanAll() // ScanAll -> Scan 方法名映射
	if err != nil {
		return nil, err
	}

	var result []webserver.Site
	for _, s := range sites {
		result = append(result, webserver.Site{
			Name:            s.ServerName,
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
	// Docker 扫描暂不支持
	return nil, nil
}

func (a *apacheScannerAdapter) ServerType() webserver.ServerType {
	return webserver.TypeApache
}
