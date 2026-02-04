// Package internal 内部实现
// 此文件负责向 pkg/webserver 注册各种 Web 服务器的实现
package internal

import (
	apacheDeployer "github.com/zhuxbo/sslctl/internal/apache/deployer"
	nginxDeployer "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

func init() {
	// 注册 Nginx 扫描器
	webserver.RegisterScanner(webserver.TypeNginx, func() webserver.Scanner {
		return &nginxScannerAdapter{scanner: nginxScanner.New()}
	})

	// 注册 Nginx 部署器
	webserver.RegisterDeployer(webserver.TypeNginx, func(certPath, keyPath, _, testCmd, reloadCmd string) webserver.Deployer {
		return &nginxDeployerAdapter{
			deployer: nginxDeployer.NewNginxDeployer(certPath, keyPath, testCmd, reloadCmd),
		}
	})

	// 注册 Apache 部署器
	webserver.RegisterDeployer(webserver.TypeApache, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) webserver.Deployer {
		return &apacheDeployerAdapter{
			deployer: apacheDeployer.NewApacheDeployer(certPath, keyPath, chainPath, testCmd, reloadCmd),
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
