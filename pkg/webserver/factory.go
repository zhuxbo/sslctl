// Package webserver Web 服务器工厂
package webserver

import (
	"fmt"

	apacheDeployer "github.com/zhuxbo/cert-deploy/internal/apache/deployer"
	nginxDeployer "github.com/zhuxbo/cert-deploy/internal/nginx/deployer"
	nginxScanner "github.com/zhuxbo/cert-deploy/internal/nginx/scanner"
)

// NewScanner 创建扫描器
func NewScanner(serverType ServerType) (Scanner, error) {
	switch serverType {
	case TypeNginx, TypeDockerNginx:
		return &nginxScannerWrapper{scanner: nginxScanner.New()}, nil
	case TypeApache, TypeDockerApache:
		// TODO: 实现 Apache 扫描器
		return nil, fmt.Errorf("Apache scanner not implemented yet")
	default:
		return nil, fmt.Errorf("unknown server type: %s", serverType)
	}
}

// NewDeployer 创建部署器
func NewDeployer(serverType ServerType, certPath, keyPath, chainPath, testCmd, reloadCmd string) (Deployer, error) {
	switch serverType {
	case TypeNginx, TypeDockerNginx:
		return &nginxDeployerWrapper{
			deployer: nginxDeployer.NewNginxDeployer(certPath, keyPath, testCmd, reloadCmd),
		}, nil
	case TypeApache, TypeDockerApache:
		return &apacheDeployerWrapper{
			deployer: apacheDeployer.NewApacheDeployer(certPath, keyPath, chainPath, testCmd, reloadCmd),
		}, nil
	default:
		return nil, fmt.Errorf("unknown server type: %s", serverType)
	}
}

// nginxScannerWrapper Nginx 扫描器包装器
type nginxScannerWrapper struct {
	scanner *nginxScanner.Scanner
}

func (w *nginxScannerWrapper) ScanLocal() ([]Site, error) {
	// 使用 ScanAll 获取所有站点
	sites, err := w.scanner.ScanAll()
	if err != nil {
		return nil, err
	}

	var result []Site
	for _, s := range sites {
		result = append(result, Site{
			Name:            s.ServerName,
			ServerName:      s.ServerName,
			ServerAlias:     s.ServerAlias,
			ConfigFile:      s.ConfigFile,
			ListenPorts:     s.ListenPorts,
			CertificatePath: s.CertificatePath,
			PrivateKeyPath:  s.PrivateKeyPath,
			ServerType:      TypeNginx,
		})
	}
	return result, nil
}

func (w *nginxScannerWrapper) ScanDocker() ([]Site, error) {
	// Docker 扫描暂不支持
	return nil, nil
}

func (w *nginxScannerWrapper) ServerType() ServerType {
	return TypeNginx
}

// nginxDeployerWrapper Nginx 部署器包装器
type nginxDeployerWrapper struct {
	deployer *nginxDeployer.NginxDeployer
}

func (w *nginxDeployerWrapper) Deploy(cert, chain, key string) error {
	return w.deployer.Deploy(cert, chain, key)
}

func (w *nginxDeployerWrapper) Reload() error {
	return w.deployer.Reload()
}

func (w *nginxDeployerWrapper) Test() error {
	return w.deployer.Test()
}

// apacheDeployerWrapper Apache 部署器包装器
type apacheDeployerWrapper struct {
	deployer *apacheDeployer.ApacheDeployer
}

func (w *apacheDeployerWrapper) Deploy(cert, chain, key string) error {
	return w.deployer.Deploy(cert, chain, key)
}

func (w *apacheDeployerWrapper) Reload() error {
	return w.deployer.Reload()
}

func (w *apacheDeployerWrapper) Test() error {
	return w.deployer.Test()
}
