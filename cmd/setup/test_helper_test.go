// Package setup 测试辅助函数
package setup

import (
	"os"
	"path/filepath"

	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// init 注册测试用的 mock 工厂函数
func init() {
	// 注册 Nginx 扫描器
	webserver.RegisterScanner(webserver.TypeNginx, func() webserver.Scanner {
		return &mockScanner{serverType: webserver.TypeNginx}
	})

	// 注册 Nginx 部署器
	webserver.RegisterDeployer(webserver.TypeNginx, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) webserver.Deployer {
		return &mockDeployer{
			certPath:  certPath,
			keyPath:   keyPath,
			chainPath: chainPath,
		}
	})

	// 注册 Apache 部署器
	webserver.RegisterDeployer(webserver.TypeApache, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) webserver.Deployer {
		return &mockDeployer{
			certPath:  certPath,
			keyPath:   keyPath,
			chainPath: chainPath,
		}
	})

	// 注册 Nginx 安装器
	webserver.RegisterInstaller(webserver.TypeNginx, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) webserver.Installer {
		return &mockInstaller{configPath: configPath}
	})

	// 注册 Apache 安装器
	webserver.RegisterInstaller(webserver.TypeApache, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) webserver.Installer {
		return &mockInstaller{configPath: configPath}
	})
}

// mockScanner 测试用 mock 扫描器
type mockScanner struct {
	serverType webserver.ServerType
}

func (m *mockScanner) Scan() ([]webserver.Site, error)       { return nil, nil }
func (m *mockScanner) ScanLocal() ([]webserver.Site, error)  { return nil, nil }
func (m *mockScanner) ScanDocker() ([]webserver.Site, error) { return nil, nil }
func (m *mockScanner) ServerType() webserver.ServerType      { return m.serverType }

// mockInstaller 测试用 mock 安装器
type mockInstaller struct {
	configPath string
}

func (m *mockInstaller) Install() (*webserver.InstallResult, error) {
	return &webserver.InstallResult{BackupPath: m.configPath + ".bak", Modified: true}, nil
}

func (m *mockInstaller) Rollback(backupPath string) error { return nil }

// mockDeployer 测试用 mock 部署器
type mockDeployer struct {
	certPath  string
	keyPath   string
	chainPath string
}

func (m *mockDeployer) Deploy(cert, chain, key string) error {
	if m.certPath != "" {
		fullchain := cert
		if chain != "" {
			fullchain = cert + "\n" + chain
		}
		if err := os.MkdirAll(filepath.Dir(m.certPath), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(m.certPath, []byte(fullchain), 0644); err != nil {
			return err
		}
	}
	if m.keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(m.keyPath), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(m.keyPath, []byte(key), 0600); err != nil {
			return err
		}
	}
	if m.chainPath != "" && chain != "" {
		if err := os.MkdirAll(filepath.Dir(m.chainPath), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(m.chainPath, []byte(chain), 0644); err != nil {
			return err
		}
	}
	return nil
}
func (m *mockDeployer) Reload() error { return nil }
func (m *mockDeployer) Test() error   { return nil }
func (m *mockDeployer) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error {
	return nil
}
