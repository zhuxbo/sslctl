// Package certops 测试辅助函数
package certops

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
}

// mockScanner 测试用 mock 扫描器
type mockScanner struct {
	serverType webserver.ServerType
}

func (m *mockScanner) Scan() ([]webserver.Site, error)      { return nil, nil }
func (m *mockScanner) ScanLocal() ([]webserver.Site, error) { return nil, nil }
func (m *mockScanner) ScanDocker() ([]webserver.Site, error) { return nil, nil }
func (m *mockScanner) ServerType() webserver.ServerType     { return m.serverType }

// mockDeployer 测试用 mock 部署器
// 为了集成测试能够验证文件写入，实际执行文件操作
type mockDeployer struct {
	certPath  string
	keyPath   string
	chainPath string
}

func (m *mockDeployer) Deploy(cert, chain, key string) error {
	// 实际写入文件以便测试验证
	if m.certPath != "" {
		// 组合证书和中间证书
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
	// 实际执行回滚
	if backupCertPath != "" && m.certPath != "" {
		data, err := os.ReadFile(backupCertPath)
		if err == nil {
			_ = os.WriteFile(m.certPath, data, 0644)
		}
	}
	if backupKeyPath != "" && m.keyPath != "" {
		data, err := os.ReadFile(backupKeyPath)
		if err == nil {
			_ = os.WriteFile(m.keyPath, data, 0600)
		}
	}
	if backupChainPath != "" && m.chainPath != "" {
		data, err := os.ReadFile(backupChainPath)
		if err == nil {
			_ = os.WriteFile(m.chainPath, data, 0644)
		}
	}
	return nil
}
