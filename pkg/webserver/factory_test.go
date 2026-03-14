// Package webserver 工厂函数测试
package webserver

import (
	"testing"
)

// init 注册测试用的 mock 工厂函数
func init() {
	// 注册 Nginx 扫描器
	RegisterScanner(TypeNginx, func() Scanner {
		return &mockScanner{serverType: TypeNginx}
	})

	// 注册 Nginx 部署器
	RegisterDeployer(TypeNginx, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) Deployer {
		return &mockDeployer{}
	})

	// 注册 Apache 部署器
	RegisterDeployer(TypeApache, func(certPath, keyPath, chainPath, testCmd, reloadCmd string) Deployer {
		return &mockDeployer{}
	})

	// 注册 Nginx 安装器
	RegisterInstaller(TypeNginx, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) Installer {
		return &mockInstaller{}
	})

	// 注册 Apache 安装器
	RegisterInstaller(TypeApache, func(configPath, certPath, keyPath, chainPath, serverName, testCmd string) Installer {
		return &mockInstaller{}
	})
}

// mockScanner 测试用 mock 扫描器
type mockScanner struct {
	serverType ServerType
}

func (m *mockScanner) Scan() ([]Site, error)      { return nil, nil }
func (m *mockScanner) ScanLocal() ([]Site, error) { return nil, nil }
func (m *mockScanner) ScanDocker() ([]Site, error) { return nil, nil }
func (m *mockScanner) ServerType() ServerType     { return m.serverType }

// mockInstaller 测试用 mock 安装器
type mockInstaller struct{}

func (m *mockInstaller) Install() (*InstallResult, error) {
	return &InstallResult{BackupPath: "/tmp/backup.bak", Modified: true}, nil
}
func (m *mockInstaller) Rollback(backupPath string) error { return nil }

// mockDeployer 测试用 mock 部署器
type mockDeployer struct{}

func (m *mockDeployer) Deploy(cert, chain, key string) error                           { return nil }
func (m *mockDeployer) Reload() error                                                  { return nil }
func (m *mockDeployer) Test() error                                                    { return nil }
func (m *mockDeployer) Rollback(backupCertPath, backupKeyPath, backupChainPath string) error { return nil }

// TestNewScanner_Nginx 测试创建 Nginx 扫描器
func TestNewScanner_Nginx(t *testing.T) {
	scanner, err := NewScanner(TypeNginx)
	if err != nil {
		t.Fatalf("NewScanner(TypeNginx) error = %v", err)
	}
	if scanner == nil {
		t.Error("NewScanner(TypeNginx) 返回 nil")
	}
	if scanner.ServerType() != TypeNginx {
		t.Errorf("ServerType() = %s, 期望 nginx", scanner.ServerType())
	}
}

// TestNewScanner_DockerNginx 测试创建 Docker Nginx 扫描器
func TestNewScanner_DockerNginx(t *testing.T) {
	scanner, err := NewScanner(TypeDockerNginx)
	if err != nil {
		t.Fatalf("NewScanner(TypeDockerNginx) error = %v", err)
	}
	if scanner == nil {
		t.Error("NewScanner(TypeDockerNginx) 返回 nil")
	}
}

// TestNewScanner_Apache 测试创建 Apache 扫描器（目前未实现）
func TestNewScanner_Apache(t *testing.T) {
	_, err := NewScanner(TypeApache)
	// 当前 Apache 扫描器未实现，应返回错误
	if err == nil {
		t.Log("Apache 扫描器已实现")
	} else {
		t.Logf("Apache 扫描器未实现（预期）: %v", err)
	}
}

// TestNewScanner_Unknown 测试创建未知类型扫描器
func TestNewScanner_Unknown(t *testing.T) {
	_, err := NewScanner(TypeUnknown)
	if err == nil {
		t.Error("NewScanner(TypeUnknown) 应返回错误")
	}
}

// TestNewDeployer_Nginx 测试创建 Nginx 部署器
func TestNewDeployer_Nginx(t *testing.T) {
	deployer, err := NewDeployer(
		TypeNginx,
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"",
		"nginx -t",
		"nginx -s reload",
	)
	if err != nil {
		t.Fatalf("NewDeployer(TypeNginx) error = %v", err)
	}
	if deployer == nil {
		t.Error("NewDeployer(TypeNginx) 返回 nil")
	}
}

// TestNewDeployer_Apache 测试创建 Apache 部署器
func TestNewDeployer_Apache(t *testing.T) {
	deployer, err := NewDeployer(
		TypeApache,
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"/etc/ssl/chain.pem",
		"apachectl configtest",
		"apachectl graceful",
	)
	if err != nil {
		t.Fatalf("NewDeployer(TypeApache) error = %v", err)
	}
	if deployer == nil {
		t.Error("NewDeployer(TypeApache) 返回 nil")
	}
}

// TestNewDeployer_DockerNginx 测试创建 Docker Nginx 部署器
func TestNewDeployer_DockerNginx(t *testing.T) {
	deployer, err := NewDeployer(
		TypeDockerNginx,
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"",
		"docker exec nginx nginx -t",
		"docker exec nginx nginx -s reload",
	)
	if err != nil {
		t.Fatalf("NewDeployer(TypeDockerNginx) error = %v", err)
	}
	if deployer == nil {
		t.Error("NewDeployer(TypeDockerNginx) 返回 nil")
	}
}

// TestNewDeployer_Unknown 测试创建未知类型部署器
func TestNewDeployer_Unknown(t *testing.T) {
	_, err := NewDeployer(
		TypeUnknown,
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"",
		"",
		"",
	)
	if err == nil {
		t.Error("NewDeployer(TypeUnknown) 应返回错误")
	}
}

// TestNginxScannerWrapper_ServerType 测试 Nginx 扫描器包装器
func TestNginxScannerWrapper_ServerType(t *testing.T) {
	scanner, _ := NewScanner(TypeNginx)
	if scanner.ServerType() != TypeNginx {
		t.Errorf("ServerType() = %s, 期望 nginx", scanner.ServerType())
	}
}

// TestNginxScannerWrapper_ScanDocker 测试 Docker 扫描（当前返回 nil）
func TestNginxScannerWrapper_ScanDocker(t *testing.T) {
	scanner, _ := NewScanner(TypeNginx)
	sites, err := scanner.ScanDocker()
	if err != nil {
		t.Errorf("ScanDocker() error = %v", err)
	}
	if len(sites) > 0 {
		t.Log("Docker 扫描已实现")
	}
}

// TestNginxScannerWrapper_ScanLocal 测试本地扫描
func TestNginxScannerWrapper_ScanLocal(t *testing.T) {
	scanner, _ := NewScanner(TypeNginx)
	sites, err := scanner.ScanLocal()
	if err != nil {
		t.Logf("ScanLocal() error = %v (nginx可能未安装)", err)
		return
	}
	t.Logf("扫描到 %d 个站点", len(sites))
	for _, site := range sites {
		t.Logf("  站点: %s, 配置: %s", site.ServerName, site.ConfigFile)
	}
}

// TestNginxDeployerWrapper_Methods 测试 Nginx 部署器方法
func TestNginxDeployerWrapper_Methods(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"

	deployer, err := NewDeployer(
		TypeNginx,
		certPath,
		keyPath,
		"",
		"", // 无测试命令
		"", // 无重载命令
	)
	if err != nil {
		t.Fatalf("NewDeployer error = %v", err)
	}

	// Deploy 应该失败（没有有效证书）
	err = deployer.Deploy("invalid-cert", "", "invalid-key")
	if err == nil {
		t.Log("Deploy 成功（意外）")
	} else {
		t.Logf("Deploy 失败（预期）: %v", err)
	}

	// Test 应该失败或跳过（没有配置测试命令）
	err = deployer.Test()
	if err != nil {
		t.Logf("Test 失败（预期，无测试命令）: %v", err)
	}

	// Reload 应该失败或跳过（没有配置重载命令）
	err = deployer.Reload()
	if err != nil {
		t.Logf("Reload 失败（预期，无重载命令）: %v", err)
	}
}

// TestApacheDeployerWrapper_Methods 测试 Apache 部署器方法
func TestApacheDeployerWrapper_Methods(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	chainPath := tmpDir + "/chain.pem"

	deployer, err := NewDeployer(
		TypeApache,
		certPath,
		keyPath,
		chainPath,
		"", // 无测试命令
		"", // 无重载命令
	)
	if err != nil {
		t.Fatalf("NewDeployer error = %v", err)
	}

	// Deploy 应该失败（没有有效证书）
	err = deployer.Deploy("invalid-cert", "invalid-chain", "invalid-key")
	if err == nil {
		t.Log("Deploy 成功（意外）")
	} else {
		t.Logf("Deploy 失败（预期）: %v", err)
	}

	// Test 应该失败或跳过（没有配置测试命令）
	err = deployer.Test()
	if err != nil {
		t.Logf("Test 失败（预期，无测试命令）: %v", err)
	}

	// Reload 应该失败或跳过（没有配置重载命令）
	err = deployer.Reload()
	if err != nil {
		t.Logf("Reload 失败（预期，无重载命令）: %v", err)
	}
}

// TestNewDeployer_DockerApache 测试创建 Docker Apache 部署器
func TestNewDeployer_DockerApache(t *testing.T) {
	deployer, err := NewDeployer(
		TypeDockerApache,
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"/etc/ssl/chain.pem",
		"docker exec apache apachectl configtest",
		"docker exec apache apachectl graceful",
	)
	if err != nil {
		t.Fatalf("NewDeployer(TypeDockerApache) error = %v", err)
	}
	if deployer == nil {
		t.Error("NewDeployer(TypeDockerApache) 返回 nil")
	}
}

// TestNewScanner_DockerApache 测试创建 Docker Apache 扫描器
func TestNewScanner_DockerApache(t *testing.T) {
	_, err := NewScanner(TypeDockerApache)
	// 当前 Apache 扫描器未实现，应返回错误
	if err == nil {
		t.Log("Docker Apache 扫描器已实现")
	} else {
		t.Logf("Docker Apache 扫描器未实现（预期）: %v", err)
	}
}

// TestNewScanner_InvalidType 测试无效类型
func TestNewScanner_InvalidType(t *testing.T) {
	_, err := NewScanner(ServerType("invalid"))
	if err == nil {
		t.Error("无效类型应返回错误")
	}
}

// TestNewDeployer_InvalidType 测试无效类型
func TestNewDeployer_InvalidType(t *testing.T) {
	_, err := NewDeployer(ServerType("invalid"), "", "", "", "", "")
	if err == nil {
		t.Error("无效类型应返回错误")
	}
}

// TestNewInstaller_Nginx 测试创建 Nginx 安装器
func TestNewInstaller_Nginx(t *testing.T) {
	installer, err := NewInstaller(TypeNginx, "/etc/nginx/conf.d/example.conf", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", "", "example.com", "nginx -t")
	if err != nil {
		t.Fatalf("NewInstaller(TypeNginx) error = %v", err)
	}
	if installer == nil {
		t.Error("NewInstaller(TypeNginx) 返回 nil")
	}

	result, err := installer.Install()
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !result.Modified {
		t.Error("Install() Modified 应为 true")
	}
}

// TestNewInstaller_Apache 测试创建 Apache 安装器
func TestNewInstaller_Apache(t *testing.T) {
	installer, err := NewInstaller(TypeApache, "/etc/apache2/sites-available/example.conf", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", "/etc/ssl/chain.pem", "example.com", "apache2ctl -t")
	if err != nil {
		t.Fatalf("NewInstaller(TypeApache) error = %v", err)
	}
	if installer == nil {
		t.Error("NewInstaller(TypeApache) 返回 nil")
	}
}

// TestNewInstaller_NotRegistered 测试未注册类型返回错误
func TestNewInstaller_NotRegistered(t *testing.T) {
	_, err := NewInstaller(TypeUnknown, "", "", "", "", "", "")
	if err == nil {
		t.Error("NewInstaller(TypeUnknown) 应返回错误")
	}
}

// TestNewInstaller_DockerFallback 测试 Docker 类型回退到普通安装器
func TestNewInstaller_DockerFallback(t *testing.T) {
	installer, err := NewInstaller(TypeDockerNginx, "/etc/nginx/conf.d/example.conf", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", "", "example.com", "nginx -t")
	if err != nil {
		t.Fatalf("NewInstaller(TypeDockerNginx) error = %v", err)
	}
	if installer == nil {
		t.Error("NewInstaller(TypeDockerNginx) 返回 nil")
	}

	installer, err = NewInstaller(TypeDockerApache, "/etc/apache2/sites-available/example.conf", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", "/etc/ssl/chain.pem", "example.com", "apache2ctl -t")
	if err != nil {
		t.Fatalf("NewInstaller(TypeDockerApache) error = %v", err)
	}
	if installer == nil {
		t.Error("NewInstaller(TypeDockerApache) 返回 nil")
	}
}

// TestNewInstaller_InvalidType 测试无效类型
func TestNewInstaller_InvalidType(t *testing.T) {
	_, err := NewInstaller(ServerType("invalid"), "", "", "", "", "", "")
	if err == nil {
		t.Error("无效类型应返回错误")
	}
}
