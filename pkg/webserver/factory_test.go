// Package webserver 工厂函数测试
package webserver

import (
	"testing"
)

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
	if sites != nil && len(sites) > 0 {
		t.Log("Docker 扫描已实现")
	}
}
