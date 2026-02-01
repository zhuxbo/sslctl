// Package webserver 检测器测试
package webserver

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectLocalServer 测试本地服务器检测
func TestDetectLocalServer(t *testing.T) {
	serverType := DetectLocalServer()
	// 根据测试环境，可能返回不同的类型
	t.Logf("检测到的本地服务器类型: %s", serverType)

	// 验证返回的是有效类型
	validTypes := []ServerType{TypeNginx, TypeApache, TypeUnknown}
	found := false
	for _, vt := range validTypes {
		if serverType == vt {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DetectLocalServer() 返回无效类型: %s", serverType)
	}
}

// TestIsNginxInstalled 测试 Nginx 安装检测
func TestIsNginxInstalled(t *testing.T) {
	installed := isNginxInstalled()
	t.Logf("Nginx 已安装: %v", installed)
}

// TestIsApacheInstalled 测试 Apache 安装检测
func TestIsApacheInstalled(t *testing.T) {
	installed := isApacheInstalled()
	t.Logf("Apache 已安装: %v", installed)
}

// TestGetNginxConfigPath 测试获取 Nginx 配置路径
func TestGetNginxConfigPath(t *testing.T) {
	configPath := GetNginxConfigPath()
	if configPath != "" {
		t.Logf("Nginx 配置路径: %s", configPath)
		// 验证路径存在
		if _, err := os.Stat(configPath); err != nil {
			t.Logf("配置路径不存在: %v", err)
		}
	} else {
		t.Log("未找到 Nginx 配置路径")
	}
}

// TestGetApacheConfigPath 测试获取 Apache 配置路径
func TestGetApacheConfigPath(t *testing.T) {
	configPath := GetApacheConfigPath()
	if configPath != "" {
		t.Logf("Apache 配置路径: %s", configPath)
	} else {
		t.Log("未找到 Apache 配置路径")
	}
}

// TestGetNginxSitesDir 测试获取 Nginx 站点目录
func TestGetNginxSitesDir(t *testing.T) {
	sitesDir := GetNginxSitesDir()
	if sitesDir != "" {
		t.Logf("Nginx 站点目录: %s", sitesDir)
	} else {
		t.Log("未找到 Nginx 站点目录")
	}
}

// TestGetApacheSitesDir 测试获取 Apache 站点目录
func TestGetApacheSitesDir(t *testing.T) {
	sitesDir := GetApacheSitesDir()
	if sitesDir != "" {
		t.Logf("Apache 站点目录: %s", sitesDir)
	} else {
		t.Log("未找到 Apache 站点目录")
	}
}

// TestGetNginxConfigPath_WithMockPaths 测试使用模拟路径获取配置
func TestGetNginxConfigPath_WithMockPaths(t *testing.T) {
	// 创建临时目录模拟配置
	tmpDir := t.TempDir()
	mockConfPath := filepath.Join(tmpDir, "nginx.conf")

	// 创建模拟配置文件
	if err := os.WriteFile(mockConfPath, []byte("# nginx config"), 0644); err != nil {
		t.Fatalf("创建模拟配置失败: %v", err)
	}

	// 注意：这个测试只是验证函数不会崩溃
	// 实际路径检测逻辑在系统路径中
	_ = GetNginxConfigPath()
}

// TestGetApacheConfigPath_WithMockPaths 测试使用模拟路径获取配置
func TestGetApacheConfigPath_WithMockPaths(t *testing.T) {
	// 创建临时目录模拟配置
	tmpDir := t.TempDir()
	mockConfPath := filepath.Join(tmpDir, "httpd.conf")

	// 创建模拟配置文件
	if err := os.WriteFile(mockConfPath, []byte("# apache config"), 0644); err != nil {
		t.Fatalf("创建模拟配置失败: %v", err)
	}

	// 注意：这个测试只是验证函数不会崩溃
	_ = GetApacheConfigPath()
}

// TestDetectDockerServer 测试 Docker 服务器检测
func TestDetectDockerServer(t *testing.T) {
	// 使用不存在的容器 ID 测试
	serverType := DetectDockerServer("nonexistent-container-id")
	if serverType != TypeUnknown {
		t.Logf("检测到容器类型: %s", serverType)
	} else {
		t.Log("Docker 检测返回 unknown（预期，无 Docker 或容器不存在）")
	}
}
