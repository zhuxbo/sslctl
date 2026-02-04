//go:build linux

// Package service systemd 服务管理器测试
package service

import (
	"strings"
	"testing"
)

// TestNewSystemdManager 测试创建 systemd 管理器
func TestNewSystemdManager(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test-service",
		Description: "Test Service",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/var/test",
	}

	mgr := NewSystemdManager(cfg)

	if mgr == nil {
		t.Fatal("NewSystemdManager 返回 nil")
	}

	if mgr.cfg != cfg {
		t.Error("配置未正确保存")
	}
}

// TestSystemdManager_servicePath 测试服务路径生成
func TestSystemdManager_servicePath(t *testing.T) {
	cfg := &ServiceConfig{Name: "test-service"}
	mgr := NewSystemdManager(cfg)

	path := mgr.servicePath()
	expected := "/etc/systemd/system/test-service.service"

	if path != expected {
		t.Errorf("servicePath() = %s, 期望 %s", path, expected)
	}
}

// TestSystemdManager_serviceContent 测试服务文件内容生成
func TestSystemdManager_serviceContent(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "sslctl",
		Description: "SSL 证书自动部署服务",
		ExecPath:    "/usr/local/bin/sslctl",
		WorkDir:     "/opt/sslctl",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	// 验证包含必要的部分
	checks := []string{
		"[Unit]",
		"[Service]",
		"[Install]",
		"Description=" + cfg.Description,
		"ExecStart=" + cfg.ExecPath + " daemon",
		"WorkingDirectory=" + cfg.WorkDir,
		"After=network-online.target",
		"Restart=always",
		"WantedBy=multi-user.target",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("服务文件内容缺少: %s", check)
		}
	}
}

// TestSystemdManager_serviceContent_Format 测试服务文件格式
func TestSystemdManager_serviceContent_Format(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	// 验证 INI 格式
	lines := strings.Split(content, "\n")

	// 检查是否有有效的 section 头
	sectionCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sectionCount++
		}
	}

	if sectionCount != 3 {
		t.Errorf("期望 3 个 section（Unit, Service, Install），实际 %d", sectionCount)
	}
}

// TestSystemdManager_Status 测试状态获取
func TestSystemdManager_Status(t *testing.T) {
	cfg := DefaultConfig()
	mgr := NewSystemdManager(cfg)

	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if status == nil {
		t.Fatal("Status() 返回 nil")
	}

	// 状态值应该是布尔值（不需要验证具体值，因为取决于系统状态）
	t.Logf("Running: %v, Enabled: %v", status.Running, status.Enabled)
}

// TestSystemdManager_Stop_NoError 测试停止服务不报错
func TestSystemdManager_Stop_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-service-12345"}
	mgr := NewSystemdManager(cfg)

	// 停止不存在的服务不应该报错
	err := mgr.Stop()
	if err != nil {
		t.Errorf("Stop() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestSystemdManager_Disable_NoError 测试禁用服务不报错
func TestSystemdManager_Disable_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-service-12345"}
	mgr := NewSystemdManager(cfg)

	// 禁用不存在的服务不应该报错
	err := mgr.Disable()
	if err != nil {
		t.Errorf("Disable() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestSystemdManager_serviceContent_RestartConfig 测试重启配置
func TestSystemdManager_serviceContent_RestartConfig(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	// 验证重启相关配置
	checks := []string{
		"Restart=always",
		"RestartSec=30",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("服务文件内容应包含: %s", check)
		}
	}
}

// TestSystemdManager_serviceContent_Security 测试安全配置
func TestSystemdManager_serviceContent_Security(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	// 验证用户和组配置
	if !strings.Contains(content, "User=root") {
		t.Error("服务文件应配置 User=root")
	}
	if !strings.Contains(content, "Group=root") {
		t.Error("服务文件应配置 Group=root")
	}
}

// TestSystemdManager_serviceContent_Logging 测试日志配置
func TestSystemdManager_serviceContent_Logging(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	// 验证日志配置
	if !strings.Contains(content, "StandardOutput=journal") {
		t.Error("服务文件应配置 StandardOutput=journal")
	}
	if !strings.Contains(content, "StandardError=journal") {
		t.Error("服务文件应配置 StandardError=journal")
	}
}

// TestSystemdManager_serviceContent_Type 测试服务类型
func TestSystemdManager_serviceContent_Type(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewSystemdManager(cfg)

	content := mgr.serviceContent()

	if !strings.Contains(content, "Type=simple") {
		t.Error("服务文件应配置 Type=simple")
	}
}

// TestDefaultConfig_Systemd 测试默认配置
func TestDefaultConfig_Systemd(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() 返回 nil")
	}

	if cfg.Name == "" {
		t.Error("默认配置的 Name 不应为空")
	}

	if cfg.ExecPath == "" {
		t.Error("默认配置的 ExecPath 不应为空")
	}

	if cfg.WorkDir == "" {
		t.Error("默认配置的 WorkDir 不应为空")
	}
}
