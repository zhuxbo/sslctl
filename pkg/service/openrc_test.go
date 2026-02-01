//go:build linux

// Package service OpenRC 服务管理器测试
package service

import (
	"strings"
	"testing"
)

// TestNewOpenRCManager 测试创建 OpenRC 管理器
func TestNewOpenRCManager(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test-service",
		DisplayName: "Test Service",
		Description: "A test service",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/var/test",
	}

	mgr := NewOpenRCManager(cfg)

	if mgr == nil {
		t.Fatal("NewOpenRCManager 返回 nil")
	}

	if mgr.cfg != cfg {
		t.Error("配置未正确保存")
	}
}

// TestOpenRCManager_servicePath 测试服务路径生成
func TestOpenRCManager_servicePath(t *testing.T) {
	cfg := &ServiceConfig{Name: "test-service"}
	mgr := NewOpenRCManager(cfg)

	path := mgr.servicePath()
	expected := "/etc/init.d/test-service"

	if path != expected {
		t.Errorf("servicePath() = %s, 期望 %s", path, expected)
	}
}

// TestOpenRCManager_serviceContent 测试服务脚本内容生成
func TestOpenRCManager_serviceContent(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "cert-deploy",
		DisplayName: "SSL 证书部署服务",
		Description: "SSL 证书自动部署和管理服务",
		ExecPath:    "/usr/local/bin/cert-deploy",
		WorkDir:     "/opt/cert-deploy",
	}
	mgr := NewOpenRCManager(cfg)

	content := mgr.serviceContent()

	// 验证包含 OpenRC 头
	if !strings.Contains(content, "#!/sbin/openrc-run") {
		t.Error("服务脚本应包含 OpenRC shebang")
	}

	// 验证包含服务名称
	if !strings.Contains(content, cfg.DisplayName) {
		t.Errorf("服务脚本应包含显示名称: %s", cfg.DisplayName)
	}

	// 验证包含描述
	if !strings.Contains(content, cfg.Description) {
		t.Errorf("服务脚本应包含描述: %s", cfg.Description)
	}

	// 验证包含执行路径
	if !strings.Contains(content, cfg.ExecPath) {
		t.Errorf("服务脚本应包含执行路径: %s", cfg.ExecPath)
	}

	// 验证包含工作目录
	if !strings.Contains(content, cfg.WorkDir) {
		t.Errorf("服务脚本应包含工作目录: %s", cfg.WorkDir)
	}
}

// TestOpenRCManager_serviceContent_Variables 测试服务脚本变量
func TestOpenRCManager_serviceContent_Variables(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test",
		DisplayName: "Test Service",
		Description: "Test",
		ExecPath:    "/bin/test",
		WorkDir:     "/tmp",
	}
	mgr := NewOpenRCManager(cfg)

	content := mgr.serviceContent()

	// 验证包含必要的变量
	variables := []string{
		"name=",
		"description=",
		"command=",
		"command_args=",
		"command_background=",
		"pidfile=",
		"directory=",
	}

	for _, v := range variables {
		if !strings.Contains(content, v) {
			t.Errorf("服务脚本应包含变量: %s", v)
		}
	}
}

// TestOpenRCManager_serviceContent_DaemonArgs 测试 daemon 参数
func TestOpenRCManager_serviceContent_DaemonArgs(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "cert-deploy",
		ExecPath: "/usr/local/bin/cert-deploy",
		WorkDir:  "/opt/cert-deploy",
	}
	mgr := NewOpenRCManager(cfg)

	content := mgr.serviceContent()

	// 验证包含 daemon 参数
	if !strings.Contains(content, `command_args="daemon"`) {
		t.Error("服务脚本应包含 command_args=\"daemon\"")
	}

	// 验证后台运行
	if !strings.Contains(content, "command_background=true") {
		t.Error("服务脚本应设置 command_background=true")
	}
}

// TestOpenRCManager_serviceContent_Dependencies 测试服务依赖
func TestOpenRCManager_serviceContent_Dependencies(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewOpenRCManager(cfg)

	content := mgr.serviceContent()

	// 验证依赖函数
	if !strings.Contains(content, "depend()") {
		t.Error("服务脚本应包含 depend() 函数")
	}

	// 验证网络依赖
	if !strings.Contains(content, "need net") {
		t.Error("服务脚本应依赖网络")
	}

	// 验证防火墙依赖
	if !strings.Contains(content, "after firewall") {
		t.Error("服务脚本应在防火墙之后启动")
	}
}

// TestOpenRCManager_serviceContent_PidFile 测试 PID 文件配置
func TestOpenRCManager_serviceContent_PidFile(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "cert-deploy",
		ExecPath: "/usr/local/bin/cert-deploy",
		WorkDir:  "/opt/cert-deploy",
	}
	mgr := NewOpenRCManager(cfg)

	content := mgr.serviceContent()

	// 验证 PID 文件路径
	if !strings.Contains(content, "pidfile=") {
		t.Error("服务脚本应配置 pidfile")
	}

	// 验证使用 RC_SVCNAME 变量
	if !strings.Contains(content, "RC_SVCNAME") {
		t.Error("服务脚本应使用 RC_SVCNAME 变量")
	}
}

// TestOpenRCManager_Status 测试状态获取
func TestOpenRCManager_Status(t *testing.T) {
	cfg := DefaultConfig()
	mgr := NewOpenRCManager(cfg)

	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if status == nil {
		t.Fatal("Status() 返回 nil")
	}

	// 状态值应该是布尔值
	t.Logf("OpenRC Running: %v, Enabled: %v", status.Running, status.Enabled)
}

// TestOpenRCManager_Stop_NoError 测试停止服务不报错
func TestOpenRCManager_Stop_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-openrc-service-12345"}
	mgr := NewOpenRCManager(cfg)

	// 停止不存在的服务不应该报错
	err := mgr.Stop()
	if err != nil {
		t.Errorf("Stop() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestOpenRCManager_Disable_NoError 测试禁用服务不报错
func TestOpenRCManager_Disable_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-openrc-service-12345"}
	mgr := NewOpenRCManager(cfg)

	// 禁用不存在的服务不应该报错
	err := mgr.Disable()
	if err != nil {
		t.Errorf("Disable() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestOpenRCManager_servicePath_Format 测试服务路径格式
func TestOpenRCManager_servicePath_Format(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"cert-deploy", "/etc/init.d/cert-deploy"},
		{"nginx", "/etc/init.d/nginx"},
		{"my-app", "/etc/init.d/my-app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ServiceConfig{Name: tt.name}
			mgr := NewOpenRCManager(cfg)
			got := mgr.servicePath()
			if got != tt.expected {
				t.Errorf("servicePath() = %s, 期望 %s", got, tt.expected)
			}
		})
	}
}

// TestOpenRCManager_serviceContent_MultipleConfigs 测试不同配置生成的脚本
func TestOpenRCManager_serviceContent_MultipleConfigs(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		description string
		execPath    string
		workDir     string
	}{
		{
			name:        "cert-deploy",
			displayName: "Certificate Deploy",
			description: "SSL certificate deployment service",
			execPath:    "/usr/local/bin/cert-deploy",
			workDir:     "/opt/cert-deploy",
		},
		{
			name:        "my-app",
			displayName: "My Application",
			description: "A custom application",
			execPath:    "/usr/bin/my-app",
			workDir:     "/var/lib/my-app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ServiceConfig{
				Name:        tt.name,
				DisplayName: tt.displayName,
				Description: tt.description,
				ExecPath:    tt.execPath,
				WorkDir:     tt.workDir,
			}
			mgr := NewOpenRCManager(cfg)
			content := mgr.serviceContent()

			// 验证所有配置值都出现在脚本中
			if !strings.Contains(content, tt.displayName) {
				t.Errorf("脚本应包含 displayName: %s", tt.displayName)
			}
			if !strings.Contains(content, tt.description) {
				t.Errorf("脚本应包含 description: %s", tt.description)
			}
			if !strings.Contains(content, tt.execPath) {
				t.Errorf("脚本应包含 execPath: %s", tt.execPath)
			}
			if !strings.Contains(content, tt.workDir) {
				t.Errorf("脚本应包含 workDir: %s", tt.workDir)
			}
		})
	}
}
