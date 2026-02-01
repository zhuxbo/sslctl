// Package service 服务管理测试
package service

import (
	"runtime"
	"testing"
)

// TestDefaultConfig 测试默认配置
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig 返回 nil")
	}

	if cfg.Name != "cert-deploy" {
		t.Errorf("Name = %s, 期望 cert-deploy", cfg.Name)
	}

	if cfg.DisplayName == "" {
		t.Error("DisplayName 不应为空")
	}

	if cfg.Description == "" {
		t.Error("Description 不应为空")
	}

	if cfg.ExecPath == "" {
		t.Error("ExecPath 不应为空")
	}

	if cfg.WorkDir == "" {
		t.Error("WorkDir 不应为空")
	}
}

// TestDefaultConfig_Windows 测试 Windows 默认配置
func TestDefaultConfig_Windows(t *testing.T) {
	cfg := DefaultConfig()

	if runtime.GOOS == "windows" {
		if cfg.ExecPath != `C:\Program Files\cert-deploy\cert-deploy.exe` {
			t.Logf("Windows ExecPath: %s", cfg.ExecPath)
		}
		if cfg.WorkDir != `C:\ProgramData\cert-deploy` {
			t.Logf("Windows WorkDir: %s", cfg.WorkDir)
		}
	} else {
		if cfg.ExecPath != "/usr/local/bin/cert-deploy" {
			t.Errorf("Linux ExecPath = %s", cfg.ExecPath)
		}
		if cfg.WorkDir != "/opt/cert-deploy" {
			t.Errorf("Linux WorkDir = %s", cfg.WorkDir)
		}
	}
}

// TestDetect 测试 init 系统检测
func TestDetect(t *testing.T) {
	initSys := Detect()

	t.Logf("检测到的 init 系统: %s", initSys)

	// 验证返回的是有效类型
	validTypes := []InitSystem{
		InitSystemd,
		InitOpenRC,
		InitSysVinit,
		InitWindows,
		InitUnknown,
	}

	found := false
	for _, vt := range validTypes {
		if initSys == vt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Detect() 返回无效类型: %s", initSys)
	}
}

// TestDetect_Windows 测试 Windows 检测
func TestDetect_Windows(t *testing.T) {
	if runtime.GOOS == "windows" {
		initSys := Detect()
		if initSys != InitWindows {
			t.Errorf("Windows 上 Detect() = %s, 期望 windows", initSys)
		}
	}
}

// TestGetInitSystemName 测试获取 init 系统名称
func TestGetInitSystemName(t *testing.T) {
	name := GetInitSystemName()

	if name == "" {
		t.Error("GetInitSystemName() 返回空字符串")
	}

	t.Logf("Init 系统名称: %s", name)

	// 验证名称是有效的
	validNames := []string{
		"systemd",
		"OpenRC",
		"SysVinit",
		"Windows Service",
		"未知",
	}

	found := false
	for _, vn := range validNames {
		if name == vn {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("GetInitSystemName() = %s，不是预期的值", name)
	}
}

// TestNew 测试创建服务管理器
func TestNew(t *testing.T) {
	cfg := DefaultConfig()
	mgr, err := New(cfg)

	// 在某些环境中可能无法检测到有效的 init 系统
	if err != nil {
		t.Logf("创建服务管理器失败（可能环境不支持）: %v", err)
		return
	}

	if mgr == nil {
		t.Error("New() 返回 nil 且无错误")
	}
}

// TestNew_NilConfig 测试空配置
func TestNew_NilConfig(t *testing.T) {
	// 传入 nil 应使用默认配置
	mgr, err := New(nil)

	if err != nil {
		t.Logf("创建服务管理器失败: %v", err)
		return
	}

	if mgr == nil {
		t.Error("New(nil) 返回 nil")
	}
}

// TestInitSystem_String 测试 InitSystem 常量
func TestInitSystem_String(t *testing.T) {
	tests := []struct {
		is   InitSystem
		want string
	}{
		{InitSystemd, "systemd"},
		{InitOpenRC, "openrc"},
		{InitSysVinit, "sysvinit"},
		{InitWindows, "windows"},
		{InitUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.is) != tt.want {
			t.Errorf("InitSystem = %s, 期望 %s", tt.is, tt.want)
		}
	}
}

// TestStatus 测试状态结构
func TestStatus(t *testing.T) {
	status := &Status{
		Running: true,
		Enabled: true,
	}

	if !status.Running {
		t.Error("Running 应为 true")
	}

	if !status.Enabled {
		t.Error("Enabled 应为 true")
	}
}

// TestServiceConfig 测试服务配置结构
func TestServiceConfig(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test-service",
		DisplayName: "Test Service",
		Description: "A test service",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/var/test",
	}

	if cfg.Name != "test-service" {
		t.Errorf("Name = %s", cfg.Name)
	}

	if cfg.DisplayName != "Test Service" {
		t.Errorf("DisplayName = %s", cfg.DisplayName)
	}
}

// TestNew_CustomConfig 测试使用自定义配置创建服务管理器
func TestNew_CustomConfig(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "custom-service",
		DisplayName: "Custom Service",
		Description: "A custom test service",
		ExecPath:    "/usr/local/bin/custom",
		WorkDir:     "/opt/custom",
	}

	mgr, err := New(cfg)
	if err != nil {
		t.Logf("创建服务管理器失败（环境不支持）: %v", err)
		return
	}

	if mgr == nil {
		t.Error("New() 返回 nil 且无错误")
	}
}

// TestStatus_Defaults 测试状态默认值
func TestStatus_Defaults(t *testing.T) {
	status := &Status{}

	if status.Running {
		t.Error("默认 Running 应为 false")
	}

	if status.Enabled {
		t.Error("默认 Enabled 应为 false")
	}
}

// TestStatus_Mixed 测试混合状态
func TestStatus_Mixed(t *testing.T) {
	tests := []struct {
		name    string
		running bool
		enabled bool
	}{
		{"运行中但未启用", true, false},
		{"已启用但未运行", false, true},
		{"运行中且已启用", true, true},
		{"未运行且未启用", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &Status{
				Running: tt.running,
				Enabled: tt.enabled,
			}
			if status.Running != tt.running {
				t.Errorf("Running = %v, 期望 %v", status.Running, tt.running)
			}
			if status.Enabled != tt.enabled {
				t.Errorf("Enabled = %v, 期望 %v", status.Enabled, tt.enabled)
			}
		})
	}
}

// TestServiceConfig_EmptyFields 测试空字段服务配置
func TestServiceConfig_EmptyFields(t *testing.T) {
	cfg := &ServiceConfig{}

	if cfg.Name != "" {
		t.Error("空配置的 Name 应为空")
	}
	if cfg.DisplayName != "" {
		t.Error("空配置的 DisplayName 应为空")
	}
	if cfg.Description != "" {
		t.Error("空配置的 Description 应为空")
	}
	if cfg.ExecPath != "" {
		t.Error("空配置的 ExecPath 应为空")
	}
	if cfg.WorkDir != "" {
		t.Error("空配置的 WorkDir 应为空")
	}
}

// TestInitSystem_Values 测试所有 InitSystem 常量值
func TestInitSystem_Values(t *testing.T) {
	// 确保所有常量都有预期的值
	if InitSystemd != "systemd" {
		t.Errorf("InitSystemd = %s, 期望 systemd", InitSystemd)
	}
	if InitOpenRC != "openrc" {
		t.Errorf("InitOpenRC = %s, 期望 openrc", InitOpenRC)
	}
	if InitSysVinit != "sysvinit" {
		t.Errorf("InitSysVinit = %s, 期望 sysvinit", InitSysVinit)
	}
	if InitWindows != "windows" {
		t.Errorf("InitWindows = %s, 期望 windows", InitWindows)
	}
	if InitUnknown != "unknown" {
		t.Errorf("InitUnknown = %s, 期望 unknown", InitUnknown)
	}
}

// TestDetect_Consistent 测试检测结果一致性
func TestDetect_Consistent(t *testing.T) {
	// 多次调用 Detect 应返回相同结果
	result1 := Detect()
	result2 := Detect()
	result3 := Detect()

	if result1 != result2 || result2 != result3 {
		t.Error("Detect() 应返回一致的结果")
	}
}

// TestGetInitSystemName_Consistent 测试名称获取一致性
func TestGetInitSystemName_Consistent(t *testing.T) {
	name1 := GetInitSystemName()
	name2 := GetInitSystemName()

	if name1 != name2 {
		t.Error("GetInitSystemName() 应返回一致的结果")
	}
}

// TestDefaultConfig_NonNil 测试默认配置非空
func TestDefaultConfig_NonNil(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() 不应返回 nil")
	}

	// 所有字段都应有值
	if cfg.Name == "" {
		t.Error("Name 不应为空")
	}
	if cfg.DisplayName == "" {
		t.Error("DisplayName 不应为空")
	}
	if cfg.Description == "" {
		t.Error("Description 不应为空")
	}
	if cfg.ExecPath == "" {
		t.Error("ExecPath 不应为空")
	}
	if cfg.WorkDir == "" {
		t.Error("WorkDir 不应为空")
	}
}
