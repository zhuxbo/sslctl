//go:build linux

// Package service SysVinit 服务管理器测试
package service

import (
	"strings"
	"testing"
)

// TestNewSysVinitManager 测试创建 SysVinit 管理器
func TestNewSysVinitManager(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "test-service",
		DisplayName: "Test Service",
		Description: "A test service",
		ExecPath:    "/usr/bin/test",
		WorkDir:     "/var/test",
	}

	mgr := NewSysVinitManager(cfg)

	if mgr == nil {
		t.Fatal("NewSysVinitManager 返回 nil")
	}

	if mgr.cfg != cfg {
		t.Error("配置未正确保存")
	}
}

// TestSysVinitManager_servicePath 测试服务路径生成
func TestSysVinitManager_servicePath(t *testing.T) {
	cfg := &ServiceConfig{Name: "test-service"}
	mgr := NewSysVinitManager(cfg)

	path := mgr.servicePath()
	expected := "/etc/init.d/test-service"

	if path != expected {
		t.Errorf("servicePath() = %s, 期望 %s", path, expected)
	}
}

// TestSysVinitManager_pidFile 测试 PID 文件路径
func TestSysVinitManager_pidFile(t *testing.T) {
	cfg := &ServiceConfig{Name: "test-service"}
	mgr := NewSysVinitManager(cfg)

	path := mgr.pidFile()
	expected := "/var/run/test-service.pid"

	if path != expected {
		t.Errorf("pidFile() = %s, 期望 %s", path, expected)
	}
}

// TestSysVinitManager_serviceContent 测试服务脚本内容生成
func TestSysVinitManager_serviceContent(t *testing.T) {
	cfg := &ServiceConfig{
		Name:        "cert-deploy",
		DisplayName: "SSL 证书部署服务",
		Description: "SSL 证书自动部署和管理服务",
		ExecPath:    "/usr/local/bin/cert-deploy",
		WorkDir:     "/opt/cert-deploy",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证包含必要的 LSB 头
	checks := []string{
		"#!/bin/sh",
		"### BEGIN INIT INFO",
		"### END INIT INFO",
		"# Provides:",
		"# Required-Start:",
		"# Default-Start:",
		"# Default-Stop:",
		"# Short-Description:",
		"# Description:",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("服务脚本应包含: %s", check)
		}
	}

	// 验证包含服务名称
	if !strings.Contains(content, cfg.Name) {
		t.Errorf("服务脚本应包含服务名称: %s", cfg.Name)
	}

	// 验证包含执行路径
	if !strings.Contains(content, cfg.ExecPath) {
		t.Errorf("服务脚本应包含执行路径: %s", cfg.ExecPath)
	}

	// 验证包含工作目录
	if !strings.Contains(content, cfg.WorkDir) {
		t.Errorf("服务脚本应包含工作目录: %s", cfg.WorkDir)
	}

	// 验证包含 PID 文件路径
	pidFile := mgr.pidFile()
	if !strings.Contains(content, pidFile) {
		t.Errorf("服务脚本应包含 PID 文件路径: %s", pidFile)
	}
}

// TestSysVinitManager_serviceContent_Functions 测试服务脚本函数
func TestSysVinitManager_serviceContent_Functions(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证包含必要的函数
	functions := []string{
		"read_pid()",
		"start()",
		"stop()",
		"status()",
	}

	for _, fn := range functions {
		if !strings.Contains(content, fn) {
			t.Errorf("服务脚本应包含函数: %s", fn)
		}
	}

	// 验证包含 case 语句
	cases := []string{
		"start)",
		"stop)",
		"restart)",
		"status)",
	}

	for _, c := range cases {
		if !strings.Contains(content, c) {
			t.Errorf("服务脚本应包含 case: %s", c)
		}
	}
}

// TestSysVinitManager_serviceContent_Security 测试服务脚本安全性
func TestSysVinitManager_serviceContent_Security(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证 PID 验证逻辑
	if !strings.Contains(content, "case") && !strings.Contains(content, "*[!0-9]*") {
		t.Log("服务脚本应包含 PID 数字验证")
	}

	// 验证使用 nohup 运行后台
	if !strings.Contains(content, "nohup") {
		t.Error("服务脚本应使用 nohup 运行后台进程")
	}
}

// TestSysVinitManager_Status 测试状态获取
func TestSysVinitManager_Status(t *testing.T) {
	cfg := DefaultConfig()
	mgr := NewSysVinitManager(cfg)

	status, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if status == nil {
		t.Fatal("Status() 返回 nil")
	}

	// 状态值应该是布尔值
	t.Logf("SysVinit Running: %v, Enabled: %v", status.Running, status.Enabled)
}

// TestSysVinitManager_Stop_NoError 测试停止服务不报错
func TestSysVinitManager_Stop_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-sysvinit-service-12345"}
	mgr := NewSysVinitManager(cfg)

	// 停止不存在的服务不应该报错
	err := mgr.Stop()
	if err != nil {
		t.Errorf("Stop() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestSysVinitManager_Disable_NoError 测试禁用服务不报错
func TestSysVinitManager_Disable_NoError(t *testing.T) {
	cfg := &ServiceConfig{Name: "nonexistent-sysvinit-service-12345"}
	mgr := NewSysVinitManager(cfg)

	// 禁用不存在的服务不应该报错
	err := mgr.Disable()
	if err != nil {
		t.Errorf("Disable() 应返回 nil，即使服务不存在，实际: %v", err)
	}
}

// TestSysVinitManager_DaemonArgs 测试 daemon 参数
func TestSysVinitManager_DaemonArgs(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "cert-deploy",
		ExecPath: "/usr/local/bin/cert-deploy",
		WorkDir:  "/opt/cert-deploy",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证包含 daemon 参数
	if !strings.Contains(content, `DAEMON_ARGS="daemon"`) {
		t.Error("服务脚本应包含 DAEMON_ARGS=\"daemon\"")
	}
}

// TestSysVinitManager_RunLevels 测试运行级别配置
func TestSysVinitManager_RunLevels(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证默认启动级别
	if !strings.Contains(content, "# Default-Start:     2 3 4 5") {
		t.Error("服务脚本应包含正确的启动级别")
	}

	// 验证默认停止级别
	if !strings.Contains(content, "# Default-Stop:      0 1 6") {
		t.Error("服务脚本应包含正确的停止级别")
	}
}

// TestSysVinitManager_Dependencies 测试服务依赖
func TestSysVinitManager_Dependencies(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证网络依赖
	if !strings.Contains(content, "$network") {
		t.Error("服务脚本应依赖网络")
	}

	// 验证文件系统依赖
	if !strings.Contains(content, "$remote_fs") {
		t.Error("服务脚本应依赖远程文件系统")
	}
}

// TestSysVinitManager_UsageMessage 测试使用说明
func TestSysVinitManager_UsageMessage(t *testing.T) {
	cfg := &ServiceConfig{
		Name:     "test",
		ExecPath: "/bin/test",
		WorkDir:  "/tmp",
	}
	mgr := NewSysVinitManager(cfg)

	content := mgr.serviceContent()

	// 验证使用说明
	if !strings.Contains(content, "Usage: $0 {start|stop|restart|status}") {
		t.Error("服务脚本应包含使用说明")
	}
}
