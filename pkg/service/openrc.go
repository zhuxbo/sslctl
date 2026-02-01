//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OpenRCManager OpenRC 服务管理器
type OpenRCManager struct {
	cfg *ServiceConfig
}

// NewOpenRCManager 创建 OpenRC 管理器
func NewOpenRCManager(cfg *ServiceConfig) *OpenRCManager {
	return &OpenRCManager{cfg: cfg}
}

func (m *OpenRCManager) servicePath() string {
	return fmt.Sprintf("/etc/init.d/%s", m.cfg.Name)
}

func (m *OpenRCManager) serviceContent() string {
	return fmt.Sprintf(`#!/sbin/openrc-run

name="%s"
description="%s"
command="%s"
command_args="daemon"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="%s"

depend() {
    need net
    after firewall
}
`, m.cfg.DisplayName, m.cfg.Description, m.cfg.ExecPath, m.cfg.WorkDir)
}

// Install 安装服务
func (m *OpenRCManager) Install() error {
	// 创建工作目录
	if err := os.MkdirAll(m.cfg.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}

	// 写入服务脚本
	if err := os.WriteFile(m.servicePath(), []byte(m.serviceContent()), 0755); err != nil {
		return fmt.Errorf("写入服务脚本失败: %w", err)
	}

	return nil
}

// Uninstall 卸载服务
func (m *OpenRCManager) Uninstall() error {
	_ = m.Stop()
	_ = m.Disable()

	if err := os.Remove(m.servicePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除服务脚本失败: %w", err)
	}

	return nil
}

// Start 启动服务
func (m *OpenRCManager) Start() error {
	cmd := exec.Command("rc-service", m.cfg.Name, "start")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("启动服务失败: %w\n%s", err, output)
	}
	return nil
}

// Stop 停止服务
func (m *OpenRCManager) Stop() error {
	_ = exec.Command("rc-service", m.cfg.Name, "stop").Run()
	return nil
}

// Restart 重启服务
func (m *OpenRCManager) Restart() error {
	cmd := exec.Command("rc-service", m.cfg.Name, "restart")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("重启服务失败: %w\n%s", err, output)
	}
	return nil
}

// Status 获取服务状态
func (m *OpenRCManager) Status() (*Status, error) {
	status := &Status{}

	// 检查是否运行中
	output, _ := exec.Command("rc-service", m.cfg.Name, "status").Output()
	if strings.Contains(string(output), "started") {
		status.Running = true
	}

	// 检查是否启用
	output, _ = exec.Command("rc-update", "show", "default").Output()
	if strings.Contains(string(output), m.cfg.Name) {
		status.Enabled = true
	}

	return status, nil
}

// Enable 启用开机自启
func (m *OpenRCManager) Enable() error {
	if err := exec.Command("rc-update", "add", m.cfg.Name, "default").Run(); err != nil {
		return fmt.Errorf("启用服务失败: %w", err)
	}
	return nil
}

// Disable 禁用开机自启
func (m *OpenRCManager) Disable() error {
	_ = exec.Command("rc-update", "del", m.cfg.Name, "default").Run()
	return nil
}
