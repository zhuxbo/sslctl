//go:build linux

package service

import (
	"fmt"
	"os"

	"github.com/zhuxbo/sslctl/internal/executor"
)

// SystemdManager systemd 服务管理器
type SystemdManager struct {
	cfg *ServiceConfig
}

// NewSystemdManager 创建 systemd 管理器
func NewSystemdManager(cfg *ServiceConfig) *SystemdManager {
	return &SystemdManager{cfg: cfg}
}

func (m *SystemdManager) servicePath() string {
	return fmt.Sprintf("/etc/systemd/system/%s.service", m.cfg.Name)
}

func (m *SystemdManager) serviceContent() string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s daemon
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=%s
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/sslctl /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt

[Install]
WantedBy=multi-user.target
`, m.cfg.Description, m.cfg.ExecPath, m.cfg.WorkDir)
}

// Install 安装服务
func (m *SystemdManager) Install() error {
	// 创建工作目录
	if err := os.MkdirAll(m.cfg.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}

	// 写入服务文件
	if err := os.WriteFile(m.servicePath(), []byte(m.serviceContent()), 0644); err != nil {
		return fmt.Errorf("写入服务文件失败: %w", err)
	}

	// 重新加载 systemd（使用 executor 白名单）
	if err := executor.Run("systemctl daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload 失败: %w", err)
	}

	return nil
}

// Uninstall 卸载服务
func (m *SystemdManager) Uninstall() error {
	// 停止服务
	_ = m.Stop()
	_ = m.Disable()

	// 删除服务文件
	if err := os.Remove(m.servicePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除服务文件失败: %w", err)
	}

	// 重新加载 systemd（使用 executor 白名单）
	_ = executor.Run("systemctl daemon-reload")

	return nil
}

// Start 启动服务
func (m *SystemdManager) Start() error {
	if err := executor.Run("systemctl start " + m.cfg.Name); err != nil {
		return fmt.Errorf("启动服务失败: %w", err)
	}
	return nil
}

// Stop 停止服务
func (m *SystemdManager) Stop() error {
	_ = executor.Run("systemctl stop " + m.cfg.Name)
	return nil
}

// Restart 重启服务
func (m *SystemdManager) Restart() error {
	if err := executor.Run("systemctl restart " + m.cfg.Name); err != nil {
		return fmt.Errorf("重启服务失败: %w", err)
	}
	return nil
}

// Status 获取服务状态
func (m *SystemdManager) Status() (*Status, error) {
	status := &Status{}

	// 检查是否运行中（使用白名单命令）
	if executor.Run("systemctl is-active "+m.cfg.Name) == nil {
		status.Running = true
	}

	// 检查是否启用（使用白名单命令）
	if executor.Run("systemctl is-enabled "+m.cfg.Name) == nil {
		status.Enabled = true
	}

	return status, nil
}

// Enable 启用开机自启
func (m *SystemdManager) Enable() error {
	if err := executor.Run("systemctl enable " + m.cfg.Name); err != nil {
		return fmt.Errorf("启用服务失败: %w", err)
	}
	return nil
}

// Disable 禁用开机自启
func (m *SystemdManager) Disable() error {
	_ = executor.Run("systemctl disable " + m.cfg.Name)
	return nil
}
