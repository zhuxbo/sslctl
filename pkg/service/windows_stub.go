//go:build !windows

package service

import "fmt"

// WindowsManager Windows 服务管理器 (stub)
type WindowsManager struct {
	cfg *ServiceConfig
}

// NewWindowsManager 创建 Windows 管理器 (stub)
func NewWindowsManager(cfg *ServiceConfig) *WindowsManager {
	return &WindowsManager{cfg: cfg}
}

func (m *WindowsManager) Install() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Uninstall() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Start() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Stop() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Restart() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Status() (*Status, error) {
	return nil, fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Enable() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

func (m *WindowsManager) Disable() error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}

// IsWindowsService 检查是否以 Windows 服务方式运行 (stub)
func IsWindowsService() bool {
	return false
}

// RunAsService 以 Windows 服务方式运行 (stub)
func RunAsService(name string, handler func()) error {
	return fmt.Errorf("Windows 服务仅在 Windows 系统上可用")
}
