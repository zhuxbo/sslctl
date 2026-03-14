//go:build !linux

package service

import "fmt"

// SystemdManager systemd 服务管理器 (stub)
type SystemdManager struct {
	cfg *ServiceConfig
}

// NewSystemdManager 创建 systemd 管理器 (stub)
func NewSystemdManager(cfg *ServiceConfig) *SystemdManager {
	return &SystemdManager{cfg: cfg}
}

func (m *SystemdManager) Install() error   { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Uninstall() error { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Start() error     { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Stop() error      { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Restart() error   { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Status() (*Status, error) {
	return nil, fmt.Errorf("systemd 仅在 Linux 上可用")
}
func (m *SystemdManager) Enable() error  { return fmt.Errorf("systemd 仅在 Linux 上可用") }
func (m *SystemdManager) Disable() error { return fmt.Errorf("systemd 仅在 Linux 上可用") }

// OpenRCManager OpenRC 服务管理器 (stub)
type OpenRCManager struct {
	cfg *ServiceConfig
}

// NewOpenRCManager 创建 OpenRC 管理器 (stub)
func NewOpenRCManager(cfg *ServiceConfig) *OpenRCManager {
	return &OpenRCManager{cfg: cfg}
}

func (m *OpenRCManager) Install() error   { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Uninstall() error { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Start() error     { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Stop() error      { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Restart() error   { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Status() (*Status, error) {
	return nil, fmt.Errorf("OpenRC 仅在 Linux 上可用")
}
func (m *OpenRCManager) Enable() error  { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }
func (m *OpenRCManager) Disable() error { return fmt.Errorf("OpenRC 仅在 Linux 上可用") }

// SysVinitManager SysVinit 服务管理器 (stub)
type SysVinitManager struct {
	cfg *ServiceConfig
}

// NewSysVinitManager 创建 SysVinit 管理器 (stub)
func NewSysVinitManager(cfg *ServiceConfig) *SysVinitManager {
	return &SysVinitManager{cfg: cfg}
}

func (m *SysVinitManager) Install() error   { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Uninstall() error { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Start() error     { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Stop() error      { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Restart() error   { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Status() (*Status, error) {
	return nil, fmt.Errorf("SysVinit 仅在 Linux 上可用")
}
func (m *SysVinitManager) Enable() error  { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
func (m *SysVinitManager) Disable() error { return fmt.Errorf("SysVinit 仅在 Linux 上可用") }
