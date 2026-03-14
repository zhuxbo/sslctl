//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsManager Windows 服务管理器
type WindowsManager struct {
	cfg *ServiceConfig
}

// NewWindowsManager 创建 Windows 管理器
func NewWindowsManager(cfg *ServiceConfig) *WindowsManager {
	return &WindowsManager{cfg: cfg}
}

// Install 安装服务
func (m *WindowsManager) Install() error {
	// 创建工作目录
	if err := os.MkdirAll(m.cfg.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}

	// 打开服务管理器
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败: %w", err)
	}
	defer manager.Disconnect()

	// 检查服务是否已存在
	s, err := manager.OpenService(m.cfg.Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("服务已存在")
	}

	// 创建服务
	s, err = manager.CreateService(m.cfg.Name, m.cfg.ExecPath,
		mgr.Config{
			DisplayName:  m.cfg.DisplayName,
			Description:  m.cfg.Description,
			StartType:    mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
		},
		"daemon",
	)
	if err != nil {
		return fmt.Errorf("创建服务失败: %w", err)
	}
	defer s.Close()

	// 设置恢复选项（失败后自动重启）
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(recoveryActions, 86400); err != nil {
		// 非致命错误，继续
	}

	return nil
}

// Uninstall 卸载服务
func (m *WindowsManager) Uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败: %w", err)
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		return nil // 服务不存在
	}
	defer s.Close()

	// 停止服务（记录日志但继续，服务可能已停止）
	if _, err := s.Control(svc.Stop); err != nil {
		// 停止失败不阻塞卸载，服务可能已停止
	}
	time.Sleep(time.Second)

	// 删除服务
	if err := s.Delete(); err != nil {
		return fmt.Errorf("删除服务失败: %w", err)
	}

	return nil
}

// Start 启动服务
func (m *WindowsManager) Start() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败: %w", err)
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		return fmt.Errorf("打开服务失败: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务失败: %w", err)
	}

	return nil
}

// Stop 停止服务
func (m *WindowsManager) Stop() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败: %w", err)
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		// 服务不存在视为已停止
		return nil
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("停止服务失败: %w", err)
	}
	return nil
}

// Restart 重启服务
func (m *WindowsManager) Restart() error {
	m.Stop()
	time.Sleep(time.Second)
	return m.Start()
}

// Status 获取服务状态
func (m *WindowsManager) Status() (*Status, error) {
	status := &Status{}

	manager, err := mgr.Connect()
	if err != nil {
		return status, nil
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		return status, nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return status, nil
	}

	status.Running = st.State == svc.Running

	cfg, err := s.Config()
	if err == nil {
		status.Enabled = cfg.StartType == mgr.StartAutomatic
	}

	return status, nil
}

// Enable 启用开机自启
func (m *WindowsManager) Enable() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败: %w", err)
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		return fmt.Errorf("打开服务失败: %w", err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("获取服务配置失败: %w", err)
	}

	cfg.StartType = mgr.StartAutomatic
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("更新服务配置失败: %w", err)
	}

	return nil
}

// Disable 禁用开机自启
func (m *WindowsManager) Disable() error {
	manager, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer manager.Disconnect()

	s, err := manager.OpenService(m.cfg.Name)
	if err != nil {
		return nil
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return nil
	}

	cfg.StartType = mgr.StartManual
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("更新服务配置失败: %w", err)
	}

	return nil
}

// IsWindowsService 检查是否以 Windows 服务方式运行
func IsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

// RunAsService 以 Windows 服务方式运行
func RunAsService(name string, handler func()) error {
	return svc.Run(name, &serviceHandler{handler: handler})
}

type serviceHandler struct {
	handler func()
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// 启动主逻辑
	done := make(chan struct{})
	go func() {
		h.handler()
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				// 等待 handler 完成（最多 30 秒），避免 goroutine 泄漏
				// handler 内部会响应 SIGINT/SIGTERM 信号
				select {
				case <-done:
					// handler 已完成
				case <-time.After(30 * time.Second):
					// 超时，强制退出
				}
				return
			}
		}
	}
}

// InstallWithSC 使用 sc.exe 安装服务（备用方案）
func (m *WindowsManager) InstallWithSC() error {
	// 创建工作目录
	if err := os.MkdirAll(m.cfg.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}

	// 使用 sc.exe 创建服务
	binPath := fmt.Sprintf(`"%s" daemon`, m.cfg.ExecPath)
	cmd := exec.Command("sc", "create", m.cfg.Name,
		"binPath="+binPath,
		"DisplayName="+m.cfg.DisplayName,
		"start=auto",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("创建服务失败: %w\n%s", err, output)
	}

	// 设置描述
	exec.Command("sc", "description", m.cfg.Name, m.cfg.Description).Run()

	// 设置失败后重启
	exec.Command("sc", "failure", m.cfg.Name, "reset=86400", "actions=restart/30000/restart/30000/restart/30000").Run()

	return nil
}

// UninstallWithSC 使用 sc.exe 卸载服务（备用方案）
func (m *WindowsManager) UninstallWithSC() error {
	exec.Command("sc", "stop", m.cfg.Name).Run()
	time.Sleep(time.Second)

	cmd := exec.Command("sc", "delete", m.cfg.Name)
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "1060") { // 服务不存在
			return fmt.Errorf("删除服务失败: %w\n%s", err, output)
		}
	}
	return nil
}
