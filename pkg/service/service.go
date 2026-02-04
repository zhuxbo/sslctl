// Package service 跨平台服务管理
package service

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
)

// serviceNameRegex 服务名格式校验正则：只允许字母、数字、连字符、下划线
var serviceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// InitSystem init 系统类型
type InitSystem string

const (
	InitSystemd  InitSystem = "systemd"
	InitOpenRC   InitSystem = "openrc"
	InitSysVinit InitSystem = "sysvinit"
	InitWindows  InitSystem = "windows"
	InitUnknown  InitSystem = "unknown"
)

// Status 服务状态
type Status struct {
	Running bool
	Enabled bool
}

// Manager 服务管理接口
type Manager interface {
	// Install 安装服务
	Install() error
	// Uninstall 卸载服务
	Uninstall() error
	// Start 启动服务
	Start() error
	// Stop 停止服务
	Stop() error
	// Restart 重启服务
	Restart() error
	// Status 获取服务状态
	Status() (*Status, error)
	// Enable 启用开机自启
	Enable() error
	// Disable 禁用开机自启
	Disable() error
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Name        string // 服务名称
	DisplayName string // 显示名称
	Description string // 描述
	ExecPath    string // 可执行文件路径
	WorkDir     string // 工作目录
}

// DefaultConfig 默认服务配置
func DefaultConfig() *ServiceConfig {
	execPath := "/usr/local/bin/sslctl"
	if runtime.GOOS == "windows" {
		execPath = `C:\Program Files\sslctl\sslctl.exe`
	}

	workDir := "/opt/sslctl"
	if runtime.GOOS == "windows" {
		workDir = `C:\ProgramData\sslctl`
	}

	return &ServiceConfig{
		Name:        "sslctl",
		DisplayName: "SSL Certificate Manager",
		Description: "SSL 证书自动部署服务",
		ExecPath:    execPath,
		WorkDir:     workDir,
	}
}

// Detect 检测当前系统的 init 系统类型
func Detect() InitSystem {
	if runtime.GOOS == "windows" {
		return InitWindows
	}

	// 检测 systemd（检查目录存在即可，is-system-running 在 degraded 状态会返回错误）
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return InitSystemd
	}

	// 检测 OpenRC
	if _, err := exec.LookPath("rc-service"); err == nil {
		return InitOpenRC
	}
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		return InitOpenRC
	}

	// 检测 SysVinit
	if _, err := os.Stat("/etc/init.d"); err == nil {
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			return InitSysVinit
		}
		if _, err := exec.LookPath("chkconfig"); err == nil {
			return InitSysVinit
		}
		// 如果有 /etc/init.d 但没有管理工具，也认为是 sysvinit
		return InitSysVinit
	}

	return InitUnknown
}

// New 根据当前系统创建服务管理器
func New(cfg *ServiceConfig) (Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 服务名格式校验（防御深度：防止命令注入）
	if !serviceNameRegex.MatchString(cfg.Name) {
		return nil, fmt.Errorf("服务名格式无效（只允许字母、数字、连字符、下划线）: %s", cfg.Name)
	}
	if len(cfg.Name) > 64 {
		return nil, fmt.Errorf("服务名过长（最大 64 字符）: %d", len(cfg.Name))
	}

	initSys := Detect()

	switch initSys {
	case InitSystemd:
		return NewSystemdManager(cfg), nil
	case InitOpenRC:
		return NewOpenRCManager(cfg), nil
	case InitSysVinit:
		return NewSysVinitManager(cfg), nil
	case InitWindows:
		return NewWindowsManager(cfg), nil
	default:
		return nil, fmt.Errorf("不支持的 init 系统")
	}
}

// GetInitSystemName 获取 init 系统名称
func GetInitSystemName() string {
	switch Detect() {
	case InitSystemd:
		return "systemd"
	case InitOpenRC:
		return "OpenRC"
	case InitSysVinit:
		return "SysVinit"
	case InitWindows:
		return "Windows Service"
	default:
		return "未知"
	}
}
