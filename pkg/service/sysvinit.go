//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SysVinitManager SysVinit 服务管理器
type SysVinitManager struct {
	cfg *ServiceConfig
}

// NewSysVinitManager 创建 SysVinit 管理器
func NewSysVinitManager(cfg *ServiceConfig) *SysVinitManager {
	return &SysVinitManager{cfg: cfg}
}

func (m *SysVinitManager) servicePath() string {
	return fmt.Sprintf("/etc/init.d/%s", m.cfg.Name)
}

func (m *SysVinitManager) pidFile() string {
	return fmt.Sprintf("/var/run/%s.pid", m.cfg.Name)
}

func (m *SysVinitManager) serviceContent() string {
	return fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          %s
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: %s
# Description:       %s
### END INIT INFO

NAME="%s"
DAEMON="%s"
DAEMON_ARGS="daemon"
PIDFILE="%s"
WORKDIR="%s"

read_pid() {
    local pid=""
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        # 验证 PID 为纯数字（使用 case 模式匹配，更安全）
        if [ -n "$pid" ]; then
            case "$pid" in
                ''|*[!0-9]*) pid="" ;;
            esac
        fi
        if [ -n "$pid" ]; then
            echo "$pid"
        fi
    fi
}

start() {
    echo "Starting $NAME..."
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is already running"
        return 1
    fi
    cd "$WORKDIR"
    nohup "$DAEMON" $DAEMON_ARGS > /dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "$NAME started"
}

stop() {
    echo "Stopping $NAME..."
    if [ ! -f "$PIDFILE" ]; then
        echo "$NAME is not running"
        return 1
    fi
    local pid=$(read_pid)
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
}

status() {
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is running (PID: $pid)"
        return 0
    else
        echo "$NAME is not running"
        return 1
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 1
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
`, m.cfg.Name, m.cfg.DisplayName, m.cfg.Description,
		m.cfg.Name, m.cfg.ExecPath, m.pidFile(), m.cfg.WorkDir)
}

// Install 安装服务
func (m *SysVinitManager) Install() error {
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
func (m *SysVinitManager) Uninstall() error {
	_ = m.Stop()
	_ = m.Disable()

	if err := os.Remove(m.servicePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除服务脚本失败: %w", err)
	}

	return nil
}

// Start 启动服务
func (m *SysVinitManager) Start() error {
	cmd := exec.Command(m.servicePath(), "start")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("启动服务失败: %w\n%s", err, output)
	}
	return nil
}

// Stop 停止服务
func (m *SysVinitManager) Stop() error {
	_ = exec.Command(m.servicePath(), "stop").Run()
	return nil
}

// Restart 重启服务
func (m *SysVinitManager) Restart() error {
	cmd := exec.Command(m.servicePath(), "restart")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("重启服务失败: %w\n%s", err, output)
	}
	return nil
}

// Status 获取服务状态
func (m *SysVinitManager) Status() (*Status, error) {
	status := &Status{}

	// 检查是否运行中
	if exec.Command(m.servicePath(), "status").Run() == nil {
		status.Running = true
	}

	// 检查是否启用 (Debian/Ubuntu)
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		// 检查 /etc/rc2.d 中是否有启动链接
		links, _ := os.ReadDir("/etc/rc2.d")
		for _, link := range links {
			if strings.HasPrefix(link.Name(), "S") && strings.Contains(link.Name(), m.cfg.Name) {
				status.Enabled = true
				break
			}
		}
	}

	// 检查是否启用 (CentOS/RHEL)
	if _, err := exec.LookPath("chkconfig"); err == nil {
		output, _ := exec.Command("chkconfig", "--list", m.cfg.Name).Output()
		if strings.Contains(string(output), "3:on") {
			status.Enabled = true
		}
	}

	return status, nil
}

// Enable 启用开机自启
func (m *SysVinitManager) Enable() error {
	// Debian/Ubuntu
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		if err := exec.Command("update-rc.d", m.cfg.Name, "defaults").Run(); err != nil {
			return fmt.Errorf("启用服务失败: %w", err)
		}
		return nil
	}

	// CentOS/RHEL
	if _, err := exec.LookPath("chkconfig"); err == nil {
		if err := exec.Command("chkconfig", "--add", m.cfg.Name).Run(); err != nil {
			return fmt.Errorf("启用服务失败: %w", err)
		}
		if err := exec.Command("chkconfig", m.cfg.Name, "on").Run(); err != nil {
			return fmt.Errorf("启用服务失败: %w", err)
		}
		return nil
	}

	return fmt.Errorf("未找到服务管理工具")
}

// Disable 禁用开机自启
func (m *SysVinitManager) Disable() error {
	// Debian/Ubuntu
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		_ = exec.Command("update-rc.d", "-f", m.cfg.Name, "remove").Run()
		return nil
	}

	// CentOS/RHEL
	if _, err := exec.LookPath("chkconfig"); err == nil {
		_ = exec.Command("chkconfig", m.cfg.Name, "off").Run()
		_ = exec.Command("chkconfig", "--del", m.cfg.Name).Run()
		return nil
	}

	return nil
}
