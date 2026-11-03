//go:build windows

package executor

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ListProcessIDsByExecutable 精确查询指定可执行路径对应的进程 PID。
func ListProcessIDsByExecutable(ctx context.Context, executable string) ([]int, error) {
	processName := strings.ToLower(filepath.Base(executable))
	if processName != "nginx.exe" && processName != "httpd.exe" {
		return nil, fmt.Errorf("unsupported managed process: %s", processName)
	}

	script := fmt.Sprintf(
		`[Console]::OutputEncoding = (New-Object System.Text.UTF8Encoding $false); Get-CimInstance Win32_Process -Filter "Name='%s'" | ForEach-Object { Write-Output ($_.ProcessId.ToString() + '|' + $_.ExecutablePath) }`,
		processName,
	)
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("query %s processes: %w: %s", processName, err, strings.TrimSpace(string(out)))
	}
	processes := parseWindowsProcessList(string(out))
	if hasUnknownExecutablePath(processes) {
		return nil, fmt.Errorf("cannot safely identify every running %s executable path", processName)
	}
	return processIDsForExecutable(processes, executable), nil
}

// TerminateProcessByPID 仅终止指定 PID，不按镜像名影响其他安装实例。
func TerminateProcessByPID(ctx context.Context, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid process id: %d", pid)
	}
	out, err := exec.CommandContext(ctx, "taskkill", "/F", "/PID", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("terminate process %d: %w: %s", pid, err, strings.TrimSpace(string(out)))
	}
	return nil
}
