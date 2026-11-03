//go:build windows

package webserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// FindWebServerService 在 Windows 服务管理器中查找一个可用的 nginx/apache 服务。
//
// 匹配规则（按顺序全部满足才算命中）：
//  1. 服务名或 BinaryPathName（小写）包含 matchSubstr。
//  2. BinaryPathName 解析出的 exe 文件存在于磁盘（防止旧服务卸载后只留注册项）。
//  3. 若 processName 非空且当前有同名进程在运行，进程 ExecutablePath 必须与服务
//     BinaryPath 指向同一可执行文件（防止把"系统里有这名服务"等同于"用户实际跑的就是它"，
//     例如宝塔面板装过 nginx 服务但用户用 `start nginx` 跑的是另一个 binary 的情况）。
//
// 命中时返回服务名，未命中或出错时返回 ""。
func FindWebServerService(matchSubstr, processName string) string {
	if matchSubstr == "" {
		return ""
	}
	needle := strings.ToLower(matchSubstr)

	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer func() { _ = m.Disconnect() }()

	names, err := m.ListServices()
	if err != nil {
		return ""
	}

	// 优先精确名匹配（性能 + 稳定）：常见服务名直接命中即可返回
	lowerNames := make(map[string]string, len(names))
	for _, n := range names {
		lowerNames[strings.ToLower(n)] = n
	}
	if exact, ok := lowerNames[needle]; ok {
		if isServiceMatching(m, exact, needle, processName) {
			return exact
		}
	}

	// 其次扫描所有服务的 BinaryPathName
	for _, name := range names {
		if isServiceMatching(m, name, needle, processName) {
			return name
		}
	}
	return ""
}

// FindWebServerServiceForExecutable 只返回 BinaryPath 精确指向 executable 的服务。
// 多套同名 Web 服务器共存时，不能仅凭服务名或任一同名运行进程判定。
func FindWebServerServiceForExecutable(matchSubstr, executable string) string {
	if matchSubstr == "" || executable == "" {
		return ""
	}
	needle := strings.ToLower(matchSubstr)
	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer func() { _ = m.Disconnect() }()

	names, err := m.ListServices()
	if err != nil {
		return ""
	}
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		cfg, cfgErr := s.Config()
		_ = s.Close()
		if cfgErr != nil {
			continue
		}
		if !strings.Contains(strings.ToLower(name), needle) &&
			!strings.Contains(strings.ToLower(cfg.BinaryPathName), needle) {
			continue
		}
		serviceExe := extractServiceExePath(cfg.BinaryPathName)
		if serviceExecutableMatchesTarget(serviceExe, executable) {
			return name
		}
	}
	return ""
}

// isServiceMatching 打开服务并判断：
//   - BinaryPathName 是否包含 needle（小写）
//   - BinaryPath 指向的 exe 文件是否存在
//   - 若 processName 非空，是否与当前运行的同名进程路径一致
func isServiceMatching(m *mgr.Mgr, name, needle, processName string) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	defer func() { _ = s.Close() }()
	cfg, err := s.Config()
	if err != nil {
		return false
	}
	if !strings.Contains(strings.ToLower(cfg.BinaryPathName), needle) {
		return false
	}
	exe := extractServiceExePath(cfg.BinaryPathName)
	if exe == "" {
		return false
	}
	if _, err := os.Stat(exe); err != nil {
		return false
	}
	if processName != "" && !runningProcessMatchesService(processName, exe) {
		return false
	}
	return true
}

// runningProcessMatchesService 判断当前运行的 processName 进程是否由 svcExe 启动。
//
//   - 没有同名运行进程：返回 true（不能据此排除该服务，可能服务还没启动）
//   - 有同名运行进程：必须任一进程的 ExecutablePath 与 svcExe 规范化后一致才返回 true
//
// 用于避免 detector 把"系统里曾经装过的服务"等同于"用户实际跑的进程"。
func runningProcessMatchesService(processName, svcExe string) bool {
	paths := listRunningProcessPaths(processName)
	if len(paths) == 0 {
		return true
	}
	target := normalizeWindowsPath(svcExe)
	if target == "" {
		return false
	}
	for _, p := range paths {
		if normalizeWindowsPath(p) == target {
			return true
		}
	}
	return false
}

// listRunningProcessPaths 通过 wmic 列出指定进程名的所有 ExecutablePath。
// 查询失败或无结果返回 nil。
func listRunningProcessPaths(processName string) []string {
	if processName == "" {
		return nil
	}
	cmd := exec.Command("wmic", "process", "where",
		fmt.Sprintf("name='%s'", processName), "get", "ExecutablePath")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "ExecutablePath") {
			continue
		}
		paths = append(paths, line)
	}
	return paths
}

// RestartWindowsService 通过 SCM 重启指定服务：先 Stop 并轮询至 Stopped，再 Start。
//
// 等待 Stopped 最多 30 秒，避免 wrapper（如 nginxservice.exe）回收 nginx master 较慢
// 时直接 Start 失败。若服务原本已停止则跳过停止步骤，直接尝试启动。
func RestartWindowsService(ctx context.Context, name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer func() { _ = s.Close() }()

	// 查询当前状态
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %q: %w", name, err)
	}

	// 若不是 Stopped，则发送 Stop 并轮询
	if st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			// 再次查询，可能恰好已停止
			if st2, qErr := s.Query(); qErr == nil && st2.State == svc.Stopped {
				// fall through to start
			} else {
				return fmt.Errorf("stop service %q: %w", name, err)
			}
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			st, err = s.Query()
			if err != nil {
				return fmt.Errorf("query service %q during stop: %w", name, err)
			}
			if st.State == svc.Stopped {
				break
			}
			// 关停信号必须能中断这段最长 30s 的轮询，否则 daemon 的强杀窗口被它撑满
			select {
			case <-ctx.Done():
				return fmt.Errorf("stop service %q aborted: %w", name, ctx.Err())
			case <-time.After(500 * time.Millisecond):
			}
		}
		if st.State != svc.Stopped {
			return fmt.Errorf("service %q did not stop within 30s (state=%d)", name, st.State)
		}
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", name, err)
	}
	return nil
}
