package deployer

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/webserver"
)

func TestRestartProcessArgsPreserveNginxPrefix(t *testing.T) {
	got := restartProcessArgs(`G:\soft\nginx-1.26.3\nginx.exe`, []string{
		"-p", `G:\soft\nginx-1.26.3\`, "-s", "reload",
	})
	want := []string{"-p", `G:\soft\nginx-1.26.3\`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restartProcessArgs() = %v, want %v", got, want)
	}
}

func TestStopExecutableProcessesTerminatesOnlyReturnedTargetPIDs(t *testing.T) {
	origList := listProcessIDsByExecutableFunc
	origTerminate := terminateProcessByPIDFunc
	defer func() {
		listProcessIDsByExecutableFunc = origList
		terminateProcessByPIDFunc = origTerminate
	}()

	listProcessIDsByExecutableFunc = func(context.Context, string) ([]int, error) {
		return []int{19856, 20100}, nil
	}
	var terminated []int
	terminateProcessByPIDFunc = func(_ context.Context, pid int) error {
		terminated = append(terminated, pid)
		return nil
	}

	if err := stopExecutableProcesses(t.Context(), `G:\soft\nginx-1.26.3\nginx.exe`); err != nil {
		t.Fatalf("stopExecutableProcesses() error = %v", err)
	}
	if want := []int{19856, 20100}; !reflect.DeepEqual(terminated, want) {
		t.Fatalf("terminated = %v, want %v", terminated, want)
	}
}

// TestReloadService_WinSvcSentinel 验证 ReloadService 识别 winsvc: 哨兵后
// 直接调用 restartWindowsServiceFunc，跳过 executor.Run。
func TestReloadService_WinSvcSentinel(t *testing.T) {
	called := ""
	orig := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(_ context.Context, name string) error {
		called = name
		return nil
	}
	defer func() { restartWindowsServiceFunc = orig }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx"}
	if err := b.ReloadService(context.Background()); err != nil {
		t.Fatalf("ReloadService 返回错误: %v", err)
	}
	if called != "nginx" {
		t.Fatalf("restartWindowsServiceFunc 收到的 name = %q, 期望 nginx", called)
	}
}

// TestReloadService_WinSvcSentinelError 验证服务重启失败、且无 fallback 时错误透传。
func TestReloadService_WinSvcSentinelError(t *testing.T) {
	wantErr := errors.New("scm boom")
	orig := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(_ context.Context, _ string) error { return wantErr }
	defer func() { restartWindowsServiceFunc = orig }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "Apache2.4"}
	err := b.ReloadService(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, 期望 wrap %v", err, wantErr)
	}
}

// TestReloadService_WinSvcFallbackSuccess 验证 SCM 失败但 fallback 命令成功时返回 nil。
func TestReloadService_WinSvcFallbackSuccess(t *testing.T) {
	origSvc := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(_ context.Context, _ string) error { return errors.New("scm failed") }
	defer func() { restartWindowsServiceFunc = origSvc }()

	origFallback := reloadFallbackCommandFunc
	var receivedCmd string
	var receivedPrev error
	reloadFallbackCommandFunc = func(_ context.Context, cmd string, prev error) error {
		receivedCmd = cmd
		receivedPrev = prev
		return nil
	}
	defer func() { reloadFallbackCommandFunc = origFallback }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx" + webserver.WinSvcFallbackSep + `C:\nginx\nginx.exe -s reload`}
	if err := b.ReloadService(context.Background()); err != nil {
		t.Fatalf("ReloadService 返回错误: %v", err)
	}
	if receivedCmd != `C:\nginx\nginx.exe -s reload` {
		t.Fatalf("fallback 命令 = %q, 期望 %q", receivedCmd, `C:\nginx\nginx.exe -s reload`)
	}
	if receivedPrev == nil || receivedPrev.Error() != "scm failed" {
		t.Fatalf("前置错误 = %v, 期望 scm failed", receivedPrev)
	}
}

// TestReloadService_WinSvcFallbackBothFail 验证 SCM 和 fallback 都失败时返回 fallback 错误，
// 且错误信息包含前置 SCM 错误以便排查。
func TestReloadService_WinSvcFallbackBothFail(t *testing.T) {
	origSvc := restartWindowsServiceFunc
	scmErr := errors.New("scm cannot find binary")
	restartWindowsServiceFunc = func(_ context.Context, _ string) error { return scmErr }
	defer func() { restartWindowsServiceFunc = origSvc }()

	origFallback := reloadFallbackCommandFunc
	fallbackErr := errors.New("nginx reload failed")
	reloadFallbackCommandFunc = func(_ context.Context, _ string, _ error) error {
		return fallbackErr
	}
	defer func() { reloadFallbackCommandFunc = origFallback }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx" + webserver.WinSvcFallbackSep + `nginx -s reload`}
	err := b.ReloadService(context.Background())
	if err == nil {
		t.Fatal("期望返回错误")
	}
	if !errors.Is(err, fallbackErr) {
		t.Errorf("err 应 wrap fallback 错误，实际 = %v", err)
	}
}

// TestReloadService_WinSvcOldFormatCompat 验证旧格式 winsvc:<name>（无 fallback）仍可正常工作。
func TestReloadService_WinSvcOldFormatCompat(t *testing.T) {
	called := ""
	orig := restartWindowsServiceFunc
	restartWindowsServiceFunc = func(_ context.Context, name string) error {
		called = name
		return nil
	}
	defer func() { restartWindowsServiceFunc = orig }()

	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "Apache2.4"}
	if err := b.ReloadService(context.Background()); err != nil {
		t.Fatalf("旧格式应可用: %v", err)
	}
	if called != "Apache2.4" {
		t.Fatalf("svcName = %q, 期望 Apache2.4", called)
	}
}

// TestParseWinSvcSentinel 验证哨兵串解析。
func TestParseWinSvcSentinel(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSvc string
		wantFB  string
	}{
		{"old format", "winsvc:nginx", "nginx", ""},
		{"new format", "winsvc:nginx|nginx -s reload", "nginx", "nginx -s reload"},
		{"path with backslash", `winsvc:Apache2.4|C:\Apache\bin\httpd.exe -k graceful`, "Apache2.4", `C:\Apache\bin\httpd.exe -k graceful`},
		{"empty fallback", "winsvc:nginx|", "nginx", ""},
		{"no service name", "winsvc:|nginx -s reload", "", "nginx -s reload"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, fb := parseWinSvcSentinel(c.input)
			if svc != c.wantSvc || fb != c.wantFB {
				t.Errorf("parseWinSvcSentinel(%q) = (%q, %q), want (%q, %q)",
					c.input, svc, fb, c.wantSvc, c.wantFB)
			}
		})
	}
}

// TestNeedsProcessRestart_WinSvc 验证 winsvc: 哨兵被视为「需要进程级重启」，
// 这样 setup 流程会提前向用户提示部署期间会有短暂中断。
func TestNeedsProcessRestart_WinSvc(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only relevant on windows")
	}
	b := &Base{ReloadCommand: webserver.WinSvcReloadPrefix + "nginx"}
	if !b.NeedsProcessRestart() {
		t.Fatalf("winsvc: 哨兵应被识别为需要进程重启")
	}
}

// TestReloadFallbackTriggers 在 Windows 下验证错误信息白名单：
// "Access is denied" 等错误会触发进程重启回退（而不是直接抛错）。
func TestReloadFallbackTriggers(t *testing.T) {
	cases := []struct {
		msg         string
		shouldRetry bool
	}{
		{"reload failed: No installed service", true},
		{"reload failed: could not open error log", true},
		{"OpenEvent(\"Global\\ngx_reload_8216\") failed (5: Access is denied)", true},
		{"some other unrelated error", false},
	}
	for _, c := range cases {
		got := strings.Contains(c.msg, "No installed service") ||
			strings.Contains(c.msg, "could not open error log") ||
			strings.Contains(c.msg, "Access is denied")
		if got != c.shouldRetry {
			t.Errorf("msg=%q got=%v want=%v", c.msg, got, c.shouldRetry)
		}
	}
}

func TestHasNewPID(t *testing.T) {
	tests := []struct {
		name   string
		before map[int]struct{}
		after  map[int]struct{}
		want   bool
	}{
		{"新 worker", map[int]struct{}{10: {}}, map[int]struct{}{10: {}, 11: {}}, true},
		{"原 generation 未变", map[int]struct{}{10: {}, 11: {}}, map[int]struct{}{10: {}, 11: {}}, false},
		{"旧 worker 退出但无新 worker", map[int]struct{}{10: {}, 11: {}}, map[int]struct{}{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasNewPID(tt.before, tt.after); got != tt.want {
				t.Fatalf("hasNewPID() = %v, want %v", got, tt.want)
			}
		})
	}
}
