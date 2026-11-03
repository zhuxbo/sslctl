package deployer

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRestartProcessLifecycle(t *testing.T) {
	failure := errors.New("probe failed")
	for _, tc := range []struct {
		name                                string
		stopErr, killErr                    error
		failProbe                           int
		alwaysRunning, auto, startErr, exit bool
		exe                                 string
		args, wantArgs                      []string
		want                                string
	}{
		{name: "relative", exe: "nginx.exe", want: "绝对路径"},
		{name: "stop query", stopErr: failure, want: "停止目标进程失败"},
		{name: "stop kill", killErr: failure, want: "停止目标进程失败"},
		{name: "exit query", failProbe: 2, want: "确认目标进程退出失败"},
		{name: "still running", alwaysRunning: true, want: "等待停止后仍运行"},
		{name: "recovery query", failProbe: 3, want: "确认目标进程恢复失败"},
		{name: "automatic", auto: true},
		{name: "manual nginx", args: []string{"-p", "instance", "-s", "reload"}, wantArgs: []string{"-p", "instance"}},
		{name: "manual apache", exe: "/apache/bin/httpd.exe", args: []string{"-k", "graceful"}, wantArgs: []string{"-d", "/apache"}},
		{name: "apache explicit root", exe: "/apache/bin/httpd.exe", args: []string{"-k", "graceful", "-d", "chosen"}, wantArgs: []string{"-d", "chosen"}},
		{name: "start failure", startErr: true, want: "重启失败"},
		{name: "start query", failProbe: 13, want: "确认目标进程启动失败"},
		{name: "start exited", exit: true, want: "进程启动后退出"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldList, oldKill, oldSleep, oldStart := listProcessIDsByExecutableFunc, terminateProcessByPIDFunc, restartSleep, restartDetached
			defer func() {
				listProcessIDsByExecutableFunc, terminateProcessByPIDFunc, restartSleep, restartDetached = oldList, oldKill, oldSleep, oldStart
			}()
			exe := tc.exe
			if exe == "" {
				exe = filepath.Join(t.TempDir(), "nginx.exe")
			}
			if strings.HasPrefix(exe, "/apache/") {
				root := t.TempDir()
				exe = filepath.Join(root, "bin", "httpd.exe")
				if tc.name == "manual apache" {
					tc.wantArgs = []string{"-d", root}
				}
			}
			wantCalls := 13
			var wantSleeps []time.Duration
			switch tc.name {
			case "relative":
				wantCalls = 0
			case "stop query", "stop kill":
				wantCalls = 1
			case "exit query":
				wantCalls = 2
				wantSleeps = []time.Duration{500 * time.Millisecond}
			case "still running":
				wantCalls = 21
				for range 20 {
					wantSleeps = append(wantSleeps, 500*time.Millisecond)
				}
			case "recovery query", "automatic":
				wantCalls = 3
				wantSleeps = []time.Duration{500 * time.Millisecond, time.Second}
			default:
				wantSleeps = []time.Duration{500 * time.Millisecond}
				for range 10 {
					wantSleeps = append(wantSleeps, time.Second)
				}
				if tc.startErr {
					wantCalls = 12
				} else {
					wantSleeps = append(wantSleeps, 2*time.Second)
				}
			}
			var sleeps []time.Duration
			calls, kills, starts := 0, 0, 0
			listProcessIDsByExecutableFunc = func(ctx context.Context, path string) ([]int, error) {
				calls++
				if calls > wantCalls {
					t.Fatalf("probe count exceeded %d", wantCalls)
				}
				if calls > 1 && len(sleeps) != calls-1 {
					t.Fatalf("probe %d without its preceding wait: %v", calls, sleeps)
				}
				if path != exe {
					t.Fatalf("wrong executable %q", path)
				}
				if calls == 1 {
					return []int{7}, tc.stopErr
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("probe has no deadline")
				}
				if calls == tc.failProbe {
					return nil, failure
				}
				if tc.alwaysRunning || (tc.auto && calls == 3) || (calls == 13 && !tc.exit) {
					return []int{7}, nil
				}
				return nil, nil
			}
			terminateProcessByPIDFunc = func(_ context.Context, pid int) error {
				kills++
				if pid != 7 {
					t.Fatalf("wrong pid %d", pid)
				}
				return tc.killErr
			}
			restartSleep = func(delay time.Duration) {
				if len(sleeps) >= len(wantSleeps) || delay != wantSleeps[len(sleeps)] {
					t.Fatalf("unexpected wait #%d: %s, want %v", len(sleeps)+1, delay, wantSleeps)
				}
				sleeps = append(sleeps, delay)
			}
			restartDetached = func(path string, args ...string) error {
				starts++
				if path != exe {
					t.Fatalf("wrong start %q", path)
				}
				if tc.wantArgs != nil && !reflect.DeepEqual(args, tc.wantArgs) {
					t.Fatalf("args %v want %v", args, tc.wantArgs)
				}
				if tc.startErr {
					return failure
				}
				return nil
			}
			err := restartProcessWindows(t.Context(), exe, tc.args, errors.New("reload denied"))
			if calls != wantCalls || !reflect.DeepEqual(sleeps, wantSleeps) {
				t.Fatalf("calls=%d want %d, waits=%v want %v", calls, wantCalls, sleeps, wantSleeps)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %s", err, tc.want)
			}
			if tc.stopErr != nil || tc.killErr != nil || tc.failProbe > 0 || tc.startErr {
				if !errors.Is(err, failure) {
					t.Fatalf("lost cause: %v", err)
				}
			}
			if tc.name == "relative" && (calls != 0 || kills != 0 || starts != 0) {
				t.Fatal("relative target reached process operations")
			}
			if tc.name == "automatic" && (starts != 0 || calls != 3) {
				t.Fatalf("auto calls=%d starts=%d", calls, starts)
			}
			if tc.want == "" && !tc.auto && (starts != 1 || calls != 13) {
				t.Fatalf("manual calls=%d starts=%d", calls, starts)
			}
			if tc.alwaysRunning && (calls != 21 || starts != 0) {
				t.Fatalf("stop boundary calls=%d starts=%d", calls, starts)
			}
		})
	}
}

func TestWindowsAbsolutePathBoundaries(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{{"", false}, {"C", false}, {"C:", false}, {`C:\`, true}, {"C:/", true}, {"C:x", false}, {"ab/", false}, {"abc", false}, {"nginx.exe", false}, {filepath.Join(t.TempDir(), "nginx.exe"), true}} {
		if got := isAbsoluteWindowsExecutablePath(tc.path); got != tc.want {
			t.Errorf("%q=%v", tc.path, got)
		}
	}
}

func TestRestartArgsPreserveTrailingSignalAndFollowingOptions(t *testing.T) {
	for _, tc := range []struct{ in, out []string }{
		{[]string{"-k", "graceful", "-d", "root"}, []string{"-d", "root"}},
		{[]string{"-s"}, []string{"-s"}},
		{[]string{"-k"}, []string{"-k"}},
		{[]string{"-s", "reload", "-k", "graceful", "-p", "root"}, []string{"-p", "root"}},
	} {
		if got := restartProcessArgs("", tc.in); !reflect.DeepEqual(got, tc.out) {
			t.Fatalf("%v => %v want %v", tc.in, got, tc.out)
		}
	}
	if containsCommandArg([]string{"-p", "root"}, "-d") || !containsCommandArg([]string{"-p", "root", "-d"}, "-d") {
		t.Fatal("argument matching failed")
	}
}

func TestReloadWindowsPropagatesRestartFailure(t *testing.T) {
	oldRun, oldList := reloadRunWithin, listProcessIDsByExecutableFunc
	defer func() { reloadRunWithin, listProcessIDsByExecutableFunc = oldRun, oldList }()
	denied := errors.New("Access is denied")
	cause := errors.New("enumeration denied")
	reloadRunWithin = func(context.Context, string) error { return denied }
	listProcessIDsByExecutableFunc = func(context.Context, string) ([]int, error) { return nil, cause }
	err := runReloadCommandWindows(t.Context(), `C:/nginx/nginx.exe -s reload`, errors.New("SCM failed"))
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "SCM failed") {
		t.Fatalf("lost failure: %v", err)
	}
}

func TestReloadWindowsCommandOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, command, message string
		wantRestart, success   bool
	}{
		{name: "command succeeds", command: "nginx -s reload", success: true},
		{name: "unrelated failure", command: "nginx -s reload", message: "configuration invalid"},
		{name: "empty command", message: "No installed service"},
		{name: "access fallback", command: "C:/nginx/nginx.exe -s reload", message: "Access is denied", wantRestart: true, success: true},
		{name: "service fallback", command: "C:/nginx/nginx.exe -s reload", message: "No installed service", wantRestart: true, success: true},
		{name: "log fallback", command: "C:/nginx/nginx.exe -s reload", message: "could not open error log", wantRestart: true, success: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldRun, oldList, oldKill, oldSleep := reloadRunWithin, listProcessIDsByExecutableFunc, terminateProcessByPIDFunc, restartSleep
			defer func() {
				reloadRunWithin, listProcessIDsByExecutableFunc, terminateProcessByPIDFunc, restartSleep = oldRun, oldList, oldKill, oldSleep
			}()
			var commandErr error
			if tc.message != "" {
				commandErr = errors.New(tc.message)
			}
			runs, probes, kills := 0, 0, 0
			reloadRunWithin = func(ctx context.Context, command string) error {
				runs++
				if ctx != t.Context() || command != tc.command {
					t.Fatalf("wrong reload command %q", command)
				}
				return commandErr
			}
			listProcessIDsByExecutableFunc = func(_ context.Context, path string) ([]int, error) {
				probes++
				if !tc.wantRestart || probes > 3 {
					t.Fatalf("unexpected probe #%d", probes)
				}
				if path != "C:/nginx/nginx.exe" {
					t.Fatalf("target %q", path)
				}
				if probes == 2 {
					return nil, nil
				}
				return []int{17}, nil
			}
			terminateProcessByPIDFunc = func(_ context.Context, pid int) error {
				kills++
				if pid != 17 || kills > 1 {
					t.Fatalf("unexpected termination %d", pid)
				}
				return nil
			}
			var sleeps []time.Duration
			restartSleep = func(delay time.Duration) {
				sleeps = append(sleeps, delay)
				if len(sleeps) > 2 {
					t.Fatal("unexpected fallback loop")
				}
			}
			err := runReloadCommandWindows(t.Context(), tc.command, errors.New("SCM failed"))
			if tc.success {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, commandErr) || !strings.Contains(err.Error(), "SCM failed") {
				t.Fatalf("lost command failure: %v", err)
			}
			if runs != 1 {
				t.Fatalf("runs=%d", runs)
			}
			if tc.wantRestart {
				if probes != 3 || kills != 1 || !reflect.DeepEqual(sleeps, []time.Duration{500 * time.Millisecond, time.Second}) {
					t.Fatalf("probes=%d kills=%d waits=%v", probes, kills, sleeps)
				}
			} else if probes != 0 || kills != 0 || len(sleeps) != 0 {
				t.Fatal("unexpected restart")
			}
		})
	}
}
