package scanner

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func isolateScanSystem(t *testing.T) {
	t.Helper()
	old := scanSystem
	t.Cleanup(func() { scanSystem = old })
	scanSystem.goos = "linux"
	scanSystem.findBinary = func() string { return "/selected/nginx" }
	scanSystem.runScan = func(string, ...string) ([]byte, error) { return []byte("unavailable"), errors.New("unavailable") }
	scanSystem.runOutput = func(string) ([]byte, error) { return nil, errors.New("unavailable") }
	scanSystem.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	scanSystem.commandOutput = func(*exec.Cmd) ([]byte, error) { t.Fatal("unexpected process query"); return nil, nil }
}

func TestScannerKeepsDetectedExecutable(t *testing.T) {
	isolateScanSystem(t)
	s := New()
	if s.ExecutablePath() != "" {
		t.Fatal("new scanner already bound")
	}
	if got := s.ensureExecutablePath(); got != "/selected/nginx" {
		t.Fatalf("detected %q", got)
	}
	scanSystem.findBinary = func() string { t.Fatal("bound scanner must not redetect"); return "" }
	if got := s.ensureExecutablePath(); got != "/selected/nginx" {
		t.Fatalf("bound %q", got)
	}
	if got := s.ExecutablePath(); got != "/selected/nginx" {
		t.Fatalf("accessor %q", got)
	}
}

func TestDetectNginxUsesSelectedInstance(t *testing.T) {
	for _, source := range []string{"test", "version", "windows", "missing", "unknown"} {
		t.Run(source, func(t *testing.T) {
			isolateScanSystem(t)
			scanSystem.goos = "windows"
			executable := `G:\apps\nginx.exe`
			want := `G:\apps\conf\nginx.conf`
			scanSystem.runScan = func(path string, args ...string) ([]byte, error) {
				if path != executable {
					t.Fatalf("wrong executable %q", path)
				}
				if source == "test" && args[len(args)-1] == "-t" {
					return []byte("nginx: the configuration file " + want + " syntax is ok"), nil
				}
				if source == "test" && args[0] == "-V" {
					t.Fatal("successful -t must stop detection")
				}
				if source == "version" && args[0] == "-V" {
					return []byte("--conf-path=" + want), nil
				}
				return []byte("unavailable"), errors.New("unavailable")
			}
			var checked []string
			scanSystem.stat = func(path string) (os.FileInfo, error) {
				checked = append(checked, path)
				if path == want && source != "missing" {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
			if source == "unknown" {
				executable = "nginx"
			}
			got, err := detectNginxFor(executable)
			if source == "missing" {
				if err == nil || !strings.Contains(err.Error(), want) || got != "" {
					t.Fatalf("missing: %q, %v", got, err)
				}
				if !reflect.DeepEqual(checked, []string{want}) {
					t.Fatalf("cross-instance fallback: %v", checked)
				}
				return
			}
			if source == "unknown" {
				if err == nil {
					t.Fatal("unknown instance succeeded")
				}
				return
			}
			if len(checked) != 1 {
				t.Fatalf("unexpected repeated/fallback stat: %v", checked)
			}
			if got != want || err != nil {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestWindowsConfigExecutableBoundaries(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{`C:\nginx.exe`, ""}, {`abc\nginx.exe`, `abc\conf\nginx.conf`}, {`nginx.exe`, ""}, {`G:\apps\other.exe`, ""}, {` G:/apps/NGINX.EXE `, `G:\apps\conf\nginx.conf`},
	} {
		if got := windowsConfigPathForExecutable(tt.in); got != tt.want {
			t.Errorf("%q: %q want %q", tt.in, got, tt.want)
		}
	}
}

func TestRelativeWebrootUsesSelectedOrDetectedExecutable(t *testing.T) {
	for _, bound := range []bool{false, true} {
		for _, all := range []bool{false, true} {
			t.Run(map[bool]string{true: "bound", false: "detected"}[bound]+map[bool]string{true: "All", false: "SSL"}[all], func(t *testing.T) {
				isolateScanSystem(t)
				root := t.TempDir()
				configPath := filepath.Join(root, "nginx.conf")
				if err := os.WriteFile(configPath, []byte("server {\n listen 443 ssl;\n server_name example.com;\n ssl_certificate cert.pem;\n ssl_certificate_key key.pem;\n root html;\n }"), 0600); err != nil {
					t.Fatal(err)
				}
				s := NewWithConfig(configPath)
				expected := "/selected/nginx"
				if bound {
					s.executablePath = "/bound/nginx"
					expected = s.executablePath
					scanSystem.findBinary = func() string { t.Fatal("bound instance rediscovered"); return "" }
				}
				scanSystem.runScan = func(path string, args ...string) ([]byte, error) {
					if path != expected || !reflect.DeepEqual(args, []string{"-V"}) {
						t.Fatalf("wrong probe %q %v", path, args)
					}
					return []byte("--prefix=" + root), nil
				}
				if all {
					sites, err := s.resolveSitePaths([]*Site{{Webroot: "html"}})
					if err != nil || sites[0].Webroot != filepath.Join(root, "html") {
						t.Fatalf("sites=%+v err=%v", sites, err)
					}
				} else {
					sites, err := s.Scan()
					if err != nil || len(sites) != 1 || sites[0].Webroot != filepath.Join(root, "html") {
						t.Fatalf("sites=%+v err=%v", sites, err)
					}
				}
			})
		}
	}
}

func TestWindowsProcessPrefixUsesExactExecutable(t *testing.T) {
	isolateScanSystem(t)
	scanSystem.goos = "windows"
	executable := `G:\apps\nginx.exe`
	scanSystem.commandOutput = func(cmd *exec.Cmd) ([]byte, error) {
		if cmd.Args[len(cmd.Args)-1] != executable || !strings.Contains(strings.Join(cmd.Args, " "), "ExecutablePath.Equals($args[0]") {
			t.Fatalf("unscoped query %v", cmd.Args)
		}
		return []byte(`nginx.exe -p "G:\runtime\"`), nil
	}
	prefix, candidates, ok := getNginxPrefix(executable)
	if prefix != `G:\runtime\` || candidates != nil || !ok {
		t.Fatalf("%q %v %v", prefix, candidates, ok)
	}
	scanSystem.commandOutput = func(*exec.Cmd) ([]byte, error) { t.Fatal("empty executable must not query processes"); return nil, nil }
	if got := getPrefixFromProcessCmdline(""); got != "" {
		t.Fatalf("empty instance prefix %q", got)
	}
}

func TestConfigDetectionCommandFallbacks(t *testing.T) {
	for _, kind := range []string{"test", "version"} {
		for _, selected := range []string{"", "/selected/nginx"} {
			t.Run(kind+selected, func(t *testing.T) {
				isolateScanSystem(t)
				want := filepath.Join(t.TempDir(), "nginx.conf")
				scanSystem.runScan = func(string, ...string) ([]byte, error) { return nil, errors.New("selected command unavailable") }
				calls := 0
				scanSystem.runOutput = func(command string) ([]byte, error) {
					calls++
					if kind == "test" {
						if command != "nginx -t" {
							t.Fatalf("command %q", command)
						}
						return []byte("nginx: the configuration file " + want + " syntax is ok"), nil
					}
					if command != "nginx -V" {
						t.Fatalf("command %q", command)
					}
					return []byte("--conf-path=" + want), nil
				}
				scanSystem.stat = func(path string) (os.FileInfo, error) {
					if path != want {
						t.Fatalf("wrong path %q", path)
					}
					return nil, nil
				}
				var got string
				var err error
				if kind == "test" {
					got, err = getNginxConfigFromTestFor(selected)
				} else {
					got, err = getNginxConfigFromVersionFor(selected)
				}
				if got != want || err != nil || calls != 1 {
					t.Fatalf("got %q, %v, calls %d", got, err, calls)
				}
			})
		}
	}
}

func TestVersionConfigPrefixRequiresExistingFile(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[exists], func(t *testing.T) {
			isolateScanSystem(t)
			prefix := t.TempDir()
			want := filepath.Join(prefix, "conf", "nginx.conf")
			scanSystem.runScan = func(string, ...string) ([]byte, error) { return []byte("--prefix=" + prefix), nil }
			calls := 0
			scanSystem.stat = func(path string) (os.FileInfo, error) {
				calls++
				if path != want {
					t.Fatalf("wrong configuration path %q", path)
				}
				if exists {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
			got, err := getNginxConfigFromVersionFor("/selected/nginx")
			if calls != 1 {
				t.Fatalf("stat calls %d", calls)
			}
			if exists {
				if got != want || err != nil {
					t.Fatalf("got %q, %v", got, err)
				}
			} else if got != "" || err == nil {
				t.Fatalf("missing config: %q, %v", got, err)
			}
		})
	}
}

func TestDetectNginxCommonPathFallback(t *testing.T) {
	isolateScanSystem(t)
	paths := getCommonNginxPaths()
	want := paths[1]
	var checked []string
	scanSystem.stat = func(path string) (os.FileInfo, error) {
		checked = append(checked, path)
		if path == want {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	got, err := detectNginxFor("/selected/nginx")
	if got != want || err != nil || !reflect.DeepEqual(checked, paths[:2]) {
		t.Fatalf("got %q, %v; checked %v", got, err, checked)
	}
}

func TestPrefixVersionCommandFallback(t *testing.T) {
	isolateScanSystem(t)
	want := t.TempDir()
	scanSystem.runScan = func(string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
	calls := 0
	scanSystem.runOutput = func(command string) ([]byte, error) {
		calls++
		if command != "nginx -V" {
			t.Fatalf("command %q", command)
		}
		return []byte("--prefix=" + want), nil
	}
	if got := getPrefixFromVersion("/selected/nginx"); got != want || calls != 1 {
		t.Fatalf("prefix %q, calls %d", got, calls)
	}
}

func TestNonWindowsPrefixFailureDoesNotProbeWindows(t *testing.T) {
	isolateScanSystem(t)
	// 使用当前平台绝对路径，若错误进入 Windows 启发式会返回候选列表。
	executable := filepath.Join(t.TempDir(), "nginx")
	prefix, candidates, ok := getNginxPrefix(executable)
	if prefix != "" || candidates != nil || ok {
		t.Fatalf("prefix %q, candidates %v, ok %v", prefix, candidates, ok)
	}
	if got := getPrefixFromProcessCmdline(executable); got != "" {
		t.Fatalf("non-Windows process prefix %q", got)
	}
}
