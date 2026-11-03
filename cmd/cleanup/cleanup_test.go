package cleanup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRun_RequiresExactlyOneTarget(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing", args: nil},
		{name: "both", args: []string{"--site", "a.example.com", "--cert", "cert-a"}},
		{name: "positional", args: []string{"--site", "a.example.com", "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(tt.args, strings.NewReader(""), &output, &output, cm); err == nil {
				t.Fatal("run() error = nil, want target validation error")
			}
		})
	}
}

func TestRun_HelpIsSuccessful(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	var output bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run(--help) error = %v", err)
	}
	if !strings.Contains(output.String(), "sslctl cleanup --site") {
		t.Fatalf("help output = %q", output.String())
	}
}

func TestRun_ListShowsAllCertificatesAndSiteBindings(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.Save(&config.Config{Certificates: []config.CertConfig{
		{
			CertName: "enabled-cert",
			Enabled:  true,
			Bindings: []config.SiteBinding{
				{ServerName: "enabled.example.com", Enabled: true},
				{ServerName: "disabled.example.com", Enabled: false},
			},
		},
		{CertName: "disabled-cert", Enabled: false},
		{CertName: "enabled-cert", Enabled: true, Bindings: []config.SiteBinding{{ServerName: "duplicate.example.com", Enabled: true}}},
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--list"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run(--list) error = %v", err)
	}
	for _, want := range []string{
		"受管证书：3 条记录",
		"  - enabled-cert [启用]\n",
		"  - disabled-cert [禁用]\n",
		"受管站点绑定：3 条",
		"  - enabled.example.com -> enabled-cert [启用]\n",
		"  - disabled.example.com -> enabled-cert [禁用]\n",
		"  - duplicate.example.com -> enabled-cert [启用]\n",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output = %q, want %q", output.String(), want)
		}
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Certificates) != 3 {
		t.Fatalf("--list changed config: %+v", cfg.Certificates)
	}
}

func TestRun_ListMustBeUsedAlone(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	for _, args := range [][]string{
		{"--list", "--site", "a.example.com"},
		{"--list", "--cert", "cert-a"},
		{"--list", "--yes"},
	} {
		var output bytes.Buffer
		err := run(args, strings.NewReader(""), &output, &output, cm)
		if err == nil || !strings.Contains(err.Error(), "--list 必须单独使用") {
			t.Fatalf("run(%v) error = %v, want standalone list error", args, err)
		}
	}
}

func TestRun_DeclinedConfirmationPreservesManagementState(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{
		CertName: "keep-cert",
		Bindings: []config.SiteBinding{{ServerName: "keep.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--site", "keep.example.com"}, strings.NewReader("n\n"), &output, &output, cm); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("declined cleanup changed config: %v", err)
	}
	if !strings.Contains(output.String(), "已取消") {
		t.Fatalf("output = %q, want cancellation message", output.String())
	}
}

func TestRun_OutputFailureDoesNotStartCleanup(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{CertName: "keep-cert"}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	err = run([]string{"--cert", "keep-cert"}, strings.NewReader("y\n"), failingWriter{}, &bytes.Buffer{}, cm)
	if err == nil || !strings.Contains(err.Error(), "输出") {
		t.Fatalf("run() error = %v, want output failure", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("output failure changed config: %v", err)
	}
}

func TestRun_YesRemovesCertificateAndReportsPreservedFiles(t *testing.T) {
	workDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(workDir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{
		CertName: "remove-cert",
		Bindings: []config.SiteBinding{{ServerName: "remove.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	deployed := filepath.Join(cm.GetCertsDir(), "remove.example.com", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(deployed), 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(deployed, []byte("live"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var output bytes.Buffer
	if err := run([]string{"--cert", "remove-cert", "--yes"}, strings.NewReader(""), &output, &output, cm); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := cm.GetCert("remove-cert"); err == nil {
		t.Fatal("certificate config still exists")
	}
	if _, err := os.Stat(deployed); err != nil {
		t.Fatalf("deployed file was removed: %v", err)
	}
	for _, want := range []string{"已解除", "1 个站点绑定", "在线证书文件和 Web 配置已保留"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output = %q, want %q", output.String(), want)
		}
	}
}

func TestRun_RefusesCleanupWhileRenewalLockIsHeld(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&config.CertConfig{CertName: "keep-cert"}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	release, acquired, err := config.AcquireRenewalLock(cm.GetWorkDir())
	if err != nil || !acquired {
		t.Fatalf("AcquireRenewalLock() = acquired %v, err %v", acquired, err)
	}
	defer release()

	var output bytes.Buffer
	err = run([]string{"--cert", "keep-cert", "--yes"}, strings.NewReader(""), &output, &output, cm)
	if err == nil || !strings.Contains(err.Error(), "正在执行") {
		t.Fatalf("run() error = %v, want lock conflict", err)
	}
	if _, err := cm.GetCert("keep-cert"); err != nil {
		t.Fatalf("lock conflict changed config: %v", err)
	}
}

type failOnWrite struct {
	count, at int
	err       error
}

func (w *failOnWrite) Write(p []byte) (int, error) {
	w.count++
	if w.count == w.at {
		return 0, w.err
	}
	return len(p), nil
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func testManager(t *testing.T) *config.ConfigManager {
	t.Helper()
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := cm.AddCert(&config.CertConfig{CertName: "cert", Enabled: true, Bindings: []config.SiteBinding{{ServerName: "example.com", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	return cm
}

func TestRunConfirmationAndTrimmedTargets(t *testing.T) {
	for _, target := range []string{"--site", "--cert"} {
		for _, answer := range []string{" y\n", " YES \n", "yes"} {
			t.Run(target+answer, func(t *testing.T) {
				cm := testManager(t)
				name := "cert"
				kind := "证书"
				if target == "--site" {
					name = "example.com"
					kind = "站点"
				}
				var out bytes.Buffer
				if err := run([]string{target, " " + name + " "}, strings.NewReader(answer), &out, &out, cm); err != nil {
					t.Fatal(err)
				}
				if certs, err := cm.ListCerts(); err != nil || len(certs) != 0 {
					t.Fatalf("target retained: %v %v", certs, err)
				}
				if !strings.Contains(out.String(), "将解除"+kind+" "+name) || !strings.Contains(out.String(), "已解除"+kind+" "+name) {
					t.Fatalf("wrong target output: %q", out.String())
				}
			})
		}
	}
}

func TestRunUnknownFlagReportsParseError(t *testing.T) {
	cm := testManager(t)
	var out, errOut bytes.Buffer
	err := run([]string{"--cert", "cert", "--yes", "--unknown"}, strings.NewReader(""), &out, &errOut, cm)
	if err == nil || !strings.Contains(err.Error(), "unknown") || !strings.Contains(errOut.String(), "unknown") || out.Len() != 0 {
		t.Fatalf("err=%v stderr=%q stdout=%q", err, errOut.String(), out.String())
	}
	if _, err := cm.GetCert("cert"); err != nil {
		t.Fatalf("parse failure removed certificate: %v", err)
	}
}

func TestRunIOFailuresWrapOriginalError(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		answer  string
		at      int
		removed bool
	}{
		{"warning", []string{"--cert", "cert"}, "yes\n", 1, false},
		{"prompt", []string{"--cert", "cert"}, "yes\n", 2, false},
		{"cancel", []string{"--cert", "cert"}, "no\n", 3, false},
		{"summary", []string{"--cert", "cert", "--yes"}, "", 1, true},
		{"preserved", []string{"--cert", "cert", "--yes"}, "", 2, true},
		{"list-count", []string{"--list"}, "", 1, false},
		{"list-cert", []string{"--list"}, "", 2, false},
		{"list-bind-count", []string{"--list"}, "", 3, false},
		{"list-binding", []string{"--list"}, "", 4, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cm := testManager(t)
			sentinel := errors.New(tt.name)
			w := &failOnWrite{at: tt.at, err: sentinel}
			err := run(tt.args, strings.NewReader(tt.answer), w, &bytes.Buffer{}, cm)
			if !errors.Is(err, sentinel) {
				t.Fatalf("lost write error: %v", err)
			}
			certs, getErr := cm.ListCerts()
			if getErr != nil || (len(certs) == 0) != tt.removed {
				t.Fatalf("wrong cleanup state: %v %v", certs, getErr)
			}
		})
	}
	t.Run("read", func(t *testing.T) {
		cm := testManager(t)
		sentinel := errors.New("read failed")
		var out bytes.Buffer
		err := run([]string{"--cert", "cert"}, errorReader{sentinel}, &out, &out, cm)
		if !errors.Is(err, sentinel) {
			t.Fatalf("lost read error: %v", err)
		}
		if _, err := cm.GetCert("cert"); err != nil {
			t.Fatalf("read error removed cert: %v", err)
		}
	})
}

func TestRunLockAndListFilesystemErrors(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		cm := testManager(t)
		if err := os.Mkdir(filepath.Join(cm.GetWorkDir(), config.RenewalLockFile), 0700); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err := run([]string{"--cert", "cert", "--yes"}, strings.NewReader(""), &out, &out, cm)
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("lost lock error: %v", err)
		}
		if _, err := cm.GetCert("cert"); err != nil {
			t.Fatalf("lock error removed cert: %v", err)
		}
	})
	t.Run("list", func(t *testing.T) {
		cm := testManager(t)
		if err := os.Remove(cm.GetConfigPath()); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(cm.GetConfigPath(), 0700); err != nil {
			t.Fatal(err)
		}
		err := listManaged(&bytes.Buffer{}, cm)
		if err == nil || errors.Unwrap(err) == nil || !strings.Contains(err.Error(), "读取管理配置失败") {
			t.Fatalf("lost list error: %v", err)
		}
	})
}

func TestListEnabledCertificateCannotBeMaskedByAnotherRecord(t *testing.T) {
	cm := testManager(t)
	var out bytes.Buffer
	if err := listManaged(&out, cm); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  - cert [启用]\n", "  - example.com -> cert [启用]\n"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want exact record %q", out.String(), want)
		}
	}
}

func TestRunEntryExitAndDiagnostics(t *testing.T) {
	oldCheck, oldNew, oldExit := checkRootPrivilege, newConfigManager, exitProcess
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	t.Cleanup(func() {
		checkRootPrivilege, newConfigManager, exitProcess = oldCheck, oldNew, oldExit
		os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	})
	for _, stage := range []string{"root", "config", "command", "success"} {
		t.Run(stage, func(t *testing.T) {
			cm := testManager(t)
			sentinel := errors.New("failure-" + stage)
			initialized := false
			checkRootPrivilege = func() error {
				if stage == "root" {
					return sentinel
				}
				return nil
			}
			newConfigManager = func() (*config.ConfigManager, error) {
				initialized = true
				if stage == "config" {
					return nil, sentinel
				}
				return cm, nil
			}
			type exitSignal struct{ code int }
			exitProcess = func(code int) { panic(exitSignal{code}) }
			output, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			os.Stdout, os.Stderr = output, output
			code := -1
			func() {
				defer func() {
					if p := recover(); p != nil {
						if e, ok := p.(exitSignal); ok {
							code = e.code
						} else {
							panic(p)
						}
					}
				}()
				args := []string{"--list"}
				if stage == "command" {
					args = []string{"--unknown"}
				}
				Run(args)
			}()
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if stage == "success" {
				if code != -1 || !strings.Contains(string(data), "受管证书：1") {
					t.Fatalf("code=%d output=%s", code, data)
				}
			} else {
				want := sentinel.Error()
				if stage == "command" {
					want = "清理失败"
				}
				if code != 1 || !strings.Contains(string(data), want) {
					t.Fatalf("code=%d output=%s", code, data)
				}
			}
			if stage == "root" && initialized {
				t.Fatal("configuration initialized after privilege failure")
			}
		})
	}
}
