package deployer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/util"
)

func TestPrepareCertificateBoundaries(t *testing.T) {
	t.Run("empty paths and directory mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "cert")
		b := &Base{}
		if err := b.PrepareFiles("", path); err != nil {
			t.Fatal(err)
		}
		if len(b.certificateFiles) != 1 || b.certificateFiles[path] == nil {
			t.Fatalf("wrong prepared paths: %v", b.certificateFiles)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Dir(path))
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatalf("directory mode: %v %v", info, err)
			}
		}
	})
	t.Run("directory failure", func(t *testing.T) {
		old := ensureCertificateDir
		t.Cleanup(func() { ensureCertificateDir = old })
		injected := errors.New("directory permission denied")
		ensureCertificateDir = func(string, os.FileMode) error { return injected }
		b := &Base{}
		if err := b.PrepareFiles(filepath.Join(t.TempDir(), "cert")); !errors.Is(err, injected) {
			t.Fatalf("error lost: %v", err)
		}
		if b.certificateFiles != nil {
			t.Fatal("partially initialized files")
		}
	})
	t.Run("invalid target", func(t *testing.T) {
		b := &Base{}
		path := filepath.Join(t.TempDir(), "cert")
		if err := os.Symlink("missing", path); err != nil {
			t.Skip(err)
		}
		if err := b.PrepareFiles(path); err == nil {
			t.Fatal("accepted dangling link")
		}
		if b.certificateFiles != nil {
			t.Fatal("partially initialized files")
		}
	})
	t.Run("duplicate target", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cert")
		b := &Base{}
		if err := b.PrepareFiles(path, path); err == nil || !strings.Contains(err.Error(), "同一目标") {
			t.Fatalf("duplicate target error: %v", err)
		}
		if b.certificateFiles != nil {
			t.Fatal("partially initialized files")
		}
	})
}

func TestCertificateWriteChecksEveryPinnedTarget(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := &Base{}
	if err := b.PrepareFiles(first, second); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("first", second); err != nil {
		t.Skip(err)
	}
	if err := b.PrepareFiles(first, second); err == nil {
		t.Fatal("reprepare accepted changed target")
	}
	if err := b.WriteCertificate(first, []byte("wrong"), 0600); err == nil {
		t.Fatal("write accepted changed peer")
	}
	got, err := os.ReadFile(first)
	if err != nil || string(got) != "original" {
		t.Fatalf("wrote after validation failure: %q %v", got, err)
	}
	old := restoreCertificateFileContext
	t.Cleanup(func() { restoreCertificateFileContext = old })
	calls := 0
	restoreCertificateFileContext = func(string) error { calls++; return nil }
	if err := b.RestoreCertificateContext(first); err == nil {
		t.Fatal("restore context accepted changed peer")
	}
	if calls != 0 {
		t.Fatal("restore context ran after validation failure")
	}
}

func TestCertificateWriteRequiresPreparedPath(t *testing.T) {
	if err := (&Base{}).WriteCertificate(filepath.Join(t.TempDir(), "cert"), []byte("bad"), 0600); err == nil || !strings.Contains(err.Error(), "未初始化") {
		t.Fatalf("missing initialization error: %v", err)
	}
}

func TestRestoreCertificateReadAndStatFailures(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(target, []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	b := &Base{}
	if err := b.PrepareFiles(target); err != nil {
		t.Fatal(err)
	}
	if err := b.RestoreCertificate(source, target); err == nil {
		t.Fatal("accepted missing backup")
	}
	if err := os.WriteFile(source, []byte("backup"), 0640); err != nil {
		t.Fatal(err)
	}
	linkedSource := filepath.Join(dir, "linked-backup")
	if err := os.Symlink("source", linkedSource); err != nil {
		t.Skip(err)
	}
	if err := b.RestoreCertificate(linkedSource, target); err == nil {
		t.Fatal("accepted symlink backup")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "current" {
		t.Fatalf("unsafe backup modified target: %q %v", got, err)
	}
	old := certificateStat
	t.Cleanup(func() { certificateStat = old })
	injected := errors.New("stat failed after read")
	certificateStat = func(string) (os.FileInfo, error) { return nil, injected }
	if err := b.RestoreCertificate(source, target); !errors.Is(err, injected) {
		t.Fatalf("stat error lost: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "current" {
		t.Fatalf("failed backup modified target: %q %v", got, err)
	}
	certificateStat = old
	if err := b.RestoreCertificate(source, target); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(target)
	if err != nil || string(got) != "backup" {
		t.Fatalf("restored bytes: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil || info.Mode().Perm() != 0640 {
			t.Fatalf("restored permissions: %v %v", info, err)
		}
	}
}

func TestRestoreCertificateSizeLimit(t *testing.T) {
	for _, size := range []int{16 << 20, (16 << 20) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "backup")
			target := filepath.Join(dir, "target")
			data := bytes.Repeat([]byte("x"), size)
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			b := &Base{}
			if err := b.PrepareFiles(target); err != nil {
				t.Fatal(err)
			}
			err := b.RestoreCertificate(source, target)
			if size == 16<<20 {
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatal("restore truncated backup")
				}
			} else {
				if err == nil {
					t.Fatal("accepted oversized backup")
				}
				if _, err := os.Stat(target); !os.IsNotExist(err) {
					t.Fatal("oversized backup modified target")
				}
			}
		})
	}
}

func TestRestoreContextUsesResolvedTargetAndReturnsFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Skip(err)
	}
	b := &Base{}
	if err := b.PrepareFiles(link); err != nil {
		t.Fatal(err)
	}
	old := restoreCertificateFileContext
	t.Cleanup(func() { restoreCertificateFileContext = old })
	injected := errors.New("restorecon denied")
	calls := 0
	restoreCertificateFileContext = func(path string) error {
		calls++
		if path != b.certificateFiles[link].Target {
			t.Fatalf("unresolved context path: %s", path)
		}
		return injected
	}
	if err := b.RestoreCertificateContext(link); !errors.Is(err, injected) {
		t.Fatalf("context error lost: %v", err)
	}
	if calls != 1 {
		t.Fatalf("context calls: %d", calls)
	}
}

func TestTargetChecksStopCommandsBeforeAndAfterConfigTest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command fixture")
	}
	for _, rollback := range []bool{false, true} {
		for _, changeAt := range []string{"before-test", "during-test"} {
			t.Run(fmt.Sprintf("rollback=%v/%s", rollback, changeAt), func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "target")
				link := filepath.Join(dir, "link")
				marker := filepath.Join(dir, "commands")
				for _, path := range []string{target, filepath.Join(dir, "renewed")} {
					if err := os.WriteFile(path, []byte("cert"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("target", link); err != nil {
					t.Skip(err)
				}
				script := "#!/bin/sh\necho $1 >> " + util.ShellQuote(marker) + "\nif [ \"$1\" = '-t' ]; then\nrm " + util.ShellQuote(link) + "\nln -s renewed " + util.ShellQuote(link) + "\nfi\n"
				if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
				b := &Base{TestCommand: "nginx -t", ReloadCommand: "nginx -s reload"}
				if err := b.PrepareFiles(link); err != nil {
					t.Fatal(err)
				}
				if changeAt == "before-test" {
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("renewed", link); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if rollback {
					err = b.TestAndReloadForRollback(t.Context())
				} else {
					err = b.TestAndReload(t.Context())
				}
				if err == nil {
					t.Fatal("changed target accepted")
				}
				got, readErr := os.ReadFile(marker)
				if changeAt == "before-test" {
					if !os.IsNotExist(readErr) {
						t.Fatalf("test executed after failed check: %q %v", got, readErr)
					}
				} else if readErr != nil || string(got) != "-t\n" {
					t.Fatalf("reload executed after failed check: %q %v", got, readErr)
				}
			})
		}
	}
}
