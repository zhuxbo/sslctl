package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/util"
)

func backupFixture(t *testing.T) (*Manager, []string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "cert"), filepath.Join(dir, "key"), filepath.Join(dir, "chain")}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("old-"+filepath.Base(p)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return NewManager(filepath.Join(dir, "backups"), 5), paths
}

func preserveBackupIO(t *testing.T) {
	t.Helper()
	hash, copyFile, read, stat := backupFileHash, backupCopyFile, restoreReadFile, restoreFileStat
	t.Cleanup(func() { backupFileHash, backupCopyFile, restoreReadFile, restoreFileStat = hash, copyFile, read, stat })
}

func requireBackupFailure(t *testing.T, m *Manager, paths []string, message string, cause error) {
	t.Helper()
	result, err := m.Backup("site", paths[0], paths[1], nil, paths[2])
	if result != nil || err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("backup = %+v, %v; want %s", result, err, message)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("error chain lost: %v", err)
	}
	backups, err := m.ListBackups("site")
	if err != nil || len(backups) != 0 {
		t.Fatalf("invalid backup retained: %v, %v", backups, err)
	}
}

func TestBackupChainFailureCleanup(t *testing.T) {
	for _, phase := range []string{"initial hash", "copy", "recheck error", "recheck mismatch"} {
		t.Run(phase, func(t *testing.T) {
			m, p := backupFixture(t)
			preserveBackupIO(t)
			fault := errors.New("chain I/O fault")
			calls := 0
			backupFileHash = func(path string) (string, error) {
				hash, err := computeFileHash(path)
				if path == p[2] {
					calls++
					if phase == "initial hash" && calls == 1 || phase == "recheck error" && calls == 2 {
						return hash, fault
					}
					if phase == "recheck mismatch" && calls == 2 {
						return "changed", nil
					}
				}
				return hash, err
			}
			backupCopyFile = func(src, dst string) error {
				if src == p[2] && phase == "copy" {
					return fault
				}
				return util.CopyFile(src, dst)
			}
			message := "备份证书链失败"
			cause := fault
			if strings.HasPrefix(phase, "recheck") {
				message = "证书链在备份期间发生变化: " + p[2]
				cause = nil
			}
			requireBackupFailure(t, m, p, message, cause)
		})
	}
}

func TestBackupVerifiesEverySavedFile(t *testing.T) {
	for index, name := range []string{"cert.pem", "key.pem", "chain.pem"} {
		for _, faultKind := range []string{"corrupt copy", "source hash error", "copy hash error"} {
			t.Run(name+"/"+faultKind, func(t *testing.T) {
				m, p := backupFixture(t)
				preserveBackupIO(t)
				calls := 0
				fault := errors.New("verification I/O fault")
				backupCopyFile = func(src, dst string) error {
					if err := util.CopyFile(src, dst); err != nil {
						return err
					}
					if filepath.Base(dst) == name && faultKind == "corrupt copy" {
						return os.WriteFile(dst, []byte("tampered"), 0600)
					}
					return nil
				}
				backupFileHash = func(path string) (string, error) {
					hash, err := computeFileHash(path)
					if path == p[index] {
						calls++
						if calls == 3 && faultKind == "source hash error" {
							return hash, fault
						}
					}
					if filepath.Base(path) == name && faultKind == "copy hash error" {
						return hash, fault
					}
					return hash, err
				}
				requireBackupFailure(t, m, p, "备份内容校验失败: "+p[index], nil)
			})
		}
	}
}

func TestBackupRejectsLinkRetargetDuringCopy(t *testing.T) {
	m, p := backupFixture(t)
	preserveBackupIO(t)
	link := p[0] + "-link"
	if err := os.Symlink(p[0], link); err != nil {
		t.Skip(err)
	}
	replacement := p[0] + "-new"
	if err := os.WriteFile(replacement, []byte("old-cert"), 0600); err != nil {
		t.Fatal(err)
	}
	backupCopyFile = func(src, dst string) error {
		if err := util.CopyFile(src, dst); err != nil {
			return err
		}
		if src == p[2] {
			if err := os.Remove(link); err != nil {
				return err
			}
			return os.Symlink(replacement, link)
		}
		return nil
	}
	p[0] = link
	requireBackupFailure(t, m, p, "证书路径在操作期间发生变化", nil)
}

func TestBackupResolveErrorsRetainCause(t *testing.T) {
	for index, label := range []string{"certificate", "private key"} {
		t.Run(label, func(t *testing.T) {
			m, p := backupFixture(t)
			if err := os.Remove(p[index]); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", p[index]); err != nil {
				t.Skip(err)
			}
			requireBackupFailure(t, m, p, "failed to hash "+label+" file", os.ErrNotExist)
		})
	}
}

func TestContainerBackupRejectsSnapshotSymlink(t *testing.T) {
	m, p := backupFixture(t)
	link := p[0] + "-link"
	if err := os.Symlink(p[0], link); err != nil {
		t.Skip(err)
	}
	if result, err := m.BackupContainer("site", "nginx", "/cert", "/key", link, p[1]); result != nil || err == nil || !strings.Contains(err.Error(), "symbolic link not allowed") {
		t.Fatalf("container snapshot = %+v, %v", result, err)
	}
}

func TestRestoreResolutionAndLegacySafety(t *testing.T) {
	for index, label := range []string{"证书", "私钥", "证书链"} {
		t.Run(label, func(t *testing.T) {
			m, p := backupFixture(t)
			saved, err := m.Backup("site", p[0], p[1], nil, p[2])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p[index]); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing", p[index]); err != nil {
				t.Skip(err)
			}
			got, err := m.Restore("site", filepath.Base(saved.BackupPath))
			if got != nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "恢复"+label+"失败") {
				t.Fatalf("restore = %+v, %v", got, err)
			}
		})
	}
	t.Run("legacy symlink", func(t *testing.T) {
		m, p := backupFixture(t)
		saved, err := m.Backup("site", p[0], p[1], nil, p[2])
		if err != nil {
			t.Fatal(err)
		}
		meta, err := m.LoadMetadata(saved.BackupPath)
		if err != nil {
			t.Fatal(err)
		}
		meta.ResolvedPaths = nil
		if err := m.saveMetadata(filepath.Join(saved.BackupPath, "metadata.json"), meta); err != nil {
			t.Fatal(err)
		}
		target := p[0] + "-target"
		if err := os.Rename(p[0], target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p[0]); err != nil {
			t.Skip(err)
		}
		got, err := m.Restore("site", filepath.Base(saved.BackupPath))
		if got != nil || err == nil || !strings.Contains(err.Error(), "旧备份未记录符号链接目标") {
			t.Fatalf("restore = %+v, %v", got, err)
		}
	})
	t.Run("missing saved chain", func(t *testing.T) {
		m, p := backupFixture(t)
		saved, err := m.Backup("site", p[0], p[1], nil, p[2])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(saved.BackupPath, "chain.pem")); err != nil {
			t.Fatal(err)
		}
		got, err := m.Restore("site", filepath.Base(saved.BackupPath))
		if got != nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restore = %+v, %v", got, err)
		}
	})
}

func TestRestoreReadAndStatFailures(t *testing.T) {
	for index, label := range []string{"证书", "私钥", "证书链"} {
		for _, phase := range []string{"read", "stat"} {
			t.Run(label+"/"+phase, func(t *testing.T) {
				m, p := backupFixture(t)
				preserveBackupIO(t)
				saved, err := m.Backup("site", p[0], p[1], nil, p[2])
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range p {
					if err := os.WriteFile(path, []byte("current"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				source := filepath.Join(saved.BackupPath, []string{"cert.pem", "key.pem", "chain.pem"}[index])
				fault := errors.New("restore I/O fault")
				restoreReadFile = func(path string, limit int64) ([]byte, error) {
					if path == source && phase == "read" {
						return nil, fault
					}
					return util.SafeReadFile(path, limit)
				}
				restoreFileStat = func(path string) (os.FileInfo, error) {
					if path == source && phase == "stat" {
						return nil, fault
					}
					return os.Stat(path)
				}
				got, err := m.Restore("site", filepath.Base(saved.BackupPath))
				if got != nil || !errors.Is(err, fault) || !strings.Contains(err.Error(), "恢复"+label+"失败") {
					t.Fatalf("restore = %+v, %v", got, err)
				}
				for _, path := range p[index:] {
					data, err := os.ReadFile(path)
					if err != nil || string(data) != "current" {
						t.Fatalf("modified after failure: %s = %q, %v", path, data, err)
					}
				}
			})
		}
	}
}

func TestRestoreBackupAssetSizeLimit(t *testing.T) {
	for _, size := range []int64{16 << 20, (16 << 20) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			m, p := backupFixture(t)
			saved, err := m.Backup("site", p[0], p[1], nil, p[2])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(filepath.Join(saved.BackupPath, "cert.pem"), size); err != nil {
				t.Fatal(err)
			}
			got, err := m.Restore("site", filepath.Base(saved.BackupPath))
			if size == 16<<20 {
				if err != nil || got == nil {
					t.Fatalf("limit-sized restore: %v", err)
				}
				info, err := os.Stat(p[0])
				if err != nil || info.Size() != size {
					t.Fatalf("restored size: %v, %v", info, err)
				}
			} else if got != nil || err == nil || !strings.Contains(err.Error(), "file too large") {
				t.Fatalf("oversized restore: %+v, %v", got, err)
			}
		})
	}
}

func TestRestoreRechecksOtherPathsBeforeFirstWrite(t *testing.T) {
	m, p := backupFixture(t)
	preserveBackupIO(t)
	saved, err := m.Backup("site", p[0], p[1], nil, p[2])
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range p {
		if err := os.WriteFile(path, []byte("current"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	replacement := p[1] + "-new"
	if err := os.WriteFile(replacement, []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	// 在恢复前快照的最后一次内容核验结束后，模拟另一进程改向私钥链接。
	backupFileHash = func(path string) (string, error) {
		hash, err := computeFileHash(path)
		if strings.HasSuffix(path, ".pem") {
			count++
			if count == 3 {
				if err := os.Remove(p[1]); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, p[1]); err != nil {
					t.Fatal(err)
				}
			}
		}
		return hash, err
	}
	got, err := m.Restore("site", filepath.Base(saved.BackupPath))
	if got != nil || err == nil || !strings.Contains(err.Error(), "证书路径在操作期间发生变化") {
		t.Fatalf("restore = %+v, %v", got, err)
	}
	data, err := os.ReadFile(p[0])
	if err != nil || string(data) != "current" {
		t.Fatalf("certificate changed before all paths checked: %q, %v", data, err)
	}
}

func TestBackupEmptyRequiredPathRetainsFilesystemCause(t *testing.T) {
	for _, index := range []int{0, 1} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			m, p := backupFixture(t)
			p[index] = ""
			requireBackupFailure(t, m, p, "failed to hash", os.ErrNotExist)
		})
	}
}

func TestBackupTimestampCollisionPreservesExistingSnapshot(t *testing.T) {
	m, p := backupFixture(t)
	now := time.Date(2026, 11, 3, 12, 0, 0, 123456789, time.UTC)
	originalNow := backupNow
	backupNow = func() time.Time { return now }
	t.Cleanup(func() { backupNow = originalNow })
	first, err := m.Backup("site", p[0], p[1], nil, p[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p[0], []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := m.Backup("site", p[0], p[1], nil, p[2])
	if err != nil {
		t.Fatal(err)
	}
	if first.BackupPath == second.BackupPath {
		t.Fatal("backup collision overwrote first snapshot")
	}
	data, err := os.ReadFile(filepath.Join(first.BackupPath, "cert.pem"))
	if err != nil || string(data) != "old-cert" {
		t.Fatalf("first snapshot changed: %q, %v", data, err)
	}
}

func TestBackupRequiredPathDiagnosticsWithOptionalChain(t *testing.T) {
	for _, index := range []int{0, 1} {
		t.Run("missing required path also used as chain/"+fmt.Sprint(index), func(t *testing.T) {
			m, p := backupFixture(t)
			if err := os.Remove(p[index]); err != nil {
				t.Fatal(err)
			}
			_, err := m.Backup("site", p[0], p[1], nil, p[index])
			var pathErr *os.PathError
			if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != p[index] {
				t.Fatalf("missing required file diagnostic = %v; want PathError for %s", err, p[index])
			}
		})
	}
	t.Run("empty path does not suppress later link resolution error", func(t *testing.T) {
		m, p := backupFixture(t)
		missing := p[1] + "-missing"
		if err := os.Remove(p[1]); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(missing, p[1]); err != nil {
			t.Skip(err)
		}
		_, err := m.Backup("site", "", p[1], nil, p[2])
		var pathErr *os.PathError
		if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || pathErr.Path != missing || !strings.Contains(err.Error(), "failed to hash private key file") {
			t.Fatalf("invalid link diagnostic = %v; want missing key link target %s", err, missing)
		}
	})
}

func TestBackupPairCopyFailuresRetainCause(t *testing.T) {
	for index, label := range []string{"certificate", "private key"} {
		t.Run(label, func(t *testing.T) {
			m, p := backupFixture(t)
			preserveBackupIO(t)
			fault := errors.New("copy destination I/O fault")
			backupCopyFile = func(src, dst string) error {
				if src == p[index] {
					return fault
				}
				return util.CopyFile(src, dst)
			}
			result, err := m.Backup("site", p[0], p[1], nil, p[2])
			if result != nil || !errors.Is(err, fault) || !strings.Contains(err.Error(), "failed to backup "+label) {
				t.Fatalf("backup = %+v, %v", result, err)
			}
		})
	}
}

func TestContainerBackupUsesNanosecondVersionName(t *testing.T) {
	m, p := backupFixture(t)
	now := time.Date(2026, 11, 3, 12, 0, 0, 123456789, time.UTC)
	originalNow := backupNow
	backupNow = func() time.Time { return now }
	t.Cleanup(func() { backupNow = originalNow })
	result, err := m.BackupContainer("site", "nginx", "/cert", "/key", p[0], p[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := filepath.Base(result.BackupPath), now.Format("20060102-150405.000000000"); got != want {
		t.Fatalf("container backup version = %s, want %s", got, want)
	}
}
