package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerBackupDoesNotRestoreIntoHostPaths(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for name, content := range map[string]string{certPath: "old-cert", keyPath: "old-key"} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mgr := NewManager(filepath.Join(dir, "backups"), 5)
	result, err := mgr.BackupContainer("site", "web", "/etc/nginx/cert.pem", "/etc/nginx/key.pem", certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mgr.LoadMetadata(result.BackupPath)
	if err != nil || meta.ContainerName != "web" || meta.CertPath != "/etc/nginx/cert.pem" || meta.KeyPath != "/etc/nginx/key.pem" {
		t.Fatalf("未记录容器备份的目标: %v, %v", meta, err)
	}
	if _, err := mgr.Restore("site"); err == nil || !strings.Contains(err.Error(), "拒绝写入宿主机同名路径") {
		t.Fatalf("宿主机恢复入口必须在写入前拒绝容器备份: %v", err)
	}
	firstPath := result.BackupPath
	result, err = mgr.BackupContainer("site", "web", "/etc/nginx/cert.pem", "/etc/nginx/key.pem", certPath, keyPath)
	if err != nil || result.BackupPath == firstPath {
		t.Fatalf("连续容器部署必须保留独立备份: %v, %v", result, err)
	}
}

func TestContainerBackupFailureAndModes(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	mgr := NewManager(filepath.Join(dir, "backups"), 5)
	if result, err := mgr.BackupContainer("site", "web", "/cert", "/key", cert, key); result != nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "failed to hash certificate file") {
		t.Fatalf("缺失快照必须保留文件错误且不返回可恢复备份: %+v, %v", result, err)
	}
	for name, mode := range map[string]os.FileMode{cert: 0640, key: 0660} {
		if err := os.WriteFile(name, []byte("snapshot"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	result, err := mgr.BackupContainer("site", "web", "/cert", "/key", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"cert.pem": cert, "key.pem": key} {
		want, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.Stat(filepath.Join(result.BackupPath, name))
		if err != nil || got.Mode().Perm() != want.Mode().Perm() {
			t.Fatalf("备份必须保留 %s 的权限: %v", name, err)
		}
	}
}

func TestResolveBackupPathRetainsFailure(t *testing.T) {
	mgr := NewManager(t.TempDir(), 5)
	if name, err := mgr.ResolveBackupPath("missing"); err == nil || name != "" {
		t.Fatalf("不存在的最新备份必须失败: %q %v", name, err)
	}
	_, err := mgr.ResolveBackupPath("../outside", "version")
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatalf("非法备份路径必须保留底层原因: %v", err)
	}
	bad := filepath.Join(mgr.backupDir, "not-directory")
	if err := os.WriteFile(bad, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.ResolveBackupPath("not-directory")
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("读取备份列表失败必须保留 PathError: %v", err)
	}
}

func TestContainerBackupPreservesFilesystemErrors(t *testing.T) {
	for _, phase := range []string{"stat", "chmod"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
			for _, p := range []string{cert, key} {
				if err := os.WriteFile(p, []byte("snapshot"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			originalStat, originalChmod := containerSnapshotStat, containerSnapshotChmod
			t.Cleanup(func() { containerSnapshotStat, containerSnapshotChmod = originalStat, originalChmod })
			fault := &os.PathError{Op: phase, Path: cert, Err: os.ErrPermission}
			if phase == "stat" {
				containerSnapshotStat = func(string) (os.FileInfo, error) { return nil, fault }
			} else {
				containerSnapshotChmod = func(string, os.FileMode) error { return fault }
			}
			result, err := NewManager(t.TempDir(), 5).BackupContainer("test", "web", "/cert", "/key", cert, key)
			if !errors.Is(err, fault) || result != nil {
				t.Fatalf("必须返回权限错误且不能返回成功备份: %+v %v", result, err)
			}
		})
	}
}
