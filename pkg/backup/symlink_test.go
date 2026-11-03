package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRestoreSymlinks(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 3)
	for i, name := range []string{"cert", "key", "chain"} {
		target := filepath.Join(dir, name+"1.pem")
		_ = os.WriteFile(target, []byte("old-"+name), 0600)
		paths[i] = filepath.Join(dir, name+".pem")
		if err := os.Symlink(name+"1.pem", paths[i]); err != nil {
			t.Skip(err)
		}
	}
	mgr := NewManager(filepath.Join(dir, "backup"), 5)
	result, err := mgr.Backup("site", paths[0], paths[1], nil, paths[2])
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mgr.LoadMetadata(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if meta.CertPath != paths[0] || meta.KeyPath != paths[1] || meta.ChainPath != paths[2] || len(meta.ResolvedPaths) != 3 {
		t.Fatalf("metadata: %+v", meta)
	}
	for i, path := range paths {
		want, err := filepath.EvalSymlinks(filepath.Join(dir, []string{"cert1.pem", "key1.pem", "chain1.pem"}[i]))
		if err != nil {
			t.Fatal(err)
		}
		if meta.ResolvedPaths[path] != want {
			t.Fatalf("resolved %s = %s, want %s", path, meta.ResolvedPaths[path], want)
		}
		if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := mgr.Restore("site", filepath.Base(result.BackupPath)); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"cert", "key", "chain"} {
		got, err := os.ReadFile(paths[i])
		if err != nil || string(got) != "old-"+name {
			t.Fatalf("restore %s: %q %v", name, got, err)
		}
		if got, err := os.Readlink(paths[i]); err != nil || got != name+"1.pem" {
			t.Fatalf("link lost: %s", name)
		}
	}
	// 后续续签切换链接仍然可用，但历史备份不得覆盖新目标。
	renewed := filepath.Join(dir, "cert2.pem")
	_ = os.WriteFile(renewed, []byte("renewed"), 0600)
	_ = os.Remove(paths[0])
	_ = os.Symlink("cert2.pem", paths[0])
	if _, err := mgr.Restore("site", filepath.Base(result.BackupPath)); err == nil {
		t.Fatal("restore overwrote renewed target")
	}
	got, _ := os.ReadFile(renewed)
	if string(got) != "renewed" {
		t.Fatal("new certificate changed")
	}
}

func TestBackupRejectsDanglingChainLink(t *testing.T) {
	dir := t.TempDir()
	cert, key, chain := filepath.Join(dir, "cert"), filepath.Join(dir, "key"), filepath.Join(dir, "chain")
	_ = os.WriteFile(cert, []byte("cert"), 0600)
	_ = os.WriteFile(key, []byte("key"), 0600)
	if err := os.Symlink("missing", chain); err != nil {
		t.Skip(err)
	}
	mgr := NewManager(filepath.Join(dir, "backup"), 5)
	if result, err := mgr.Backup("site", cert, key, nil, chain); err == nil || result != nil {
		t.Fatalf("不能丢弃无法备份的证书链: %v %v", result, err)
	}
}

func TestRestoreMissingChainDoesNotOverwritePair(t *testing.T) {
	dir := t.TempDir()
	c, k, ch := filepath.Join(dir, "cert"), filepath.Join(dir, "key"), filepath.Join(dir, "chain")
	for _, p := range []string{c, k, ch} {
		_ = os.WriteFile(p, []byte("old"), 0600)
	}
	mgr := NewManager(filepath.Join(dir, "backup"), 5)
	saved, err := mgr.Backup("site", c, k, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{c, k, ch} {
		_ = os.WriteFile(p, []byte("new"), 0600)
	}
	if err := os.Remove(filepath.Join(saved.BackupPath, "chain.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Restore("site", filepath.Base(saved.BackupPath)); err == nil {
		t.Fatal("missing chain must fail restore")
	}
	for _, p := range []string{c, k, ch} {
		got, _ := os.ReadFile(p)
		if string(got) != "new" {
			t.Fatalf("partial restore: %s", p)
		}
	}
}
