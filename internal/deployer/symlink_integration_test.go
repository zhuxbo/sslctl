package deployer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	apache "github.com/zhuxbo/sslctl/internal/apache/deployer"
	base "github.com/zhuxbo/sslctl/internal/deployer"
	nginx "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	"github.com/zhuxbo/sslctl/pkg/backup"
)

func TestSymlinkDeployAndRollback(t *testing.T) {
	for _, kind := range []string{"nginx", "apache"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			paths := make([]string, 3)
			for i, name := range []string{"cert", "key", "chain"} {
				_ = os.WriteFile(filepath.Join(dir, name+"1.pem"), []byte("old-"+name), 0600)
				paths[i] = filepath.Join(dir, name+".pem")
				if err := os.Symlink(name+"1.pem", paths[i]); err != nil {
					t.Skip(err)
				}
			}
			cfg := base.Config{CertPath: paths[0], KeyPath: paths[1], ChainPath: paths[2]}
			mgr := backup.NewManager(filepath.Join(dir, "backup"), 5)
			var prepare func() error
			var deploy func(context.Context, string, string, string) error
			var rollback func(context.Context, string, string, string) error
			if kind == "nginx" {
				d := nginx.NewNginxDeployer(cfg)
				prepare = d.Prepare
				deploy = d.Deploy
				rollback = func(ctx context.Context, c, k, _ string) error { return d.Rollback(ctx, c, k) }
			} else {
				d := apache.NewApacheDeployer(cfg)
				prepare = d.Prepare
				deploy = d.Deploy
				rollback = d.Rollback
			}
			if err := prepare(); err != nil {
				t.Fatal(err)
			}
			saved, err := mgr.Backup("site", paths[0], paths[1], nil, paths[2])
			if err != nil {
				t.Fatal(err)
			}
			if err := deploy(context.Background(), "new-cert", "new-chain", "new-key"); err != nil {
				t.Fatal(err)
			}
			wantCert := "new-cert"
			if kind == "nginx" {
				wantCert += "\nnew-chain"
			}
			for i, want := range []string{wantCert, "new-key"} {
				got, _ := os.ReadFile(paths[i])
				if string(got) != want {
					t.Fatalf("deploy %d: %q", i, got)
				}
			}
			c, k, ch := mgr.GetBackupPathsWithChain(saved.BackupPath)
			if err := rollback(context.Background(), c, k, ch); err != nil {
				t.Fatal(err)
			}
			for i, name := range []string{"cert", "key", "chain"} {
				got, _ := os.ReadFile(paths[i])
				if string(got) != "old-"+name {
					t.Fatalf("rollback %s: %q", name, got)
				}
				if got, err := os.Readlink(paths[i]); err != nil || got != name+"1.pem" {
					t.Fatalf("lost link: %s", name)
				}
			}
			// 同一个部署器的目标已固定；外部续签切换链接后拒绝继续部署或回滚。
			_ = os.WriteFile(filepath.Join(dir, "cert2.pem"), []byte("renewed"), 0600)
			_ = os.Remove(paths[0])
			_ = os.Symlink("cert2.pem", paths[0])
			if err := deploy(context.Background(), "bad", "bad", "bad"); err == nil {
				t.Fatal("accepted redirected link")
			}
			if err := rollback(context.Background(), c, k, ch); err == nil {
				t.Fatal("rollback accepted redirected link")
			}
			got, _ := os.ReadFile(paths[0])
			if string(got) != "renewed" {
				t.Fatal("renewed file changed")
			}
		})
	}
}
