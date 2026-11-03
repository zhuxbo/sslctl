package certops

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	base "github.com/zhuxbo/sslctl/internal/deployer"
	nginx "github.com/zhuxbo/sslctl/internal/nginx/deployer"
	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	deployerrors "github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

type symlinkFailureDeployer struct {
	*nginx.NginxDeployer
	afterWrite func()
}

func (d *symlinkFailureDeployer) Deploy(ctx context.Context, cert, chain, key string) error {
	if err := d.NginxDeployer.Deploy(ctx, cert, chain, key); err != nil {
		return err
	}
	if d.afterWrite != nil {
		d.afterWrite()
	}
	return deployerrors.NewStructuredDeployError(deployerrors.DeployErrorReload, deployerrors.PhaseReload, "模拟写入后重载失败", nil)
}

func (d *symlinkFailureDeployer) Rollback(ctx context.Context, c, k, _ string) error {
	return d.NginxDeployer.Rollback(ctx, c, k)
}

func TestSymlinkAutomaticRollback(t *testing.T) {
	pair, err := certs.GenerateValidCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, redirect := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "renewal-redirect"}[redirect], func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "live.pem")
			keyPath := filepath.Join(dir, "live.key")
			for link, content := range map[string]string{certPath: "old-cert", keyPath: "old-key"} {
				if err := os.WriteFile(link+".archive", []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(link)+".archive", link); err != nil {
					t.Skip(err)
				}
			}
			calls := 0
			serverType := webserver.ServerType("symlink-rollback-" + t.Name())
			webserver.RegisterDeployer(serverType, func(c, k, _, test, reload string) webserver.Deployer {
				calls++
				d := &symlinkFailureDeployer{NginxDeployer: nginx.NewNginxDeployer(base.Config{CertPath: c, KeyPath: k, TestCommand: test, ReloadCommand: reload})}
				if redirect {
					d.afterWrite = func() {
						if err := os.WriteFile(certPath+".renewed", []byte("renewed"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(certPath); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(filepath.Base(certPath)+".renewed", certPath); err != nil {
							t.Fatal(err)
						}
					}
				}
				return d
			})
			cm, err := config.NewConfigManagerWithDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			binding := &config.SiteBinding{ServerName: "example.com", ServerType: string(serverType), Paths: config.BindingPaths{Certificate: certPath, PrivateKey: keyPath}}
			err = svc.DeployToBinding(t.Context(), binding, &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
			if err == nil {
				t.Fatal("deploy must report failure")
			}
			if calls != 1 {
				t.Fatalf("rollback must reuse prepared deployer, got %d instances", calls)
			}
			if redirect {
				if !strings.Contains(err.Error(), "回滚失败") {
					t.Fatal(err)
				}
				got, _ := os.ReadFile(certPath)
				if string(got) != "renewed" {
					t.Fatal("renewed certificate overwritten")
				}
			} else {
				if !strings.Contains(err.Error(), "已回滚") {
					t.Fatal(err)
				}
				for path, want := range map[string]string{certPath: "old-cert", keyPath: "old-key"} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("rollback: %s %q %v", path, got, err)
					}
					if _, err := os.Readlink(path); err != nil {
						t.Fatal("link replaced", err)
					}
				}
			}
		})
	}
}

func TestBackupFailureDoesNotClaimPermission(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	badRoot := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(badRoot, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	svc.backupMgr = backup.NewManager(badRoot, 5)
	pair, err := certs.GenerateValidCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	_ = os.WriteFile(c, []byte("old cert"), 0600)
	_ = os.WriteFile(k, []byte("old key"), 0600)
	binding := &config.SiteBinding{ServerName: "example.com", ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{Certificate: c, PrivateKey: k}}
	err = svc.DeployToBinding(t.Context(), binding, &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
	var structured *deployerrors.StructuredDeployError
	if !stderrors.As(err, &structured) || structured.Type != deployerrors.DeployErrorUnknown || structured.Phase != deployerrors.PhaseBackup {
		t.Fatalf("wrong classification: %v", err)
	}
	if strings.Contains(err.Error(), "权限") {
		t.Fatalf("misleading permission hint: %v", err)
	}
	got, _ := os.ReadFile(c)
	if string(got) != "old cert" {
		t.Fatal("certificate changed after backup failure")
	}
}

type prepareFailureProbe struct {
	webserver.Deployer
	err   error
	calls int
}

func (p *prepareFailureProbe) Prepare() error { p.calls++; return p.err }
func (p *prepareFailureProbe) Deploy(context.Context, string, string, string) error {
	panic("准备失败后不能部署")
}

func TestPrepareFailurePreservesCauseAndStops(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	pair, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	for _, p := range []string{c, k} {
		if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := stderrors.New("prepare failure")
	probe := &prepareFailureProbe{err: want}
	typ := webserver.ServerType(t.Name())
	webserver.RegisterDeployer(typ, func(string, string, string, string, string) webserver.Deployer { return probe })
	root := filepath.Join(dir, "no-backup")
	svc.backupMgr = backup.NewManager(root, 5)
	b := &config.SiteBinding{ServerName: "site", ServerType: string(typ), Paths: config.BindingPaths{Certificate: c, PrivateKey: k}}
	err = svc.DeployToBinding(t.Context(), b, &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
	if !stderrors.Is(err, want) || !strings.Contains(err.Error(), "准备证书文件失败") || probe.calls != 1 {
		t.Fatalf("prepare result: %v calls=%d", err, probe.calls)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("准备失败创建备份: %v", err)
	}
	for _, p := range []string{c, k} {
		if data, err := os.ReadFile(p); err != nil || string(data) != "old" {
			t.Fatalf("文件改变: %s %q %v", p, data, err)
		}
	}
}

func TestBackupPermissionFailureClassification(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "locked")
	if err := os.Mkdir(root, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0700) })
	probe := filepath.Join(root, "probe")
	if err := os.WriteFile(probe, nil, 0600); err == nil {
		_ = os.Remove(probe)
		t.Skip("当前用户绕过文件权限")
	}
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(cm, logger.NewNopLogger())
	svc.backupMgr = backup.NewManager(root, 5)
	pair, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	for _, p := range []string{c, k} {
		if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := &config.SiteBinding{ServerName: "site", ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{Certificate: c, PrivateKey: k}}
	err = svc.DeployToBinding(t.Context(), b, &fetcher.CertData{Cert: pair.CertPEM}, pair.KeyPEM)
	var structured *deployerrors.StructuredDeployError
	if !stderrors.As(err, &structured) || structured.Type != deployerrors.DeployErrorPermission || structured.Phase != deployerrors.PhaseBackup || !stderrors.Is(err, os.ErrPermission) {
		t.Fatalf("权限错误分类/错误链丢失: %v", err)
	}
	for _, p := range []string{c, k} {
		if data, err := os.ReadFile(p); err != nil || string(data) != "old" {
			t.Fatalf("文件改变: %s %q %v", p, data, err)
		}
	}
}
