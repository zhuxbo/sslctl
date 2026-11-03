package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

type prepareProbe struct {
	webserver.Deployer
	err   error
	calls int
}

func (p *prepareProbe) Prepare() error { p.calls++; return p.err }
func (p *prepareProbe) Deploy(context.Context, string, string, string) error {
	panic("准备失败后不能继续部署")
}

func TestDeployPrepareFailureStopsBeforeBackup(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	for _, p := range []string{c, k} {
		if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("prepare failure")
	probe := &prepareProbe{err: want}
	typ := webserver.ServerType(t.Name())
	webserver.RegisterDeployer(typ, func(string, string, string, string, string) webserver.Deployer { return probe })
	root := filepath.Join(dir, "backups")
	b := &config.SiteBinding{ServerName: "site", ServerType: string(typ), Paths: config.BindingPaths{Certificate: c, PrivateKey: k}}
	err := deployToBinding(t.Context(), b, &fetcher.CertData{}, "", backup.NewManager(root, 5), logger.NewNopLogger())
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "准备证书文件失败") || probe.calls != 1 {
		t.Fatalf("prepare result: %v calls=%d", err, probe.calls)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("准备失败创建了备份: %v", err)
	}
	for _, p := range []string{c, k} {
		if data, err := os.ReadFile(p); err != nil || string(data) != "old" {
			t.Fatalf("文件改变: %s %q %v", p, data, err)
		}
	}
}

func TestDeployFactoryErrorPreservesCause(t *testing.T) {
	dir := t.TempDir()
	b := &config.SiteBinding{ServerType: "unregistered-prepare-test", Paths: config.BindingPaths{Certificate: filepath.Join(dir, "cert"), PrivateKey: filepath.Join(dir, "key")}}
	err := deployToBinding(t.Context(), b, &fetcher.CertData{}, "", backup.NewManager(t.TempDir(), 5), nil)
	if err == nil || errors.Unwrap(err) == nil || !strings.Contains(errors.Unwrap(err).Error(), "deployer not registered") {
		t.Fatalf("工厂错误链丢失: %v", err)
	}
}
