package deploy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

type failedInstall struct{ err error }

func (i *failedInstall) Install() (*webserver.InstallResult, error) { return nil, i.err }
func (i *failedInstall) Rollback(string) error                      { return nil }

func TestInstallSSLForSiteUsesSelectedNginx(t *testing.T) {
	material, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "data": map[string]interface{}{
			"total": 1, "data": []map[string]interface{}{{"order_id": 1, "status": "active", "domains": "example.com", "certificate": material.CertPEM, "private_key": material.KeyPEM}},
		}})
	}))
	defer server.Close()
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	site := &config.ScannedSite{ServerName: "example.com", ConfigFile: filepath.Join(dir, "nginx.conf"), ExecutablePath: filepath.Join(dir, "selected-nginx")}
	binding := &config.SiteBinding{ServerName: site.ServerName, ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{Certificate: filepath.Join(dir, "cert.pem"), PrivateKey: filepath.Join(dir, "key.pem")}}
	cert := &config.CertConfig{CertName: "example.com-1", OrderID: 1, API: config.APIConfig{URL: server.URL, Token: "test-token"}}
	installErr := errors.New("配置测试拒绝安装")
	calls := 0
	oldInstaller := newSiteInstaller
	t.Cleanup(func() { newSiteInstaller = oldInstaller })
	newSiteInstaller = func(serverType webserver.ServerType, configPath, certPath, keyPath, chainPath, serverName, testCmd string) (webserver.Installer, error) {
		calls++
		if serverType != webserver.TypeNginx {
			t.Fatalf("安装器类型 = %q", serverType)
		}
		if testCmd != site.ExecutablePath+" -t" {
			t.Fatalf("未使用目标实例测试配置: %q", testCmd)
		}
		if configPath != site.ConfigFile || certPath != binding.Paths.Certificate || keyPath != binding.Paths.PrivateKey || chainPath != "" || serverName != site.ServerName {
			t.Fatal("安装器收到错误的站点或证书路径")
		}
		return &failedInstall{err: installErr}, nil
	}
	if err := installSSLForSite(t.Context(), site, binding, cm, cert, fetcher.New()); !errors.Is(err, installErr) {
		t.Fatalf("安装错误未返回: %v", err)
	}
	if calls != 1 {
		t.Fatalf("安装器调用次数 = %d", calls)
	}
	for path, want := range map[string]string{binding.Paths.Certificate: material.CertPEM, binding.Paths.PrivateKey: material.KeyPEM} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("安装前证书材料未写入: %s: %v", path, err)
		}
	}
}
