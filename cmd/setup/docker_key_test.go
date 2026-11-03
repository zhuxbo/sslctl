package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

func TestSetupReadsExistingDockerCopyKeyWhenAPIOmitsIt(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	pair, err := certs.GenerateValidCert("test.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.WritePair(t, pair.CertPEM, pair.KeyPEM)
	bindings := []config.SiteBinding{{Enabled: true, ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{Certificate: f.CertPath, PrivateKey: f.KeyPath}}}
	data := &fetcher.CertData{Cert: pair.CertPEM}
	key, err := getAndValidatePrivateKey("", bindings, data, validator.New(""), false)
	if err != nil || key != pair.KeyPEM {
		t.Fatalf("setup 应从容器读取配对私钥: %v", err)
	}
	trace, err := os.ReadFile(f.Trace)
	if err != nil || !strings.Contains(string(trace), "exec --user 0 fixture-id sh -c") {
		t.Fatal("默认私钥必须通过容器读取")
	}
	f.WritePair(t, pair.CertPEM, "wrong-key")
	if _, err := getAndValidatePrivateKey("", bindings, data, validator.New(""), false); !errors.Is(err, errNeedPrivateKey) {
		t.Fatalf("不匹配的容器私钥必须报需提供私钥: %v", err)
	}
}

func TestBatchCopyCannotInstallHTTPSOrWriteHostFiles(t *testing.T) {
	dir := t.TempDir()
	binding := config.SiteBinding{ServerName: "copy.example.com", Enabled: true, ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{Certificate: filepath.Join(dir, "cert.pem"), PrivateKey: filepath.Join(dir, "key.pem")}}
	plan := &certDeployPlan{Bindings: []config.SiteBinding{binding}, CertData: &fetcher.CertData{Cert: "certificate"}, PrivateKey: "key"}
	errOutput, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = errOutput
	t.Cleanup(func() { os.Stderr = originalStderr; _ = errOutput.Close() })
	installSSLForBatch(&matcher.ScannedSiteInfo{ServerName: binding.ServerName}, plan, &setupParams{})
	os.Stderr = originalStderr
	output, err := os.ReadFile(errOutput.Name())
	if err != nil || !strings.Contains(string(output), "Docker copy 仅支持已有 HTTPS 配置") {
		t.Fatalf("必须解释拒绝安装的原因: %v", err)
	}
	if plan.Bindings[0].Enabled {
		t.Fatal("不能启用未安装 HTTPS 的 copy 绑定")
	}
	for _, file := range []string{binding.Paths.Certificate, binding.Paths.PrivateKey} {
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("不能写入宿主机同名路径: %v", err)
		}
	}
}

func TestCreateBindingHostHintsRequireDockerVolume(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, serverType := range []string{config.ServerTypeNginx, config.ServerTypeDockerNginx} {
		for _, volume := range []bool{false, true} {
			for _, hostCert := range []string{"", "/host/cert.pem"} {
				for _, hostKey := range []string{"", "/host/key.pem"} {
					site := &matcher.ScannedSiteInfo{ServerName: "example.com", ServerType: serverType, CertPath: "/container/cert.pem", KeyPath: "/container/key.pem", HostCertPath: hostCert, HostKeyPath: hostKey, VolumeMode: volume, ContainerName: "web"}
					got := createBinding(site, cm)
					wantCert, wantKey := site.CertPath, site.KeyPath
					if serverType == config.ServerTypeDockerNginx && volume {
						if hostCert != "" {
							wantCert = hostCert
						}
						if hostKey != "" {
							wantKey = hostKey
						}
					}
					if got.Paths.Certificate != wantCert || got.Paths.PrivateKey != wantKey {
						t.Fatalf("type=%s volume=%v cert=%s key=%s: got %+v", serverType, volume, hostCert, hostKey, got.Paths)
					}
				}
			}
		}
	}
}
