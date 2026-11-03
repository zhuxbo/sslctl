package setup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/validator"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	"github.com/zhuxbo/sslctl/testdata/certs"
	"github.com/zhuxbo/sslctl/testdata/testutil"
)

type setupExitCode int

func captureSetup(t *testing.T, run func()) (string, int) {
	t.Helper()
	oldExit := exitSetup
	exitSetup = func(code int) { panic(setupExitCode(code)) }
	defer func() { exitSetup = oldExit }()
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = output, output
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; _ = output.Close() }()
	code := 0
	func() {
		defer func() {
			if value := recover(); value != nil {
				if exit, ok := value.(setupExitCode); ok {
					code = int(exit)
				} else {
					panic(value)
				}
			}
		}()
		run()
	}()
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data), code
}

func registerSetupSites(t *testing.T, sites []webserver.Site) {
	t.Helper()
	original, err := webserver.NewScanner(webserver.TypeNginx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { webserver.RegisterScanner(webserver.TypeNginx, func() webserver.Scanner { return original }) })
	webserver.RegisterScanner(webserver.TypeNginx, func() webserver.Scanner { return &staticScanner{serverType: webserver.TypeNginx, sites: sites} })
}

func TestSetupCopyFileValidationStopsBeforeDeployment(t *testing.T) {
	for _, mode := range []string{"single-file", "batch-file", "batch-dns"} {
		t.Run(mode, func(t *testing.T) {
			f := testutil.NewDockerCLI(t)
			f.WritePair(t, "old-cert", "old-key")
			cm, err := config.NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var data []fetcher.CertData
			var sites []webserver.Site
			count := 2
			if mode == "batch-dns" {
				count = 1
			}
			for i := range count {
				name := fmt.Sprintf("copy%d.example.com", i)
				host := fmt.Sprintf("host%d.example.com", i)
				pair, err := certs.GenerateValidCert(name, []string{name, host})
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, fetcher.CertData{OrderID: i + 1, Status: config.OrderStatusActive, Cert: pair.CertPEM, PrivateKey: pair.KeyPEM, IntermediateCert: pair.CertPEM})
				// 第一个本地绑定之后还有 copy 绑定，不能只检查首项。
				if mode != "batch-dns" {
					sites = append(sites, webserver.Site{ServerName: host, ServerType: webserver.TypeNginx, CertificatePath: filepath.Join(t.TempDir(), "cert.pem"), PrivateKeyPath: filepath.Join(t.TempDir(), "key.pem")})
				}
				sites = append(sites, webserver.Site{ServerName: name, ServerType: webserver.TypeDockerNginx, ContainerID: "fixture-id", ContainerName: "web", CertificatePath: f.CertPath, PrivateKeyPath: f.KeyPath})
			}
			registerSetupSites(t, sites)
			var posts atomic.Int32
			server := testutil.NewMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{}})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": data})
			})
			p := &setupParams{ctx: t.Context(), cfgManager: cm, log: logger.NewNopLogger(), apiURL: server.URL, token: "token", yes: true, noService: true, fileValidation: mode != "batch-dns", webroot: t.TempDir()}
			output, code := captureSetup(t, func() {
				if mode == "single-file" {
					runSingle(p, 1)
				} else {
					runBatch(p, "1,2")
				}
			})
			if mode == "batch-dns" {
				if code != 0 || strings.Contains(output, "不支持文件验证") {
					t.Fatalf("DNS copy 不应被拒绝: code=%d output=%s", code, output)
				}
				f.AssertPair(t, data[0].Cert+"\n"+data[0].IntermediateCert, data[0].PrivateKey)
				if posts.Load() == 0 {
					t.Fatal("已部署结果应被上报")
				}
			} else {
				wantMessages := 2
				if mode == "single-file" {
					wantMessages = 1
				}
				if code != 1 || strings.Count(output, "Docker copy 暂不支持文件验证") != wantMessages {
					t.Fatalf("必须逐项拒绝 copy 文件验证: code=%d output=%s", code, output)
				}
				if posts.Load() != 0 {
					t.Fatal("部署前拒绝不能发送部署结果回调")
				}
				f.AssertPair(t, "old-cert", "old-key")
				if _, err := os.Stat(cm.GetConfigPath()); !os.IsNotExist(err) {
					t.Fatal("失败的证书不能被保存为有效配置")
				}
			}
		})
	}
}

func TestSingleSetupDisablesEachCopySiteWithoutHTTPS(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "old-cert", "old-key")
	pair, err := certs.GenerateValidCert("first.example.com", []string{"first.example.com", "second.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var sites []webserver.Site
	for _, name := range []string{"first.example.com", "second.example.com"} {
		sites = append(sites, webserver.Site{ServerName: name, ServerType: webserver.TypeDockerNginx, ContainerID: "fixture-id", ContainerName: "web", PrivateKeyPath: f.KeyPath})
	}
	registerSetupSites(t, sites)
	server := testutil.NewMockAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{"code": 1, "data": map[string]any{}}
		if r.Method == http.MethodGet {
			response["data"] = fetcher.CertData{OrderID: 1, Status: config.OrderStatusActive, Cert: pair.CertPEM, PrivateKey: pair.KeyPEM, IntermediateCert: pair.CertPEM}
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	p := &setupParams{ctx: t.Context(), cfgManager: cm, log: logger.NewNopLogger(), apiURL: server.URL, token: "token", yes: true, noService: true}
	output, code := captureSetup(t, func() { runSingle(p, 1) })
	if code != 1 || strings.Count(output, "Docker copy 仅支持已有 HTTPS 配置的站点") != 2 || strings.Count(output, "跳过部署（SSL 配置安装失败）") != 2 {
		t.Fatalf("必须禁用每个未配置 HTTPS 的 copy 绑定: code=%d output=%s", code, output)
	}
	f.AssertPair(t, "old-cert", "old-key")
}

func TestCopyPrivateKeyPromptDoesNotSuggestHostPath(t *testing.T) {
	f := testutil.NewDockerCLI(t)
	f.WritePair(t, "cert", "wrong-key")
	pair, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(t.TempDir(), "missing-key")
	bindings := []config.SiteBinding{{Enabled: true, ServerType: config.ServerTypeNginx, Paths: config.BindingPaths{PrivateKey: hostKey}}, {Enabled: true, ServerType: config.ServerTypeDockerNginx, Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"}, Paths: config.BindingPaths{PrivateKey: f.KeyPath}}}
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = original; _ = input.Close() }()
	output, _ := captureSetup(t, func() {
		_, err = getAndValidatePrivateKey("", bindings, &fetcher.CertData{Cert: pair.CertPEM}, validator.New(""), true)
	})
	if err == nil || !strings.Contains(err.Error(), "读取输入失败") {
		t.Fatalf("应进入私钥提示后遇到输入 EOF: %v", err)
	}
	if strings.Contains(output, hostKey) || strings.Contains(output, f.KeyPath) || strings.Contains(output, "按回车") {
		t.Fatal("包含 copy 绑定时不能把路径建议为宿主机默认文件")
	}
	if !strings.Contains(output, "请输入私钥文件绝对路径") {
		t.Fatal("应提示提供新的私钥路径")
	}
}
