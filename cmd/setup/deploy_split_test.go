// Package setup 部署失败按错误性质分流的测试（P1-2）
package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

// TestDeploySingleBindings_PermanentErrorDisablesBinding 永久性错误（绑定配置本身有问题）
// 才禁用绑定：Docker 站点缺少容器命令属于必须重新配置的情形。
func TestDeploySingleBindings_PermanentErrorDisablesBinding(t *testing.T) {
	tmpDir := t.TempDir()
	testCert, err := certs.GenerateValidCert("docker.example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	bindings := []config.SiteBinding{{
		ServerName: "docker.example.com",
		ServerType: config.ServerTypeDockerNginx,
		Enabled:    true,
		// copy 绑定缺少容器检查/重载命令：ValidateDockerBinding 失败 → Config@write_cert
		Docker: &config.DockerInfo{ContainerName: "web", DeployMode: "copy"},
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "docker", "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "docker", "key.pem"),
		},
	}}

	certData := &fetcher.CertData{OrderID: 1, Cert: testCert.CertPEM}
	svc := newTestDeployService(t, tmpDir)
	success, failedSites, retryableSites := deploySingleBindings(t.Context(), svc, bindings, certData, testCert.KeyPEM)

	if success != 0 {
		t.Errorf("success = %d, 期望 0", success)
	}
	if len(failedSites) != 1 || failedSites[0] != "docker.example.com" {
		t.Errorf("failedSites = %v, 期望 [docker.example.com]", failedSites)
	}
	if len(retryableSites) != 0 {
		t.Errorf("retryableSites = %v, 期望空（永久性错误不交给 daemon 重试）", retryableSites)
	}
	if bindings[0].Enabled {
		t.Error("永久性错误应禁用绑定")
	}
}

// TestDeploySingleBindings_RetryableErrorKeepsBinding 可重试错误不得禁用绑定：
// 禁用后 daemon 永不接手，站点一路静默到真实过期——正是 P1-2 要消除的洞。
func TestDeploySingleBindings_RetryableErrorKeepsBinding(t *testing.T) {
	tmpDir := t.TempDir()
	testCert, err := certs.GenerateValidCert("retry.example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 只读父目录：创建证书目录失败 → Permission@write_cert（可重试）
	readonly := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(readonly, 0500); err != nil {
		t.Fatalf("创建只读目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0700) })

	bindings := []config.SiteBinding{{
		ServerName: "retry.example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(readonly, "sub", "cert.pem"),
			PrivateKey:  filepath.Join(readonly, "sub", "key.pem"),
		},
	}}

	certData := &fetcher.CertData{OrderID: 1, Cert: testCert.CertPEM}
	svc := newTestDeployService(t, tmpDir)
	success, failedSites, retryableSites := deploySingleBindings(t.Context(), svc, bindings, certData, testCert.KeyPEM)

	if success != 0 {
		t.Errorf("success = %d, 期望 0", success)
	}
	if len(retryableSites) != 1 || retryableSites[0] != "retry.example.com" {
		t.Errorf("retryableSites = %v, 期望 [retry.example.com]", retryableSites)
	}
	if len(failedSites) != 0 {
		t.Errorf("failedSites = %v, 期望空（可重试错误不进已禁用列表）", failedSites)
	}
	if !bindings[0].Enabled {
		t.Error("可重试错误必须保留绑定启用状态，否则 daemon 永不接手")
	}
}
