// Package deploy 证书部署命令测试
package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/testdata/certs"
)

// TestDeployToBinding_Nginx 测试 Nginx 部署
func TestDeployToBinding_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	certData := &fetcher.CertData{
		OrderID:          12345,
		Cert:             testCert.CertPEM,
		IntermediateCert: "",
	}

	err = deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证证书文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}

	// 验证私钥文件已创建
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}

	// 验证私钥权限
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("私钥权限 = %o, 期望 0600", info.Mode().Perm())
	}
}

// TestDeployToBinding_Apache 测试 Apache 部署
func TestDeployToBinding_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			ChainFile:   chainPath,
		},
		Reload: config.ReloadConfig{
			TestCommand:   "",
			ReloadCommand: "",
		},
	}

	certData := &fetcher.CertData{
		OrderID:          12345,
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	err = deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证所有文件已创建
	for _, path := range []string{certPath, keyPath, chainPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("文件未创建: %s", path)
		}
	}
}

// TestDeployToBinding_UnsupportedType 测试不支持的服务器类型
func TestDeployToBinding_UnsupportedType(t *testing.T) {
	tmpDir := t.TempDir()

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: "unsupported",
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: filepath.Join(tmpDir, "cert.pem"),
			PrivateKey:  filepath.Join(tmpDir, "key.pem"),
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err == nil {
		t.Error("期望返回错误，但实际成功")
	}
}

// TestDeployToBinding_CreateDirectory 测试目录自动创建
func TestDeployToBinding_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "subdir1", "subdir2")
	certPath := filepath.Join(nestedDir, "cert.pem")
	keyPath := filepath.Join(nestedDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: config.ServerTypeNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证目录已创建
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("嵌套目录未创建")
	}
}

// TestDeployToBinding_DockerNginx 测试 Docker Nginx 部署
func TestDeployToBinding_DockerNginx(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: config.ServerTypeDockerNginx,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	// 验证文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
}

// TestDeployToBinding_DockerApache 测试 Docker Apache 部署
func TestDeployToBinding_DockerApache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)

	binding := &config.SiteBinding{
		SiteName:   "example.com",
		ServerType: config.ServerTypeDockerApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
		},
	}

	certData := &fetcher.CertData{
		Cert: testCert.CertPEM,
	}

	err := deployToBinding(binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployToBinding() error = %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
}
