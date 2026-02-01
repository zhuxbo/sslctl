// Package setup 一键部署命令测试
package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/fetcher"
	"github.com/zhuxbo/cert-deploy/pkg/matcher"
	"github.com/zhuxbo/cert-deploy/testdata/certs"
)

// TestParseDomains 测试域名解析
func TestParseDomains(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []string
	}{
		{
			name:   "单个域名",
			input:  "example.com",
			expect: []string{"example.com"},
		},
		{
			name:   "多个域名",
			input:  "example.com,www.example.com,api.example.com",
			expect: []string{"example.com", "www.example.com", "api.example.com"},
		},
		{
			name:   "带空格",
			input:  "example.com, www.example.com , api.example.com",
			expect: []string{"example.com", "www.example.com", "api.example.com"},
		},
		{
			name:   "空字符串",
			input:  "",
			expect: nil,
		},
		{
			name:   "只有逗号",
			input:  ",,",
			expect: nil,
		},
		{
			name:   "通配符域名",
			input:  "*.example.com,example.com",
			expect: []string{"*.example.com", "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDomains(tt.input)
			if len(result) != len(tt.expect) {
				t.Errorf("parseDomains(%q) = %v, want %v", tt.input, result, tt.expect)
				return
			}
			for i, d := range result {
				if d != tt.expect[i] {
					t.Errorf("parseDomains(%q)[%d] = %s, want %s", tt.input, i, d, tt.expect[i])
				}
			}
		})
	}
}

// TestCreateBinding_Nginx 测试创建 Nginx 绑定
func TestCreateBinding_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ServerAlias: []string{"www.example.com"},
		ConfigFile:  "/etc/nginx/conf.d/example.conf",
		HasSSL:      true,
		CertPath:    "/etc/ssl/certs/example.pem",
		KeyPath:     "/etc/ssl/private/example.key",
		ServerType:  config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	if binding.SiteName != "example.com" {
		t.Errorf("SiteName = %s, want example.com", binding.SiteName)
	}

	if binding.ServerType != config.ServerTypeNginx {
		t.Errorf("ServerType = %s, want nginx", binding.ServerType)
	}

	if !binding.Enabled {
		t.Error("Enabled 应为 true")
	}

	if binding.Paths.Certificate != "/etc/ssl/certs/example.pem" {
		t.Errorf("Certificate = %s", binding.Paths.Certificate)
	}

	if binding.Reload.TestCommand != "nginx -t" {
		t.Errorf("TestCommand = %s, want 'nginx -t'", binding.Reload.TestCommand)
	}

	if binding.Reload.ReloadCommand != "nginx -s reload" {
		t.Errorf("ReloadCommand = %s, want 'nginx -s reload'", binding.Reload.ReloadCommand)
	}
}

// TestCreateBinding_Apache 测试创建 Apache 绑定
func TestCreateBinding_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ConfigFile:  "/etc/apache2/sites-available/example.conf",
		HasSSL:      true,
		CertPath:    "/etc/ssl/certs/example.pem",
		KeyPath:     "/etc/ssl/private/example.key",
		ServerType:  config.ServerTypeApache,
	}

	binding := createBinding(site, cfgManager)

	if binding.ServerType != config.ServerTypeApache {
		t.Errorf("ServerType = %s, want apache", binding.ServerType)
	}

	if binding.Reload.TestCommand != "apache2ctl -t" {
		t.Errorf("TestCommand = %s, want 'apache2ctl -t'", binding.Reload.TestCommand)
	}

	if binding.Reload.ReloadCommand != "systemctl reload apache2" {
		t.Errorf("ReloadCommand = %s", binding.Reload.ReloadCommand)
	}
}

// TestCreateBinding_NoSSL 测试无 SSL 站点创建绑定
func TestCreateBinding_NoSSL(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName:  "example.com",
		ConfigFile:  "/etc/nginx/conf.d/example.conf",
		HasSSL:      false,
		CertPath:    "", // 无 SSL 配置
		KeyPath:     "",
		ServerType:  config.ServerTypeNginx,
	}

	binding := createBinding(site, cfgManager)

	// 应该使用默认路径
	if binding.Paths.Certificate == "" {
		t.Error("Certificate 路径不应为空")
	}

	if binding.Paths.PrivateKey == "" {
		t.Error("PrivateKey 路径不应为空")
	}
}

// TestDeployCert_Nginx 测试 Nginx 证书部署
func TestDeployCert_Nginx(t *testing.T) {
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

	err = deployCert(nil, binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件已创建
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}

	// 验证私钥文件已创建
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestDeployCert_Apache 测试 Apache 证书部署
func TestDeployCert_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
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
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	err := deployCert(nil, binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证所有文件已创建
	for _, path := range []string{certPath, keyPath, chainPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("文件未创建: %s", path)
		}
	}
}

// TestDeployCert_CreateDirectory 测试目录自动创建
func TestDeployCert_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "certs", "example.com")
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

	err := deployCert(nil, binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证嵌套目录已创建
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("嵌套目录未创建")
	}
}

// TestDetectWebServer 测试 Web 服务器检测
func TestDetectWebServer(t *testing.T) {
	// 这个测试依赖系统环境，只验证函数不会 panic
	serverType := detectWebServer()
	t.Logf("检测到的 Web 服务器: %s", serverType)

	// 验证返回值是有效的类型
	validTypes := []string{"nginx", "apache", ""}
	found := false
	for _, vt := range validTypes {
		if serverType == vt {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("detectWebServer() = %s, 不是有效类型", serverType)
	}
}

// TestConfirm 测试确认提示（仅验证函数签名）
func TestConfirm(t *testing.T) {
	// confirm 函数需要交互式输入，这里只验证函数存在
	// 实际测试需要模拟 stdin
	_ = confirm
}

// TestScanSites 测试站点扫描（仅验证函数签名）
func TestScanSites(t *testing.T) {
	// scanSites 依赖系统环境，这里只验证函数存在
	_ = scanSites
}

// TestInstallService 测试服务安装（仅验证函数签名）
func TestInstallService(t *testing.T) {
	// installService 需要 root 权限，这里只验证函数存在
	_ = installService
}
