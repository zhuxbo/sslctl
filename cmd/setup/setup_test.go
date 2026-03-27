// Package setup 一键部署命令测试
package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/webserver"
	"github.com/zhuxbo/sslctl/testdata/certs"
)

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

	if binding.ServerName != "example.com" {
		t.Errorf("ServerName = %s, want example.com", binding.ServerName)
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

	if !strings.HasSuffix(binding.Reload.TestCommand, " -t") || !strings.Contains(binding.Reload.TestCommand, "nginx") {
		t.Errorf("TestCommand = %s, 应包含 nginx 和 -t", binding.Reload.TestCommand)
	}

	if !strings.HasSuffix(binding.Reload.ReloadCommand, " -s reload") || !strings.Contains(binding.Reload.ReloadCommand, "nginx") {
		t.Errorf("ReloadCommand = %s, 应包含 nginx 和 -s reload", binding.Reload.ReloadCommand)
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

	validTestCmds := map[string]bool{
		"apache2ctl -t": true,
		"apachectl -t":  true,
		"httpd -t":      true,
	}
	if !validTestCmds[binding.Reload.TestCommand] {
		t.Errorf("TestCommand = %s, 不在合法命令集合中", binding.Reload.TestCommand)
	}

	validReloadCmds := map[string]bool{
		"apache2ctl graceful": true,
		"apachectl graceful":  true,
		"httpd -k graceful":   true,
	}
	if !validReloadCmds[binding.Reload.ReloadCommand] {
		t.Errorf("ReloadCommand = %s, 不在合法命令集合中", binding.Reload.ReloadCommand)
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
		ServerName: "example.com",
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

	err = deployToSiteBinding(t.Context(), binding, certData, testCert.KeyPEM, nil)
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
		ServerName: "example.com",
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

	err := deployToSiteBinding(t.Context(), binding, certData, testCert.KeyPEM, nil)
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

// TestDeployCert_Apache_Fullchain 测试 Apache fullchain 模式部署（无 ChainFile）
func TestDeployCert_Apache_Fullchain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	testCert, _ := certs.GenerateValidCert("example.com", nil)
	intermediateCert, _ := certs.GenerateValidCert("Intermediate CA", nil)

	binding := &config.SiteBinding{
		ServerName: "example.com",
		ServerType: config.ServerTypeApache,
		Enabled:    true,
		Paths: config.BindingPaths{
			Certificate: certPath,
			PrivateKey:  keyPath,
			// 不设置 ChainFile — fullchain 模式
		},
	}

	certData := &fetcher.CertData{
		Cert:             testCert.CertPEM,
		IntermediateCert: intermediateCert.CertPEM,
	}

	err := deployToSiteBinding(t.Context(), binding, certData, testCert.KeyPEM, nil)
	if err != nil {
		t.Fatalf("deployCert() error = %v", err)
	}

	// 验证证书文件包含 cert + intermediate（fullchain）
	certData2, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}
	certContent := string(certData2)
	if !strings.Contains(certContent, testCert.CertPEM) {
		t.Error("证书文件应包含服务器证书")
	}
	if !strings.Contains(certContent, intermediateCert.CertPEM) {
		t.Error("证书文件应包含中间证书（fullchain 模式）")
	}

	// 不应创建 chain.pem
	chainPath := filepath.Join(tmpDir, "chain.pem")
	if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
		t.Error("fullchain 模式下不应创建独立的 chain.pem")
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
		ServerName: "example.com",
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

	err := deployToSiteBinding(t.Context(), binding, certData, testCert.KeyPEM, nil)
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
	serverType := webserver.DetectWebServerType()
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
		t.Errorf("DetectWebServerType() = %s, 不是有效类型", serverType)
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

// TestInstallSSLConfig_Nginx 测试自动安装 SSL 配置
func TestInstallSSLConfig_Nginx(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/nginx/conf.d/example.conf",
		HasSSL:     false,
		ServerType: config.ServerTypeNginx,
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}

	if result.BackupPath == "" {
		t.Error("installSSLConfig() BackupPath 不应为空")
	}
}

// TestInstallSSLConfig_Apache 测试 Apache 自动安装 SSL 配置
func TestInstallSSLConfig_Apache(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)

	site := &matcher.ScannedSiteInfo{
		ServerName: "example.com",
		ConfigFile: "/etc/apache2/sites-available/example.conf",
		HasSSL:     false,
		ServerType: config.ServerTypeApache,
	}

	result, err := installSSLConfig(site, cfgManager)
	if err != nil {
		t.Fatalf("installSSLConfig() error = %v", err)
	}

	if !result.Modified {
		t.Error("installSSLConfig() Modified 应为 true")
	}
}

// TestMergeSameNameSites 测试同域名站点合并
func TestMergeSameNameSites(t *testing.T) {
	t.Run("80和443分开的server block合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s，期望 /etc/ssl/cert.pem", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot = /var/www/html，实际 %s", result[0].Webroot)
		}
	})

	t.Run("80在前443在后", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     false,
				ServerType: "nginx",
				Webroot:    "/var/www/html",
			},
			{
				ServerName: "example.com",
				ConfigFile: "/etc/nginx/conf.d/example.conf",
				HasSSL:     true,
				CertPath:   "/etc/ssl/cert.pem",
				KeyPath:    "/etc/ssl/key.pem",
				ServerType: "nginx",
			},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("合并后应有 1 个站点，实际 %d", len(result))
		}
		if !result[0].HasSSL {
			t.Error("合并后应保留 SSL 状态")
		}
		if result[0].CertPath != "/etc/ssl/cert.pem" {
			t.Errorf("合并后 CertPath = %s", result[0].CertPath)
		}
		if result[0].Webroot != "/var/www/html" {
			t.Errorf("合并后应继承 Webroot，实际 %s", result[0].Webroot)
		}
	})

	t.Run("不同域名不合并", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
			{ServerName: "b.com", HasSSL: false, ServerType: "nginx"},
		}

		result := mergeSameNameSites(sites)
		if len(result) != 2 {
			t.Fatalf("不同域名不应合并，期望 2 实际 %d", len(result))
		}
	})

	t.Run("单条目不变", func(t *testing.T) {
		sites := []*matcher.ScannedSiteInfo{
			{ServerName: "a.com", HasSSL: true, CertPath: "/a.pem", KeyPath: "/a.key", ServerType: "nginx"},
		}
		result := mergeSameNameSites(sites)
		if len(result) != 1 {
			t.Fatalf("单条目应保持，期望 1 实际 %d", len(result))
		}
	})

	t.Run("空列表", func(t *testing.T) {
		result := mergeSameNameSites(nil)
		if len(result) != 0 {
			t.Fatalf("空列表应返回空，实际 %d", len(result))
		}
	})
}

// TestBuildCertName 测试证书名称生成
func TestBuildCertName(t *testing.T) {
	tests := []struct {
		domain  string
		orderID int
		want    string
	}{
		{"example.com", 12345, "example.com-12345"},
		{"*.example.com", 99999, "WILDCARD.example.com-99999"},
		{"sub.example.com", 1, "sub.example.com-1"},
		{"*.sub.example.com", 100, "WILDCARD.sub.example.com-100"},
	}

	for _, tt := range tests {
		got := buildCertName(tt.domain, tt.orderID)
		if got != tt.want {
			t.Errorf("buildCertName(%q, %d) = %q, want %q", tt.domain, tt.orderID, got, tt.want)
		}
	}
}
