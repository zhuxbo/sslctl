package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	// 获取 testdata 目录的绝对路径
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	testdataPath := filepath.Join(wd, "..", "..", "..", "testdata", "apache", "ssl-site.conf")

	s := NewWithConfig(testdataPath)
	sites, err := s.ScanFile(testdataPath)
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望解析出 2 个站点，实际 %d", len(sites))
	}

	// 验证第一个站点
	if len(sites) > 0 {
		site := sites[0]
		if site.ServerName != "example.com" {
			t.Errorf("站点1 ServerName 期望 example.com，实际 %s", site.ServerName)
		}
		if site.CertificatePath != "/etc/ssl/certs/example.com.crt" {
			t.Errorf("站点1 证书路径不正确: %s", site.CertificatePath)
		}
		if site.PrivateKeyPath != "/etc/ssl/private/example.com.key" {
			t.Errorf("站点1 私钥路径不正确: %s", site.PrivateKeyPath)
		}
		if site.ChainPath != "/etc/ssl/certs/example.com.chain.crt" {
			t.Errorf("站点1 证书链路径不正确: %s", site.ChainPath)
		}
	}

	// 验证第二个站点
	if len(sites) > 1 {
		site := sites[1]
		if site.ServerName != "test.example.com" {
			t.Errorf("站点2 ServerName 期望 test.example.com，实际 %s", site.ServerName)
		}
		// 第二个站点没有证书链
		if site.ChainPath != "" {
			t.Errorf("站点2 不应该有证书链，实际: %s", site.ChainPath)
		}
	}
}

func TestParseConfigFile_NoSSL(t *testing.T) {
	// 创建临时配置文件（无 SSL）
	content := `
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 0 {
		t.Errorf("期望 0 个 SSL 站点，实际 %d", len(sites))
	}
}

func TestParseConfigFile_SSLEngineOff(t *testing.T) {
	// 测试 SSL 配置但缺少证书文件
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html
    SSLEngine on
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	// 没有证书文件配置，不应该识别为 SSL 站点
	if len(sites) != 0 {
		t.Errorf("期望 0 个 SSL 站点（缺少证书配置），实际 %d", len(sites))
	}
}

func TestParseConfigFile_QuotedPaths(t *testing.T) {
	// 测试带引号的路径
	content := `
<VirtualHost *:443>
    ServerName "example.com"
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile "/etc/ssl/certs/example.crt"
    SSLCertificateKeyFile '/etc/ssl/private/example.key'
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	// 路径应该去除引号
	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 未正确去除引号: %s", sites[0].ServerName)
	}
	if sites[0].CertificatePath != "/etc/ssl/certs/example.crt" {
		t.Errorf("证书路径未正确去除引号: %s", sites[0].CertificatePath)
	}
	if sites[0].PrivateKeyPath != "/etc/ssl/private/example.key" {
		t.Errorf("私钥路径未正确去除引号: %s", sites[0].PrivateKeyPath)
	}
}

func TestParseConfigFile_Comments(t *testing.T) {
	// 测试注释处理
	content := `
<VirtualHost *:443>
    ServerName example.com
    # SSLCertificateFile /etc/ssl/old.crt
    SSLCertificateFile /etc/ssl/new.crt
    SSLCertificateKeyFile /etc/ssl/new.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	// 应该使用非注释的证书路径
	if sites[0].CertificatePath != "/etc/ssl/new.crt" {
		t.Errorf("证书路径应为新路径，实际: %s", sites[0].CertificatePath)
	}
}

func TestParseConfigFile_CaseInsensitive(t *testing.T) {
	// 测试大小写不敏感
	content := `
<virtualhost *:443>
    servername example.com
    sslcertificatefile /etc/ssl/example.crt
    SSLCERTIFICATEKEYFILE /etc/ssl/example.key
</virtualhost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}
}

func TestFindIncludes(t *testing.T) {
	// 创建主配置文件和 include 的文件
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建 include 的配置文件
	includedContent := `
<VirtualHost *:443>
    ServerName included.example.com
    SSLCertificateFile /etc/ssl/included.crt
    SSLCertificateKeyFile /etc/ssl/included.key
</VirtualHost>
`
	includedFile := filepath.Join(tmpDir, "included.conf")
	if err := os.WriteFile(includedFile, []byte(includedContent), 0644); err != nil {
		t.Fatalf("创建 include 文件失败: %v", err)
	}

	// 创建主配置文件
	mainContent := `
<VirtualHost *:443>
    ServerName main.example.com
    SSLCertificateFile /etc/ssl/main.crt
    SSLCertificateKeyFile /etc/ssl/main.key
</VirtualHost>

Include ` + includedFile + `
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到两个站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点，实际 %d", len(sites))
	}
}

func TestFindIncludes_IncludeOptional(t *testing.T) {
	// 测试 IncludeOptional 指令
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建主配置文件（引用不存在的文件）
	mainContent := `
<VirtualHost *:443>
    ServerName main.example.com
    SSLCertificateFile /etc/ssl/main.crt
    SSLCertificateKeyFile /etc/ssl/main.key
</VirtualHost>

IncludeOptional ` + filepath.Join(tmpDir, "nonexistent.conf") + `
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到一个站点（IncludeOptional 不存在不报错）
	if len(sites) != 1 {
		t.Errorf("期望 1 个站点，实际 %d", len(sites))
	}
}

func TestGetCommonApachePaths(t *testing.T) {
	paths := getCommonApachePaths()
	if len(paths) == 0 {
		t.Error("应该返回至少一个常见路径")
	}
}

func TestListenPort(t *testing.T) {
	// 测试监听端口解析
	content := `
<VirtualHost 192.168.1.1:8443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}

	if sites[0].ListenPort != "192.168.1.1:8443" {
		t.Errorf("ListenPort 期望 192.168.1.1:8443，实际 %s", sites[0].ListenPort)
	}
}

// TestParseConfigFile_ServerAlias 测试 ServerAlias 多域名
func TestParseConfigFile_ServerAlias(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com api.example.com
    ServerAlias admin.example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}

	// 应该有 3 个别名
	if len(sites[0].ServerAlias) != 3 {
		t.Errorf("期望 3 个 ServerAlias，实际 %d: %v", len(sites[0].ServerAlias), sites[0].ServerAlias)
	}
}

// TestParseConfigFile_SSLEngine 测试 SSLEngine on 检测
func TestParseConfigFile_SSLEngine(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", len(sites))
	}
}

// TestScanAll_MixedVHosts 测试混合 SSL/非 SSL VirtualHost
func TestScanAll_MixedVHosts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
# HTTP 站点
<VirtualHost *:80>
    ServerName http.example.com
    DocumentRoot /var/www/http
</VirtualHost>

# HTTPS 站点
<VirtualHost *:443>
    ServerName ssl.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/ssl.crt
    SSLCertificateKeyFile /etc/ssl/ssl.key
</VirtualHost>

# 另一个 HTTP 站点
<VirtualHost *:80>
    ServerName http2.example.com
    DocumentRoot /var/www/http2
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到所有 3 个站点
	if len(sites) != 3 {
		t.Errorf("期望 3 个站点，实际 %d", len(sites))
	}

	// 验证 SSL 标记
	sslCount := 0
	for _, site := range sites {
		if site.HasSSL {
			sslCount++
		}
	}
	if sslCount != 1 {
		t.Errorf("期望 1 个 SSL 站点，实际 %d", sslCount)
	}
}

// TestFindByDomain_WildcardMatch 测试通配符域名匹配
func TestFindByDomain_WildcardMatch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
<VirtualHost *:443>
    ServerName example.com
    ServerAlias *.example.com
    SSLCertificateFile /etc/ssl/wildcard.crt
    SSLCertificateKeyFile /etc/ssl/wildcard.key
</VirtualHost>
<VirtualHost *:443>
    ServerName specific.test.com
    SSLCertificateFile /etc/ssl/specific.crt
    SSLCertificateKeyFile /etc/ssl/specific.key
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)

	tests := []struct {
		domain string
		expect string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"specific.test.com", "specific.test.com"},
	}

	for _, tt := range tests {
		// 重置扫描状态
		s.scannedFiles = make(map[string]bool)
		site, err := s.FindByDomain(tt.domain)
		if err != nil {
			t.Errorf("FindByDomain(%s) 错误: %v", tt.domain, err)
			continue
		}
		if site == nil {
			t.Errorf("FindByDomain(%s) 未找到站点", tt.domain)
			continue
		}
		if site.ServerName != tt.expect {
			t.Errorf("FindByDomain(%s) = %s，期望 %s", tt.domain, site.ServerName, tt.expect)
		}
	}
}

// TestParseConfigFile_ChainFile 测试证书链文件解析
func TestParseConfigFile_ChainFile(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
    SSLCertificateChainFile /etc/ssl/chain.crt
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ChainPath != "/etc/ssl/chain.crt" {
		t.Errorf("ChainPath 期望 /etc/ssl/chain.crt，实际 %s", sites[0].ChainPath)
	}
}

// TestParseConfigFile_DocumentRoot 测试 DocumentRoot 解析
func TestParseConfigFile_DocumentRoot(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].Webroot != "/var/www/example" {
		t.Errorf("Webroot 期望 /var/www/example，实际 %s", sites[0].Webroot)
	}
}

// TestHasSSLConfig 测试 SSL 配置检测
func TestHasSSLConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "有 SSLEngine on",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`,
			want: true,
		},
		{
			name: "有 SSLCertificateFile",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
</VirtualHost>`,
			want: true,
		},
		{
			name: "无 SSL 配置",
			content: `
<VirtualHost *:80>
    ServerName example.com
</VirtualHost>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
			if err != nil {
				t.Fatalf("创建临时文件失败: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			_, _ = tmpFile.WriteString(tt.content)
			_ = tmpFile.Close()

			s := NewWithConfig(tmpFile.Name())
			got := s.HasSSLConfig(tmpFile.Name())
			if got != tt.want {
				t.Errorf("HasSSLConfig() = %v，期望 %v", got, tt.want)
			}
		})
	}
}

// TestScanHTTPSites 测试 HTTP 站点扫描
func TestScanHTTPSites(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
<VirtualHost *:80>
    ServerName http1.example.com
    DocumentRoot /var/www/http1
</VirtualHost>
<VirtualHost *:443>
    ServerName ssl.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>
<VirtualHost *:80>
    ServerName http2.example.com
    DocumentRoot /var/www/http2
</VirtualHost>
`
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanHTTPSites()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到 2 个 HTTP 站点（排除 SSL）
	if len(sites) != 2 {
		t.Errorf("期望 2 个 HTTP 站点，实际 %d", len(sites))
	}
}

// TestSetDebug 测试调试模式设置
func TestSetDebug(t *testing.T) {
	s := New()

	var logOutput string
	logFn := func(format string, args ...interface{}) {
		logOutput = format
	}

	s.SetDebug(true, logFn)
	s.logDebug("test message")

	if logOutput != "test message" {
		t.Errorf("调试日志未正确输出")
	}

	// 关闭调试模式
	s.SetDebug(false, nil)
	logOutput = ""
	s.logDebug("should not appear")

	if logOutput != "" {
		t.Errorf("调试模式关闭后不应有输出")
	}
}

// TestFindIncludes_GlobPattern 测试 glob 模式的 Include
func TestFindIncludes_GlobPattern(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建 sites-enabled 目录和多个配置文件
	sitesDir := filepath.Join(tmpDir, "sites-enabled")
	_ = os.MkdirAll(sitesDir, 0755)

	site1 := `
<VirtualHost *:443>
    ServerName site1.example.com
    SSLCertificateFile /etc/ssl/site1.crt
    SSLCertificateKeyFile /etc/ssl/site1.key
</VirtualHost>
`
	site2 := `
<VirtualHost *:443>
    ServerName site2.example.com
    SSLCertificateFile /etc/ssl/site2.crt
    SSLCertificateKeyFile /etc/ssl/site2.key
</VirtualHost>
`
	_ = os.WriteFile(filepath.Join(sitesDir, "site1.conf"), []byte(site1), 0644)
	_ = os.WriteFile(filepath.Join(sitesDir, "site2.conf"), []byte(site2), 0644)

	// 主配置使用 glob 模式
	mainContent := "Include " + sitesDir + "/*.conf"
	mainFile := filepath.Join(tmpDir, "httpd.conf")
	_ = os.WriteFile(mainFile, []byte(mainContent), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（通过 glob 模式包含），实际 %d", len(sites))
	}
}

// TestScan_CircularInclude 测试循环 Include 处理
func TestScan_CircularInclude(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "apache-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建循环 Include
	file1 := filepath.Join(tmpDir, "a.conf")
	file2 := filepath.Join(tmpDir, "b.conf")

	content1 := `
<VirtualHost *:443>
    ServerName a.example.com
    SSLCertificateFile /etc/ssl/a.crt
    SSLCertificateKeyFile /etc/ssl/a.key
</VirtualHost>
Include ` + file2 + `
`
	content2 := `
<VirtualHost *:443>
    ServerName b.example.com
    SSLCertificateFile /etc/ssl/b.crt
    SSLCertificateKeyFile /etc/ssl/b.key
</VirtualHost>
Include ` + file1 + `
`
	_ = os.WriteFile(file1, []byte(content1), 0644)
	_ = os.WriteFile(file2, []byte(content2), 0644)

	s := NewWithConfig(file1)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该正确处理循环引用，找到 2 个站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（循环引用被正确处理），实际 %d", len(sites))
	}
}

// TestParseConfigFile_NestedDirectoryBlocks 测试嵌套的 Directory 块
func TestParseConfigFile_NestedDirectoryBlocks(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key

    <Directory /var/www/example>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Location /admin>
        Require user admin
    </Location>
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}
}

// TestParseConfigFile_QuotedAngleBracket 测试引号内 < 不会被误判为嵌套标签
func TestParseConfigFile_QuotedAngleBracket(t *testing.T) {
	content := `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/example.crt
    SSLCertificateKeyFile /etc/ssl/example.key
    ErrorDocument 404 "<html><body>Not Found</body></html>"
    <Directory /var/www/example>
        Options Indexes
    </Directory>
</VirtualHost>
`
	tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}

	if sites[0].ServerName != "example.com" {
		t.Errorf("ServerName 期望 example.com，实际 %s", sites[0].ServerName)
	}
}

// TestGetConfigPath 测试获取配置路径
func TestGetConfigPath(t *testing.T) {
	s := NewWithConfig("/etc/apache2/httpd.conf")
	if s.GetConfigPath() != "/etc/apache2/httpd.conf" {
		t.Errorf("GetConfigPath() = %s，期望 /etc/apache2/httpd.conf", s.GetConfigPath())
	}
}

// TestParseConfigFile_MissingCertOrKey 测试缺少证书或私钥
func TestParseConfigFile_MissingCertOrKey(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "只有证书，没有私钥",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
</VirtualHost>`,
			want: 0,
		},
		{
			name: "只有私钥，没有证书",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>`,
			want: 0,
		},
		{
			name: "完整的 SSL 配置",
			content: `
<VirtualHost *:443>
    ServerName example.com
    SSLCertificateFile /etc/ssl/cert.crt
    SSLCertificateKeyFile /etc/ssl/cert.key
</VirtualHost>`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "apache-test-*.conf")
			if err != nil {
				t.Fatalf("创建临时文件失败: %v", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			_, _ = tmpFile.WriteString(tt.content)
			_ = tmpFile.Close()

			s := NewWithConfig(tmpFile.Name())
			sites, err := s.ScanFile(tmpFile.Name())
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if len(sites) != tt.want {
				t.Errorf("期望 %d 个站点，实际 %d", tt.want, len(sites))
			}
		})
	}
}

// TestScanConfigFile_DeepInclude 测试多层嵌套 Include 正确递归处理
func TestScanConfigFile_DeepInclude(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建 3 层嵌套: main.conf → level1.conf → level2.conf
	level2 := filepath.Join(tmpDir, "level2.conf")
	_ = os.WriteFile(level2, []byte(`
<VirtualHost *:443>
    ServerName deep.example.com
    SSLCertificateFile /etc/ssl/deep.crt
    SSLCertificateKeyFile /etc/ssl/deep.key
</VirtualHost>
`), 0644)

	level1 := filepath.Join(tmpDir, "level1.conf")
	_ = os.WriteFile(level1, []byte(`
<VirtualHost *:443>
    ServerName mid.example.com
    SSLCertificateFile /etc/ssl/mid.crt
    SSLCertificateKeyFile /etc/ssl/mid.key
</VirtualHost>
Include `+level2+`
`), 0644)

	main := filepath.Join(tmpDir, "main.conf")
	_ = os.WriteFile(main, []byte(`
<VirtualHost *:443>
    ServerName top.example.com
    SSLCertificateFile /etc/ssl/top.crt
    SSLCertificateKeyFile /etc/ssl/top.key
</VirtualHost>
Include `+level1+`
`), 0644)

	s := NewWithConfig(main)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	if len(sites) != 3 {
		t.Errorf("期望 3 个站点（3 层嵌套），实际 %d", len(sites))
		for _, site := range sites {
			t.Logf("  站点: %s", site.ServerName)
		}
	}
}

// TestScanConfigFile_MaxFilesLimit 测试 maxScanFiles 限制正确截断扫描
func TestScanConfigFile_MaxFilesLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建 main.conf 包含大量 Include
	var includes string
	fileCount := maxScanFiles + 10 // 超出限制
	for i := 0; i < fileCount; i++ {
		confPath := filepath.Join(tmpDir, "site"+filepath.Base(t.Name())+string(rune('A'+i%26))+string(rune('0'+i/26))+".conf")
		content := `
<VirtualHost *:443>
    ServerName site` + filepath.Base(confPath) + `.example.com
    SSLCertificateFile /etc/ssl/` + filepath.Base(confPath) + `.crt
    SSLCertificateKeyFile /etc/ssl/` + filepath.Base(confPath) + `.key
</VirtualHost>
`
		_ = os.WriteFile(confPath, []byte(content), 0644)
		includes += "Include " + confPath + "\n"
	}

	mainConf := filepath.Join(tmpDir, "main.conf")
	_ = os.WriteFile(mainConf, []byte(includes), 0644)

	s := NewWithConfig(mainConf)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该被 maxScanFiles 截断，站点数不超过 maxScanFiles
	if len(s.scannedFiles) > maxScanFiles {
		t.Errorf("扫描文件数 %d 超过限制 %d", len(s.scannedFiles), maxScanFiles)
	}

	// 应该找到一些站点但不是全部
	if len(sites) >= fileCount {
		t.Errorf("站点数 %d 应小于总文件数 %d（被截断）", len(sites), fileCount)
	}
	if len(sites) == 0 {
		t.Error("应至少找到一些站点")
	}
}
