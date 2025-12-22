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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
	defer os.RemoveAll(tmpDir)

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
	defer os.RemoveAll(tmpDir)

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
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	tmpFile.Close()

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
