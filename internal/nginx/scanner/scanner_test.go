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
	// 向上查找到项目根目录
	testdataPath := filepath.Join(wd, "..", "..", "..", "testdata", "nginx", "ssl-site.conf")

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
	}

	// 验证第二个站点
	if len(sites) > 1 {
		site := sites[1]
		if site.ServerName != "test.example.com" {
			t.Errorf("站点2 ServerName 期望 test.example.com，实际 %s", site.ServerName)
		}
	}
}

func TestParseConfigFile_NoSSL(t *testing.T) {
	// 创建临时配置文件（无 SSL）
	content := `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}
`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

func TestParseConfigFile_MultipleServerNames(t *testing.T) {
	// 测试多个 server_name
	content := `
server {
    listen 443 ssl;
    server_name example.com www.example.com api.example.com;

    ssl_certificate /etc/ssl/example.crt;
    ssl_certificate_key /etc/ssl/example.key;
}
`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// 应该取第一个非通配符域名
	if sites[0].ServerName != "example.com" {
		t.Errorf("期望 ServerName 为 example.com，实际 %s", sites[0].ServerName)
	}
}

func TestParseConfigFile_WildcardServerName(t *testing.T) {
	// 测试通配符 server_name
	content := `
server {
    listen 443 ssl;
    server_name *.example.com example.com;

    ssl_certificate /etc/ssl/example.crt;
    ssl_certificate_key /etc/ssl/example.key;
}
`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// 应该取第一个非通配符域名
	if sites[0].ServerName != "example.com" {
		t.Errorf("期望 ServerName 为 example.com，实际 %s", sites[0].ServerName)
	}
}

func TestParseConfigFile_QuotedPaths(t *testing.T) {
	// 测试带引号的路径
	content := `
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate "/etc/ssl/certs/example.crt";
    ssl_certificate_key '/etc/ssl/private/example.key';
}
`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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
server {
    listen 443 ssl;
    server_name example.com;
    # ssl_certificate /etc/ssl/old.crt;
    ssl_certificate /etc/ssl/new.crt;
    ssl_certificate_key /etc/ssl/new.key;
}
`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

func TestFindIncludes(t *testing.T) {
	// 创建主配置文件和 include 的文件
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 创建 include 的配置文件
	includedContent := `
server {
    listen 443 ssl;
    server_name included.example.com;
    ssl_certificate /etc/ssl/included.crt;
    ssl_certificate_key /etc/ssl/included.key;
}
`
	includedFile := filepath.Join(tmpDir, "included.conf")
	if err := os.WriteFile(includedFile, []byte(includedContent), 0644); err != nil {
		t.Fatalf("创建 include 文件失败: %v", err)
	}

	// 创建主配置文件
	mainContent := `
server {
    listen 443 ssl;
    server_name main.example.com;
    ssl_certificate /etc/ssl/main.crt;
    ssl_certificate_key /etc/ssl/main.key;
}

include ` + includedFile + `;
`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.Scan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到两个站点：主配置和 include 的
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点，实际 %d", len(sites))
	}
}

func TestGetCommonNginxPaths(t *testing.T) {
	paths := getCommonNginxPaths()
	if len(paths) == 0 {
		t.Error("应该返回至少一个常见路径")
	}
}
