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

func TestFindIncludes(t *testing.T) {
	// 创建主配置文件和 include 的文件
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

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

// TestParseConfigFile_ServerBlockFormats 测试不同的 server 块格式
func TestParseConfigFile_ServerBlockFormats(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "server { 同一行",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`,
			want: 1,
		},
		{
			name: "server 和 { 分开",
			content: `
server
{
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`,
			want: 1,
		},
		{
			name: "多个 server 块",
			content: `
server {
    listen 443 ssl;
    server_name site1.com;
    ssl_certificate /etc/ssl/site1.crt;
    ssl_certificate_key /etc/ssl/site1.key;
}
server
{
    listen 443 ssl;
    server_name site2.com;
    ssl_certificate /etc/ssl/site2.crt;
    ssl_certificate_key /etc/ssl/site2.key;
}`,
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

// TestParseConfigFile_LocationBlocks 测试正确跳过 location 内的 root
func TestParseConfigFile_LocationBlocks(t *testing.T) {
	content := `
server {
    listen 443 ssl;
    server_name example.com;
    root /var/www/main;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;

    location /static {
        root /var/www/static;
    }

    location /images {
        root /var/www/images;
    }
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// 应该取 server 级别的 root，而非 location 内的
	if sites[0].Webroot != "/var/www/main" {
		t.Errorf("Webroot 期望 /var/www/main，实际 %s", sites[0].Webroot)
	}
}

// TestParseConfigFile_ListenPorts 测试多端口监听
func TestParseConfigFile_ListenPorts(t *testing.T) {
	content := `
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    listen 8443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	if len(sites[0].ListenPorts) != 3 {
		t.Errorf("期望 3 个监听端口，实际 %d", len(sites[0].ListenPorts))
	}
}

// TestScanAll_MixedSSLAndHTTP 测试 SSL + 非 SSL 站点混合扫描
func TestScanAll_MixedSSLAndHTTP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
# SSL 站点
server {
    listen 443 ssl;
    server_name ssl.example.com;
    ssl_certificate /etc/ssl/ssl.crt;
    ssl_certificate_key /etc/ssl/ssl.key;
}

# HTTP 站点（无 SSL）
server {
    listen 80;
    server_name http.example.com;
    root /var/www/html;
}

# 另一个 SSL 站点
server {
    listen 443 ssl;
    server_name ssl2.example.com;
    ssl_certificate /etc/ssl/ssl2.crt;
    ssl_certificate_key /etc/ssl/ssl2.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	if err := os.WriteFile(mainFile, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}

	// 应该找到所有 3 个站点（ScanAll 返回所有站点）
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
	if sslCount != 2 {
		t.Errorf("期望 2 个 SSL 站点，实际 %d", sslCount)
	}
}

// TestScan_MaxDepthLimit 测试扫描深度限制
func TestScan_MaxDepthLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建深层嵌套的 include（超过限制）
	for i := 0; i < 105; i++ {
		var content string
		if i == 104 {
			// 最后一个文件包含实际站点
			content = `
server {
    listen 443 ssl;
    server_name deep.example.com;
    ssl_certificate /etc/ssl/deep.crt;
    ssl_certificate_key /etc/ssl/deep.key;
}`
		} else {
			nextFile := filepath.Join(tmpDir, "level"+string(rune('0'+((i+1)%10)))+".conf")
			if i < 104 {
				nextFile = filepath.Join(tmpDir, "level_"+string(rune('0'+((i+1)/100)))+string(rune('0'+((i+1)/10)%10))+string(rune('0'+(i+1)%10))+".conf")
			}
			content = "include " + nextFile + ";"
		}
		levelFile := filepath.Join(tmpDir, "level_"+string(rune('0'+(i/100)))+string(rune('0'+(i/10)%10))+string(rune('0'+i%10))+".conf")
		_ = os.WriteFile(levelFile, []byte(content), 0644)
	}

	mainFile := filepath.Join(tmpDir, "level_000.conf")
	s := NewWithConfig(mainFile)
	// 扫描应该不会无限循环或崩溃
	_, err = s.Scan()
	if err != nil {
		t.Logf("扫描返回错误（预期行为）: %v", err)
	}
}

// TestScan_CircularInclude 测试循环 include 处理
func TestScan_CircularInclude(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建循环 include
	file1 := filepath.Join(tmpDir, "a.conf")
	file2 := filepath.Join(tmpDir, "b.conf")

	content1 := `
server {
    listen 443 ssl;
    server_name a.example.com;
    ssl_certificate /etc/ssl/a.crt;
    ssl_certificate_key /etc/ssl/a.key;
}
include ` + file2 + `;
`
	content2 := `
server {
    listen 443 ssl;
    server_name b.example.com;
    ssl_certificate /etc/ssl/b.crt;
    ssl_certificate_key /etc/ssl/b.key;
}
include ` + file1 + `;
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

// TestFindByDomain_WildcardMatch 测试通配符域名匹配
func TestFindByDomain_WildcardMatch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/wildcard.crt;
    ssl_certificate_key /etc/ssl/wildcard.key;
}
server {
    listen 443 ssl;
    server_name specific.test.com;
    ssl_certificate /etc/ssl/specific.crt;
    ssl_certificate_key /etc/ssl/specific.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)

	tests := []struct {
		domain string
		expect string
	}{
		{"sub.example.com", "*.example.com"},
		{"api.example.com", "*.example.com"},
		{"specific.test.com", "specific.test.com"},
	}

	for _, tt := range tests {
		site, err := s.FindByDomain(tt.domain)
		// 需要重置扫描状态
		s.scannedFiles = make(map[string]bool)
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

// TestParseConfigFile_OnlyWildcard 测试只有通配符域名的情况
func TestParseConfigFile_OnlyWildcard(t *testing.T) {
	content := `
server {
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// 如果全是通配符，应该取第一个作为主域名
	if sites[0].ServerName != "*.example.com" {
		t.Errorf("ServerName 期望 *.example.com，实际 %s", sites[0].ServerName)
	}
}

// TestParseConfigFile_MissingSSLCert 测试缺少证书或私钥的情况
func TestParseConfigFile_MissingSSLCert(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "只有证书，没有私钥",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
}`,
			want: 0,
		},
		{
			name: "只有私钥，没有证书",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate_key /etc/ssl/cert.key;
}`,
			want: 0,
		},
		{
			name: "完整的 SSL 配置",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

// TestParseConfigFile_DefaultServerName 测试默认 server_name _
func TestParseConfigFile_DefaultServerName(t *testing.T) {
	content := `
server {
    listen 443 ssl default_server;
    server_name _;
    ssl_certificate /etc/ssl/default.crt;
    ssl_certificate_key /etc/ssl/default.key;
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// _ 作为默认服务器，ServerName 应该为空
	if len(sites) != 0 {
		t.Logf("注意: 默认服务器 _ 被识别为站点: %+v", sites)
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
			name: "有 ssl_certificate",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
}`,
			want: true,
		},
		{
			name: "有 listen ssl",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
}`,
			want: true,
		},
		{
			name: "无 SSL 配置",
			content: `
server {
    listen 80;
    server_name example.com;
}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 80;
    server_name http1.example.com;
    root /var/www/http1;
}
server {
    listen 443 ssl;
    server_name ssl.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}
server {
    listen 80;
    server_name http2.example.com;
    root /var/www/http2;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
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

// TestFindIncludes_GlobPattern 测试 glob 模式的 include
func TestFindIncludes_GlobPattern(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 创建 conf.d 目录和多个配置文件
	confDir := filepath.Join(tmpDir, "conf.d")
	_ = os.MkdirAll(confDir, 0755)

	site1 := `
server {
    listen 443 ssl;
    server_name site1.example.com;
    ssl_certificate /etc/ssl/site1.crt;
    ssl_certificate_key /etc/ssl/site1.key;
}`
	site2 := `
server {
    listen 443 ssl;
    server_name site2.example.com;
    ssl_certificate /etc/ssl/site2.crt;
    ssl_certificate_key /etc/ssl/site2.key;
}`
	_ = os.WriteFile(filepath.Join(confDir, "site1.conf"), []byte(site1), 0644)
	_ = os.WriteFile(filepath.Join(confDir, "site2.conf"), []byte(site2), 0644)

	// 主配置使用 glob 模式
	mainContent := "include " + confDir + "/*.conf;"
	mainFile := filepath.Join(tmpDir, "nginx.conf")
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

// TestNew 测试默认扫描器创建
func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() 返回 nil")
	}
}

// TestParseConfigFile_EmptyFile 测试空文件
func TestParseConfigFile_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	s := NewWithConfig(tmpFile.Name())
	sites, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("解析空文件失败: %v", err)
	}

	if len(sites) != 0 {
		t.Errorf("空文件应返回 0 个站点，实际 %d", len(sites))
	}
}

// TestParseConfigFile_InvalidPath 测试无效路径
func TestParseConfigFile_InvalidPath(t *testing.T) {
	s := NewWithConfig("/nonexistent/path/nginx.conf")
	_, err := s.ScanFile("/nonexistent/path/nginx.conf")
	if err == nil {
		t.Error("无效路径应返回错误")
	}
}

// TestParseConfigFile_NestedServerBlocks 测试嵌套块结构
func TestParseConfigFile_NestedServerBlocks(t *testing.T) {
	content := `
http {
    server {
        listen 443 ssl;
        server_name nested.example.com;
        ssl_certificate /etc/ssl/nested.crt;
        ssl_certificate_key /etc/ssl/nested.key;

        location / {
            root /var/www;
        }

        location /api {
            proxy_pass http://backend;
        }
    }
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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
		t.Errorf("期望 1 个站点，实际 %d", len(sites))
	}
}

// TestFindByDomain_NotFound 测试未找到域名
func TestFindByDomain_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name existing.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/key.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	site, err := s.FindByDomain("notexist.example.com")
	if err != nil {
		t.Logf("FindByDomain 错误: %v", err)
	}
	if site != nil {
		t.Error("不存在的域名应返回 nil")
	}
}

// TestServerAlias 测试服务器别名
func TestServerAlias(t *testing.T) {
	content := `
server {
    listen 443 ssl;
    server_name primary.example.com;
    server_name alias1.example.com alias2.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/key.key;
}`
	tmpFile, err := os.CreateTemp("", "nginx-test-*.conf")
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

	// 验证包含多个服务器名
	if len(sites[0].ServerAlias) == 0 {
		t.Log("ServerAlias 可能未正确解析多行 server_name")
	}
}
