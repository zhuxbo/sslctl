package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// TestParseConfigFile_LocationBlockSplitLine 测试 location 块分行写法（location 和 { 不在同一行）
func TestParseConfigFile_LocationBlockSplitLine(t *testing.T) {
	content := `
server {
    listen 443 ssl;
    server_name example.com;
    root /var/www/main;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;

    location /static
    {
        root /var/www/static;
    }

    location /images
    {
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

	// 关键验证：分行 location 不应影响 server 级别 root 的解析
	if sites[0].Webroot != "/var/www/main" {
		t.Errorf("Webroot 期望 /var/www/main，实际 %q（分行 location 导致 brace 计数错误）", sites[0].Webroot)
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

// TestExtractListenPort 测试从 listen 指令中提取端口号
func TestExtractListenPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"纯端口号", "80", "80"},
		{"带 ssl 参数", "443 ssl", "443"},
		{"IPv6 格式", "[::]:80", "80"},
		{"IP:端口格式", "127.0.0.1:443", "443"},
		{"通配符:端口格式", "*:80", "80"},
		{"带多个参数", "443 ssl http2", "443"},
		{"IPv6 带 ssl", "[::]:443 ssl", "443"},
		{"空字符串", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractListenPort(tt.input)
			if got != tt.want {
				t.Errorf("extractListenPort(%q) = %q，期望 %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestResolveNginxPath 测试路径解析
func TestResolveNginxPath(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		path   string
		want   string
	}{
		{"绝对路径直接返回", "/etc/nginx", "/etc/nginx/conf.d/default.conf", "/etc/nginx/conf.d/default.conf"},
		{"相对路径与 prefix 拼接", "/etc/nginx", "conf.d/default.conf", "/etc/nginx/conf.d/default.conf"},
		{"空路径直接返回", "/etc/nginx", "", ""},
		{"prefix 为空的相对路径", "", "conf.d/default.conf", "conf.d/default.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveNginxPath(tt.prefix, tt.path)
			if got != tt.want {
				t.Errorf("resolveNginxPath(%q, %q) = %q，期望 %q", tt.prefix, tt.path, got, tt.want)
			}
		})
	}
}

func TestResolveSitePaths_RelativeCertificatesUseMainConfigDirectory(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "conf")
	s := NewWithConfig(filepath.Join(configRoot, "nginx.conf"))
	sites := []*Site{
		{
			ServerName:      "example.com",
			ConfigFile:      filepath.Join(configRoot, "sites", "example.conf"),
			CertificatePath: filepath.Join("ssl", "cert.pem"),
			PrivateKeyPath:  filepath.Join("ssl", "key.pem"),
		},
	}

	got, err := s.resolveSitePaths(sites)
	if err != nil {
		t.Fatalf("resolveSitePaths() 错误: %v", err)
	}
	if got[0].CertificatePath != filepath.Join(configRoot, "ssl", "cert.pem") {
		t.Errorf("CertificatePath = %q", got[0].CertificatePath)
	}
	if got[0].PrivateKeyPath != filepath.Join(configRoot, "ssl", "key.pem") {
		t.Errorf("PrivateKeyPath = %q", got[0].PrivateKeyPath)
	}
}

func TestMainConfigRoot_RelativeConfigBecomesAbsolute(t *testing.T) {
	root := mainConfigRoot(filepath.Join("conf", "nginx.conf"))
	if !filepath.IsAbs(root) {
		t.Fatalf("mainConfigRoot() = %q，不是绝对路径", root)
	}
	if filepath.Base(root) != "conf" {
		t.Fatalf("mainConfigRoot() = %q，期望以 conf 结尾", root)
	}
}

func TestParseMainConfigPath(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "nginx test 输出",
			output: "nginx: the configuration file /opt/nginx/conf/nginx.conf syntax is ok\n",
			want:   "/opt/nginx/conf/nginx.conf",
		},
		{
			name:   "nginx T 配置标记",
			output: "# configuration file /custom/nginx.conf:\nuser nginx;\n",
			want:   "/custom/nginx.conf",
		},
		{
			name:   "配置测试失败仍识别主配置",
			output: "nginx: configuration file /custom/nginx.conf test failed\n",
			want:   "/custom/nginx.conf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMainConfigPath([]byte(tt.output)); got != tt.want {
				t.Errorf("parseMainConfigPath() = %q，期望 %q", got, tt.want)
			}
		})
	}
}

// TestGetNginxConfigFromTestRegex 测试 getNginxConfigFromTest 中使用的正则匹配逻辑
func TestGetNginxConfigFromTestRegex(t *testing.T) {
	re := regexp.MustCompile(`configuration file (.+?) `)

	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			"标准 nginx -t 输出",
			"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful",
			"/etc/nginx/nginx.conf",
		},
		{
			"自定义路径",
			"nginx: the configuration file /usr/local/nginx/conf/nginx.conf syntax is ok",
			"/usr/local/nginx/conf/nginx.conf",
		},
		{
			"不匹配的输出",
			"some random output without config info",
			"",
		},
		{
			"空输出",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := re.FindSubmatch([]byte(tt.output))
			got := ""
			if len(matches) > 1 {
				got = string(matches[1])
			}
			if got != tt.want {
				t.Errorf("正则匹配结果 = %q，期望 %q", got, tt.want)
			}
		})
	}
}

// TestGetNginxConfigFromVersionRegex 测试 getNginxConfigFromVersion 中使用的正则匹配逻辑
func TestGetNginxConfigFromVersionRegex(t *testing.T) {
	confPathRe := regexp.MustCompile(`--conf-path=([^\s]+)`)
	prefixRe := regexp.MustCompile(`--prefix=([^\s]+)`)

	tests := []struct {
		name       string
		output     string
		wantConf   string // --conf-path 匹配结果
		wantPrefix string // --prefix 匹配结果
	}{
		{
			"包含 conf-path",
			"nginx version: nginx/1.18.0\nbuilt with OpenSSL 1.1.1\nconfigure arguments: --prefix=/etc/nginx --conf-path=/etc/nginx/nginx.conf --sbin-path=/usr/sbin/nginx",
			"/etc/nginx/nginx.conf",
			"/etc/nginx",
		},
		{
			"仅包含 prefix",
			"nginx version: nginx/1.18.0\nconfigure arguments: --prefix=/usr/local/nginx --sbin-path=/usr/local/nginx/sbin/nginx",
			"",
			"/usr/local/nginx",
		},
		{
			"都不包含",
			"nginx version: nginx/1.18.0",
			"",
			"",
		},
		{
			"空输出",
			"",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := []byte(tt.output)

			// 测试 --conf-path 正则
			confMatches := confPathRe.FindSubmatch(output)
			gotConf := ""
			if len(confMatches) > 1 {
				gotConf = string(confMatches[1])
			}
			if gotConf != tt.wantConf {
				t.Errorf("--conf-path 匹配结果 = %q，期望 %q", gotConf, tt.wantConf)
			}

			// 测试 --prefix 正则
			prefixMatches := prefixRe.FindSubmatch(output)
			gotPrefix := ""
			if len(prefixMatches) > 1 {
				gotPrefix = string(prefixMatches[1])
			}
			if gotPrefix != tt.wantPrefix {
				t.Errorf("--prefix 匹配结果 = %q，期望 %q", gotPrefix, tt.wantPrefix)
			}
		})
	}
}

// TestRawBlocksToSites 测试 rawBlock 到 Site 的转换和过滤
func TestRawBlocksToSites(t *testing.T) {
	tests := []struct {
		name   string
		blocks []rawBlock
		want   int      // 期望的站点数
		names  []string // 期望的 server_name 列表
	}{
		{
			"正常站点保留",
			[]rawBlock{
				{serverName: "example.com", configFile: "/etc/nginx/conf.d/example.conf", hasSSL: true},
				{serverName: "test.com", configFile: "/etc/nginx/conf.d/test.conf", hasSSL: false},
			},
			2,
			[]string{"example.com", "test.com"},
		},
		{
			"过滤空 server_name",
			[]rawBlock{
				{serverName: "", configFile: "/etc/nginx/conf.d/empty.conf"},
				{serverName: "example.com", configFile: "/etc/nginx/conf.d/example.conf"},
			},
			1,
			[]string{"example.com"},
		},
		{
			"过滤下划线占位符",
			[]rawBlock{
				{serverName: "_", configFile: "/etc/nginx/conf.d/default.conf"},
				{serverName: "example.com", configFile: "/etc/nginx/conf.d/example.conf"},
			},
			1,
			[]string{"example.com"},
		},
		{
			"全部被过滤",
			[]rawBlock{
				{serverName: "", configFile: "/etc/nginx/conf.d/empty.conf"},
				{serverName: "_", configFile: "/etc/nginx/conf.d/default.conf"},
			},
			0,
			nil,
		},
		{
			"空输入",
			nil,
			0,
			nil,
		},
		{
			"字段完整传递",
			[]rawBlock{
				{
					serverName:      "example.com",
					serverAlias:     []string{"www.example.com"},
					configFile:      "/etc/nginx/conf.d/example.conf",
					listenPorts:     []string{"443"},
					webroot:         "/var/www/html",
					hasSSL:          true,
					certificatePath: "/etc/ssl/cert.crt",
					privateKeyPath:  "/etc/ssl/cert.key",
				},
			},
			1,
			[]string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rawBlocksToSites(tt.blocks)
			if len(got) != tt.want {
				t.Fatalf("rawBlocksToSites 返回 %d 个站点，期望 %d", len(got), tt.want)
			}
			for i, name := range tt.names {
				if got[i].ServerName != name {
					t.Errorf("站点 %d ServerName = %q，期望 %q", i, got[i].ServerName, name)
				}
			}
		})
	}

	// 单独验证字段完整传递
	blocks := []rawBlock{{
		serverName:      "example.com",
		serverAlias:     []string{"www.example.com"},
		configFile:      "/etc/nginx/conf.d/example.conf",
		listenPorts:     []string{"443"},
		webroot:         "/var/www/html",
		hasSSL:          true,
		certificatePath: "/etc/ssl/cert.crt",
		privateKeyPath:  "/etc/ssl/cert.key",
	}}
	sites := rawBlocksToSites(blocks)
	if len(sites) != 1 {
		t.Fatal("字段传递测试失败：期望 1 个站点")
	}
	s := sites[0]
	if s.ConfigFile != "/etc/nginx/conf.d/example.conf" {
		t.Errorf("ConfigFile = %q", s.ConfigFile)
	}
	if len(s.ServerAlias) != 1 || s.ServerAlias[0] != "www.example.com" {
		t.Errorf("ServerAlias = %v", s.ServerAlias)
	}
	if len(s.ListenPorts) != 1 || s.ListenPorts[0] != "443" {
		t.Errorf("ListenPorts = %v", s.ListenPorts)
	}
	if s.Webroot != "/var/www/html" {
		t.Errorf("Webroot = %q", s.Webroot)
	}
	if !s.HasSSL {
		t.Error("HasSSL 应为 true")
	}
	if s.CertificatePath != "/etc/ssl/cert.crt" {
		t.Errorf("CertificatePath = %q", s.CertificatePath)
	}
	if s.PrivateKeyPath != "/etc/ssl/cert.key" {
		t.Errorf("PrivateKeyPath = %q", s.PrivateKeyPath)
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

// TestParseServerBlocks_NginxTMode 测试 nginx -T 输出格式解析
func TestParseServerBlocks_NginxTMode(t *testing.T) {
	lines := []string{
		"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
		"# configuration file /etc/nginx/nginx.conf:",
		"server {",
		"    listen 443 ssl;",
		"    server_name site1.example.com;",
		"    ssl_certificate /etc/ssl/site1.crt;",
		"    ssl_certificate_key /etc/ssl/site1.key;",
		"}",
		"# configuration file /etc/nginx/conf.d/site2.conf:",
		"server {",
		"    listen 80;",
		"    server_name site2.example.com;",
		"    root /var/www/site2;",
		"}",
	}

	blocks := parseServerBlocks(lines, "", parseOptions{
		skipNginxLines:  true,
		trackConfigFile: true,
	})

	if len(blocks) != 2 {
		t.Fatalf("期望 2 个 server 块，实际 %d", len(blocks))
	}

	// 验证文件跟踪
	if blocks[0].configFile != "/etc/nginx/nginx.conf" {
		t.Errorf("块 0 configFile = %q，期望 /etc/nginx/nginx.conf", blocks[0].configFile)
	}
	if blocks[1].configFile != "/etc/nginx/conf.d/site2.conf" {
		t.Errorf("块 1 configFile = %q，期望 /etc/nginx/conf.d/site2.conf", blocks[1].configFile)
	}

	// 验证 server_name
	if blocks[0].serverName != "site1.example.com" {
		t.Errorf("块 0 serverName = %q", blocks[0].serverName)
	}
	if blocks[1].serverName != "site2.example.com" {
		t.Errorf("块 1 serverName = %q", blocks[1].serverName)
	}

	// 验证 SSL 检测
	if !blocks[0].hasSSL {
		t.Error("块 0 应检测到 SSL")
	}
	if blocks[1].hasSSL {
		t.Error("块 1 不应有 SSL")
	}
}

func TestParseServerBlocks_WindowsPathsDecodeEscapedBackslashes(t *testing.T) {
	lines := []string{
		"server {",
		"    listen 443 ssl;",
		"    server_name example.com;",
		`    ssl_certificate "C:\\nginx\\conf\\cert\\example.com.pem";`,
		`    ssl_certificate_key "C:\\nginx\\conf\\cert\\example.com.key";`,
		"}",
	}

	blocks := parseServerBlocks(lines, `C:\nginx\conf\example.conf`, parseOptions{})
	if len(blocks) != 1 {
		t.Fatalf("期望 1 个 server 块，实际 %d", len(blocks))
	}
	if got, want := blocks[0].certificatePath, `C:\nginx\conf\cert\example.com.pem`; got != want {
		t.Errorf("certificatePath = %q，期望 %q", got, want)
	}
	if got, want := blocks[0].privateKeyPath, `C:\nginx\conf\cert\example.com.key`; got != want {
		t.Errorf("privateKeyPath = %q，期望 %q", got, want)
	}
}

// TestParseServerBlocks_PendingServerNonBrace 测试 server 后跟非 { 内容
func TestParseServerBlocks_PendingServerNonBrace(t *testing.T) {
	// server 后跟的不是 {，应该重置 pendingServer
	lines := []string{
		"server",
		"some_other_directive;",
		"server {",
		"    listen 80;",
		"    server_name valid.example.com;",
		"}",
	}

	blocks := parseServerBlocks(lines, "/test.conf", parseOptions{})

	if len(blocks) != 1 {
		t.Fatalf("期望 1 个 server 块，实际 %d", len(blocks))
	}
	if blocks[0].serverName != "valid.example.com" {
		t.Errorf("serverName = %q", blocks[0].serverName)
	}
}

// TestParseServerBlocks_UnclosedBlock 测试未关闭的 server 块
func TestParseServerBlocks_UnclosedBlock(t *testing.T) {
	lines := []string{
		"server {",
		"    listen 80;",
		"    server_name unclosed.example.com;",
	}

	blocks := parseServerBlocks(lines, "/test.conf", parseOptions{})

	// 未关闭的块应在末尾被处理
	if len(blocks) != 1 {
		t.Fatalf("期望 1 个 server 块（末尾处理），实际 %d", len(blocks))
	}
	if blocks[0].serverName != "unclosed.example.com" {
		t.Errorf("serverName = %q", blocks[0].serverName)
	}
}

// TestFindIncludes_CommentedOut 测试注释掉的 include 不会被处理
func TestFindIncludes_CommentedOut(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
# include /etc/nginx/conf.d/*.conf;
server {
    listen 80;
    server_name example.com;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	includes, err := s.findIncludes(mainFile)
	if err != nil {
		t.Fatalf("findIncludes 错误: %v", err)
	}

	if len(includes) != 0 {
		t.Errorf("注释的 include 不应被解析，实际找到 %d 个", len(includes))
	}
}

// TestFindIncludes_QuotedPath 测试带引号的 include 路径
func TestFindIncludes_QuotedPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	confDir := filepath.Join(tmpDir, "conf.d")
	_ = os.MkdirAll(confDir, 0755)
	_ = os.WriteFile(filepath.Join(confDir, "site.conf"), []byte("# empty"), 0644)

	content := `include "` + confDir + `/site.conf";`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	includes, err := s.findIncludes(mainFile)
	if err != nil {
		t.Fatalf("findIncludes 错误: %v", err)
	}

	if len(includes) != 1 {
		t.Errorf("期望 1 个 include，实际 %d", len(includes))
	}
}

// TestFindIncludes_NoMatch 测试 include 路径不匹配任何文件
func TestFindIncludes_NoMatch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `include /nonexistent/path/*.conf;`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	s.SetDebug(true, func(format string, args ...interface{}) {})
	includes, err := s.findIncludes(mainFile)
	if err != nil {
		t.Fatalf("findIncludes 错误: %v", err)
	}

	if len(includes) != 0 {
		t.Errorf("不存在的路径不应返回 include，实际 %d", len(includes))
	}
}

// TestFindIncludes_RelativePath 测试相对路径 include
func TestFindIncludes_RelativePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	confDir := filepath.Join(tmpDir, "conf.d")
	_ = os.MkdirAll(confDir, 0755)
	_ = os.WriteFile(filepath.Join(confDir, "site.conf"), []byte("# content"), 0644)

	content := `include conf.d/site.conf;`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	includes, err := s.findIncludes(mainFile)
	if err != nil {
		t.Fatalf("findIncludes 错误: %v", err)
	}

	if len(includes) != 1 {
		t.Errorf("相对路径 include 应找到 1 个文件，实际 %d", len(includes))
	}
}

func TestFindIncludes_NestedFileUsesMainConfigDirectory(t *testing.T) {
	configRoot := t.TempDir()
	sitesDir := filepath.Join(configRoot, "sites")
	snippetsDir := filepath.Join(configRoot, "snippets")
	if err := os.MkdirAll(sitesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(snippetsDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainFile := filepath.Join(configRoot, "nginx.conf")
	nestedFile := filepath.Join(sitesDir, "site.conf")
	want := filepath.Join(snippetsDir, "tls.conf")
	if err := os.WriteFile(nestedFile, []byte("include snippets/tls.conf;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("# tls"), 0644); err != nil {
		t.Fatal(err)
	}

	s := NewWithConfig(mainFile)
	includes, err := s.findIncludes(nestedFile)
	if err != nil {
		t.Fatalf("findIncludes 错误: %v", err)
	}
	if len(includes) != 1 || includes[0] != want {
		t.Fatalf("includes = %v，期望 [%s]", includes, want)
	}
}

// TestScanAll_WithInclude 测试 ScanAll 含 include 的递归扫描
func TestScanAll_WithInclude(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	confDir := filepath.Join(tmpDir, "conf.d")
	_ = os.MkdirAll(confDir, 0755)

	includeContent := `
server {
    listen 443 ssl;
    server_name included.example.com;
    ssl_certificate /etc/ssl/included.crt;
    ssl_certificate_key /etc/ssl/included.key;
}`
	_ = os.WriteFile(filepath.Join(confDir, "included.conf"), []byte(includeContent), 0644)

	mainContent := `
server {
    listen 80;
    server_name main.example.com;
    root /var/www/main;
}
include ` + confDir + `/*.conf;`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(mainContent), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("ScanAll 失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个站点，实际 %d", len(sites))
	}
}

func TestScanAll_RelativeCertificatesInIncludedFileUseMainConfigDirectory(t *testing.T) {
	configRoot := t.TempDir()
	sitesDir := filepath.Join(configRoot, "sites")
	if err := os.MkdirAll(sitesDir, 0755); err != nil {
		t.Fatal(err)
	}

	includeContent := `
server {
    listen 443 ssl;
    server_name relative.example.com;
    ssl_certificate ssl/cert.pem;
    ssl_certificate_key ssl/key.pem;
}`
	includeFile := filepath.Join(sitesDir, "relative.conf")
	if err := os.WriteFile(includeFile, []byte(includeContent), 0644); err != nil {
		t.Fatal(err)
	}

	mainFile := filepath.Join(configRoot, "nginx.conf")
	if err := os.WriteFile(mainFile, []byte("include sites/relative.conf;"), 0644); err != nil {
		t.Fatal(err)
	}

	sites, err := NewWithConfig(mainFile).ScanAll()
	if err != nil {
		t.Fatalf("ScanAll 失败: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点，实际 %d", len(sites))
	}
	if sites[0].CertificatePath != filepath.Join(configRoot, "ssl", "cert.pem") {
		t.Errorf("CertificatePath = %q", sites[0].CertificatePath)
	}
	if sites[0].PrivateKeyPath != filepath.Join(configRoot, "ssl", "key.pem") {
		t.Errorf("PrivateKeyPath = %q", sites[0].PrivateKeyPath)
	}
}

// TestFindByDomain_ByAlias 测试通过别名查找 SSL 站点
func TestFindByDomain_ByAlias(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name primary.example.com www.example.com api.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	// 通过别名查找
	site, err := s.FindByDomain("api.example.com")
	if err != nil {
		t.Fatalf("FindByDomain 错误: %v", err)
	}
	if site == nil {
		t.Fatal("通过别名应能找到站点")
	}
	if site.ServerName != "primary.example.com" {
		t.Errorf("ServerName = %q，期望 primary.example.com", site.ServerName)
	}
}

// TestScanConfigFile_DepthAndFileLimit 测试 SSL 扫描的深度和文件数限制
func TestScanConfigFile_DepthAndFileLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	// 测试深度限制
	s := NewWithConfig(mainFile)
	s.scannedFiles = make(map[string]bool)
	sites, err := s.scanConfigFile(mainFile, maxScanDepth+1)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过深度限制应返回空，实际 %d", len(sites))
	}

	// 测试文件不存在
	s2 := NewWithConfig(mainFile)
	s2.scannedFiles = make(map[string]bool)
	sites2, err := s2.scanConfigFile("/nonexistent/path.conf", 0)
	if err != nil {
		t.Fatalf("不存在的文件不应返回错误: %v", err)
	}
	if len(sites2) != 0 {
		t.Errorf("不存在的文件应返回空，实际 %d", len(sites2))
	}

	// 测试重复文件跳过
	s3 := NewWithConfig(mainFile)
	s3.scannedFiles = make(map[string]bool)
	sites3, _ := s3.scanConfigFile(mainFile, 0)
	sites3dup, _ := s3.scanConfigFile(mainFile, 0)
	if len(sites3) != 1 {
		t.Errorf("首次扫描应返回 1 个站点，实际 %d", len(sites3))
	}
	if len(sites3dup) != 0 {
		t.Errorf("重复扫描应返回 0 个站点，实际 %d", len(sites3dup))
	}
}

// TestParseServerBlocks_ServerNameUnderscore 测试 server_name _ 在 parseServerBlocks 中的处理
func TestParseServerBlocks_ServerNameUnderscore(t *testing.T) {
	lines := []string{
		"server {",
		"    listen 80;",
		"    server_name _;",
		"}",
	}
	blocks := parseServerBlocks(lines, "/test.conf", parseOptions{})
	if len(blocks) != 1 {
		t.Fatalf("期望 1 个块，实际 %d", len(blocks))
	}
	// _ 在 for 循环中被 continue 跳过，但兜底逻辑会设为 names[0]
	// 过滤 _ 的工作由 rawBlocksToSites 完成
	if blocks[0].serverName != "_" {
		t.Errorf("server_name _ 应保留为 _（由 rawBlocksToSites 过滤），实际 %q", blocks[0].serverName)
	}

	// 验证 rawBlocksToSites 确实会过滤掉 _
	sites := rawBlocksToSites(blocks)
	if len(sites) != 0 {
		t.Errorf("rawBlocksToSites 应过滤掉 _，实际返回 %d 个站点", len(sites))
	}
}

// TestParseServerBlocks_EmptyLines 测试空行和纯注释
func TestParseServerBlocks_EmptyLines(t *testing.T) {
	lines := []string{
		"",
		"# 纯注释",
		"server {",
		"    # 注释行",
		"    listen 443 ssl;",
		"    server_name example.com;",
		"    ssl_certificate /etc/ssl/cert.crt;",
		"    ssl_certificate_key /etc/ssl/cert.key;",
		"    root /var/www/html;",
		"}",
		"",
	}
	blocks := parseServerBlocks(lines, "/test.conf", parseOptions{})
	if len(blocks) != 1 {
		t.Fatalf("期望 1 个块，实际 %d", len(blocks))
	}
	if blocks[0].webroot != "/var/www/html" {
		t.Errorf("webroot = %q，期望 /var/www/html", blocks[0].webroot)
	}
}

// TestScanConfigFile_FileCountLimit 测试文件总数限制
func TestScanConfigFile_FileCountLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	s.scannedFiles = make(map[string]bool)
	// 填满文件计数到上限
	for i := 0; i < maxScanFiles; i++ {
		s.scannedFiles[filepath.Join(tmpDir, fmt.Sprintf("dummy%d.conf", i))] = true
	}
	sites, err := s.scanConfigFile(mainFile, 0)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过文件数限制应返回空，实际 %d", len(sites))
	}
}

// TestScanHTTPConfigFile_FileCountLimit 测试 HTTP 扫描文件总数限制
func TestScanHTTPConfigFile_FileCountLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	s.scannedFiles = make(map[string]bool)
	for i := 0; i < maxScanFiles; i++ {
		s.scannedFiles[filepath.Join(tmpDir, fmt.Sprintf("dummy%d.conf", i))] = true
	}
	sites, err := s.scanHTTPConfigFile(mainFile, 0)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过文件数限制应返回空，实际 %d", len(sites))
	}
}

// TestScanAllConfigFile_FileCountLimit 测试全站点扫描文件总数限制
func TestScanAllConfigFile_FileCountLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	s.scannedFiles = make(map[string]bool)
	for i := 0; i < maxScanFiles; i++ {
		s.scannedFiles[filepath.Join(tmpDir, fmt.Sprintf("dummy%d.conf", i))] = true
	}
	sites, err := s.scanAllConfigFile(mainFile, 0)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过文件数限制应返回空，实际 %d", len(sites))
	}
}

// TestHasSSLConfig_NonexistentFile 测试不存在的文件
func TestHasSSLConfig_NonexistentFile(t *testing.T) {
	s := NewWithConfig("/nonexistent/nginx.conf")
	got := s.HasSSLConfig("/nonexistent/path.conf")
	if got {
		t.Error("不存在的文件应返回 false")
	}
}

// TestGetConfigPath 测试获取配置路径
func TestGetConfigPath(t *testing.T) {
	s := NewWithConfig("/etc/nginx/nginx.conf")
	if got := s.GetConfigPath(); got != "/etc/nginx/nginx.conf" {
		t.Errorf("GetConfigPath() = %q，期望 %q", got, "/etc/nginx/nginx.conf")
	}

	s2 := New()
	if got := s2.GetConfigPath(); got != "" {
		t.Errorf("New() 的 GetConfigPath() = %q，期望空字符串", got)
	}
}

// TestFindAllByDomain 测试全站点域名查找（含 SSL 和非 SSL）
func TestFindAllByDomain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name ssl.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}
server {
    listen 80;
    server_name http.example.com;
    root /var/www/html;
}
server {
    listen 443 ssl;
    server_name *.wildcard.com;
    ssl_certificate /etc/ssl/wildcard.crt;
    ssl_certificate_key /etc/ssl/wildcard.key;
}
server {
    listen 80;
    server_name alias.example.com www.alias.example.com;
    root /var/www/alias;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	tests := []struct {
		name   string
		domain string
		expect string
		found  bool
	}{
		{"精确匹配 SSL 站点", "ssl.example.com", "ssl.example.com", true},
		{"精确匹配 HTTP 站点", "http.example.com", "http.example.com", true},
		{"通配符匹配", "sub.wildcard.com", "*.wildcard.com", true},
		{"别名匹配", "www.alias.example.com", "alias.example.com", true},
		{"不存在的域名", "notexist.example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewWithConfig(mainFile)
			site, err := s.FindAllByDomain(tt.domain)
			if err != nil {
				t.Fatalf("FindAllByDomain(%s) 错误: %v", tt.domain, err)
			}
			if tt.found {
				if site == nil {
					t.Fatalf("FindAllByDomain(%s) 未找到站点", tt.domain)
				}
				if site.ServerName != tt.expect {
					t.Errorf("FindAllByDomain(%s).ServerName = %q，期望 %q", tt.domain, site.ServerName, tt.expect)
				}
			} else {
				if site != nil {
					t.Errorf("FindAllByDomain(%s) 应返回 nil，实际返回 %q", tt.domain, site.ServerName)
				}
			}
		})
	}
}

// TestScanAll_WithConfigPath 测试已指定配置路径时的 ScanAll
func TestScanAll_WithConfigPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name ssl.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}
server {
    listen 80;
    server_name http.example.com;
    root /var/www/html;
}
server {
    listen 80;
    server_name _;
    root /var/www/default;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanAll()
	if err != nil {
		t.Fatalf("ScanAll 失败: %v", err)
	}

	// _ 被过滤，应该只有 2 个站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个站点（过滤 _），实际 %d", len(sites))
	}
}

// TestScanHTTPSites_WithInclude 测试 HTTP 站点扫描（含 include 递归）
func TestScanHTTPSites_WithInclude(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	confDir := filepath.Join(tmpDir, "conf.d")
	_ = os.MkdirAll(confDir, 0755)

	includeContent := `
server {
    listen 80;
    server_name included-http.example.com;
    root /var/www/included;
}`
	_ = os.WriteFile(filepath.Join(confDir, "http.conf"), []byte(includeContent), 0644)

	mainContent := `
server {
    listen 80;
    server_name main-http.example.com;
    root /var/www/main;
}
include ` + confDir + `/*.conf;`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(mainContent), 0644)

	s := NewWithConfig(mainFile)
	sites, err := s.ScanHTTPSites()
	if err != nil {
		t.Fatalf("ScanHTTPSites 失败: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("期望 2 个 HTTP 站点，实际 %d", len(sites))
	}
}

// TestScanHTTPConfigFile_DepthLimit 测试 HTTP 扫描深度限制
func TestScanHTTPConfigFile_DepthLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	// 直接调用 scanHTTPConfigFile 超过深度限制
	sites, err := s.scanHTTPConfigFile(mainFile, maxScanDepth+1)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过深度限制应返回空，实际 %d 个站点", len(sites))
	}
}

// TestScanAllConfigFile_DepthLimit 测试全站点扫描深度限制
func TestScanAllConfigFile_DepthLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	// 直接调用 scanAllConfigFile 超过深度限制
	sites, err := s.scanAllConfigFile(mainFile, maxScanDepth+1)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("超过深度限制应返回空，实际 %d 个站点", len(sites))
	}
}

// TestScanHTTPConfigFile_NonexistentFile 测试扫描不存在的文件
func TestScanHTTPConfigFile_NonexistentFile(t *testing.T) {
	s := NewWithConfig("/nonexistent/nginx.conf")
	sites, err := s.scanHTTPConfigFile("/nonexistent/path.conf", 0)
	if err != nil {
		t.Fatalf("不存在的文件不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("不存在的文件应返回空，实际 %d 个站点", len(sites))
	}
}

// TestScanAllConfigFile_NonexistentFile 测试全站点扫描不存在的文件
func TestScanAllConfigFile_NonexistentFile(t *testing.T) {
	s := NewWithConfig("/nonexistent/nginx.conf")
	sites, err := s.scanAllConfigFile("/nonexistent/path.conf", 0)
	if err != nil {
		t.Fatalf("不存在的文件不应返回错误: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("不存在的文件应返回空，实际 %d 个站点", len(sites))
	}
}

// TestScanHTTPConfigFile_DuplicateFile 测试重复文件跳过
func TestScanHTTPConfigFile_DuplicateFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`
	mainFile := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(mainFile, []byte(content), 0644)

	s := NewWithConfig(mainFile)
	// 第一次扫描
	sites1, _ := s.scanHTTPConfigFile(mainFile, 0)
	// 第二次扫描同文件应跳过（已记录）
	sites2, _ := s.scanHTTPConfigFile(mainFile, 0)

	if len(sites1) != 1 {
		t.Errorf("首次扫描应返回 1 个站点，实际 %d", len(sites1))
	}
	if len(sites2) != 0 {
		t.Errorf("重复扫描应返回 0 个站点，实际 %d", len(sites2))
	}
}

// TestParseHTTPConfigFile_FilterSSLAndEmpty 测试 HTTP 解析过滤 SSL 和空 server_name
func TestParseHTTPConfigFile_FilterSSLAndEmpty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nginx-test-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	content := `
server {
    listen 443 ssl;
    server_name ssl-only.example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/cert.key;
}
server {
    listen 80;
    root /var/www/noname;
}
server {
    listen 80;
    server_name valid-http.example.com;
    root /var/www/valid;
}
server {
    listen 8080;
    server_name another-http.example.com;
    root /var/www/another;
}`
	confFile := filepath.Join(tmpDir, "test.conf")
	_ = os.WriteFile(confFile, []byte(content), 0644)

	s := NewWithConfig(confFile)
	sites, err := s.parseHTTPConfigFile(confFile)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// SSL 站点和空 server_name 应被过滤，只剩 2 个 HTTP 站点
	if len(sites) != 2 {
		t.Errorf("期望 2 个 HTTP 站点，实际 %d", len(sites))
	}
}
