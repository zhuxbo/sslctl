// Package installer Nginx HTTPS 安装器测试
package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewNginxInstaller 测试创建安装器
func TestNewNginxInstaller(t *testing.T) {
	installer := NewNginxInstaller(
		"/etc/nginx/sites-enabled/test.conf",
		"/etc/ssl/certs/test.crt",
		"/etc/ssl/private/test.key",
		"test.example.com",
		"",
	)

	if installer == nil {
		t.Fatal("NewNginxInstaller 返回 nil")
	}

	if installer.configPath != "/etc/nginx/sites-enabled/test.conf" {
		t.Errorf("configPath = %s, 期望 /etc/nginx/sites-enabled/test.conf", installer.configPath)
	}

	if installer.certPath != "/etc/ssl/certs/test.crt" {
		t.Errorf("certPath = %s, 期望 /etc/ssl/certs/test.crt", installer.certPath)
	}

	if installer.keyPath != "/etc/ssl/private/test.key" {
		t.Errorf("keyPath = %s, 期望 /etc/ssl/private/test.key", installer.keyPath)
	}

	if installer.serverName != "test.example.com" {
		t.Errorf("serverName = %s, 期望 test.example.com", installer.serverName)
	}

	// 空命令时不设默认值（由调用方决定）
	if installer.testCommand != "" {
		t.Errorf("testCommand = %s, 期望空字符串", installer.testCommand)
	}
}

// TestNewNginxInstaller_CustomTestCommand 测试自定义测试命令
func TestNewNginxInstaller_CustomTestCommand(t *testing.T) {
	installer := NewNginxInstaller(
		"/etc/nginx/test.conf",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"example.com",
		"docker exec nginx nginx -t",
	)

	if installer.testCommand != "docker exec nginx nginx -t" {
		t.Errorf("testCommand = %s, 期望 docker exec nginx nginx -t", installer.testCommand)
	}
}

// TestHasSSLConfig 测试 SSL 配置检测
func TestHasSSLConfig(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		serverName string
		want       bool
	}{
		{
			name: "无 SSL 配置",
			content: `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`,
			serverName: "example.com",
			want:       false,
		},
		{
			name: "已有 SSL 配置",
			content: `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/key.key;
}`,
			serverName: "example.com",
			want:       true,
		},
		{
			name: "不同域名有 SSL",
			content: `
server {
    listen 443 ssl;
    server_name other.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/key.key;
}
server {
    listen 80;
    server_name example.com;
}`,
			serverName: "example.com",
			want:       false,
		},
		{
			name: "注释中的 SSL 配置",
			content: `
server {
    listen 80;
    server_name example.com;
    # ssl_certificate /etc/ssl/cert.crt;
    # ssl_certificate_key /etc/ssl/key.key;
}`,
			serverName: "example.com",
			want:       false,
		},
		{
			name: "多 server 块，目标有 SSL",
			content: `
server {
    listen 80;
    server_name first.com;
}
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
}`,
			serverName: "example.com",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer := NewNginxInstaller("", "", "", tt.serverName, "")
			got := installer.hasSSLConfig(tt.content)
			if got != tt.want {
				t.Errorf("hasSSLConfig() = %v, 期望 %v", got, tt.want)
			}
		})
	}
}

// TestAddSSLConfig 测试添加 SSL 配置
func TestAddSSLConfig(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "基本 HTTP 站点添加 SSL",
			content: `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`,
			wantContains: []string{
				"listen 443 ssl;",
				"listen [::]:443 ssl;",
				"ssl_certificate",
				"ssl_certificate_key",
				"ssl_protocols TLSv1.2 TLSv1.3;",
			},
		},
		{
			name: "非 80 端口不添加 SSL",
			content: `
server {
    listen 8080;
    server_name example.com;
    root /var/www/html;
}`,
			wantNotContain: []string{
				"listen 443 ssl;",
				"ssl_certificate",
			},
		},
		{
			name: "IPv6 监听",
			content: `
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    root /var/www/html;
}`,
			wantContains: []string{
				"listen 443 ssl;",
				"listen [::]:443 ssl;",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer := NewNginxInstaller(
				"",
				"/etc/ssl/cert.crt",
				"/etc/ssl/key.key",
				"example.com",
				"",
			)

			result, err := installer.addSSLConfig(tt.content)
			if err != nil {
				t.Fatalf("addSSLConfig() error = %v", err)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("结果应包含 %s", want)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(result, notWant) {
					t.Errorf("结果不应包含 %s", notWant)
				}
			}
		})
	}
}

// TestGetIndent 测试缩进检测
func TestGetIndent(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "4 空格缩进",
			line: "    listen 80;",
			want: "    ",
		},
		{
			name: "Tab 缩进",
			line: "\tlisten 80;",
			want: "\t",
		},
		{
			name: "无缩进",
			line: "listen 80;",
			want: "",
		},
		{
			name: "混合缩进",
			line: "  \t  listen 80;",
			want: "  \t  ",
		},
		{
			name: "空行",
			line: "",
			want: "",
		},
		{
			name: "纯空白行",
			line: "    ",
			want: "",  // getIndent 遍历到非空白字符时返回，纯空白行返回空
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer := &NginxInstaller{}
			got := installer.getIndent(tt.line)
			if got != tt.want {
				t.Errorf("getIndent() = %q, 期望 %q", got, tt.want)
			}
		})
	}
}

// TestInsertSSLDirectives 测试插入 SSL 指令
func TestInsertSSLDirectives(t *testing.T) {
	installer := NewNginxInstaller(
		"",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"example.com",
		"",
	)

	lines := []string{
		"server {",
		"    listen 80;",
		"    server_name example.com;",
		"}",
	}

	// 在 listen 80 后插入（索引 1）
	result := installer.insertSSLDirectives(lines, 1)

	// 验证长度增加
	if len(result) <= len(lines) {
		t.Errorf("插入后行数应增加，原 %d，现 %d", len(lines), len(result))
	}

	// 验证包含 SSL 配置
	joined := strings.Join(result, "\n")
	if !strings.Contains(joined, "listen 443 ssl;") {
		t.Error("应包含 listen 443 ssl;")
	}
	if !strings.Contains(joined, "ssl_certificate /etc/ssl/cert.crt;") {
		t.Error("应包含证书路径")
	}
	if !strings.Contains(joined, "ssl_certificate_key /etc/ssl/key.key;") {
		t.Error("应包含私钥路径")
	}
}

// TestBackup 测试备份功能
func TestBackup(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")
	content := "original content"

	installer := NewNginxInstaller(configPath, "", "", "", "")

	backupPath, err := installer.backup(content)
	if err != nil {
		t.Fatalf("backup() error = %v", err)
	}

	// 验证备份文件存在
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("备份文件不存在")
	}

	// 验证备份内容
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("读取备份文件失败: %v", err)
	}

	if string(data) != content {
		t.Errorf("备份内容 = %s, 期望 %s", string(data), content)
	}

	// 验证备份文件名格式
	if !strings.Contains(backupPath, ".bak") {
		t.Error("备份文件应包含 .bak 后缀")
	}
}

// TestRollback 测试回滚功能
func TestRollback(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "test.conf")
	backupPath := filepath.Join(tmpDir, "test.conf.backup")

	// 创建备份文件
	backupContent := "backup content"
	if err := os.WriteFile(backupPath, []byte(backupContent), 0644); err != nil {
		t.Fatalf("创建备份文件失败: %v", err)
	}

	// 创建当前配置文件
	currentContent := "current content"
	if err := os.WriteFile(configPath, []byte(currentContent), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(configPath, "", "", "", "")

	// 执行回滚
	if err := installer.Rollback(backupPath); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	// 验证配置已回滚
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}

	if string(data) != backupContent {
		t.Errorf("回滚后内容 = %s, 期望 %s", string(data), backupContent)
	}
}

// TestInstallResult 测试安装结果结构
func TestInstallResult(t *testing.T) {
	// 未修改
	noModify := &InstallResult{
		BackupPath: "",
		Modified:   false,
	}
	if noModify.Modified {
		t.Error("未修改结果的 Modified 应为 false")
	}

	// 已修改
	modified := &InstallResult{
		BackupPath: "/path/to/backup",
		Modified:   true,
	}
	if !modified.Modified {
		t.Error("已修改结果的 Modified 应为 true")
	}
	if modified.BackupPath == "" {
		t.Error("已修改结果应有备份路径")
	}
}

// TestFindHTTPServerBlock 测试查找 HTTP server 块
func TestFindHTTPServerBlock(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建主配置文件
	mainConfig := filepath.Join(tmpDir, "nginx.conf")
	mainContent := `
http {
    include /etc/nginx/conf.d/*.conf;
}
`
	if err := os.WriteFile(mainConfig, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建主配置失败: %v", err)
	}

	// 创建站点配置
	confDir := filepath.Join(tmpDir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("创建 conf.d 目录失败: %v", err)
	}

	siteConfig := filepath.Join(confDir, "site.conf")
	siteContent := `
server {
    listen 80;
    server_name target.example.com;
    root /var/www/html;
}
`
	if err := os.WriteFile(siteConfig, []byte(siteContent), 0644); err != nil {
		t.Fatalf("创建站点配置失败: %v", err)
	}

	// 查找目标 server 块
	found, err := FindHTTPServerBlock(siteConfig, "target.example.com")
	if err != nil {
		t.Fatalf("FindHTTPServerBlock() error = %v", err)
	}

	if found != siteConfig {
		t.Errorf("找到的配置文件 = %s, 期望 %s", found, siteConfig)
	}

	// 查找不存在的 server
	notFound, err := FindHTTPServerBlock(siteConfig, "notexist.example.com")
	if err != nil {
		t.Logf("查找不存在的 server: %v", err)
	}
	if notFound != "" {
		t.Errorf("不应找到不存在的 server，结果 = %s", notFound)
	}
}

// TestFindConfigWithServerName_Include 测试带 include 的查找
func TestFindConfigWithServerName_Include(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建被 include 的文件
	includedPath := filepath.Join(tmpDir, "included.conf")
	includedContent := `
server {
    listen 80;
    server_name included.example.com;
    root /var/www/included;
}
`
	if err := os.WriteFile(includedPath, []byte(includedContent), 0644); err != nil {
		t.Fatalf("创建 included 文件失败: %v", err)
	}

	// 创建主文件
	mainPath := filepath.Join(tmpDir, "main.conf")
	mainContent := `
server {
    listen 80;
    server_name main.example.com;
}
include ` + includedPath + `;
`
	if err := os.WriteFile(mainPath, []byte(mainContent), 0644); err != nil {
		t.Fatalf("创建 main 文件失败: %v", err)
	}

	// 从主文件查找 included server
	found, err := findConfigWithServerName(mainPath, "included.example.com")
	if err != nil {
		t.Fatalf("findConfigWithServerName() error = %v", err)
	}

	if found != includedPath {
		t.Errorf("找到的文件 = %s, 期望 %s", found, includedPath)
	}
}

// TestAddSSLConfig_Listen80Variations 测试各种 listen 80 变体
func TestAddSSLConfig_Listen80Variations(t *testing.T) {
	tests := []struct {
		name       string
		listen     string
		shouldAdd  bool
	}{
		{"标准 listen 80", "listen 80;", true},
		{"带默认服务器", "listen 80 default_server;", true},
		{"IPv6 格式", "listen [::]:80;", true},
		{"0.0.0.0:80", "listen 0.0.0.0:80;", true},
		{"8080 端口", "listen 8080;", false},
		{"18080 端口", "listen 18080;", false},
		{"80 在中间 180", "listen 180;", false},
		// 443 ssl 端口，addSSLConfig 不会添加额外的 listen 443 行，因为 listen80Re 不匹配
		// 但是 listen80Re 检查的是端口 80，所以 443 ssl 应该不匹配添加 SSL 的条件
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `
server {
    ` + tt.listen + `
    server_name example.com;
    root /var/www/html;
}`
			installer := NewNginxInstaller(
				"",
				"/etc/ssl/cert.crt",
				"/etc/ssl/key.key",
				"example.com",
				"",
			)

			result, _ := installer.addSSLConfig(content)

			containsSSL := strings.Contains(result, "listen 443 ssl;")
			if containsSSL != tt.shouldAdd {
				t.Errorf("listen=%s, containsSSL=%v, shouldAdd=%v", tt.listen, containsSSL, tt.shouldAdd)
			}
		})
	}
}

// TestInstall_FileDoesNotExist 测试配置文件不存在
func TestInstall_FileDoesNotExist(t *testing.T) {
	installer := NewNginxInstaller(
		"/nonexistent/path/nginx.conf",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"example.com",
		"",
	)

	_, err := installer.Install()
	if err == nil {
		t.Error("配置文件不存在时应返回错误")
	}
}

// TestInstall_AlreadyHasSSL 测试已有 SSL 配置
func TestInstall_AlreadyHasSSL(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	content := `
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/cert.crt;
    ssl_certificate_key /etc/ssl/key.key;
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(
		configPath,
		"/etc/ssl/new-cert.crt",
		"/etc/ssl/new-key.key",
		"example.com",
		"echo 'skip test'", // 使用简单命令避免实际调用 nginx
	)

	result, err := installer.Install()
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	if result.Modified {
		t.Error("已有 SSL 配置时不应修改")
	}
}

// TestHasSSLConfig_BraceCount 测试大括号计数
func TestHasSSLConfig_BraceCount(t *testing.T) {
	content := `
server {
    listen 80;
    server_name example.com;
    location / {
        if ($request_method = POST) {
            return 405;
        }
    }
}
server {
    listen 443 ssl;
    server_name other.com;
    ssl_certificate /etc/ssl/cert.crt;
}`

	installer := NewNginxInstaller("", "", "", "example.com", "")
	hasSSL := installer.hasSSLConfig(content)

	// example.com 的 server 块没有 SSL
	if hasSSL {
		t.Error("example.com 不应检测到 SSL")
	}

	// other.com 应该有 SSL
	installer2 := NewNginxInstaller("", "", "", "other.com", "")
	hasSSL2 := installer2.hasSSLConfig(content)
	if !hasSSL2 {
		t.Error("other.com 应检测到 SSL")
	}
}

// TestLoadTestdataFile 测试加载 testdata 文件
func TestLoadTestdataFile(t *testing.T) {
	// 获取 testdata 目录
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}

	testdataDir := filepath.Join(wd, "testdata")

	tests := []struct {
		filename   string
		serverName string
		wantSSL    bool
	}{
		{"simple.conf", "example.com", false},
		{"with_ssl.conf", "ssl.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			filePath := filepath.Join(testdataDir, tt.filename)
			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Skipf("无法读取测试文件 %s: %v", filePath, err)
			}

			installer := NewNginxInstaller("", "", "", tt.serverName, "")
			hasSSL := installer.hasSSLConfig(string(content))

			if hasSSL != tt.wantSSL {
				t.Errorf("文件 %s, hasSSL = %v, 期望 %v", tt.filename, hasSSL, tt.wantSSL)
			}
		})
	}
}
