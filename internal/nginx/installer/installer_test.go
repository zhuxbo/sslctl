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
		{
			name: "无 IPv6 不添加 IPv6 443",
			content: `
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
}`,
			wantNotContain: []string{
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

// TestAddSSLConfig_RootInLocation 验证 root 写在 location 块内时（SPA / 前后端分离 / 反代的常见配置），
// SSL 证书指令必须插入 server 块顶层，而非 location 块内。
// 回归：root 在 location 内会让 ssl_certificate 被插进 location 块，nginx 报 "ssl_certificate directive is not allowed here"。
func TestAddSSLConfig_RootInLocation(t *testing.T) {
	content := `map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name 1.14.125.7;

    client_max_body_size 50m;

    location / {
        root /opt/jixun-im/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
    }
}`

	installer := NewNginxInstaller(
		"",
		"/opt/sslctl/certs/cert.pem",
		"/opt/sslctl/certs/key.pem",
		"1.14.125.7",
		"",
	)

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}

	// 必须确实插入了 SSL（存在 listen 80）
	if !strings.Contains(result, "ssl_certificate ") {
		t.Fatalf("结果应包含 ssl_certificate 指令\n%s", result)
	}

	// ssl_certificate 必须位于 server 块顶层（花括号深度 1），不能落入 location 块（深度 ≥ 2）
	if depth := sslCertBraceDepth(result); depth != 1 {
		t.Errorf("ssl_certificate 应在 server 顶层（深度 1），实际深度 %d，会触发 nginx \"not allowed here\"\n%s", depth, result)
	}
}

// sslCertBraceDepth 返回首个 ssl_certificate 指令所在的花括号嵌套深度（server 顶层为 1，location 内为 2）
func sslCertBraceDepth(config string) int {
	depth := 0
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ssl_certificate ") {
			return depth
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
	}
	return -1
}

// TestAddSSLConfig_CommentWithUnbalancedBrace 验证配置注释中含未配对花括号时，
// 不影响 server 块边界判断，SSL 指令仍正确插入 server 块顶层。
// 回归：addSSLConfig 曾把注释里的 { / } 计入 braceCount，导致 server 块边界错乱
// （注释多一个 { 会让块结束永不触发，SSL 完全插不进去）。
func TestAddSSLConfig_CommentWithUnbalancedBrace(t *testing.T) {
	content := `server {
    listen 80;
    server_name example.com;
    root /var/www/html;
    # 旧配置 location /old {
    location / {
        try_files $uri $uri/ =404;
    }
}`

	installer := NewNginxInstaller(
		"",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"example.com",
		"",
	)

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}

	// 注释中的未配对花括号不应阻止 SSL 安装
	if !strings.Contains(result, "ssl_certificate ") {
		t.Fatalf("结果应包含 ssl_certificate 指令（注释中的花括号不应影响块解析）\n%s", result)
	}
	// 注释行必须被原样保留（不能因跳过解析而丢失输出）
	if !strings.Contains(result, "# 旧配置 location /old {") {
		t.Errorf("注释行应被保留\n%s", result)
	}
	// ssl_certificate 必须在 server 块顶层（深度 1）
	if depth := sslCertBraceDepth(result); depth != 1 {
		t.Errorf("ssl_certificate 应在 server 顶层（深度 1），实际深度 %d\n%s", depth, result)
	}
}

// TestAddSSLConfig_MultipleServerBlocksOnlyTargetInjected 验证同文件多个 :80 server 块
// （不同域名共存一个 conf）时，仅目标 server_name 的块被注入证书，其余块保持不变。
func TestAddSSLConfig_MultipleServerBlocksOnlyTargetInjected(t *testing.T) {
	content := `server {
    listen 80;
    server_name a.com www.a.com;
    root /var/www/a;
}

server {
    listen 80;
    server_name b.com;
    root /var/www/b;
}`

	installer := NewNginxInstaller(
		"",
		"/opt/sslctl/certs/a.com/cert.pem",
		"/opt/sslctl/certs/a.com/key.pem",
		"a.com",
		"",
	)

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}

	// 目标块（a.com）应被注入证书
	if !strings.Contains(result, "ssl_certificate /opt/sslctl/certs/a.com/cert.pem;") {
		t.Fatalf("目标块 a.com 应被注入证书\n%s", result)
	}
	// 全文只应出现一次 ssl_certificate（b.com 块不应被注入）
	if n := strings.Count(result, "ssl_certificate "); n != 1 {
		t.Errorf("应仅注入目标块一次 ssl_certificate，实际 %d 次\n%s", n, result)
	}
	// 只应新增一条 listen 443 ssl（b.com 块不应新增）
	if n := strings.Count(result, "listen 443 ssl;"); n != 1 {
		t.Errorf("应仅目标块新增一条 listen 443 ssl，实际 %d 次\n%s", n, result)
	}
	// b.com 块必须原样保留，不得含证书路径
	if strings.Contains(result, "certs/a.com") && strings.Count(result, "certs/a.com") != 2 {
		// cert + key 两行，恰好 2 次
		t.Errorf("目标块应恰好含 cert+key 两行 a.com 路径，实际 %d\n%s", strings.Count(result, "certs/a.com"), result)
	}
}

// TestAddSSLConfig_WildcardServerNameMatches 验证目标域名命中块内通配符 server_name。
func TestAddSSLConfig_WildcardServerNameMatches(t *testing.T) {
	content := `server {
    listen 80;
    server_name *.example.com;
    root /var/www/html;
}`

	installer := NewNginxInstaller(
		"",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"www.example.com",
		"",
	)

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}
	if !strings.Contains(result, "ssl_certificate ") {
		t.Errorf("目标域名应命中通配符 server_name 并被注入\n%s", result)
	}
}

// TestAddSSLConfig_NoServerNameMatch_NotInjected 验证无匹配 server_name 的块不被注入，
// addSSLConfig 返回原文（Install 层据此返回明确错误）。
func TestAddSSLConfig_NoServerNameMatch_NotInjected(t *testing.T) {
	content := `server {
    listen 80;
    server_name other.com;
    root /var/www/html;
}`

	installer := NewNginxInstaller(
		"",
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"target.com",
		"",
	)

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}
	if result != content {
		t.Errorf("server_name 不匹配时不应注入，应返回原文\n%s", result)
	}
}

// TestHasSSLConfig_WildcardBlockDetected 验证 hasSSLConfig 与注入逻辑共用同一匹配谓词：
// 通配符块（*.example.com）已配 SSL 时，目标 www.example.com 应判定"已配置"
// （原精确比较 *.example.com != www.example.com 漏检）。
func TestHasSSLConfig_WildcardBlockDetected(t *testing.T) {
	content := `server {
    listen 80;
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/wild.crt;
    ssl_certificate_key /etc/ssl/wild.key;
    root /var/www/html;
}`

	installer := NewNginxInstaller("", "/etc/ssl/cert.crt", "/etc/ssl/key.key", "www.example.com", "")
	if !installer.hasSSLConfig(content) {
		t.Error("通配符块已配 SSL 且匹配目标域名时应判定已配置（与注入谓词一致）")
	}
}

// TestAddSSLConfig_SkipsBlockWithExistingSSL 复现审核场景：目标块（精确名）无 SSL +
// 通配符块已有 SSL 且含 listen 80。注入必须跳过已配 SSL 的块，
// 否则二次注入 listen 443 ssl 产生 duplicate listen，配置测试失败回滚。
func TestAddSSLConfig_SkipsBlockWithExistingSSL(t *testing.T) {
	content := `server {
    listen 80;
    server_name www.example.com;
    root /var/www/www;
}

server {
    listen 80;
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/wild.crt;
    ssl_certificate_key /etc/ssl/wild.key;
    root /var/www/wild;
}`

	installer := NewNginxInstaller("", "/etc/ssl/new.crt", "/etc/ssl/new.key", "www.example.com", "")
	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}

	// 目标块（无 SSL）应被注入
	if !strings.Contains(result, "ssl_certificate /etc/ssl/new.crt;") {
		t.Fatalf("目标块应被注入新证书\n%s", result)
	}
	// 已配 SSL 的通配符块不得二次注入：全文 listen 443 ssl 应恰好 2 条（原有 1 + 新注入 1）
	if n := strings.Count(result, "listen 443 ssl;"); n != 2 {
		t.Errorf("已配 SSL 的块不应二次注入 listen 443（duplicate listen），期望 2 条实际 %d\n%s", n, result)
	}
	// 通配符块的原证书不应被改动，且新证书只注入一次
	if !strings.Contains(result, "ssl_certificate /etc/ssl/wild.crt;") {
		t.Errorf("通配符块原有 SSL 配置应保持\n%s", result)
	}
	if n := strings.Count(result, "ssl_certificate /etc/ssl/new.crt;"); n != 1 {
		t.Errorf("新证书应只注入目标块一次，实际 %d\n%s", n, result)
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
			want: "", // getIndent 遍历到非空白字符时返回，纯空白行返回空
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
		"    root /var/www;",
		"}",
	}

	// listen 443 在 listen 80 后（索引 1），SSL 配置在 root 后（索引 3）
	// 先插入靠后的 SSL 配置，再插入 listen
	result := installer.insertSSLCertDirectives(lines, 3)
	result = installer.insertListenDirectives(result, 1)

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

// TestInsertSSLDirectives_WindowsPathsUseForwardSlashes 验证写入 Nginx 配置的
// Windows 证书路径不会把 \t 等片段交给 Nginx 当作转义序列解析。
func TestInsertSSLDirectives_WindowsPathsUseForwardSlashes(t *testing.T) {
	installer := NewNginxInstaller(
		"",
		`C:\sslctl\certs\test.sslagent.com\cert.pem`,
		`C:\sslctl\certs\test.sslagent.com\key.pem`,
		"test.sslagent.com",
		"",
	)

	lines := []string{
		"server {",
		"    listen 80;",
		"}",
	}
	joined := strings.Join(installer.insertSSLCertDirectives(lines, 1), "\n")

	if !strings.Contains(joined, "ssl_certificate C:/sslctl/certs/test.sslagent.com/cert.pem;") {
		t.Errorf("Windows 证书路径应使用正斜杠写入 Nginx 配置\n%s", joined)
	}
	if !strings.Contains(joined, "ssl_certificate_key C:/sslctl/certs/test.sslagent.com/key.pem;") {
		t.Errorf("Windows 私钥路径应使用正斜杠写入 Nginx 配置\n%s", joined)
	}
	if strings.Contains(joined, `C:\sslctl`) {
		t.Errorf("Nginx 配置中不应保留 Windows 反斜杠路径\n%s", joined)
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
		name      string
		listen    string
		shouldAdd bool
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

// TestInstall_TargetInjectedDespiteWildcardSSLBlock 回归：hasSSLConfig 谓词放宽为通配符后，
// Install 的全局短路会被"通配符块已配 SSL（无 listen 80）"命中，静默跳过仍可注入的目标块
// （证书写到无人引用的默认路径并误报成功）。修复为先注入后判定：目标块应被注入且 Modified=true。
func TestInstall_TargetInjectedDespiteWildcardSSLBlock(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	content := `server {
    listen 80;
    server_name www.example.com;
    root /var/www/www;
}

server {
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/wild.crt;
    ssl_certificate_key /etc/ssl/wild.key;
    root /var/www/wild;
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(
		configPath,
		"/etc/ssl/new-cert.crt",
		"/etc/ssl/new-key.key",
		"www.example.com",
		"", // 不执行配置测试
	)

	result, err := installer.Install()
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !result.Modified {
		t.Fatal("目标块（listen 80 无 SSL）应被注入，Modified 应为 true（通配符 SSL 块不应导致全局短路）")
	}

	written, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	got := string(written)
	// 目标块被注入新证书
	if !strings.Contains(got, "ssl_certificate /etc/ssl/new-cert.crt;") {
		t.Errorf("目标块应被注入新证书\n%s", got)
	}
	// 通配符块原 SSL 配置不动，新证书只注入一次
	if !strings.Contains(got, "ssl_certificate /etc/ssl/wild.crt;") {
		t.Errorf("通配符块原有 SSL 配置应保持\n%s", got)
	}
	if n := strings.Count(got, "ssl_certificate /etc/ssl/new-cert.crt;"); n != 1 {
		t.Errorf("新证书应只注入一次，实际 %d\n%s", n, got)
	}
	// 全文 listen 443 ssl 应恰好 2 条（通配符块原有 1 + 目标块新增 1）
	if n := strings.Count(got, "listen 443 ssl;"); n != 2 {
		t.Errorf("listen 443 ssl 期望 2 条，实际 %d\n%s", n, got)
	}
}

// TestInstall_TargetAlreadySSL_NotModified 回归：目标站点自身已配 SSL 时
// Install 返回 Modified=false 且不报错（先注入后判定不改变该语义）。
func TestInstall_TargetAlreadySSL_NotModified(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	content := `server {
    listen 80;
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate /etc/ssl/existing.crt;
    ssl_certificate_key /etc/ssl/existing.key;
    root /var/www/www;
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(configPath, "/etc/ssl/new.crt", "/etc/ssl/new.key", "www.example.com", "")

	result, err := installer.Install()
	if err != nil {
		t.Fatalf("目标已有 SSL 时不应报错: %v", err)
	}
	if result.Modified {
		t.Error("目标已有 SSL 时 Modified 应为 false")
	}
	// 配置不应被改动
	written, _ := os.ReadFile(configPath)
	if string(written) != content {
		t.Error("目标已有 SSL 时配置文件不应被改动")
	}
}

// TestInstall_NoListen80_ReturnsError 验证站点没有 listen 80（如非标准端口）时，
// Install 返回明确错误，而非静默 Modified=false。
// 否则 setup/deploy 会以为"无需安装"继续部署证书并误报成功，但 HTTPS 实际未生效。
func TestInstall_NoListen80_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	content := `
server {
    listen 8080;
    server_name example.com;
    root /var/www/html;
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(
		configPath,
		"/etc/ssl/cert.crt",
		"/etc/ssl/key.key",
		"example.com",
		"",
	)

	result, err := installer.Install()
	if err == nil {
		t.Fatalf("非 80 端口站点应返回错误，实际 result=%+v, err=nil", result)
	}

	// 未实际安装时不应残留备份文件
	if baks, _ := filepath.Glob(filepath.Join(tmpDir, "*.bak")); len(baks) > 0 {
		t.Errorf("未安装时不应残留备份文件，实际残留: %v", baks)
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

// TestAddSSLConfig_ExactBlockPreferredOverWildcard 回归：同文件内精确块与通配符块并存时，
// 只向精确匹配的块注入。双向匹配会把本站点证书一并写进 *.example.com 块，
// 使通配符站点被换上只覆盖单域名的证书，其余子域名 HTTPS 证书不匹配。
func TestAddSSLConfig_ExactBlockPreferredOverWildcard(t *testing.T) {
	content := `server {
    listen 80;
    server_name www.example.com;
    root /var/www/www;
}

server {
    listen 80;
    server_name *.example.com;
    root /var/www/wild;
}`

	installer := NewNginxInstaller("", "/etc/ssl/cert.crt", "/etc/ssl/key.key", "www.example.com", "")

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}
	if n := strings.Count(result, "ssl_certificate /etc/ssl/cert.crt;"); n != 1 {
		t.Errorf("证书应只注入精确匹配块一次，实际 %d\n%s", n, result)
	}
	if n := strings.Count(result, "listen 443 ssl;"); n != 1 {
		t.Errorf("listen 443 应只注入一次，实际 %d\n%s", n, result)
	}
	// 通配符块必须原样保留
	wildIdx := strings.Index(result, "server_name *.example.com;")
	if wildIdx < 0 {
		t.Fatalf("通配符块丢失\n%s", result)
	}
	if strings.Contains(result[wildIdx:], "ssl_certificate") {
		t.Errorf("通配符块不应被注入目标站点证书\n%s", result)
	}
}

// TestAddSSLConfig_HTTPRedirectPlusSSLBlock 回归：同名的 "listen 80 跳转块 + listen 443 ssl 块"
// 常见布局下不得向 80 块二次注入，否则产生 duplicate listen 443 导致配置测试失败回滚。
func TestAddSSLConfig_HTTPRedirectPlusSSLBlock(t *testing.T) {
	content := `server {
    listen 80;
    server_name www.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate /etc/ssl/existing.crt;
    ssl_certificate_key /etc/ssl/existing.key;
    root /var/www/www;
}`

	installer := NewNginxInstaller("", "/etc/ssl/new.crt", "/etc/ssl/new.key", "www.example.com", "")

	result, err := installer.addSSLConfig(content)
	if err != nil {
		t.Fatalf("addSSLConfig() error = %v", err)
	}
	if result != content {
		t.Errorf("同名块已配 SSL 时不应再注入\n%s", result)
	}
	if !installer.hasSSLConfig(content) {
		t.Error("hasSSLConfig 应识别同名 443 块已配 SSL")
	}
}

// TestInstall_TargetOnNonStandardPort_WildcardSSLNotShortCircuit 回归：目标站点自身在非 80 端口
// 且未配 SSL、而同域族通配符块已配 SSL 时，Install 必须报明确错误。
// 若因通配符块已有 SSL 而返回 Modified=false，setup/deploy 会误以为"无需安装"继续部署并报成功，
// 但目标站点 HTTPS 实际未生效。
func TestInstall_TargetOnNonStandardPort_WildcardSSLNotShortCircuit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	content := `server {
    listen 8080;
    server_name www.example.com;
    root /var/www/www;
}

server {
    listen 443 ssl;
    server_name *.example.com;
    ssl_certificate /etc/ssl/wild.crt;
    ssl_certificate_key /etc/ssl/wild.key;
}`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("创建配置文件失败: %v", err)
	}

	installer := NewNginxInstaller(configPath, "/etc/ssl/new.crt", "/etc/ssl/new.key", "www.example.com", "")

	result, err := installer.Install()
	if err == nil {
		t.Fatalf("目标块非 80 且无 SSL 时应报错，实际 result=%+v, err=nil", result)
	}
	written, _ := os.ReadFile(configPath)
	if string(written) != content {
		t.Error("报错路径不应改动配置文件")
	}
}
