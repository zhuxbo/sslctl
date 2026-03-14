package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasSSLConfig_NoSSL(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = false for HTTP-only config")
	}
}

func TestHasSSLConfig_HasSSL(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true for matching :443 VirtualHost")
	}
}

func TestHasSSLConfig_DifferentDomain(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:443>
    ServerName other.com
    SSLEngine on
</VirtualHost>`
	if inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = false for different domain")
	}
}

func TestHasSSLConfig_CaseInsensitive(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<virtualhost *:443>
    serverName example.com
    SSLEngine on
</virtualhost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true (case insensitive)")
	}
}

func TestHasSSLConfig_WithAlias(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "www.example.com", "")
	content := `<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    SSLEngine on
</VirtualHost>`
	if !inst.hasSSLConfig(content) {
		t.Error("expected hasSSLConfig = true for matching ServerAlias")
	}
}

func TestExtractVirtualHost80_Simple(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost == "" {
		t.Fatal("expected non-empty VirtualHost")
	}
	if !strings.Contains(vhost, "ServerName example.com") {
		t.Error("expected ServerName in extracted VirtualHost")
	}
}

func TestExtractVirtualHost80_Port8080(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:8080>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost != "" {
		t.Error("expected empty result for :8080 VirtualHost")
	}
}

func TestExtractVirtualHost80_Port180(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:180>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost != "" {
		t.Error("expected empty result for :180 VirtualHost")
	}
}

func TestExtractVirtualHost80_WildcardHost(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "example.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost == "" {
		t.Error("expected non-empty result for wildcard host")
	}
}

func TestExtractVirtualHost80_MultipleVHosts(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "target.com", "")
	content := `<VirtualHost *:80>
    ServerName other.com
    DocumentRoot /var/www/other
</VirtualHost>

<VirtualHost *:80>
    ServerName target.com
    DocumentRoot /var/www/target
</VirtualHost>

<VirtualHost *:80>
    ServerName third.com
    DocumentRoot /var/www/third
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(vhost, "target.com") {
		t.Error("expected target.com in extracted VirtualHost")
	}
	if strings.Contains(vhost, "other.com") {
		t.Error("should not contain other.com")
	}
}

func TestExtractVirtualHost80_NotFound(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "notfound.com", "")
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	vhost, err := inst.extractVirtualHost80(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vhost != "" {
		t.Error("expected empty result for not found domain")
	}
}

func TestGenerateSSLVirtualHost_Basic(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	// 验证端口替换
	if !strings.Contains(result, ":443") {
		t.Error("expected :443 in generated config")
	}
	if strings.Contains(result, ":80") {
		t.Error("should not contain :80")
	}

	// 验证 SSL 指令
	if !strings.Contains(result, "SSLEngine on") {
		t.Error("expected SSLEngine on")
	}
	if !strings.Contains(result, "SSLCertificateFile /ssl/cert.pem") {
		t.Error("expected SSLCertificateFile")
	}
	if !strings.Contains(result, "SSLCertificateKeyFile /ssl/key.pem") {
		t.Error("expected SSLCertificateKeyFile")
	}
	if !strings.Contains(result, "SSLProtocol") {
		t.Error("expected SSLProtocol")
	}

	// 无链时不应包含 ChainFile
	if strings.Contains(result, "SSLCertificateChainFile") {
		t.Error("should not contain SSLCertificateChainFile without chain")
	}
}

func TestGenerateSSLVirtualHost_WithChain(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "/ssl/chain.pem", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	if !strings.Contains(result, "SSLCertificateChainFile /ssl/chain.pem") {
		t.Error("expected SSLCertificateChainFile")
	}
}

func TestGenerateSSLVirtualHost_NoChain(t *testing.T) {
	inst := NewApacheInstaller("", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	vhost80 := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`

	result := inst.generateSSLVirtualHost(vhost80)

	if strings.Contains(result, "SSLCertificateChainFile") {
		t.Error("should not contain SSLCertificateChainFile when chain is empty")
	}
}

func TestInstall_NewHTTPS(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	// 写入初始 HTTP 配置
	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	inst := NewApacheInstaller(configPath, "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	result, err := inst.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if !result.Modified {
		t.Error("expected Modified = true")
	}
	if result.BackupPath == "" {
		t.Error("expected non-empty BackupPath")
	}

	// 验证生成的配置包含 SSL
	newContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(newContent), ":443") {
		t.Error("expected :443 in new config")
	}
	if !strings.Contains(string(newContent), "SSLEngine on") {
		t.Error("expected SSLEngine on in new config")
	}

	// 验证备份文件存在
	if _, err := os.Stat(result.BackupPath); err != nil {
		t.Errorf("backup file not found: %v", err)
	}
}

func TestInstall_AlreadyHasSSL(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	inst := NewApacheInstaller(configPath, "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	result, err := inst.Install()
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if result.Modified {
		t.Error("expected Modified = false when SSL already exists")
	}
}

func TestRollback_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")
	backupPath := filepath.Join(tmpDir, "site.conf.bak")

	originalContent := "original config"
	modifiedContent := "modified config"

	if err := os.WriteFile(configPath, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte(originalContent), 0644); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	inst := NewApacheInstaller(configPath, "", "", "", "", "")
	if err := inst.Rollback(backupPath); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// 验证配置已回滚
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != originalContent {
		t.Errorf("config not rolled back: got %q", string(data))
	}
}

func TestRollback_BackupNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	inst := NewApacheInstaller(configPath, "", "", "", "", "")
	err := inst.Rollback(filepath.Join(tmpDir, "nonexistent.bak"))
	if err == nil {
		t.Error("expected error for nonexistent backup")
	}
}

func TestFindHTTPVirtualHost_Direct(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName target.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := FindHTTPVirtualHost(configPath, "target.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != configPath {
		t.Errorf("result = %q, want %q", result, configPath)
	}
}

func TestFindHTTPVirtualHost_Recursive(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建子目录
	confDir := filepath.Join(tmpDir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// 创建主配置（包含 Include）
	mainConfig := filepath.Join(tmpDir, "apache.conf")
	mainContent := `Include ` + filepath.Join(confDir, "*.conf")
	if err := os.WriteFile(mainConfig, []byte(mainContent), 0644); err != nil {
		t.Fatalf("write main: %v", err)
	}

	// 创建子配置
	subConfig := filepath.Join(confDir, "site.conf")
	subContent := `<VirtualHost *:80>
    ServerName sub.example.com
    DocumentRoot /var/www/sub
</VirtualHost>`
	if err := os.WriteFile(subConfig, []byte(subContent), 0644); err != nil {
		t.Fatalf("write sub: %v", err)
	}

	result, err := FindHTTPVirtualHost(mainConfig, "sub.example.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != subConfig {
		t.Errorf("result = %q, want %q", result, subConfig)
	}
}

func TestFindHTTPVirtualHost_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "site.conf")

	content := `<VirtualHost *:80>
    ServerName other.com
    DocumentRoot /var/www/html
</VirtualHost>`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := FindHTTPVirtualHost(configPath, "notfound.com")
	if err != nil {
		t.Fatalf("FindHTTPVirtualHost: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got %q", result)
	}
}

func TestNewApacheInstaller_DefaultCommand(t *testing.T) {
	inst := NewApacheInstaller("/etc/apache2/sites-available/site.conf", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "")
	if inst.testCommand != "" {
		t.Errorf("testCommand = %q, want empty", inst.testCommand)
	}
}

func TestNewApacheInstaller_CustomCommand(t *testing.T) {
	inst := NewApacheInstaller("/etc/apache2/sites-available/site.conf", "/ssl/cert.pem", "/ssl/key.pem", "", "example.com", "httpd -t")
	if inst.testCommand != "httpd -t" {
		t.Errorf("testCommand = %q, want 'httpd -t'", inst.testCommand)
	}
}

func TestGetIndent(t *testing.T) {
	inst := NewApacheInstaller("", "", "", "", "", "")

	tests := []struct {
		line string
		want string
	}{
		{"    ServerName example.com", "    "},
		{"\tServerName example.com", "\t"},
		{"ServerName example.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := inst.getIndent(tt.line)
		if got != tt.want {
			t.Errorf("getIndent(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}
