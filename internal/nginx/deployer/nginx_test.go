// Package deployer Nginx 部署器测试
package deployer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewNginxDeployer 测试创建 Nginx 部署器
func TestNewNginxDeployer(t *testing.T) {
	d := NewNginxDeployer(
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"nginx -t",
		"nginx -s reload",
	)

	if d == nil {
		t.Fatal("NewNginxDeployer 返回 nil")
	}

	if d.certPath != "/etc/ssl/cert.pem" {
		t.Errorf("certPath = %s, 期望 /etc/ssl/cert.pem", d.certPath)
	}

	if d.keyPath != "/etc/ssl/key.pem" {
		t.Errorf("keyPath = %s, 期望 /etc/ssl/key.pem", d.keyPath)
	}

	if d.testCommand != "nginx -t" {
		t.Errorf("testCommand = %s, 期望 nginx -t", d.testCommand)
	}

	if d.reloadCommand != "nginx -s reload" {
		t.Errorf("reloadCommand = %s, 期望 nginx -s reload", d.reloadCommand)
	}
}

// TestNewNginxDeployer_EmptyCommands 测试空命令
func TestNewNginxDeployer_EmptyCommands(t *testing.T) {
	d := NewNginxDeployer(
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"",
		"",
	)

	if d.testCommand != "" {
		t.Errorf("testCommand 应为空")
	}

	if d.reloadCommand != "" {
		t.Errorf("reloadCommand 应为空")
	}
}

// TestNginxDeployer_Deploy_WriteCert 测试证书写入
func TestNginxDeployer_Deploy_WriteCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := NewNginxDeployer(certPath, keyPath, "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----"
	intermediate := "-----BEGIN CERTIFICATE-----\ntest-intermediate\n-----END CERTIFICATE-----"
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 验证证书文件
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}

	expectedCert := cert + "\n" + intermediate
	if string(certData) != expectedCert {
		t.Errorf("证书内容不正确")
	}

	// 验证私钥文件
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取私钥文件失败: %v", err)
	}

	if string(keyData) != key {
		t.Errorf("私钥内容不正确")
	}
}

// TestNginxDeployer_Deploy_KeyPermissions 测试私钥权限
func TestNginxDeployer_Deploy_KeyPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := NewNginxDeployer(certPath, keyPath, "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	intermediate := ""
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 验证私钥权限（应为 0600）
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("获取私钥文件信息失败: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("私钥权限 = %o, 期望 0600", perm)
	}
}

// TestNginxDeployer_Deploy_CreateDirectory 测试目录创建
func TestNginxDeployer_Deploy_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir1", "subdir2", "cert.pem")
	keyPath := filepath.Join(tmpDir, "subdir3", "subdir4", "key.pem")

	d := NewNginxDeployer(certPath, keyPath, "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	intermediate := ""
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 验证目录和文件存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
}

// TestRunCommand_Whitelist 测试命令白名单验证
func TestRunCommand_Whitelist(t *testing.T) {
	d := NewNginxDeployer("", "", "", "")

	tests := []struct {
		cmd     string
		allowed bool
	}{
		{"nginx -t", true},
		{"nginx -s reload", true},
		{"systemctl reload nginx", true},
		{"service nginx reload", true},
		{"rm -rf /", false},       // 不在白名单
		{"curl malicious.com", false},
		{"", false},
		{"some-random-cmd", false},
	}

	for _, tt := range tests {
		err := d.runCommand(tt.cmd)
		if tt.allowed {
			// 允许的命令可能因为 nginx 未安装而失败，但不应该因为白名单而失败
			if err != nil && err.Error() == "command not in whitelist: "+tt.cmd {
				t.Errorf("命令 %s 应在白名单中", tt.cmd)
			}
		} else {
			if err == nil {
				t.Errorf("命令 %s 不应被允许执行", tt.cmd)
			}
		}
	}
}

// TestParseCommand 测试命令解析
func TestParseCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		wantExec string
		wantArgs []string
	}{
		{"nginx -t", "nginx", []string{"-t"}},
		{"nginx -s reload", "nginx", []string{"-s", "reload"}},
		{"systemctl reload nginx", "systemctl", []string{"reload", "nginx"}},
		{"", "", nil},
		{"single", "single", []string{}},
	}

	for _, tt := range tests {
		exec, args := parseCommand(tt.cmd)
		if exec != tt.wantExec {
			t.Errorf("parseCommand(%s) exec = %s, 期望 %s", tt.cmd, exec, tt.wantExec)
		}
		if len(args) != len(tt.wantArgs) {
			t.Errorf("parseCommand(%s) args 长度 = %d, 期望 %d", tt.cmd, len(args), len(tt.wantArgs))
		}
	}
}

// TestNginxDeployer_Reload_EmptyCommand 测试空重载命令
func TestNginxDeployer_Reload_EmptyCommand(t *testing.T) {
	d := NewNginxDeployer("", "", "", "")

	err := d.Reload()
	if err != nil {
		t.Errorf("空重载命令应返回 nil，实际: %v", err)
	}
}

// TestNginxDeployer_Test_EmptyCommand 测试空测试命令
func TestNginxDeployer_Test_EmptyCommand(t *testing.T) {
	d := NewNginxDeployer("", "", "", "")

	err := d.Test()
	if err != nil {
		t.Errorf("空测试命令应返回 nil，实际: %v", err)
	}
}

// TestNginxDeployer_Rollback 测试回滚
func TestNginxDeployer_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// 创建备份文件
	backupCertPath := filepath.Join(tmpDir, "backup", "cert.pem")
	backupKeyPath := filepath.Join(tmpDir, "backup", "key.pem")
	os.MkdirAll(filepath.Join(tmpDir, "backup"), 0755)
	os.WriteFile(backupCertPath, []byte("backup-cert"), 0644)
	os.WriteFile(backupKeyPath, []byte("backup-key"), 0600)

	// 创建当前文件
	os.WriteFile(certPath, []byte("current-cert"), 0644)
	os.WriteFile(keyPath, []byte("current-key"), 0600)

	d := NewNginxDeployer(certPath, keyPath, "", "")

	err := d.Rollback(backupCertPath, backupKeyPath)
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	// 验证文件已回滚
	certData, _ := os.ReadFile(certPath)
	if string(certData) != "backup-cert" {
		t.Error("证书未正确回滚")
	}

	keyData, _ := os.ReadFile(keyPath)
	if string(keyData) != "backup-key" {
		t.Error("私钥未正确回滚")
	}
}

// TestAllowedCommands 测试白名单完整性
func TestAllowedCommands(t *testing.T) {
	expectedCommands := []string{
		"nginx -t",
		"nginx -s reload",
		"systemctl reload nginx",
		"systemctl restart nginx",
		"service nginx reload",
		"service nginx restart",
		"rc-service nginx reload",
		"rc-service nginx restart",
		"/usr/sbin/nginx -s reload",
	}

	for _, cmd := range expectedCommands {
		if !allowedCommands[cmd] {
			t.Errorf("命令 %s 应在白名单中", cmd)
		}
	}
}
