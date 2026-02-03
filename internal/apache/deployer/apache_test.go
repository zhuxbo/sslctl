// Package deployer Apache 部署器测试
package deployer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/cert-deploy/internal/executor"
)

// TestNewApacheDeployer 测试创建 Apache 部署器
func TestNewApacheDeployer(t *testing.T) {
	d := NewApacheDeployer(
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"/etc/ssl/chain.pem",
		"apachectl -t",
		"apachectl graceful",
	)

	if d == nil {
		t.Fatal("NewApacheDeployer 返回 nil")
	}

	if d.certPath != "/etc/ssl/cert.pem" {
		t.Errorf("certPath = %s, 期望 /etc/ssl/cert.pem", d.certPath)
	}

	if d.keyPath != "/etc/ssl/key.pem" {
		t.Errorf("keyPath = %s, 期望 /etc/ssl/key.pem", d.keyPath)
	}

	if d.chainPath != "/etc/ssl/chain.pem" {
		t.Errorf("chainPath = %s, 期望 /etc/ssl/chain.pem", d.chainPath)
	}

	if d.testCommand != "apachectl -t" {
		t.Errorf("testCommand = %s, 期望 apachectl -t", d.testCommand)
	}

	if d.reloadCommand != "apachectl graceful" {
		t.Errorf("reloadCommand = %s, 期望 apachectl graceful", d.reloadCommand)
	}
}

// TestNewApacheDeployer_EmptyChainPath 测试空证书链路径
func TestNewApacheDeployer_EmptyChainPath(t *testing.T) {
	d := NewApacheDeployer(
		"/etc/ssl/cert.pem",
		"/etc/ssl/key.pem",
		"",
		"",
		"",
	)

	if d.chainPath != "" {
		t.Errorf("chainPath 应为空")
	}
}

// TestApacheDeployer_Deploy_WriteCert 测试证书写入
func TestApacheDeployer_Deploy_WriteCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	d := NewApacheDeployer(certPath, keyPath, chainPath, "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----"
	intermediate := "-----BEGIN CERTIFICATE-----\ntest-intermediate\n-----END CERTIFICATE-----"
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 验证服务器证书文件
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读取证书文件失败: %v", err)
	}
	if string(certData) != cert {
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

	// 验证证书链文件
	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("读取证书链文件失败: %v", err)
	}
	if string(chainData) != intermediate {
		t.Errorf("证书链内容不正确")
	}
}

// TestApacheDeployer_Deploy_NoChain 测试无证书链部署
func TestApacheDeployer_Deploy_NoChain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// 不指定 chainPath
	d := NewApacheDeployer(certPath, keyPath, "", "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----"
	intermediate := "-----BEGIN CERTIFICATE-----\ntest-intermediate\n-----END CERTIFICATE-----"
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 证书链文件不应被创建
	chainPath := filepath.Join(tmpDir, "chain.pem")
	if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
		t.Error("不应创建证书链文件（未指定 chainPath）")
	}
}

// TestApacheDeployer_Deploy_KeyPermissions 测试私钥权限
func TestApacheDeployer_Deploy_KeyPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := NewApacheDeployer(certPath, keyPath, "", "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, "", key)
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

// TestApacheDeployer_Deploy_CreateDirectory 测试目录创建
func TestApacheDeployer_Deploy_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "subdir1", "cert.pem")
	keyPath := filepath.Join(tmpDir, "subdir2", "key.pem")
	chainPath := filepath.Join(tmpDir, "subdir3", "chain.pem")

	d := NewApacheDeployer(certPath, keyPath, chainPath, "", "")

	cert := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	intermediate := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	key := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := d.Deploy(cert, intermediate, key)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	// 验证文件存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("证书文件未创建")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("私钥文件未创建")
	}
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		t.Error("证书链文件未创建")
	}
}

// TestRunCommand_Whitelist 测试命令白名单验证
func TestRunCommand_Whitelist(t *testing.T) {
	d := NewApacheDeployer("", "", "", "", "")

	tests := []struct {
		cmd     string
		allowed bool
	}{
		{"apachectl -t", true},
		{"apachectl graceful", true},
		{"apache2ctl -t", true},
		{"httpd -t", true},
		{"systemctl reload apache2", true},
		{"systemctl reload httpd", true},
		{"rm -rf /", false},
		{"curl malicious.com", false},
		{"", false},
	}

	for _, tt := range tests {
		err := d.runCommand(tt.cmd)
		if tt.allowed {
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
		{"apachectl -t", "apachectl", []string{"-t"}},
		{"apachectl graceful", "apachectl", []string{"graceful"}},
		{"systemctl reload apache2", "systemctl", []string{"reload", "apache2"}},
		{"", "", nil},
	}

	for _, tt := range tests {
		exec, args := executor.ParseCommand(tt.cmd)
		if exec != tt.wantExec {
			t.Errorf("ParseCommand(%s) exec = %s, 期望 %s", tt.cmd, exec, tt.wantExec)
		}
		if len(args) != len(tt.wantArgs) {
			t.Errorf("ParseCommand(%s) args 长度 = %d, 期望 %d", tt.cmd, len(args), len(tt.wantArgs))
		}
	}
}

// TestApacheDeployer_Reload_EmptyCommand 测试空重载命令
func TestApacheDeployer_Reload_EmptyCommand(t *testing.T) {
	d := NewApacheDeployer("", "", "", "", "")

	err := d.Reload()
	if err != nil {
		t.Errorf("空重载命令应返回 nil，实际: %v", err)
	}
}

// TestApacheDeployer_Test_EmptyCommand 测试空测试命令
func TestApacheDeployer_Test_EmptyCommand(t *testing.T) {
	d := NewApacheDeployer("", "", "", "", "")

	err := d.Test()
	if err != nil {
		t.Errorf("空测试命令应返回 nil，实际: %v", err)
	}
}

// TestApacheDeployer_Rollback 测试回滚
func TestApacheDeployer_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	// 创建备份文件
	backupDir := filepath.Join(tmpDir, "backup")
	_ = os.MkdirAll(backupDir, 0755)
	backupCertPath := filepath.Join(backupDir, "cert.pem")
	backupKeyPath := filepath.Join(backupDir, "key.pem")
	backupChainPath := filepath.Join(backupDir, "chain.pem")
	_ = os.WriteFile(backupCertPath, []byte("backup-cert"), 0644)
	_ = os.WriteFile(backupKeyPath, []byte("backup-key"), 0600)
	_ = os.WriteFile(backupChainPath, []byte("backup-chain"), 0644)

	// 创建当前文件
	_ = os.WriteFile(certPath, []byte("current-cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("current-key"), 0600)
	_ = os.WriteFile(chainPath, []byte("current-chain"), 0644)

	d := NewApacheDeployer(certPath, keyPath, chainPath, "", "")

	err := d.Rollback(backupCertPath, backupKeyPath, backupChainPath)
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

	chainData, _ := os.ReadFile(chainPath)
	if string(chainData) != "backup-chain" {
		t.Error("证书链未正确回滚")
	}
}

// TestApacheDeployer_Rollback_NoChain 测试无证书链回滚
func TestApacheDeployer_Rollback_NoChain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// 创建备份文件
	backupDir := filepath.Join(tmpDir, "backup")
	_ = os.MkdirAll(backupDir, 0755)
	backupCertPath := filepath.Join(backupDir, "cert.pem")
	backupKeyPath := filepath.Join(backupDir, "key.pem")
	_ = os.WriteFile(backupCertPath, []byte("backup-cert"), 0644)
	_ = os.WriteFile(backupKeyPath, []byte("backup-key"), 0600)

	// 创建当前文件
	_ = os.WriteFile(certPath, []byte("current-cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("current-key"), 0600)

	// 不指定 chainPath
	d := NewApacheDeployer(certPath, keyPath, "", "", "")

	err := d.Rollback(backupCertPath, backupKeyPath, "")
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

// TestAllowedCommands 测试白名单完整性
func TestAllowedCommands(t *testing.T) {
	expectedCommands := []string{
		"apachectl -t",
		"apachectl graceful",
		"apachectl restart",
		"apache2ctl -t",
		"apache2ctl graceful",
		"httpd -t",
		"systemctl reload apache2",
		"systemctl reload httpd",
		"service apache2 reload",
		"service httpd reload",
	}

	for _, cmd := range expectedCommands {
		if !executor.AllowedCommands[cmd] {
			t.Errorf("命令 %s 应在白名单中", cmd)
		}
	}
}
