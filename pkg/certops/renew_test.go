// Package certops 续签逻辑测试
package certops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/cert-deploy/pkg/config"
)

// TestGetPendingKeyPath 测试待确认私钥路径生成
func TestGetPendingKeyPath(t *testing.T) {
	workDir := "/opt/cert-deploy"
	certName := "order-123"

	path := getPendingKeyPath(workDir, certName)
	expected := "/opt/cert-deploy/pending-keys/order-123/pending-key.pem"

	if path != expected {
		t.Errorf("getPendingKeyPath() = %s, 期望 %s", path, expected)
	}
}

// TestSavePendingKey 测试保存待确认私钥
func TestSavePendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	err := savePendingKey(workDir, certName, keyPEM)
	if err != nil {
		t.Fatalf("savePendingKey() error = %v", err)
	}

	// 验证文件已创建
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Error("待确认私钥文件未创建")
	}

	// 验证文件内容
	data, _ := os.ReadFile(pendingPath)
	if string(data) != keyPEM {
		t.Error("待确认私钥内容不正确")
	}

	// 验证文件权限
	info, _ := os.Stat(pendingPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("文件权限 = %o, 期望 0600", info.Mode().Perm())
	}
}

// TestReadPendingKey 测试读取待确认私钥
func TestReadPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	// 先保存
	_ = savePendingKey(workDir, certName, keyPEM)

	// 读取
	readKey, err := readPendingKey(workDir, certName)
	if err != nil {
		t.Fatalf("readPendingKey() error = %v", err)
	}

	if readKey != keyPEM {
		t.Error("读取的私钥内容不正确")
	}
}

// TestReadPendingKey_NotExist 测试读取不存在的待确认私钥
func TestReadPendingKey_NotExist(t *testing.T) {
	workDir := t.TempDir()
	certName := "nonexistent"

	_, err := readPendingKey(workDir, certName)
	if err == nil {
		t.Error("读取不存在的私钥应返回错误")
	}
}

// TestCommitPendingKey 测试提交待确认私钥
func TestCommitPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

	// 先保存待确认私钥
	_ = savePendingKey(workDir, certName, keyPEM)

	// 目标路径
	targetPath := filepath.Join(workDir, "certs", certName, "key.pem")

	// 提交
	err := commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Fatalf("commitPendingKey() error = %v", err)
	}

	// 验证目标文件已创建
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		t.Error("目标私钥文件未创建")
	}

	// 验证待确认私钥已删除
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("待确认私钥文件应已删除")
	}
}

// TestCommitPendingKey_NotExist 测试提交不存在的待确认私钥
func TestCommitPendingKey_NotExist(t *testing.T) {
	workDir := t.TempDir()
	certName := "nonexistent"
	targetPath := filepath.Join(workDir, "key.pem")

	// 应该不报错（静默跳过）
	err := commitPendingKey(workDir, certName, targetPath)
	if err != nil {
		t.Errorf("commitPendingKey() 不存在时应静默跳过，但返回错误: %v", err)
	}
}

// TestCleanupPendingKey 测试清理待确认私钥
func TestCleanupPendingKey(t *testing.T) {
	workDir := t.TempDir()
	certName := "test-cert"
	keyPEM := "test-key"

	// 先保存
	_ = savePendingKey(workDir, certName, keyPEM)

	// 验证文件存在
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Fatal("待确认私钥文件未创建")
	}

	// 清理
	cleanupPendingKey(workDir, certName)

	// 验证文件已删除
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("待确认私钥文件应已删除")
	}
}

// TestGetRenewMode_Defaults 测试续签模式默认值
func TestGetRenewMode_Defaults(t *testing.T) {
	// 空 schedule
	schedule := &config.ScheduleConfig{}
	mode := getRenewMode(schedule)
	if mode != config.RenewModePull {
		t.Errorf("空模式应默认为 pull，实际: %s", mode)
	}

	// local 模式
	schedule.RenewMode = config.RenewModeLocal
	mode = getRenewMode(schedule)
	if mode != config.RenewModeLocal {
		t.Errorf("显式 local 模式应为 local，实际: %s", mode)
	}
}

// TestMaxIssueRetryCount 测试最大重试次数常量
func TestMaxIssueRetryCount(t *testing.T) {
	if MaxIssueRetryCount <= 0 {
		t.Error("MaxIssueRetryCount 应大于 0")
	}
	if MaxIssueRetryCount > 100 {
		t.Error("MaxIssueRetryCount 不应过大")
	}
}
