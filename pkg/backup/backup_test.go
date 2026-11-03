// Package backup 备份管理测试
package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewManager 测试创建备份管理器
func TestNewManager(t *testing.T) {
	m := NewManager("/tmp/backup", 5)

	if m == nil {
		t.Fatal("NewManager() returned nil")
	}

	if m.backupDir != "/tmp/backup" {
		t.Errorf("backupDir = %s, want /tmp/backup", m.backupDir)
	}

	if m.keepVersions != 5 {
		t.Errorf("keepVersions = %d, want 5", m.keepVersions)
	}
}

// TestManager_Backup 测试备份功能
func TestManager_Backup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	// 创建测试文件
	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"), 0644)
	_ = os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"), 0600)

	m := NewManager(backupDir, 3)

	certInfo := &CertInfo{
		Subject:   "example.com",
		Serial:    "1234567890",
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	result, err := m.Backup("example.com", certPath, keyPath, certInfo)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	if result.BackupPath == "" {
		t.Error("BackupPath should not be empty")
	}

	// 验证备份文件存在
	backupCert := filepath.Join(result.BackupPath, "cert.pem")
	backupKey := filepath.Join(result.BackupPath, "key.pem")
	backupMeta := filepath.Join(result.BackupPath, "metadata.json")

	for _, f := range []string{backupCert, backupKey, backupMeta} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("backup file %s not created: %v", f, err)
		}
	}

	// 验证备份目录权限
	info, _ := os.Stat(result.BackupPath)
	if info.Mode().Perm() != 0700 {
		t.Errorf("backup directory permission = %o, want 0700", info.Mode().Perm())
	}
}

// TestManager_BackupWithChain 测试包含证书链的备份
func TestManager_BackupWithChain(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	chainPath := filepath.Join(srcDir, "chain.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)
	_ = os.WriteFile(chainPath, []byte("chain"), 0644)

	m := NewManager(backupDir, 3)

	result, err := m.Backup("example.com", certPath, keyPath, nil, chainPath)
	if err != nil {
		t.Fatalf("Backup() with chain error = %v", err)
	}

	// 验证证书链文件已备份
	backupChain := filepath.Join(result.BackupPath, "chain.pem")
	if _, err := os.Stat(backupChain); err != nil {
		t.Errorf("chain file not backed up: %v", err)
	}

	// 验证元数据包含 chain 路径
	meta, err := m.LoadMetadata(result.BackupPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}
	if meta.ChainPath != chainPath {
		t.Errorf("metadata ChainPath = %s, want %s", meta.ChainPath, chainPath)
	}
}

// TestManager_ListBackups 测试列出备份
func TestManager_ListBackups(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteBackupDir := filepath.Join(backupDir, "example.com")
	_ = os.MkdirAll(siteBackupDir, 0755)

	// 手动创建不同时间戳的备份目录
	timestamps := []string{"20240101-120000", "20240101-120001", "20240101-120002"}
	for _, ts := range timestamps {
		backupPath := filepath.Join(siteBackupDir, ts)
		_ = os.MkdirAll(backupPath, 0755)
		_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
		_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)
	}

	m := NewManager(backupDir, 10)

	// 列出备份
	backups, err := m.ListBackups("example.com")
	if err != nil {
		t.Fatalf("ListBackups() error = %v", err)
	}

	if len(backups) != 3 {
		t.Errorf("ListBackups() length = %d, want 3", len(backups))
	}

	// 验证排序（最新的在前）
	for i := 0; i < len(backups)-1; i++ {
		if backups[i] < backups[i+1] {
			t.Error("backups should be sorted in descending order")
		}
	}
}

// TestManager_ListBackups_Empty 测试列出空备份
func TestManager_ListBackups_Empty(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	backups, err := m.ListBackups("nonexistent")
	if err != nil {
		t.Fatalf("ListBackups() error = %v", err)
	}

	if len(backups) != 0 {
		t.Errorf("ListBackups() for nonexistent site should return empty, got %d", len(backups))
	}
}

// TestManager_GetLatestBackup 测试获取最新备份
func TestManager_GetLatestBackup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteBackupDir := filepath.Join(backupDir, "example.com")
	_ = os.MkdirAll(siteBackupDir, 0755)

	// 手动创建不同时间戳的备份目录
	oldBackup := filepath.Join(siteBackupDir, "20240101-120000")
	newBackup := filepath.Join(siteBackupDir, "20240101-120001")
	for _, path := range []string{oldBackup, newBackup} {
		_ = os.MkdirAll(path, 0755)
		_ = os.WriteFile(filepath.Join(path, "cert.pem"), []byte("cert"), 0644)
		_ = os.WriteFile(filepath.Join(path, "key.pem"), []byte("key"), 0600)
	}

	m := NewManager(backupDir, 10)

	// 获取最新备份
	latest, err := m.GetLatestBackup("example.com")
	if err != nil {
		t.Fatalf("GetLatestBackup() error = %v", err)
	}

	if latest != newBackup {
		t.Errorf("GetLatestBackup() = %s, want %s (latest)", latest, newBackup)
	}

	// 验证不是第一个
	if latest == oldBackup {
		t.Error("GetLatestBackup() should return the most recent backup")
	}
}

// TestManager_GetLatestBackup_NotFound 测试获取不存在的最新备份
func TestManager_GetLatestBackup_NotFound(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	_, err := m.GetLatestBackup("nonexistent")
	if err == nil {
		t.Error("GetLatestBackup() should return error for nonexistent site")
	}
}

// TestManager_GetBackupPaths 测试获取备份路径
func TestManager_GetBackupPaths(t *testing.T) {
	m := NewManager("/backup", 3)
	backupPath := "/backup/example.com/20240101-120000"

	certPath, keyPath := m.GetBackupPaths(backupPath)

	if certPath != "/backup/example.com/20240101-120000/cert.pem" {
		t.Errorf("certPath = %s, unexpected", certPath)
	}
	if keyPath != "/backup/example.com/20240101-120000/key.pem" {
		t.Errorf("keyPath = %s, unexpected", keyPath)
	}
}

// TestManager_GetBackupPathsWithChain 测试获取包含证书链的备份路径
func TestManager_GetBackupPathsWithChain(t *testing.T) {
	m := NewManager("/backup", 3)
	backupPath := "/backup/example.com/20240101-120000"

	certPath, keyPath, chainPath := m.GetBackupPathsWithChain(backupPath)

	if certPath != "/backup/example.com/20240101-120000/cert.pem" {
		t.Errorf("certPath = %s, unexpected", certPath)
	}
	if keyPath != "/backup/example.com/20240101-120000/key.pem" {
		t.Errorf("keyPath = %s, unexpected", keyPath)
	}
	if chainPath != "/backup/example.com/20240101-120000/chain.pem" {
		t.Errorf("chainPath = %s, unexpected", chainPath)
	}
}

// TestManager_LoadMetadata 测试加载备份元数据
func TestManager_LoadMetadata(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 3)

	certInfo := &CertInfo{
		Subject:   "CN=example.com",
		Serial:    "ABCD1234",
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	result, _ := m.Backup("example.com", certPath, keyPath, certInfo)

	meta, err := m.LoadMetadata(result.BackupPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	if meta.ServerName != "example.com" {
		t.Errorf("ServerName = %s, want example.com", meta.ServerName)
	}

	if meta.CertInfo.Subject != "CN=example.com" {
		t.Errorf("CertInfo.Subject = %s, want CN=example.com", meta.CertInfo.Subject)
	}

	if meta.CertInfo.Serial != "ABCD1234" {
		t.Errorf("CertInfo.Serial = %s, want ABCD1234", meta.CertInfo.Serial)
	}

	if meta.CertPath != certPath {
		t.Errorf("CertPath = %s, want %s", meta.CertPath, certPath)
	}

	if meta.KeyPath != keyPath {
		t.Errorf("KeyPath = %s, want %s", meta.KeyPath, keyPath)
	}
}

// TestManager_LoadMetadata_NotFound 测试加载不存在的元数据
func TestManager_LoadMetadata_NotFound(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	_, err := m.LoadMetadata(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Error("LoadMetadata() should return error for nonexistent path")
	}
}

// TestManager_Cleanup 测试清理旧备份
func TestManager_Cleanup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteBackupDir := filepath.Join(backupDir, "example.com")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)
	_ = os.MkdirAll(siteBackupDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	// 手动创建 4 个已有的备份目录
	timestamps := []string{"20240101-120000", "20240101-120001", "20240101-120002", "20240101-120003"}
	for _, ts := range timestamps {
		backupPath := filepath.Join(siteBackupDir, ts)
		_ = os.MkdirAll(backupPath, 0755)
		_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
		_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)
	}

	// 设置只保留 2 个版本
	m := NewManager(backupDir, 2)

	// 创建第 5 个备份，触发清理
	_, err := m.Backup("example.com", certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	// 验证只剩 2 个备份
	backups, _ := m.ListBackups("example.com")
	if len(backups) != 2 {
		t.Errorf("after cleanup, backups = %d, want 2", len(backups))
	}
}

// TestManager_DeleteBackup 测试删除指定备份
func TestManager_DeleteBackup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 10)

	result, _ := m.Backup("example.com", certPath, keyPath, nil)
	timestamp := filepath.Base(result.BackupPath)

	// 删除备份
	err := m.DeleteBackup("example.com", timestamp)
	if err != nil {
		t.Fatalf("DeleteBackup() error = %v", err)
	}

	// 验证已删除
	if _, err := os.Stat(result.BackupPath); !os.IsNotExist(err) {
		t.Error("backup directory should be deleted")
	}
}

// TestManager_DeleteAllBackups 测试删除所有备份
func TestManager_DeleteAllBackups(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 10)

	// 创建多个备份（只需创建一个即可验证删除功能）
	for i := 0; i < 1; i++ {
		_, _ = m.Backup("example.com", certPath, keyPath, nil)
	}

	// 删除所有备份
	err := m.DeleteAllBackups("example.com")
	if err != nil {
		t.Fatalf("DeleteAllBackups() error = %v", err)
	}

	// 验证站点备份目录已删除
	siteBackupDir := filepath.Join(backupDir, "example.com")
	if _, err := os.Stat(siteBackupDir); !os.IsNotExist(err) {
		t.Error("site backup directory should be deleted")
	}
}

// TestManager_BackupNilCertInfo 测试备份时证书信息为 nil
func TestManager_BackupNilCertInfo(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 3)

	// certInfo 为 nil
	result, err := m.Backup("example.com", certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("Backup() with nil certInfo error = %v", err)
	}

	// 验证备份成功
	if result.BackupPath == "" {
		t.Error("BackupPath should not be empty")
	}

	// 验证元数据正常加载
	meta, err := m.LoadMetadata(result.BackupPath)
	if err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	// CertInfo 应该是零值
	if meta.CertInfo.Subject != "" {
		t.Errorf("CertInfo.Subject should be empty, got %s", meta.CertInfo.Subject)
	}
}

// TestManager_Restore 测试恢复功能
func TestManager_Restore(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("original cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("original key"), 0600)

	m := NewManager(backupDir, 5)

	certInfo := &CertInfo{
		Subject: "example.com",
		Serial:  "123",
	}
	result, err := m.Backup("example.com", certPath, keyPath, certInfo)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	backupTS := filepath.Base(result.BackupPath)

	// 等待确保恢复时内部备份的时间戳不同
	time.Sleep(time.Second)

	// 修改源文件
	_ = os.WriteFile(certPath, []byte("new cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("new key"), 0600)

	// 恢复到指定时间戳（避免 Restore 内部备份覆盖原始备份）
	meta, err := m.Restore("example.com", backupTS)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if meta.CertInfo.Subject != "example.com" {
		t.Errorf("restored metadata Subject = %s, want example.com", meta.CertInfo.Subject)
	}

	// 验证文件已恢复
	certData, _ := os.ReadFile(certPath)
	if string(certData) != "original cert" {
		t.Errorf("cert not restored, got %q", string(certData))
	}
	keyData, _ := os.ReadFile(keyPath)
	if string(keyData) != "original key" {
		t.Errorf("key not restored, got %q", string(keyData))
	}
}

// TestManager_Restore_ChainTargetChanged 测试恢复时证书链目标被改向
func TestManager_Restore_ChainTargetChanged(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	chainPath := filepath.Join(srcDir, "chain.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)
	_ = os.WriteFile(chainPath, []byte("chain"), 0644)

	m := NewManager(backupDir, 5)
	_, err := m.Backup("example.com", certPath, keyPath, nil, chainPath)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	// 将 chainPath 替换为符号链接
	_ = os.Remove(chainPath)
	targetFile := filepath.Join(dir, "malicious-target")
	_ = os.WriteFile(targetFile, []byte("target"), 0644)
	_ = os.Symlink(targetFile, chainPath)

	// 恢复应拒绝（目标与备份记录不一致）
	_, err = m.Restore("example.com")
	if err == nil {
		t.Fatal("Restore() should reject changed chain target")
	}
	if !strings.Contains(err.Error(), "链接") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

// TestManager_Restore_CertTargetChanged 测试恢复时证书目标被改向
func TestManager_Restore_CertTargetChanged(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 5)
	_, err := m.Backup("example.com", certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	// 将 certPath 替换为符号链接
	_ = os.Remove(certPath)
	targetFile := filepath.Join(dir, "malicious-target")
	_ = os.WriteFile(targetFile, []byte("target"), 0644)
	_ = os.Symlink(targetFile, certPath)

	// 恢复应拒绝
	_, err = m.Restore("example.com")
	if err == nil {
		t.Fatal("Restore() should reject changed certificate target")
	}
	if !strings.Contains(err.Error(), "链接") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

// TestManager_Restore_WithTimestamp 测试指定时间戳恢复
func TestManager_Restore_WithTimestamp(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert v1"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v1"), 0600)

	m := NewManager(backupDir, 5)
	result1, _ := m.Backup("example.com", certPath, keyPath, &CertInfo{Subject: "v1"})
	ts1 := filepath.Base(result1.BackupPath)

	// 等待一秒确保时间戳不同
	time.Sleep(time.Second)

	_ = os.WriteFile(certPath, []byte("cert v2"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v2"), 0600)
	_, _ = m.Backup("example.com", certPath, keyPath, &CertInfo{Subject: "v2"})

	// 修改为 v3
	_ = os.WriteFile(certPath, []byte("cert v3"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v3"), 0600)

	// 恢复到 v1
	meta, err := m.Restore("example.com", ts1)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if meta.CertInfo.Subject != "v1" {
		t.Errorf("restored Subject = %s, want v1", meta.CertInfo.Subject)
	}

	certData, _ := os.ReadFile(certPath)
	if string(certData) != "cert v1" {
		t.Errorf("cert not restored to v1, got %q", string(certData))
	}
}

// TestManager_Restore_NotFound 测试恢复不存在的备份
func TestManager_Restore_NotFound(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	_, err := m.Restore("nonexistent")
	if err == nil {
		t.Error("Restore() should fail for nonexistent site")
	}
}

// TestManager_BackupSourceNotExist 测试备份不存在的源文件
func TestManager_BackupSourceNotExist(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	_, err := m.Backup("example.com", "/nonexistent/cert.pem", "/nonexistent/key.pem", nil)
	if err == nil {
		t.Error("Backup() should fail for nonexistent source files")
	}
}

// TestComputeFileHash_RejectsSymlink 测试 computeFileHash 拒绝符号链接
func TestComputeFileHash_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	// 创建真实文件
	realFile := filepath.Join(dir, "real.pem")
	_ = os.WriteFile(realFile, []byte("cert content"), 0644)

	// 创建符号链接
	symlinkFile := filepath.Join(dir, "symlink.pem")
	if err := os.Symlink(realFile, symlinkFile); err != nil {
		t.Skip("无法创建符号链接:", err)
	}

	// 真实文件应正常计算哈希
	hash, err := computeFileHash(realFile)
	if err != nil {
		t.Errorf("computeFileHash 对真实文件应成功: %v", err)
	}
	if hash == "" {
		t.Error("哈希不应为空")
	}

	// 符号链接应被拒绝
	_, err = computeFileHash(symlinkFile)
	if err == nil {
		t.Error("computeFileHash 应拒绝符号链接")
	}
	if err != nil && !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("错误消息应包含 'symbolic link': %v", err)
	}
}

// TestComputeFileHash_NotExist 测试 computeFileHash 处理不存在的文件
func TestComputeFileHash_NotExist(t *testing.T) {
	_, err := computeFileHash("/nonexistent/file.pem")
	if err == nil {
		t.Error("computeFileHash 应对不存在的文件返回错误")
	}
}

// TestManager_Backup_SourceSymlink 测试 Backup 备份链接指向的内容
func TestManager_Backup_SourceSymlink(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	// 创建真实的 key 文件
	realKeyPath := filepath.Join(srcDir, "real-key.pem")
	_ = os.WriteFile(realKeyPath, []byte("key content"), 0600)

	// 创建 cert 为符号链接
	realCertPath := filepath.Join(srcDir, "real-cert.pem")
	_ = os.WriteFile(realCertPath, []byte("cert content"), 0644)

	symlinkCert := filepath.Join(srcDir, "cert.pem")
	if err := os.Symlink(realCertPath, symlinkCert); err != nil {
		t.Skip("无法创建符号链接:", err)
	}

	m := NewManager(backupDir, 3)

	// 证书文件为符号链接时备份内容并保留链接
	_, err := m.Backup("example.com", symlinkCert, realKeyPath, nil)
	if err != nil {
		t.Errorf("Backup() 应支持符号链接: %v", err)
	}
}

// TestComputeFileHash_Consistency 测试哈希计算一致性
func TestComputeFileHash_Consistency(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.pem")
	content := []byte("test certificate content")
	_ = os.WriteFile(file, content, 0644)

	// 多次计算应得到相同结果
	hash1, _ := computeFileHash(file)
	hash2, _ := computeFileHash(file)
	if hash1 != hash2 {
		t.Error("相同文件的哈希应一致")
	}

	// 修改内容后哈希应变化
	_ = os.WriteFile(file, []byte("modified content"), 0644)
	hash3, _ := computeFileHash(file)
	if hash1 == hash3 {
		t.Error("修改文件后哈希应变化")
	}
}

// TestManager_BackupChainNotExist 测试证书链文件不存在时的备份
func TestManager_BackupChainNotExist(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 3)

	// 证书链文件不存在，备份应该继续（非致命错误）
	result, err := m.Backup("example.com", certPath, keyPath, nil, "/nonexistent/chain.pem")
	if err != nil {
		t.Fatalf("Backup() should succeed even if chain file not exist: %v", err)
	}

	// 验证元数据中 ChainPath 为空
	meta, _ := m.LoadMetadata(result.BackupPath)
	if meta.ChainPath != "" {
		t.Errorf("ChainPath should be empty when chain backup fails, got %s", meta.ChainPath)
	}
}

// TestRestore_PathTraversal 测试 Restore 拒绝含 .. 的 timestamp（路径穿越防护）
func TestRestore_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 5)

	// 这些 timestamp 与 siteName 拼接后会逃逸出 backupDir
	traversalTimestamps := []string{
		"../../etc",
		"../../../tmp/evil",
	}

	for _, ts := range traversalTimestamps {
		_, err := m.Restore("example.com", ts)
		if err == nil {
			t.Errorf("Restore() with timestamp %q should return error", ts)
			continue
		}
		if !strings.Contains(err.Error(), "invalid backup path") {
			t.Errorf("Restore() with timestamp %q: error = %v, want 'invalid backup path'", ts, err)
		}
	}

	// 边界情况：timestamp 含 .. 但拼接后仍在 backupDir 下（如 ../secret 与 example.com 拼接后为 secret）
	// 此时 JoinUnderDir 不会拒绝（结果仍在 baseDir 下），但备份不存在会返回其他错误
	_, err := m.Restore("example.com", "../secret")
	if err == nil {
		t.Error("Restore() with ../secret should return error (backup does not exist)")
	}
}

// TestDeleteBackup_PathTraversal 测试 DeleteBackup 拒绝含 .. 的 timestamp（路径穿越防护）
func TestDeleteBackup_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 5)

	// 这些 timestamp 与 siteName 拼接后会逃逸出 backupDir
	traversalTimestamps := []string{
		"../../etc",
		"../../../tmp/evil",
	}

	for _, ts := range traversalTimestamps {
		err := m.DeleteBackup("example.com", ts)
		if err == nil {
			t.Errorf("DeleteBackup() with timestamp %q should return error", ts)
			continue
		}
		if !strings.Contains(err.Error(), "invalid backup path") {
			t.Errorf("DeleteBackup() with timestamp %q: error = %v, want 'invalid backup path'", ts, err)
		}
	}
}

// TestDeleteAllBackups_PathTraversal 测试 DeleteAllBackups 拒绝含 .. 的 siteName（路径穿越防护）
func TestDeleteAllBackups_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 5)

	// 这些 siteName 会逃逸出 backupDir
	traversalSiteNames := []string{
		"../../etc",
		"../secret",
	}

	for _, site := range traversalSiteNames {
		err := m.DeleteAllBackups(site)
		if err == nil {
			t.Errorf("DeleteAllBackups() with siteName %q should return error", site)
			continue
		}
		if !strings.Contains(err.Error(), "invalid site name") {
			t.Errorf("DeleteAllBackups() with siteName %q: error = %v, want 'invalid site name'", site, err)
		}
	}
}

// TestNewManager_KeepVersionsBoundary 测试 keepVersions 边界值自动修正为 5
func TestNewManager_KeepVersionsBoundary(t *testing.T) {
	tests := []struct {
		name         string
		keepVersions int
		want         int
	}{
		{"zero", 0, 5},
		{"negative", -1, 5},
		{"negative_large", -100, 5},
		{"one", 1, 1},
		{"normal", 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager("/tmp/test", tt.keepVersions)
			if m.keepVersions != tt.want {
				t.Errorf("NewManager(keepVersions=%d).keepVersions = %d, want %d", tt.keepVersions, m.keepVersions, tt.want)
			}
		})
	}
}

// TestRestore_MissingBackupFiles 测试备份目录存在但 cert.pem 缺失时 Restore 报错
func TestRestore_MissingBackupFiles(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteName := "example.com"
	timestamp := "20240101-120000"

	// 手动构造备份目录：仅有 metadata.json，没有 cert.pem / key.pem
	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   filepath.Join(dir, "src", "cert.pem"),
		KeyPath:    filepath.Join(dir, "src", "key.pem"),
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	m := NewManager(backupDir, 5)

	// cert.pem 不存在应报错
	_, err := m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail when cert.pem is missing")
	}
	if !strings.Contains(err.Error(), "备份证书文件不存在") {
		t.Errorf("error should mention missing cert, got: %v", err)
	}

	// 创建 cert.pem 但不创建 key.pem，验证 key.pem 缺失也报错
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
	_, err = m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail when key.pem is missing")
	}
	if !strings.Contains(err.Error(), "备份私钥文件不存在") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

// TestRestore_EmptyMetadataPaths 测试备份元数据中 CertPath/KeyPath 为空时 Restore 报错
func TestRestore_EmptyMetadataPaths(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteName := "example.com"
	timestamp := "20240101-120000"

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	// 创建备份文件但 metadata 中路径为空
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
	_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)

	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   "", // 空路径
		KeyPath:    "", // 空路径
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	m := NewManager(backupDir, 5)

	_, err := m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail when metadata paths are empty")
	}
	if !strings.Contains(err.Error(), "CertPath 或 KeyPath 为空") {
		t.Errorf("error should mention empty paths, got: %v", err)
	}
}

// TestRestore_WithChainFile 测试带证书链文件的完整恢复流程
func TestRestore_WithChainFile(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	chainPath := filepath.Join(srcDir, "chain.pem")
	_ = os.WriteFile(certPath, []byte("original cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("original key"), 0600)
	_ = os.WriteFile(chainPath, []byte("original chain"), 0644)

	m := NewManager(backupDir, 5)

	// 备份含 chain 的证书
	result, err := m.Backup("example.com", certPath, keyPath, &CertInfo{Subject: "v1"}, chainPath)
	if err != nil {
		t.Fatalf("Backup() error = %v", err)
	}
	backupTS := filepath.Base(result.BackupPath)

	time.Sleep(time.Second)

	// 修改源文件
	_ = os.WriteFile(certPath, []byte("new cert"), 0644)
	_ = os.WriteFile(keyPath, []byte("new key"), 0600)
	_ = os.WriteFile(chainPath, []byte("new chain"), 0644)

	// 恢复
	meta, err := m.Restore("example.com", backupTS)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if meta.ChainPath != chainPath {
		t.Errorf("restored ChainPath = %s, want %s", meta.ChainPath, chainPath)
	}

	// 验证证书链文件已恢复
	chainData, _ := os.ReadFile(chainPath)
	if string(chainData) != "original chain" {
		t.Errorf("chain not restored, got %q", string(chainData))
	}
}

// TestLoadMetadata_InvalidJSON 测试加载损坏的 JSON 元数据
func TestLoadMetadata_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "backup")
	_ = os.MkdirAll(backupPath, 0700)

	// 写入无效 JSON
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), []byte("not json{"), 0600)

	m := NewManager(dir, 5)
	_, err := m.LoadMetadata(backupPath)
	if err == nil {
		t.Fatal("LoadMetadata() should fail for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse metadata") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

// TestRestore_LatestBackup 测试不指定 timestamp 时恢复最新备份
func TestRestore_LatestBackup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	_ = os.WriteFile(certPath, []byte("cert v1"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v1"), 0600)

	m := NewManager(backupDir, 5)

	// 创建第一个备份
	_, err := m.Backup("example.com", certPath, keyPath, &CertInfo{Subject: "v1"})
	if err != nil {
		t.Fatalf("Backup() v1 error = %v", err)
	}

	time.Sleep(time.Second)

	// 创建第二个备份
	_ = os.WriteFile(certPath, []byte("cert v2"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v2"), 0600)
	_, err = m.Backup("example.com", certPath, keyPath, &CertInfo{Subject: "v2"})
	if err != nil {
		t.Fatalf("Backup() v2 error = %v", err)
	}

	// 等待确保恢复时内部备份的时间戳不同于 v2
	time.Sleep(time.Second)

	// 修改文件为 v3
	_ = os.WriteFile(certPath, []byte("cert v3"), 0644)
	_ = os.WriteFile(keyPath, []byte("key v3"), 0600)

	// 不指定 timestamp，应恢复最新备份（v2）
	meta, err := m.Restore("example.com")
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if meta.CertInfo.Subject != "v2" {
		t.Errorf("restored Subject = %s, want v2", meta.CertInfo.Subject)
	}

	certData, _ := os.ReadFile(certPath)
	if string(certData) != "cert v2" {
		t.Errorf("cert not restored to v2, got %q", string(certData))
	}
}

// TestRestore_TimestampNotExist 测试指定不存在的 timestamp 时 Restore 报错
func TestRestore_TimestampNotExist(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	// 创建站点目录使其存在
	_ = os.MkdirAll(filepath.Join(backupDir, "example.com"), 0755)

	m := NewManager(backupDir, 5)

	_, err := m.Restore("example.com", "99990101-000000")
	if err == nil {
		t.Fatal("Restore() should fail for nonexistent timestamp")
	}
	if !strings.Contains(err.Error(), "备份不存在") {
		t.Errorf("error should mention backup not exist, got: %v", err)
	}
}

// TestListBackups_ReadDirError 测试 ListBackups 对非目录的处理
func TestListBackups_ReadDirError(t *testing.T) {
	dir := t.TempDir()
	// 创建一个文件代替目录
	sitePath := filepath.Join(dir, "example.com")
	_ = os.WriteFile(sitePath, []byte("not a dir"), 0644)

	m := NewManager(dir, 5)

	_, err := m.ListBackups("example.com")
	if err == nil {
		t.Fatal("ListBackups() should fail when site path is a file, not a directory")
	}
	if !strings.Contains(err.Error(), "failed to read backup directory") {
		t.Errorf("error should mention read failure, got: %v", err)
	}
}

// TestBackup_KeySymlink 测试私钥软链接备份
func TestBackup_KeySymlink(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	_ = os.WriteFile(certPath, []byte("cert content"), 0644)

	// key 为符号链接
	realKeyPath := filepath.Join(srcDir, "real-key.pem")
	_ = os.WriteFile(realKeyPath, []byte("key content"), 0600)
	keyPath := filepath.Join(srcDir, "key.pem")
	if err := os.Symlink(realKeyPath, keyPath); err != nil {
		t.Skip("无法创建符号链接:", err)
	}

	m := NewManager(backupDir, 3)

	_, err := m.Backup("example.com", certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("Backup key symlink: %v", err)
	}
}

// TestGetLatestBackup_ListError 测试 GetLatestBackup 当目录不可读时
func TestGetLatestBackup_ListError(t *testing.T) {
	dir := t.TempDir()
	// 创建一个文件代替目录，使 ListBackups 返回错误
	sitePath := filepath.Join(dir, "example.com")
	_ = os.WriteFile(sitePath, []byte("not a dir"), 0644)

	m := NewManager(dir, 5)

	_, err := m.GetLatestBackup("example.com")
	if err == nil {
		t.Fatal("GetLatestBackup() should fail when ListBackups fails")
	}
}

// TestRestore_MetadataLoadError 测试 Restore 加载损坏元数据时报错
func TestRestore_MetadataLoadError(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteName := "example.com"
	timestamp := "20240101-120000"

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	// 写入损坏的 metadata
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), []byte("{invalid"), 0600)

	m := NewManager(backupDir, 5)

	_, err := m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail with invalid metadata")
	}
	if !strings.Contains(err.Error(), "加载备份元数据失败") {
		t.Errorf("error should mention metadata load failure, got: %v", err)
	}
}

// TestRestore_SkipPreBackupWhenFilesNotExist 测试 Restore 时目标文件不存在时跳过恢复前备份
func TestRestore_SkipPreBackupWhenFilesNotExist(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	siteName := "example.com"
	timestamp := "20240101-120000"

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	// 目标路径指向一个不存在的目录
	certDest := filepath.Join(srcDir, "cert.pem")
	keyDest := filepath.Join(srcDir, "key.pem")

	// 创建完整的备份
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("backup cert"), 0644)
	_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("backup key"), 0600)

	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   certDest,
		KeyPath:    keyDest,
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	m := NewManager(backupDir, 5)

	// 确保目标目录存在（CopyFile 需要）
	_ = os.MkdirAll(srcDir, 0755)

	// 目标文件不存在，应跳过恢复前备份，直接恢复
	meta, err := m.Restore(siteName, timestamp)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if meta.ServerName != siteName {
		t.Errorf("restored ServerName = %s, want %s", meta.ServerName, siteName)
	}

	// 验证文件已恢复
	certData, _ := os.ReadFile(certDest)
	if string(certData) != "backup cert" {
		t.Errorf("cert not restored, got %q", string(certData))
	}
}

// TestRestore_CopyFail 测试 Restore 恢复证书文件失败（目标目录不存在）
func TestRestore_CopyFail(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	siteName := "example.com"
	timestamp := "20240101-120000"

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	// 创建备份文件
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
	_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)

	// metadata 中 CertPath 指向一个不存在的目录（CopyFile 会失败）
	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   filepath.Join(dir, "nonexistent-dir", "cert.pem"),
		KeyPath:    filepath.Join(dir, "nonexistent-dir", "key.pem"),
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	m := NewManager(backupDir, 5)

	_, err := m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail when target directory does not exist")
	}
	if !strings.Contains(err.Error(), "恢复证书失败") {
		t.Errorf("error should mention cert restore failure, got: %v", err)
	}
}

// TestRestore_KeyCopyFail 测试 Restore 恢复私钥文件失败
func TestRestore_KeyCopyFail(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	siteName := "example.com"
	timestamp := "20240101-120000"

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)
	_ = os.MkdirAll(srcDir, 0755)

	// 创建备份文件
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
	_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)

	// CertPath 正常，KeyPath 指向不存在的目录
	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   filepath.Join(srcDir, "cert.pem"),
		KeyPath:    filepath.Join(dir, "nonexistent-dir", "key.pem"),
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	m := NewManager(backupDir, 5)

	_, err := m.Restore(siteName, timestamp)
	if err == nil {
		t.Fatal("Restore() should fail when key target directory does not exist")
	}
	if !strings.Contains(err.Error(), "恢复私钥失败") {
		t.Errorf("error should mention key restore failure, got: %v", err)
	}
}

// TestRestore_PreBackupFail 测试 Restore 恢复前备份当前文件失败
func TestRestore_PreBackupFail(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	siteName := "example.com"
	timestamp := "20240101-120000"
	_ = os.MkdirAll(srcDir, 0755)

	backupPath := filepath.Join(backupDir, siteName, timestamp)
	_ = os.MkdirAll(backupPath, 0700)

	certDest := filepath.Join(srcDir, "cert.pem")
	keyDest := filepath.Join(srcDir, "key.pem")

	// 备份文件
	_ = os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("backup cert"), 0644)
	_ = os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("backup key"), 0600)

	metadata := &Metadata{
		ServerName: siteName,
		BackupAt:   time.Now(),
		CertPath:   certDest,
		KeyPath:    keyDest,
	}
	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	_ = os.WriteFile(filepath.Join(backupPath, "metadata.json"), metaData, 0600)

	// 当前目标文件存在（触发恢复前备份）
	_ = os.WriteFile(certDest, []byte("current cert"), 0644)
	_ = os.WriteFile(keyDest, []byte("current key"), 0600)

	// 设置站点备份目录为只读，使 backupWithoutCleanup 创建新目录失败
	siteBackupDir := filepath.Join(backupDir, siteName)
	_ = os.Chmod(siteBackupDir, 0555)

	m := NewManager(backupDir, 5)

	_, err := m.Restore(siteName, timestamp)

	// 恢复权限以便 TempDir 清理
	_ = os.Chmod(siteBackupDir, 0755)

	if err == nil {
		t.Fatal("Restore() should fail when pre-backup fails")
	}
	if !strings.Contains(err.Error(), "恢复前备份当前文件失败") {
		t.Errorf("error should mention pre-backup failure, got: %v", err)
	}
}

// TestBackup_KeyNotExist 测试 cert 正常��� key 不存在时���份失败
func TestBackup_KeyNotExist(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	_ = os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	_ = os.WriteFile(certPath, []byte("cert content"), 0644)

	m := NewManager(backupDir, 3)

	_, err := m.Backup("example.com", certPath, filepath.Join(srcDir, "nonexistent-key.pem"), nil)
	if err == nil {
		t.Error("Backup() should fail when key file does not exist")
	}
	if !strings.Contains(err.Error(), "failed to hash private key file") {
		t.Errorf("error should mention key hash failure, got: %v", err)
	}
}
