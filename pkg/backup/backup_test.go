// Package backup 备份管理测试
package backup

import (
	"os"
	"path/filepath"
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
	os.MkdirAll(srcDir, 0755)

	// 创建测试文件
	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"), 0644)
	os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"), 0600)

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
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	chainPath := filepath.Join(srcDir, "chain.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)
	os.WriteFile(chainPath, []byte("chain"), 0644)

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
	os.MkdirAll(siteBackupDir, 0755)

	// 手动创建不同时间戳的备份目录
	timestamps := []string{"20240101-120000", "20240101-120001", "20240101-120002"}
	for _, ts := range timestamps {
		backupPath := filepath.Join(siteBackupDir, ts)
		os.MkdirAll(backupPath, 0755)
		os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
		os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)
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
	os.MkdirAll(siteBackupDir, 0755)

	// 手动创建不同时间戳的备份目录
	oldBackup := filepath.Join(siteBackupDir, "20240101-120000")
	newBackup := filepath.Join(siteBackupDir, "20240101-120001")
	for _, path := range []string{oldBackup, newBackup} {
		os.MkdirAll(path, 0755)
		os.WriteFile(filepath.Join(path, "cert.pem"), []byte("cert"), 0644)
		os.WriteFile(filepath.Join(path, "key.pem"), []byte("key"), 0600)
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
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

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

	if meta.SiteName != "example.com" {
		t.Errorf("SiteName = %s, want example.com", meta.SiteName)
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
	os.MkdirAll(srcDir, 0755)
	os.MkdirAll(siteBackupDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

	// 手动创建 4 个已有的备份目录
	timestamps := []string{"20240101-120000", "20240101-120001", "20240101-120002", "20240101-120003"}
	for _, ts := range timestamps {
		backupPath := filepath.Join(siteBackupDir, ts)
		os.MkdirAll(backupPath, 0755)
		os.WriteFile(filepath.Join(backupPath, "cert.pem"), []byte("cert"), 0644)
		os.WriteFile(filepath.Join(backupPath, "key.pem"), []byte("key"), 0600)
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
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

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
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

	m := NewManager(backupDir, 10)

	// 创建多个备份（只需创建一个即可验证删除功能）
	for i := 0; i < 1; i++ {
		m.Backup("example.com", certPath, keyPath, nil)
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
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

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

// TestManager_BackupSourceNotExist 测试备份不存在的源文件
func TestManager_BackupSourceNotExist(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, 3)

	_, err := m.Backup("example.com", "/nonexistent/cert.pem", "/nonexistent/key.pem", nil)
	if err == nil {
		t.Error("Backup() should fail for nonexistent source files")
	}
}

// TestManager_BackupChainNotExist 测试证书链文件不存在时的备份
func TestManager_BackupChainNotExist(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backup")
	srcDir := filepath.Join(dir, "src")
	os.MkdirAll(srcDir, 0755)

	certPath := filepath.Join(srcDir, "cert.pem")
	keyPath := filepath.Join(srcDir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0644)
	os.WriteFile(keyPath, []byte("key"), 0600)

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
