// Package backup 备份管理
package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/util"
)

// Metadata 备份元数据
type Metadata struct {
	SiteName  string    `json:"site_name"`
	BackupAt  time.Time `json:"backup_at"`
	CertInfo  CertInfo  `json:"cert_info"`
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path"`
	ChainPath string    `json:"chain_path,omitempty"`
}

// CertInfo 证书信息
type CertInfo struct {
	Subject   string    `json:"subject"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// Manager 备份管理器
type Manager struct {
	backupDir    string // 备份根目录
	keepVersions int    // 保留版本数
}

// BackupResult 备份结果
type BackupResult struct {
	BackupPath   string // 备份路径
	CleanupError error  // 清理错误（非致命）
}

// NewManager 创建备份管理器
func NewManager(backupDir string, keepVersions int) *Manager {
	return &Manager{
		backupDir:    backupDir,
		keepVersions: keepVersions,
	}
}

// Backup 备份证书文件
// chainPath 可选，用于 Apache 备份证书链文件
func (m *Manager) Backup(siteName, certPath, keyPath string, certInfo *CertInfo, chainPath ...string) (*BackupResult, error) {
	// 0. 记录源文件的修改时间（用于检测并发修改）
	certStat, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat certificate file: %w", err)
	}
	keyStat, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat private key file: %w", err)
	}
	certModTime := certStat.ModTime()
	keyModTime := keyStat.ModTime()

	// 1. 创建备份目录
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(m.backupDir, siteName, timestamp)

	// 备份目录包含私钥文件，使用 0700 更安全
	if err := util.EnsureDir(backupPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	// 2. 备份证书文件
	backupCertPath := filepath.Join(backupPath, "cert.pem")
	if err := util.CopyFile(certPath, backupCertPath); err != nil {
		return nil, fmt.Errorf("failed to backup certificate: %w", err)
	}

	// 3. 备份私钥文件
	backupKeyPath := filepath.Join(backupPath, "key.pem")
	if err := util.CopyFile(keyPath, backupKeyPath); err != nil {
		return nil, fmt.Errorf("failed to backup private key: %w", err)
	}

	// 3.1 验证源文件在备份期间未被修改
	newCertStat, err := os.Stat(certPath)
	if err == nil && newCertStat.ModTime() != certModTime {
		// 源文件已被修改，删除备份并返回错误
		_ = os.RemoveAll(backupPath)
		return nil, fmt.Errorf("certificate file changed during backup")
	}
	newKeyStat, err := os.Stat(keyPath)
	if err == nil && newKeyStat.ModTime() != keyModTime {
		// 源文件已被修改，删除备份并返回错误
		_ = os.RemoveAll(backupPath)
		return nil, fmt.Errorf("private key file changed during backup")
	}

	// 4. 备份证书链文件（可选）
	var actualChainPath string
	if len(chainPath) > 0 && chainPath[0] != "" {
		actualChainPath = chainPath[0]
		backupChainPath := filepath.Join(backupPath, "chain.pem")
		if err := util.CopyFile(actualChainPath, backupChainPath); err != nil {
			// chain 文件备份失败不影响整体备份
			// 清空 actualChainPath 确保 metadata 不记录未备份的文件
			// 这样回滚时不会尝试恢复不存在的 chain 文件
			actualChainPath = ""
		}
	}

	// 5. 保存元数据
	metadata := &Metadata{
		SiteName:  siteName,
		BackupAt:  time.Now(),
		CertPath:  certPath,
		KeyPath:   keyPath,
		ChainPath: actualChainPath,
	}

	if certInfo != nil {
		metadata.CertInfo = *certInfo
	}

	metaPath := filepath.Join(backupPath, "metadata.json")
	if err := m.saveMetadata(metaPath, metadata); err != nil {
		return nil, fmt.Errorf("failed to save metadata: %w", err)
	}

	result := &BackupResult{
		BackupPath: backupPath,
	}

	// 6. 清理老版本
	if err := m.cleanup(siteName); err != nil {
		result.CleanupError = err
	}

	return result, nil
}

// ListBackups 列出站点的所有备份
func (m *Manager) ListBackups(siteName string) ([]string, error) {
	siteBackupDir := filepath.Join(m.backupDir, siteName)

	entries, err := os.ReadDir(siteBackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []string
	for _, entry := range entries {
		if entry.IsDir() {
			backups = append(backups, entry.Name())
		}
	}

	// 按时间排序(最新的在前)
	sort.Sort(sort.Reverse(sort.StringSlice(backups)))

	return backups, nil
}

// GetLatestBackup 获取最新的备份
func (m *Manager) GetLatestBackup(siteName string) (string, error) {
	backups, err := m.ListBackups(siteName)
	if err != nil {
		return "", err
	}

	if len(backups) == 0 {
		return "", fmt.Errorf("no backup found for site: %s", siteName)
	}

	return filepath.Join(m.backupDir, siteName, backups[0]), nil
}

// GetBackupPaths 获取备份的证书和私钥路径
func (m *Manager) GetBackupPaths(backupPath string) (certPath, keyPath string) {
	certPath = filepath.Join(backupPath, "cert.pem")
	keyPath = filepath.Join(backupPath, "key.pem")
	return
}

// GetBackupPathsWithChain 获取备份的证书、私钥和证书链路径
func (m *Manager) GetBackupPathsWithChain(backupPath string) (certPath, keyPath, chainPath string) {
	certPath = filepath.Join(backupPath, "cert.pem")
	keyPath = filepath.Join(backupPath, "key.pem")
	chainPath = filepath.Join(backupPath, "chain.pem")
	return
}

// LoadMetadata 加载备份元数据
func (m *Manager) LoadMetadata(backupPath string) (*Metadata, error) {
	metaPath := filepath.Join(backupPath, "metadata.json")

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

// cleanup 清理老版本备份
func (m *Manager) cleanup(siteName string) error {
	backups, err := m.ListBackups(siteName)
	if err != nil {
		return err
	}

	// 如果备份数量超过限制,删除最老的
	if len(backups) > m.keepVersions {
		siteBackupDir := filepath.Join(m.backupDir, siteName)

		for i := m.keepVersions; i < len(backups); i++ {
			oldBackup := filepath.Join(siteBackupDir, backups[i])
			if err := os.RemoveAll(oldBackup); err != nil {
				return fmt.Errorf("failed to remove old backup: %w", err)
			}
		}
	}

	return nil
}

// saveMetadata 保存元数据
func (m *Manager) saveMetadata(path string, metadata *Metadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// DeleteBackup 删除指定备份
func (m *Manager) DeleteBackup(siteName, timestamp string) error {
	backupPath := filepath.Join(m.backupDir, siteName, timestamp)
	return os.RemoveAll(backupPath)
}

// DeleteAllBackups 删除站点的所有备份
func (m *Manager) DeleteAllBackups(siteName string) error {
	siteBackupDir := filepath.Join(m.backupDir, siteName)
	return os.RemoveAll(siteBackupDir)
}
