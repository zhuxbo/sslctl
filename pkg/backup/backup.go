// Package backup 备份管理
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/zhuxbo/sslctl/pkg/util"
)

// computeFileHash 计算文件 SHA256 哈希（用于 TOCTOU 保护）
// 拒绝符号链接源文件，防止路径劫持
func computeFileHash(path string) (string, error) {
	// 符号链接检查：拒绝符号链接源文件
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symbolic link not allowed for backup source: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
	if keepVersions < 1 {
		keepVersions = 5
	}
	return &Manager{
		backupDir:    backupDir,
		keepVersions: keepVersions,
	}
}

// Backup 备份证书文件
// chainPath 可选，用于 Apache 备份证书链文件
// 使用文件内容哈希进行 TOCTOU 保护，比时间戳更可靠
func (m *Manager) Backup(siteName, certPath, keyPath string, certInfo *CertInfo, chainPath ...string) (*BackupResult, error) {
	// 0. 计算源文件哈希（用于检测并发修改，比时间戳更可靠）
	certHash, err := computeFileHash(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash certificate file: %w", err)
	}
	keyHash, err := computeFileHash(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash private key file: %w", err)
	}

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

	// 3.1 验证源文件在备份期间未被修改（TOCTOU 保护）
	// 使用哈希校验比时间戳更可靠（不受文件系统精度影响，无法被 touch 欺骗）
	newCertHash, err := computeFileHash(certPath)
	if err != nil || newCertHash != certHash {
		if rmErr := os.RemoveAll(backupPath); rmErr != nil {
			fmt.Fprintf(os.Stderr, "[BACKUP WARN] 清理损坏的备份失败 %s: %v\n", backupPath, rmErr)
		}
		if err != nil {
			return nil, fmt.Errorf("certificate file changed during backup: %w", err)
		}
		return nil, fmt.Errorf("certificate file changed during backup (hash mismatch)")
	}
	newKeyHash, err := computeFileHash(keyPath)
	if err != nil || newKeyHash != keyHash {
		if rmErr := os.RemoveAll(backupPath); rmErr != nil {
			fmt.Fprintf(os.Stderr, "[BACKUP WARN] 清理损坏的备份失败 %s: %v\n", backupPath, rmErr)
		}
		if err != nil {
			return nil, fmt.Errorf("private key file changed during backup: %w", err)
		}
		return nil, fmt.Errorf("private key file changed during backup (hash mismatch)")
	}

	// 4. 备份证书链文件（可选，带 TOCTOU 保护）
	var actualChainPath string
	if len(chainPath) > 0 && chainPath[0] != "" {
		actualChainPath = chainPath[0]
		// 计算 chain 文件哈希
		chainHash, err := computeFileHash(actualChainPath)
		if err != nil {
			// chain 文件不存在或无法读取，跳过备份
			actualChainPath = ""
		} else {
			backupChainPath := filepath.Join(backupPath, "chain.pem")
			if err := util.CopyFile(actualChainPath, backupChainPath); err != nil {
				// chain 文件备份失败不影响整体备份
				actualChainPath = ""
			} else {
				// 验证 chain 文件在备份期间未被修改
				newChainHash, err := computeFileHash(actualChainPath)
				if err != nil || newChainHash != chainHash {
					// chain 文件已被修改，删除备份的 chain 文件
					if rmErr := os.Remove(backupChainPath); rmErr != nil {
						fmt.Fprintf(os.Stderr, "[BACKUP WARN] 清理损坏的 chain 备份失败 %s: %v\n", backupChainPath, rmErr)
					}
					actualChainPath = ""
				}
			}
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
