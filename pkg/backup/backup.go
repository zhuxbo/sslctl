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
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Metadata 备份元数据
type Metadata struct {
	ResolvedPaths map[string]string `json:"resolved_paths,omitempty"`
	ServerName    string            `json:"server_name"`
	ContainerName string            `json:"container_name,omitempty"`
	BackupAt      time.Time         `json:"backup_at"`
	CertInfo      CertInfo          `json:"cert_info"`
	CertPath      string            `json:"cert_path"`
	KeyPath       string            `json:"key_path"`
	ChainPath     string            `json:"chain_path,omitempty"`
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
	return m.backupInternal(siteName, certPath, keyPath, certInfo, true, nil, chainPath...)
}

var (
	containerSnapshotStat  = os.Stat
	containerSnapshotChmod = os.Chmod
)

// BackupContainer 从受保护的本地快照保存容器备份，元数据保留容器身份和容器内路径。
func (m *Manager) BackupContainer(siteName, containerName, certPath, keyPath, localCert, localKey string) (*BackupResult, error) {
	result, err := m.backupInternal(siteName, localCert, localKey, nil, true, &Metadata{
		ContainerName: containerName, CertPath: certPath, KeyPath: keyPath,
	})
	if err != nil {
		return nil, err
	}
	// CopyFile 创建文件会受 umask 影响；容器回滚必须保留原文件权限。
	for name, source := range map[string]string{"cert.pem": localCert, "key.pem": localKey} {
		info, err := containerSnapshotStat(source)
		if err != nil {
			return nil, err
		}
		if err := containerSnapshotChmod(filepath.Join(result.BackupPath, name), info.Mode().Perm()); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// backupWithoutCleanup 备份但不清理旧版本（Restore 内部使用，防止清理掉正在恢复的目标备份）
func (m *Manager) backupWithoutCleanup(siteName, certPath, keyPath string, certInfo *CertInfo, chainPath ...string) (*BackupResult, error) {
	return m.backupInternal(siteName, certPath, keyPath, certInfo, false, nil, chainPath...)
}

// backupInternal 备份核心实现
func (m *Manager) backupInternal(siteName, certPath, keyPath string, certInfo *CertInfo, doCleanup bool, target *Metadata, chainPath ...string) (*BackupResult, error) {
	originalCert, originalKey := certPath, keyPath
	originalChain := ""
	if len(chainPath) > 0 {
		originalChain = chainPath[0]
	}
	files := make(map[string]*util.CertificateFile)
	resolved := make(map[string]string)
	for _, path := range []string{certPath, keyPath, originalChain} {
		if path == "" {
			continue
		}
		if path == originalChain {
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				originalChain = ""
				continue
			}
		}
		if target != nil {
			if _, err := computeFileHash(path); err != nil {
				return nil, fmt.Errorf("failed to hash certificate file: %w", err)
			}
		}
		file, err := util.ResolveCertificateFile(path)
		if err != nil {
			label := "certificate"
			if path == keyPath {
				label = "private key"
			}
			return nil, fmt.Errorf("failed to hash %s file: %w", label, err)
		}
		files[path] = file
		resolved[path] = file.Target
	}
	certPath, keyPath = resolved[certPath], resolved[keyPath]
	if originalChain != "" {
		chainPath = []string{resolved[originalChain]}
	} else {
		chainPath = nil
	}
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
	if target != nil {
		timestamp = time.Now().Format("20060102-150405.000000000")
	}
	backupPath := filepath.Join(m.backupDir, siteName, timestamp)
	if _, err := os.Lstat(backupPath); err == nil {
		backupPath = filepath.Join(m.backupDir, siteName, time.Now().Format("20060102-150405.000000000"))
	}

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

	// 4. 已存在的独立证书链必须成功备份，不能在缺少回滚副本时继续覆盖。
	var actualChainPath string
	if len(chainPath) > 0 && chainPath[0] != "" {
		actualChainPath = chainPath[0]
		chainHash, err := computeFileHash(actualChainPath)
		if err != nil {
			_ = os.RemoveAll(backupPath)
			return nil, fmt.Errorf("备份证书链失败: %w", err)
		}
		if err := util.CopyFile(actualChainPath, filepath.Join(backupPath, "chain.pem")); err != nil {
			_ = os.RemoveAll(backupPath)
			return nil, fmt.Errorf("备份证书链失败: %w", err)
		}
		newHash, err := computeFileHash(actualChainPath)
		if err != nil || newHash != chainHash {
			_ = os.RemoveAll(backupPath)
			return nil, fmt.Errorf("证书链在备份期间发生变化: %s", originalChain)
		}
	}

	// 再次核对原始链接与备份内容；相同内容的链接改向也视为冲突。
	for path, file := range files {
		if err := file.Check(); err != nil {
			_ = os.RemoveAll(backupPath)
			return nil, err
		}
		name := ""
		switch path {
		case originalCert:
			name = "cert.pem"
		case originalKey:
			name = "key.pem"
		case originalChain:
			if actualChainPath != "" {
				name = "chain.pem"
			}
		}
		if name == "" {
			continue
		}
		sourceHash, err := computeFileHash(file.Target)
		backupHash, copyErr := computeFileHash(filepath.Join(backupPath, name))
		if err != nil || copyErr != nil || sourceHash != backupHash {
			_ = os.RemoveAll(backupPath)
			return nil, fmt.Errorf("备份内容校验失败: %s", path)
		}
	}
	if actualChainPath != "" {
		actualChainPath = originalChain
	}
	// 5. 保存元数据
	metadata := &Metadata{
		ServerName:    siteName,
		BackupAt:      time.Now(),
		CertPath:      originalCert,
		KeyPath:       originalKey,
		ResolvedPaths: resolved,
		ChainPath:     actualChainPath,
	}

	if target != nil {
		metadata.ResolvedPaths = nil
		metadata.ContainerName = target.ContainerName
		metadata.CertPath = target.CertPath
		metadata.KeyPath = target.KeyPath
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

	// 6. 清理老版本（Restore 调用时跳过，防止清理掉正在恢复的目标备份）
	if doCleanup {
		if err := m.cleanup(siteName); err != nil {
			result.CleanupError = err
		}
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

// ResolveBackupPath 安全解析指定版本或最新备份，供宿主机与容器恢复共用。
func (m *Manager) ResolveBackupPath(siteName string, timestamp ...string) (string, error) {
	var backupPath string
	var err error

	if len(timestamp) > 0 && timestamp[0] != "" {
		var joinErr error
		backupPath, joinErr = util.JoinUnderDir(m.backupDir, filepath.Join(siteName, timestamp[0]))
		if joinErr != nil {
			return "", fmt.Errorf("invalid backup path: %w", joinErr)
		}
		if _, statErr := os.Stat(backupPath); os.IsNotExist(statErr) {
			return "", fmt.Errorf("备份不存在: %s/%s", siteName, timestamp[0])
		}
	} else {
		backupPath, err = m.GetLatestBackup(siteName)
		if err != nil {
			return "", fmt.Errorf("获取最新备份失败: %w", err)
		}
	}

	return backupPath, nil
}

// Restore 从备份恢复证书文件
// timestamp 可选，为空时恢复最新备份
// 恢复前自动备份当前文件
func (m *Manager) Restore(siteName string, timestamp ...string) (*Metadata, error) {
	backupPath, err := m.ResolveBackupPath(siteName, timestamp...)
	if err != nil {
		return nil, err
	}

	// 加载备份元数据
	metadata, err := m.LoadMetadata(backupPath)
	if err != nil {
		return nil, fmt.Errorf("加载备份元数据失败: %w", err)
	}

	if metadata.ContainerName != "" {
		return nil, fmt.Errorf("容器备份必须通过 Docker 恢复，拒绝写入宿主机同名路径")
	}

	// 获取备份文件路径
	certSrc, keySrc, chainSrc := m.GetBackupPathsWithChain(backupPath)

	// 验证备份文件存在
	if _, err := os.Stat(certSrc); os.IsNotExist(err) {
		return nil, fmt.Errorf("备份证书文件不存在: cert.pem")
	}
	if _, err := os.Stat(keySrc); os.IsNotExist(err) {
		return nil, fmt.Errorf("备份私钥文件不存在: key.pem")
	}

	// 验证必要路径非空
	if metadata.CertPath == "" || metadata.KeyPath == "" {
		return nil, fmt.Errorf("备份元数据中 CertPath 或 KeyPath 为空")
	}

	if metadata.ChainPath != "" {
		if _, err := os.Stat(chainSrc); err != nil {
			return nil, fmt.Errorf("恢复证书链失败: %w", err)
		}
	}

	// 新备份只恢复到记录的真实目标，续签改向后拒绝覆盖新的证书版本。
	files := make(map[string]*util.CertificateFile)
	for _, path := range []string{metadata.CertPath, metadata.KeyPath, metadata.ChainPath} {
		if path == "" {
			continue
		}
		file, err := util.ResolveCertificateFile(path)
		if err != nil {
			label := "证书"
			if path == metadata.KeyPath {
				label = "私钥"
			}
			if path == metadata.ChainPath {
				label = "证书链"
			}
			return nil, fmt.Errorf("恢复%s失败: %w", label, err)
		}
		if expected := metadata.ResolvedPaths[path]; expected != "" {
			if expected != file.Target {
				return nil, fmt.Errorf("证书链接目标已变化，拒绝恢复: %s", path)
			}
		} else if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("旧备份未记录符号链接目标，拒绝恢复: %s", path)
		}
		files[path] = file
	}
	restore := func(source, target string) error {
		for _, file := range files {
			if err := file.Check(); err != nil {
				return err
			}
		}
		data, err := util.SafeReadFile(source, 16<<20)
		if err != nil {
			return err
		}
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		return files[target].Write(data, info.Mode().Perm())
	}

	// 恢复前备份当前文件（防止误操作）
	// 使用 backupWithoutCleanup 避免清理掉正在恢复的目标备份
	if util.FileExists(metadata.CertPath) && util.FileExists(metadata.KeyPath) {
		_, backupErr := m.backupWithoutCleanup(siteName, metadata.CertPath, metadata.KeyPath, nil, metadata.ChainPath)
		if backupErr != nil {
			return nil, fmt.Errorf("恢复前备份当前文件失败: %w", backupErr)
		}
	}

	// 恢复证书文件
	if err := restore(certSrc, metadata.CertPath); err != nil {
		return nil, fmt.Errorf("恢复证书失败: %w", err)
	}

	// 恢复私钥文件
	if err := restore(keySrc, metadata.KeyPath); err != nil {
		return nil, fmt.Errorf("恢复私钥失败: %w", err)
	}

	// 恢复证书链文件（如果有）
	if metadata.ChainPath != "" {
		if err := restore(chainSrc, metadata.ChainPath); err != nil {
			return nil, fmt.Errorf("恢复证书链失败: %w", err)
		}
	}

	return metadata, nil
}

// DeleteBackup 删除指定备份
func (m *Manager) DeleteBackup(siteName, timestamp string) error {
	backupPath, err := util.JoinUnderDir(m.backupDir, filepath.Join(siteName, timestamp))
	if err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}
	return os.RemoveAll(backupPath)
}

// DeleteAllBackups 删除站点的所有备份
func (m *Manager) DeleteAllBackups(siteName string) error {
	siteBackupDir, err := util.JoinUnderDir(m.backupDir, siteName)
	if err != nil {
		return fmt.Errorf("invalid site name: %w", err)
	}
	return os.RemoveAll(siteBackupDir)
}
