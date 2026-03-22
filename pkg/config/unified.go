// Package config 统一配置管理器
package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/zhuxbo/sslctl/pkg/validator"
)

// tokenFormatRegex Token 格式正则：允许字母、数字、连字符、下划线、点
var tokenFormatRegex = regexp.MustCompile(`^[A-Za-z0-9\-_\.]+$`)

// ConfigManager 统一配置管理器
type ConfigManager struct {
	workDir    string
	configPath string
	certsDir   string
	logsDir    string
	backupDir  string
	mu         sync.RWMutex
	config     *Config
	cachedAt   time.Time    // 缓存加载时间，用于 mtime 检测
	cachedHash [sha256.Size]byte // 缓存内容哈希，防止 NFS/VM 环境 mtime 不准
}

// NewConfigManager 创建统一配置管理器
func NewConfigManager() (*ConfigManager, error) {
	var workDir string
	if runtime.GOOS == "windows" {
		workDir = `C:\sslctl`
	} else {
		workDir = "/opt/sslctl"
	}

	return NewConfigManagerWithDir(workDir)
}

// NewConfigManagerWithDir 创建指定工作目录的配置管理器（用于测试）
func NewConfigManagerWithDir(workDir string) (*ConfigManager, error) {
	cm := &ConfigManager{
		workDir:    workDir,
		configPath: filepath.Join(workDir, "config.json"),
		certsDir:   filepath.Join(workDir, "certs"),
		logsDir:    filepath.Join(workDir, "logs"),
		backupDir:  filepath.Join(workDir, "backup"),
	}

	if err := cm.ensureDirs(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cm, nil
}

// ensureDirs 确保必要的目录存在
func (cm *ConfigManager) ensureDirs() error {
	dirs := []struct {
		path string
		perm os.FileMode
	}{
		{cm.workDir, 0700},  // 工作目录收紧权限，仅 root 可访问
		{cm.certsDir, 0700},
		{cm.logsDir, 0700},
		{cm.backupDir, 0700},
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, dir.perm); err != nil {
			return err
		}
	}

	return nil
}

// Load 加载配置
// 重要：返回配置的深拷贝副本，对返回值的修改不会影响内部缓存。
// 如需持久化修改，必须显式调用 Save() 或使用 UpdateCert() 等方法。
func (cm *ConfigManager) Load() (*Config, error) {
	cm.mu.RLock()
	if cm.config != nil {
		// 检查文件是否被外部修改（mtime 比缓存时间新则重新加载）
		needReload := false
		if !cm.cachedAt.IsZero() {
			if info, err := os.Stat(cm.configPath); err == nil && info.ModTime().After(cm.cachedAt) {
				needReload = true
			}
		}
		if !needReload {
			cfg := cm.copyConfig(cm.config)
			cm.mu.RUnlock()
			return cfg, nil
		}
		cm.mu.RUnlock()
		// 需要重新加载，升级到写锁
		cm.mu.Lock()
		// 再次检查 mtime，可能在锁升级窗口期间已被其他 goroutine 重新加载
		if cm.config != nil {
			if info, err := os.Stat(cm.configPath); err == nil && !info.ModTime().After(cm.cachedAt) {
				result := cm.copyConfig(cm.config)
				cm.mu.Unlock()
				return result, nil
			}
		}
		cm.config = nil
		cfg, err := cm.loadLocked()
		if err != nil {
			cm.mu.Unlock()
			return nil, err
		}
		result := cm.copyConfig(cfg)
		cm.mu.Unlock()
		return result, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return nil, err
	}
	return cm.copyConfig(cfg), nil
}

// copyConfig 创建配置的深拷贝
//
// 重要：并发安全保证
// 此函数确保返回的配置对象与内部缓存完全独立，调用方可以安全修改返回值。
//
// 维护注意事项：
// - 如果向 CertConfig 或 SiteBinding 添加新的引用类型字段（map、slice、指针），
//   必须在此函数中添加对应的深拷贝逻辑，否则会破坏并发安全保证！
// - 当前已处理的引用类型：Certificates(slice)、Bindings(slice)、Domains(slice)、Docker(*DockerInfo)、FailedBindings(slice)
func (cm *ConfigManager) copyConfig(src *Config) *Config {
	if src == nil {
		return nil
	}
	dst := *src
	// 深拷贝切片
	if src.Certificates != nil {
		dst.Certificates = make([]CertConfig, len(src.Certificates))
		for i, cert := range src.Certificates {
			dst.Certificates[i] = cert
			// 深拷贝 Bindings 切片
			if cert.Bindings != nil {
				dst.Certificates[i].Bindings = make([]SiteBinding, len(cert.Bindings))
				for j, binding := range cert.Bindings {
					dst.Certificates[i].Bindings[j] = binding
					// 深拷贝 Docker 指针
					if binding.Docker != nil {
						dockerCopy := *binding.Docker
						dst.Certificates[i].Bindings[j].Docker = &dockerCopy
					}
				}
			}
			// 深拷贝 Domains 切片
			if cert.Domains != nil {
				dst.Certificates[i].Domains = make([]string, len(cert.Domains))
				copy(dst.Certificates[i].Domains, cert.Domains)
			}
			// 深拷贝 FailedBindings 切片
			if cert.Metadata.FailedBindings != nil {
				dst.Certificates[i].Metadata.FailedBindings = make([]string, len(cert.Metadata.FailedBindings))
				copy(dst.Certificates[i].Metadata.FailedBindings, cert.Metadata.FailedBindings)
			}
		}
	}
	return &dst
}

// loadLocked 加载配置（调用者需持有锁）
func (cm *ConfigManager) loadLocked() (*Config, error) {
	// 双重检查
	if cm.config != nil {
		return cm.config, nil
	}

	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 返回默认配置
			cm.config = &Config{
				Schedule:     defaultSchedule(),
				Certificates: []CertConfig{},
			}
			cm.cachedAt = time.Now()
			cm.cachedHash = sha256.Sum256(nil)
			return cm.config, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// 计算内容哈希，防止 mtime 变更但内容未变时不必要的重新加载
	// 设计说明：mtime 变更时仍需 ReadFile（无法避免 I/O），但哈希匹配时跳过 JSON 解析。
	// 此检查仅在 mtime 触发重新加载时生效，正常缓存命中不涉及文件读取。
	hash := sha256.Sum256(data)
	if cm.cachedHash == hash && cm.config != nil {
		cm.cachedAt = time.Now()
		return cm.config, nil
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cm.config = &cfg
	cm.cachedAt = time.Now()
	cm.cachedHash = hash

	return cm.config, nil
}

// Save 保存配置
func (cm *ConfigManager) Save(cfg *Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.saveLocked(cfg)
}

// saveLocked 保存配置（调用者需持有锁）
// 注意：序列化在文件锁之前完成，减少文件锁持有时间
// 使用 flock 机制，多个进程可以同时打开锁文件，但只有一个能获得排他锁
func (cm *ConfigManager) saveLocked(cfg *Config) error {
	// 1. 创建配置副本进行修改，避免修改原始对象
	cfgCopy := cm.copyConfig(cfg)
	cfgCopy.Metadata.UpdatedAt = time.Now()
	if cfgCopy.Metadata.CreatedAt.IsZero() {
		cfgCopy.Metadata.CreatedAt = time.Now()
	}

	// 2. 序列化配置（在文件锁之前完成，减少锁持有时间）
	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 3. 获取文件锁，防止并发写入和 TOCTOU 攻击
	// 注意：这里使用 flock 而非 O_EXCL，因为 flock 是基于文件描述符的锁
	// 多个进程可以同时打开同一个锁文件，但只有一个能成功获得 flock
	lockPath := cm.configPath + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}

	if err := lockFile(lf); err != nil {
		_ = lf.Close()
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = unlockFile(lf)
		_ = lf.Close()
	}()

	// 4. 原子写入（在文件锁保护下）
	// 使用 O_EXCL 防止符号链接攻击：如果文件已存在则失败
	tmpPath := cm.configPath + ".tmp"
	// 先删除可能存在的临时文件（可能是上次失败遗留的）
	_ = os.Remove(tmpPath)

	// O_CREATE|O_WRONLY|O_EXCL: 创建新文件，如果已存在则失败（防止符号链接攻击）
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, writeErr := tmpFile.Write(data)
	closeErr := tmpFile.Close()
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", closeErr)
	}

	// 验证临时文件不是符号链接（防止 TOCTOU）
	if info, err := os.Lstat(tmpPath); err != nil || info.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("TOCTOU attack detected: temp file is a symlink")
	}

	// 验证目标配置路径不是符号链接（防止通过符号链接覆盖任意文件）
	if info, err := os.Lstat(cm.configPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("security: config path is a symlink, refusing to write")
	}

	if err := os.Rename(tmpPath, cm.configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// 5. 只有在所有操作成功后才更新内存缓存
	cm.config = cfgCopy
	cm.cachedAt = time.Now()
	return nil
}

// UpdateMetadata 原子更新配置元数据（重新加载最新配置，避免覆盖其他更新）
func (cm *ConfigManager) UpdateMetadata(fn func(*ConfigMetadata)) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return err
	}
	fn(&cfg.Metadata)
	return cm.saveLocked(cfg)
}

// Reload 重新加载配置
// 注意：在持有锁时完成重新加载，避免竞态条件
func (cm *ConfigManager) Reload() (*Config, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config = nil
	cfg, err := cm.loadLocked()
	if err != nil {
		return nil, err
	}
	return cm.copyConfig(cfg), nil
}

// GetCert 获取指定证书配置
func (cm *ConfigManager) GetCert(certName string) (*CertConfig, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}

	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == certName {
			return &cfg.Certificates[i], nil
		}
	}
	return nil, fmt.Errorf("certificate not found: %s", certName)
}

// GetCertByOrderID 根据订单 ID 获取证书配置
func (cm *ConfigManager) GetCertByOrderID(orderID int) (*CertConfig, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}

	for i := range cfg.Certificates {
		if cfg.Certificates[i].OrderID == orderID {
			return &cfg.Certificates[i], nil
		}
	}
	return nil, fmt.Errorf("certificate not found for order: %d", orderID)
}

// AddCert 添加证书配置
func (cm *ConfigManager) AddCert(cert *CertConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return err
	}

	// 收集新证书绑定的站点名
	newSites := make(map[string]bool)
	for _, b := range cert.Bindings {
		newSites[b.ServerName] = true
	}

	// 移除其他证书中对相同站点的绑定（一个站点只能绑定一个证书）
	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == cert.CertName {
			continue
		}
		var kept []SiteBinding
		for _, b := range cfg.Certificates[i].Bindings {
			if !newSites[b.ServerName] {
				kept = append(kept, b)
			}
		}
		cfg.Certificates[i].Bindings = kept
	}

	// 检查是否已存在同名证书
	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == cert.CertName {
			cfg.Certificates[i] = *cert
			return cm.saveLocked(cfg)
		}
	}

	cfg.Certificates = append(cfg.Certificates, *cert)
	return cm.saveLocked(cfg)
}

// UpdateCert 更新证书配置
func (cm *ConfigManager) UpdateCert(cert *CertConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return err
	}

	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == cert.CertName {
			cfg.Certificates[i] = *cert
			return cm.saveLocked(cfg)
		}
	}
	return fmt.Errorf("certificate not found: %s", cert.CertName)
}

// DeleteCert 删除证书配置
func (cm *ConfigManager) DeleteCert(certName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return err
	}

	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == certName {
			cfg.Certificates = append(cfg.Certificates[:i], cfg.Certificates[i+1:]...)
			return cm.saveLocked(cfg)
		}
	}
	return fmt.Errorf("certificate not found: %s", certName)
}

// ListCerts 列出所有证书配置
func (cm *ConfigManager) ListCerts() ([]CertConfig, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}
	return cfg.Certificates, nil
}

// ListEnabledCerts 列出所有启用的证书配置
func (cm *ConfigManager) ListEnabledCerts() ([]CertConfig, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}

	var enabled []CertConfig
	for _, cert := range cfg.Certificates {
		if cert.Enabled {
			enabled = append(enabled, cert)
		}
	}
	return enabled, nil
}

// GetWorkDir 获取工作目录
func (cm *ConfigManager) GetWorkDir() string {
	return cm.workDir
}

// GetConfigPath 获取配置文件路径
func (cm *ConfigManager) GetConfigPath() string {
	return cm.configPath
}

// GetCertsDir 获取证书目录
func (cm *ConfigManager) GetCertsDir() string {
	return cm.certsDir
}

// GetLogsDir 获取日志目录
func (cm *ConfigManager) GetLogsDir() string {
	return cm.logsDir
}

// GetBackupDir 获取备份目录
func (cm *ConfigManager) GetBackupDir() string {
	return cm.backupDir
}

// GetSiteCertsDir 获取站点证书目录
func (cm *ConfigManager) GetSiteCertsDir(siteName string) string {
	return filepath.Join(cm.certsDir, siteName)
}

// EnsureSiteCertsDir 确保站点证书目录存在
func (cm *ConfigManager) EnsureSiteCertsDir(siteName string) (string, error) {
	dir := cm.GetSiteCertsDir(siteName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// defaultSchedule 默认调度配置
func defaultSchedule() ScheduleConfig {
	return ScheduleConfig{
		RenewBeforeDays: DefaultRenewBeforeDays,
		RenewMode:       RenewModePull,
	}
}

// validateAPIURL 校验 API URL 是否有效（包含 SSRF 防护）
// 委托给 validator.ValidateAPIURL 实现，避免代码重复
func validateAPIURL(apiURL string) error {
	return validator.ValidateAPIURL(apiURL)
}

// Token 长度限制常量
const (
	minTokenLength = 32  // 最小 32 字符（128 bit 安全性）
	maxTokenLength = 512 // 最大 512 字符
)

// validateToken 校验 Token 格式
// 安全要求：最小 32 字符确保足够的熵（防止暴力破解）
func validateToken(token string) error {
	// 长度校验：32-512 字符
	if len(token) < minTokenLength {
		return fmt.Errorf("token too short (min %d characters, got %d)", minTokenLength, len(token))
	}
	if len(token) > maxTokenLength {
		return fmt.Errorf("token too long (max %d characters, got %d)", maxTokenLength, len(token))
	}
	// 格式校验：只允许安全字符（防止注入）
	if !tokenFormatRegex.MatchString(token) {
		return fmt.Errorf("token contains invalid characters (allowed: A-Za-z0-9-_.)")
	}
	return nil
}

// ConfigExists 检查配置是否存在
func (cm *ConfigManager) ConfigExists() bool {
	_, err := os.Stat(cm.configPath)
	return err == nil
}

// GetSiteBinding 根据站点名称获取绑定配置
// 遍历所有证书配置的 Bindings，返回第一个匹配的站点绑定
func (cm *ConfigManager) GetSiteBinding(siteName string) (*SiteBinding, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}

	for i := range cfg.Certificates {
		for j := range cfg.Certificates[i].Bindings {
			if cfg.Certificates[i].Bindings[j].ServerName == siteName {
				// 返回深拷贝
				binding := cfg.Certificates[i].Bindings[j]
				if binding.Docker != nil {
					dockerCopy := *binding.Docker
					binding.Docker = &dockerCopy
				}
				return &binding, nil
			}
		}
	}

	return nil, fmt.Errorf("site not found: %s", siteName)
}
