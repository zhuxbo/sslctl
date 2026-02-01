// Package config 统一配置管理器
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ConfigManager 统一配置管理器
type ConfigManager struct {
	workDir    string
	configPath string
	certsDir   string
	logsDir    string
	backupDir  string
	mu         sync.RWMutex
	config     *Config
}

// NewConfigManager 创建统一配置管理器
func NewConfigManager() (*ConfigManager, error) {
	var workDir string
	if runtime.GOOS == "windows" {
		workDir = `C:\cert-deploy`
	} else {
		workDir = "/opt/cert-deploy"
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
func (cm *ConfigManager) Load() (*Config, error) {
	cm.mu.RLock()
	if cm.config != nil {
		cfg := cm.config
		cm.mu.RUnlock()
		return cfg, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.loadLocked()
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
				Version:      "2.0",
				API:          APIConfig{},
				Schedule:     defaultSchedule(),
				Certificates: []CertConfig{},
			}
			return cm.config, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cm.config = &cfg

	// 环境变量优先级高于配置文件
	if envToken := os.Getenv(EnvAPIToken); envToken != "" {
		cm.config.API.Token = envToken
	}
	if envURL := os.Getenv(EnvAPIURL); envURL != "" {
		cm.config.API.URL = envURL
	}

	return cm.config, nil
}

// Save 保存配置
func (cm *ConfigManager) Save(cfg *Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.saveLocked(cfg)
}

// saveLocked 保存配置（调用者需持有锁）
func (cm *ConfigManager) saveLocked(cfg *Config) error {
	cfg.Metadata.UpdatedAt = time.Now()
	if cfg.Metadata.CreatedAt.IsZero() {
		cfg.Metadata.CreatedAt = time.Now()
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 获取文件锁，防止并发写入
	lockPath := cm.configPath + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer func() { _ = lf.Close() }()

	if err := lockFile(lf); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = unlockFile(lf) }()

	// 原子写入
	tmpPath := cm.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, cm.configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	cm.config = cfg
	return nil
}

// Reload 重新加载配置
func (cm *ConfigManager) Reload() (*Config, error) {
	cm.mu.Lock()
	cm.config = nil
	cm.mu.Unlock()
	return cm.Load()
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

	// 检查是否已存在
	for i := range cfg.Certificates {
		if cfg.Certificates[i].CertName == cert.CertName {
			// 更新现有配置
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

// SetAPI 设置 API 配置
func (cm *ConfigManager) SetAPI(api APIConfig) error {
	cfg, err := cm.Load()
	if err != nil {
		return err
	}
	cfg.API = api
	return cm.Save(cfg)
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
		CheckIntervalHours: DefaultCheckIntervalHours,
		RenewBeforeDays:    PullRenewDefaultDay,
		RenewMode:          RenewModePull,
	}
}

// InitConfig 初始化配置（一键部署使用）
func (cm *ConfigManager) InitConfig(apiURL, token string) error {
	cfg := &Config{
		Version: "2.0",
		API: APIConfig{
			URL:   apiURL,
			Token: token,
		},
		Schedule:     defaultSchedule(),
		Certificates: []CertConfig{},
		Metadata: ConfigMetadata{
			CreatedAt: time.Now(),
		},
	}
	return cm.Save(cfg)
}

// ConfigExists 检查配置是否存在
func (cm *ConfigManager) ConfigExists() bool {
	_, err := os.Stat(cm.configPath)
	return err == nil
}
