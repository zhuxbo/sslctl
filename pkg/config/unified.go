// Package config 统一配置管理器
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
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
// 如需持久化修改，必须显式调用 Save() 或使用 SetAPI()/UpdateCert() 等方法。
func (cm *ConfigManager) Load() (*Config, error) {
	cm.mu.RLock()
	if cm.config != nil {
		cfg := cm.copyConfig(cm.config)
		cm.mu.RUnlock()
		return cfg, nil
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

	// 环境变量优先级高于配置文件（带完整校验）
	if envToken := os.Getenv(EnvAPIToken); envToken != "" {
		// Token 基本校验：长度合理（至少 8 字符，不超过 512 字符）
		if len(envToken) >= 8 && len(envToken) <= 512 {
			if cm.config.API.Token != "" && cm.config.API.Token != envToken {
				log.Printf("[config] API Token 被环境变量覆盖")
			}
			cm.config.API.Token = envToken
		} else {
			log.Printf("[config] 环境变量 %s 值长度无效（需 8-512 字符），忽略", EnvAPIToken)
		}
	}
	if envURL := os.Getenv(EnvAPIURL); envURL != "" {
		// URL 完整校验：格式 + SSRF 防护
		if err := validateAPIURL(envURL); err != nil {
			log.Printf("[config] 环境变量 %s 校验失败: %v，忽略", EnvAPIURL, err)
		} else {
			if cm.config.API.URL != "" && cm.config.API.URL != envURL {
				log.Printf("[config] API URL 被环境变量覆盖")
			}
			cm.config.API.URL = envURL
		}
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
// 注意：文件锁在所有操作之前获取，确保原子性和一致性
func (cm *ConfigManager) saveLocked(cfg *Config) error {
	// 1. 先获取文件锁，防止并发写入和 TOCTOU 攻击
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

	// 2. 创建配置副本进行修改，避免修改原始对象
	cfgCopy := cm.copyConfig(cfg)
	cfgCopy.Metadata.UpdatedAt = time.Now()
	if cfgCopy.Metadata.CreatedAt.IsZero() {
		cfgCopy.Metadata.CreatedAt = time.Now()
	}

	// 3. 序列化配置
	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 4. 原子写入
	tmpPath := cm.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, cm.configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// 5. 只有在所有操作成功后才更新内存缓存
	cm.config = cfgCopy
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
// 注意：此方法在持有锁的情况下重新加载配置，确保不会覆盖其他并发修改
func (cm *ConfigManager) SetAPI(api APIConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := cm.loadLocked()
	if err != nil {
		return err
	}
	cfg.API = api
	return cm.saveLocked(cfg)
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

// validateAPIURL 校验 API URL 是否有效（包含 SSRF 防护）
// 仅 localhost/127.0.0.1 允许 HTTP，其他必须使用 HTTPS
func validateAPIURL(apiURL string) error {
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("API URL must use HTTP or HTTPS, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("API URL must have a valid host")
	}

	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"

	// HTTP 仅允许 localhost
	if u.Scheme == "http" && !isLocal {
		return fmt.Errorf("HTTP only allowed for localhost, use HTTPS for remote servers")
	}

	// SSRF 防护：检查是否为内网 IP 或云元数据地址
	if !isLocal {
		if err := checkSSRF(host); err != nil {
			return err
		}
	}

	return nil
}

// checkSSRF 检查 SSRF 风险
func checkSSRF(host string) error {
	// 解析 IP 地址
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS 解析失败，拒绝请求以防止 DNS rebinding 攻击
		return fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}

	for _, ip := range ips {
		// 检查回环地址
		if ip.IsLoopback() {
			return fmt.Errorf("loopback address not allowed: %s", ip)
		}
		// 检查内网 IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
		if ip.IsPrivate() {
			return fmt.Errorf("private IP not allowed: %s", ip)
		}
		// 检查链路本地地址 (169.254.0.0/16)
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("link-local address not allowed: %s", ip)
		}
		// 检查云元数据地址 (169.254.169.254)
		if ip.String() == "169.254.169.254" {
			return fmt.Errorf("cloud metadata endpoint not allowed")
		}
	}

	return nil
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

// GetSiteBinding 根据站点名称获取绑定配置
// 遍历所有证书配置的 Bindings，返回第一个匹配的站点绑定
func (cm *ConfigManager) GetSiteBinding(siteName string) (*SiteBinding, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}

	for i := range cfg.Certificates {
		for j := range cfg.Certificates[i].Bindings {
			if cfg.Certificates[i].Bindings[j].SiteName == siteName {
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
