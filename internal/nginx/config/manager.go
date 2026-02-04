// Package config 配置管理器
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager 配置管理器
type Manager struct {
	workDir   string // 工作目录(sslctl/)
	sitesDir  string // 站点配置目录(sslctl/sites/)
	logsDir   string // 日志目录(sslctl/logs/)
	backupDir string // 备份目录(sslctl/backup/)
	certsDir  string // 临时证书目录(sslctl/certs/)
	mu        sync.RWMutex

	// 简单配置缓存（可选）
	cache     map[string]*SiteConfig
	cacheTime map[string]time.Time
	cacheTTL  time.Duration
}

// NewManager 创建配置管理器
// execPath: 可执行文件路径
func NewManager(execPath string) (*Manager, error) {
	// 获取可执行文件所在目录
	execDir := filepath.Dir(execPath)

	// 工作目录: <exec-dir>/sslctl/
	workDir := filepath.Join(execDir, "sslctl")

	m := &Manager{
		workDir:   workDir,
		sitesDir:  filepath.Join(workDir, "sites"),
		logsDir:   filepath.Join(workDir, "logs"),
		backupDir: filepath.Join(workDir, "backup"),
		certsDir:  filepath.Join(workDir, "certs"),
	}

	// 允许通过环境变量开启缓存（单位：秒）
	if v := os.Getenv("CONFIG_CACHE_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			m.cacheTTL = time.Duration(n) * time.Second
			m.cache = make(map[string]*SiteConfig)
			m.cacheTime = make(map[string]time.Time)
		}
	}

	// 创建必要的目录
	if err := m.ensureDirs(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return m, nil
}

// ensureDirs 确保必要的目录存在
func (m *Manager) ensureDirs() error {
	dirs := []string{
		m.workDir,
		m.sitesDir,
		m.logsDir,
		m.backupDir,
		m.certsDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

// LoadSite 加载站点配置
func (m *Manager) LoadSite(siteName string) (*SiteConfig, error) {
	m.mu.RLock()
	configPath := m.getSiteConfigPath(siteName)
	m.mu.RUnlock()

	// 读取缓存
	if m.cacheTTL > 0 {
		m.mu.RLock()
		if sc, ok := m.cache[siteName]; ok {
			if time.Since(m.cacheTime[siteName]) < m.cacheTTL {
				m.mu.RUnlock()
				return sc, nil
			}
		}
		m.mu.RUnlock()
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SiteConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// 写入缓存
	if m.cacheTTL > 0 {
		m.mu.Lock()
		if m.cache == nil {
			m.cache = make(map[string]*SiteConfig)
			m.cacheTime = make(map[string]time.Time)
		}
		m.cache[siteName] = &config
		m.cacheTime[siteName] = time.Now()
		m.mu.Unlock()
	}

	return &config, nil
}

// SaveSite 保存站点配置
func (m *Manager) SaveSite(config *SiteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configPath := m.getSiteConfigPath(config.SiteName)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 原子写入
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}
	// 失效缓存
	if m.cache != nil {
		delete(m.cache, config.SiteName)
		delete(m.cacheTime, config.SiteName)
	}
	return nil
}

// ListSites 列出所有站点配置
func (m *Manager) ListSites() ([]*SiteConfig, error) {
	m.mu.RLock()
	sitesDir := m.sitesDir
	m.mu.RUnlock()
	entries, err := os.ReadDir(sitesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read sites directory: %w", err)
	}

	var sites []*SiteConfig
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		configPath := filepath.Join(sitesDir, entry.Name())
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		var sc SiteConfig
		if err := json.Unmarshal(data, &sc); err != nil {
			continue
		}
		sites = append(sites, &sc)
	}

	return sites, nil
}

// DeleteSite 删除站点配置
func (m *Manager) DeleteSite(siteName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configPath := m.getSiteConfigPath(siteName)
	return os.Remove(configPath)
}

// SiteExists 检查站点配置是否存在
func (m *Manager) SiteExists(siteName string) bool {
	m.mu.RLock()
	configPath := m.getSiteConfigPath(siteName)
	m.mu.RUnlock()
	_, err := os.Stat(configPath)
	return err == nil
}

// GetWorkDir 获取工作目录
func (m *Manager) GetWorkDir() string {
	return m.workDir
}

// GetSitesDir 获取站点配置目录
func (m *Manager) GetSitesDir() string {
	return m.sitesDir
}

// GetLogsDir 获取日志目录
func (m *Manager) GetLogsDir() string {
	return m.logsDir
}

// GetBackupDir 获取备份目录
func (m *Manager) GetBackupDir() string {
	return m.backupDir
}

// GetCertsDir 获取临时证书目录
func (m *Manager) GetCertsDir() string {
	return m.certsDir
}

// GetSiteBackupDir 获取站点备份目录
func (m *Manager) GetSiteBackupDir(siteName string) string {
	return filepath.Join(m.backupDir, siteName)
}

// GetSiteCertsDir 获取站点临时证书目录
func (m *Manager) GetSiteCertsDir(siteName string) string {
	return filepath.Join(m.certsDir, siteName)
}

// getSiteConfigPath 获取站点配置文件路径
func (m *Manager) getSiteConfigPath(siteName string) string {
	return filepath.Join(m.sitesDir, siteName+".json")
}
