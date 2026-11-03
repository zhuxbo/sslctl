// Package config 统一配置管理器
package config

import (
	"encoding/json"
	"errors"
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

var (
	// ErrCertNotFound 证书条目不存在（可能被并发删除）
	ErrCertNotFound = errors.New("certificate not found")
	// ErrCertCondNotMet UpdateCertIf 的前置条件在文件锁内复检时不再成立，未写盘
	ErrCertCondNotMet = errors.New("certificate condition not met")
	// ErrCertNameConflict 目标证书名已存在，拒绝改名以免制造同名条目
	ErrCertNameConflict = errors.New("certificate name already exists")
	// ErrSiteNotFound 站点绑定不存在
	ErrSiteNotFound = errors.New("site binding not found")
)

// RemoveSiteResult 站点解除管理后的配置变更摘要。
type RemoveSiteResult struct {
	RemovedBindings     int
	RemovedCertificates []CertConfig
}

// ConfigManager 统一配置管理器
type ConfigManager struct {
	workDir    string
	configPath string
	certsDir   string
	logsDir    string
	backupDir  string
	mu         sync.RWMutex
	config     *Config
	cachedAt   time.Time // 缓存加载时间，用于 mtime 检测
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
		{cm.workDir, 0700}, // 工作目录收紧权限，仅 root 可访问
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
//   - 如果向 CertConfig 或 SiteBinding 添加新的引用类型字段（map、slice、指针），
//     必须在此函数中添加对应的深拷贝逻辑，否则会破坏并发安全保证！
//   - 当前已处理的引用类型：Certificates(slice)、Bindings(slice)、Domains(slice)、Docker(*DockerInfo)、FailedBindings(slice)、StaleBindings(slice)、ValidationFiles(slice)
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
			// 深拷贝 StaleBindings 切片
			if cert.Metadata.StaleBindings != nil {
				dst.Certificates[i].Metadata.StaleBindings = make([]string, len(cert.Metadata.StaleBindings))
				copy(dst.Certificates[i].Metadata.StaleBindings, cert.Metadata.StaleBindings)
			}
			// 深拷贝 ValidationFiles 切片
			if cert.Metadata.ValidationFiles != nil {
				dst.Certificates[i].Metadata.ValidationFiles = make([]string, len(cert.Metadata.ValidationFiles))
				copy(dst.Certificates[i].Metadata.ValidationFiles, cert.Metadata.ValidationFiles)
			}
		}
	}
	return &dst
}

// refreshIfModifiedLocked 检查配置文件是否被外部修改（mtime 比缓存时间新），
// 是则丢弃内存缓存，下次 loadLocked 重读文件（内容哈希比对避免无谓的 JSON 解析）。
// 调用者需持有写锁。
func (cm *ConfigManager) refreshIfModifiedLocked() {
	if cm.config == nil || cm.cachedAt.IsZero() {
		return
	}
	if info, err := os.Stat(cm.configPath); err == nil && info.ModTime().After(cm.cachedAt) {
		cm.config = nil
	}
}

// loadLocked 加载配置（调用者需持有锁）
func (cm *ConfigManager) loadLocked() (*Config, error) {
	// 外部修改检测：CLI 与 daemon 两进程并发时，命中缓存前先校验盘上 mtime，
	// 防止写路径（Update* 系列）基于陈旧缓存读-改-写，丢掉另一进程的更新
	cm.refreshIfModifiedLocked()

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
			return cm.config, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// 配置迁移：检查并转换旧格式
	migrated, changed, migrateErr := migrateConfig(data)
	if migrateErr != nil {
		return nil, fmt.Errorf("failed to migrate config: %w", migrateErr)
	}
	if changed {
		data = migrated
		// 尽力写回迁移后的配置，失败不影响本次加载（下次启动会再次迁移���
		_ = os.WriteFile(cm.configPath, data, 0600)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cm.config = &cfg
	cm.cachedAt = time.Now()

	return cm.config, nil
}

// Save 保存配置
func (cm *ConfigManager) Save(cfg *Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.saveLocked(cfg)
}

// withConfigFileLock 获取配置文件锁执行 fn（flock 进程间互斥）
// 多个进程可以同时打开同一个锁文件，但只有一个能成功获得排他锁
func (cm *ConfigManager) withConfigFileLock(fn func() error) error {
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

	return fn()
}

// mutateLocked 在配置文件锁内执行读-改-写（进程间原子）。
// 文件锁内先感知外部修改并加载最新盘上状态，再将 fn 应用到深拷贝副本后写回，
// 消除跨进程 read-modify-write 丢更新窗口；fn 返回错误时不写盘、不污染内存缓存。
// 调用者需持有 cm.mu 写锁。
func (cm *ConfigManager) mutateLocked(fn func(*Config) error) error {
	return cm.withConfigFileLock(func() error {
		// 写路径必须基于盘上最新状态读-改-写：置空内存缓存强制 loadLocked 重读文件。
		// 仅靠 mtime 门控无法感知外部修改的两类场景——同秒写入、以及 NFS/VM 环境 mtime 粒度或时钟偏移
		// 使盘上 mtime 不晚于本进程 cachedAt——会让写路径复用陈旧缓存，覆盖另一进程的更新（跨进程丢更新）。
		// 读路径（Load）保持 mtime 缓存不变，daemon 高频读不因此每次落盘。
		cm.config = nil
		cfg, err := cm.loadLocked()
		if err != nil {
			return err
		}
		// 在副本上应用修改：fn 或保存失败时内存缓存保持与盘上一致
		working := cm.copyConfig(cfg)
		if err := fn(working); err != nil {
			return err
		}
		return cm.saveLockedHeld(working)
	})
}

// saveLocked 保存配置（调用者需持有内存锁；内部自行获取配置文件锁）
func (cm *ConfigManager) saveLocked(cfg *Config) error {
	return cm.withConfigFileLock(func() error {
		return cm.saveLockedHeld(cfg)
	})
}

// saveLockedHeld 保存配置（调用者需同时持有内存锁与配置文件锁）
func (cm *ConfigManager) saveLockedHeld(cfg *Config) error {
	// 1. 创建配置副本进行修改，避免修改原始对象
	cfgCopy := cm.copyConfig(cfg)
	cfgCopy.Metadata.UpdatedAt = time.Now()
	if cfgCopy.Metadata.CreatedAt.IsZero() {
		cfgCopy.Metadata.CreatedAt = time.Now()
	}

	// 2. 序列化配置
	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 3. 原子写入（在文件锁保护下）
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

	// 4. 只有在所有操作成功后才更新内存缓存
	cm.config = cfgCopy
	cm.cachedAt = time.Now()
	return nil
}

// UpdateMetadata 原子更新配置元数据（文件锁内读-改-写，避免覆盖其他进程的更新）
func (cm *ConfigManager) UpdateMetadata(fn func(*ConfigMetadata)) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		fn(&cfg.Metadata)
		return nil
	})
}

// UpdateSchedule 原子更新调度配置（重新加载最新配置，避免覆盖其他更新）
func (cm *ConfigManager) UpdateSchedule(fn func(*ScheduleConfig)) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		fn(&cfg.Schedule)
		return nil
	})
}

// UpdateRenewBeforeDays 按 deploy-spec §2.9 校验并回写服务端下发的提前续签天数。
// 0/负数表示响应未提供该字段；超过上限视为异常值，二者均忽略并保留现值。
func (cm *ConfigManager) UpdateRenewBeforeDays(value int) (bool, error) {
	if value <= 0 || value > MaxRenewBeforeDays {
		return false, nil
	}
	if err := cm.UpdateSchedule(func(schedule *ScheduleConfig) {
		schedule.RenewBeforeDays = value
	}); err != nil {
		return false, err
	}
	return true, nil
}

// SetUpgradeChannel 保存升级通道到配置
func (cm *ConfigManager) SetUpgradeChannel(channel string) error {
	if err := ValidateChannel(channel); err != nil {
		return err
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		cfg.UpgradeChannel = channel
		return nil
	})
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

	return cm.mutateLocked(func(cfg *Config) error {
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
				return nil
			}
		}

		cfg.Certificates = append(cfg.Certificates, *cert)
		return nil
	})
}

// UpdateCert 更新证书配置
func (cm *ConfigManager) UpdateCert(cert *CertConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		for i := range cfg.Certificates {
			if cfg.Certificates[i].CertName == cert.CertName {
				cfg.Certificates[i] = *cert
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrCertNotFound, cert.CertName)
	})
}

// UpdateCertIf 在配置文件锁内做"检查 + 写入"：cond 在**盘上最新状态**上复检，
// 不成立时返回 ErrCertCondNotMet 且不写盘；证书不存在返回 ErrCertNotFound。
//
// 用于"读取时成立、落盘时可能已失效"的守卫场景（如零绑定阻断标记）：
// 若先用 GetCert 复读再 UpdateCert，守卫看到的是 mtime 门控的缓存快照，
// 而写入走的是文件锁内强制重读的另一份快照，两者可能不一致（见 mutateLocked 注释）。
//
// 注意：mutate 作用于配置副本，调用方内存中的 CertConfig 不会被同步更新，
// 需要自行回填（日志去重等依赖内存态的逻辑要注意这一点）。
func (cm *ConfigManager) UpdateCertIf(name string, cond func(*CertConfig) bool, mutate func(*CertConfig)) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		for i := range cfg.Certificates {
			if cfg.Certificates[i].CertName != name {
				continue
			}
			if cond != nil && !cond(&cfg.Certificates[i]) {
				return ErrCertCondNotMet
			}
			mutate(&cfg.Certificates[i])
			return nil
		}
		return fmt.Errorf("%w: %s", ErrCertNotFound, name)
	})
}

// RenameCert 按旧名查找证书并替换为新配置（支持 cert_name 变更）。
// 目标名已存在时返回 ErrCertNameConflict 且不写盘：同名条目并存会让 UpdateCert
// （按名匹配首条）把健康条目整体覆盖成另一条的内容。
func (cm *ConfigManager) RenameCert(oldName string, cert *CertConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	return cm.mutateLocked(func(cfg *Config) error {
		idx := -1
		for i := range cfg.Certificates {
			if cfg.Certificates[i].CertName == oldName {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("%w: %s", ErrCertNotFound, oldName)
		}
		if cert.CertName != oldName {
			for i := range cfg.Certificates {
				if i != idx && cfg.Certificates[i].CertName == cert.CertName {
					return fmt.Errorf("%w: %s", ErrCertNameConflict, cert.CertName)
				}
			}
		}
		cfg.Certificates[idx] = *cert
		return nil
	})
}

// FindDuplicateCertNames 返回配置中重复出现的 cert_name（用于运行期告警）。
// 同名条目只能由历史上未做重名检测的改名产生，本工具不自动合并或删除，交人工处理。
func (cm *ConfigManager) FindDuplicateCertNames() ([]string, error) {
	cfg, err := cm.Load()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]int, len(cfg.Certificates))
	var dups []string
	for i := range cfg.Certificates {
		name := cfg.Certificates[i].CertName
		seen[name]++
		if seen[name] == 2 {
			dups = append(dups, name)
		}
	}
	return dups, nil
}

// DeleteCert 删除证书配置
func (cm *ConfigManager) DeleteCert(certName string) error {
	_, err := cm.RemoveCertificate(certName)
	return err
}

// RemoveCertificate 原子删除所有同名证书配置并返回删除前快照。
// 正常配置只有一条；清理历史重复条目时必须全部删除，避免残留继续被 daemon 管理。
func (cm *ConfigManager) RemoveCertificate(certName string) ([]CertConfig, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var removed []CertConfig
	err := cm.mutateLocked(func(cfg *Config) error {
		kept := make([]CertConfig, 0, len(cfg.Certificates))
		for i := range cfg.Certificates {
			if cfg.Certificates[i].CertName == certName {
				removed = append(removed, cfg.Certificates[i])
				continue
			}
			kept = append(kept, cfg.Certificates[i])
		}
		if len(removed) == 0 {
			return fmt.Errorf("%w: %s", ErrCertNotFound, certName)
		}
		cfg.Certificates = kept
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// RemoveSite 从所有证书中移除精确匹配的站点绑定及其绑定级状态。
// 证书失去最后一个绑定时一并删除，避免留下无法续签或部署的零绑定配置。
func (cm *ConfigManager) RemoveSite(siteName string) (*RemoveSiteResult, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	result := &RemoveSiteResult{}
	err := cm.mutateLocked(func(cfg *Config) error {
		keptCerts := make([]CertConfig, 0, len(cfg.Certificates))
		for i := range cfg.Certificates {
			cert := &cfg.Certificates[i]
			keptBindings := make([]SiteBinding, 0, len(cert.Bindings))
			for _, binding := range cert.Bindings {
				if binding.ServerName == siteName {
					result.RemovedBindings++
					continue
				}
				keptBindings = append(keptBindings, binding)
			}
			if len(keptBindings) == len(cert.Bindings) {
				keptCerts = append(keptCerts, *cert)
				continue
			}

			cert.Bindings = keptBindings
			cert.Metadata.FailedBindings = removeExactString(cert.Metadata.FailedBindings, siteName)
			if len(cert.Metadata.FailedBindings) == 0 {
				cert.Metadata.FailedBindingsAt = time.Time{}
				cert.Metadata.RetryAttemptCount = 0
			}
			cert.Metadata.StaleBindings = removeExactString(cert.Metadata.StaleBindings, siteName)
			if len(cert.Metadata.StaleBindings) == 0 {
				cert.Metadata.StaleSince = time.Time{}
			}
			if len(cert.Bindings) == 0 {
				result.RemovedCertificates = append(result.RemovedCertificates, *cert)
				continue
			}
			keptCerts = append(keptCerts, *cert)
		}
		if result.RemovedBindings == 0 {
			return fmt.Errorf("%w: %s", ErrSiteNotFound, siteName)
		}
		cfg.Certificates = keptCerts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func removeExactString(values []string, target string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			kept = append(kept, value)
		}
	}
	return kept
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
