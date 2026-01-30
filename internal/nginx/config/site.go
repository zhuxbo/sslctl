// Package config 站点配置管理
package config

import "time"

// SiteConfig 站点配置结构
type SiteConfig struct {
	Version    string `json:"version"`
	SiteName   string `json:"site_name"`
	Enabled    bool   `json:"enabled"`
	ServerType string `json:"server_type"` // nginx, apache

	API APIConfig `json:"api"`

	Domains []string `json:"domains"`

	Paths PathsConfig `json:"paths"`

	Reload ReloadConfig `json:"reload"`

	Schedule ScheduleConfig `json:"schedule"`

	Validation ValidationConfig `json:"validation"`

	// Key/CSR 生成配置
	Key KeyConfig `json:"key,omitempty"`
	CSR CSRConfig `json:"csr,omitempty"`

	Backup BackupConfig `json:"backup"`

	Metadata MetadataConfig `json:"metadata"`
}

// APIConfig API 配置
type APIConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// PathsConfig 路径配置
type PathsConfig struct {
	Certificate string `json:"certificate"`           // 证书文件路径 (fullchain for nginx, cert for apache)
	PrivateKey  string `json:"private_key"`           // 私钥文件路径
	ChainFile   string `json:"chain_file,omitempty"`  // 中间证书链文件路径 (apache only)
	ConfigFile  string `json:"config_file"`           // 配置文件路径
	Webroot     string `json:"webroot,omitempty"`     // Web 根目录(用于文件验证)
}

// ReloadConfig 重载配置
type ReloadConfig struct {
	TestCommand   string `json:"test_command"`   // 测试命令, 如 "nginx -t"
	ReloadCommand string `json:"reload_command"` // 重载命令, 如 "systemctl reload nginx"
}

// ScheduleConfig 调度配置
type ScheduleConfig struct {
	CheckIntervalHours int `json:"check_interval_hours"`    // 检查间隔(小时)
	RenewBeforeDays    int `json:"renew_before_days"`       // 提前续期天数
	MinImproveDays     int `json:"min_improve_days,omitempty"` // 最小改进天数
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	VerifyDomain         bool   `json:"verify_domain"`           // 是否验证域名
	TestHTTPS            bool   `json:"test_https"`              // 是否测试 HTTPS 访问
	TestURL              string `json:"test_url"`                // 测试 URL
	IgnoreDomainMismatch bool   `json:"ignore_domain_mismatch"`  // 忽略域名不匹配
	Method               string `json:"method,omitempty"`        // 验证方式: txt|file|admin|...
}

// KeyConfig 私钥生成配置
type KeyConfig struct {
	Type  string `json:"type"`            // rsa 或 ecdsa
	Size  int    `json:"size,omitempty"`  // RSA: 2048|4096
	Curve string `json:"curve,omitempty"` // ECDSA: prime256v1|secp384r1|secp521r1
}

// CSRConfig CSR 生成参数
type CSRConfig struct {
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	State        string `json:"state,omitempty"`
	Locality     string `json:"locality,omitempty"`
	Email        string `json:"email,omitempty"`
}

// BackupConfig 备份配置
type BackupConfig struct {
	Enabled      bool `json:"enabled"`       // 是否启用备份
	KeepVersions int  `json:"keep_versions"` // 保留版本数
}

// MetadataConfig 元数据
type MetadataConfig struct {
	CreatedAt       time.Time `json:"created_at"`
	LastDeployAt    time.Time `json:"last_deploy_at"`
	LastCheckAt     time.Time `json:"last_check_at"`
	NextRetryAt     time.Time `json:"next_retry_at"`
	CertExpiresAt   time.Time `json:"cert_expires_at"`
	CertSerial      string    `json:"cert_serial"`
	AutoScanned     bool      `json:"auto_scanned"`
	ConfigHash      string    `json:"config_hash,omitempty"`
	CSRSubmittedAt  time.Time `json:"csr_submitted_at,omitempty"`
	LastCSRHash     string    `json:"last_csr_hash,omitempty"`
	LastIssueState  string    `json:"last_issue_state,omitempty"`
	IssueRetryCount int       `json:"issue_retry_count,omitempty"`
}

// DaysUntilExpiry 计算证书到期剩余天数
func (s *SiteConfig) DaysUntilExpiry() int {
	if s.Metadata.CertExpiresAt.IsZero() {
		return 999
	}
	duration := time.Until(s.Metadata.CertExpiresAt)
	return int(duration.Hours() / 24)
}

// NeedsRenewal 判断是否需要续期
func (s *SiteConfig) NeedsRenewal() bool {
	days := s.DaysUntilExpiry()
	return days <= s.Schedule.RenewBeforeDays
}
