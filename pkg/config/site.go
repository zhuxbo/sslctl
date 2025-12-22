// Package config 站点配置管理
package config

import "time"

// SiteConfig 站点配置结构
type SiteConfig struct {
	Version    string `json:"version"`
	SiteName   string `json:"site_name"`
	Enabled    bool   `json:"enabled"`
	ServerType string `json:"server_type"` // nginx, apache, iis

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
