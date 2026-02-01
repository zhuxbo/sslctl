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

	// Docker 配置
	Docker DockerConfig `json:"docker,omitempty"`

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
	OrderID         int       `json:"order_id,omitempty"` // 本地私钥模式的订单 ID
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
// 本地私钥模式：
//   - 初次发起：到期前 > ServerAutoRenewDays 且 <= localRenewDays（避免与服务端自动续签冲突）
//   - 失败重试：到期前 <= localRenewDays（服务端未必开启自动续签，允许重试）
// 拉取模式：到期前 <= pullRenewDays 时续签
func (s *SiteConfig) NeedsRenewal() bool {
	days := s.DaysUntilExpiry()
	mode := s.Schedule.RenewMode
	if mode == "" {
		mode = RenewModePull
	}

	// 本地私钥模式
	if mode == RenewModeLocal {
		localRenewDays := s.Schedule.RenewBeforeDays
		if localRenewDays == 0 {
			localRenewDays = LocalRenewDefaultDay // 默认 15 天
		}
		// 如果之前发起过续签（有重试记录），允许在 <= 14 天时继续重试
		if s.Metadata.IssueRetryCount > 0 {
			return days <= localRenewDays
		}
		// 初次发起：必须在到期前 14 天之前，避免服务端自动续签冲突
		return days > ServerAutoRenewDays && days <= localRenewDays
	}

	// 拉取模式：等待服务端续签完成后拉取
	pullRenewDays := s.Schedule.RenewBeforeDays
	if pullRenewDays == 0 {
		pullRenewDays = PullRenewDefaultDay // 默认 13 天
	}
	return days <= pullRenewDays
}

// GetRenewMode 获取续签模式（带默认值）
func (s *SiteConfig) GetRenewMode() string {
	if s.Schedule.RenewMode == "" {
		return RenewModePull
	}
	return s.Schedule.RenewMode
}

// IsLocalKeyMode 是否为本地私钥模式
func (s *SiteConfig) IsLocalKeyMode() bool {
	return s.GetRenewMode() == RenewModeLocal
}

// IncrementRetryCount 增加重试计数
func (s *SiteConfig) IncrementRetryCount() {
	s.Metadata.IssueRetryCount++
}

// ResetRetryCount 重置重试计数（成功后调用）
func (s *SiteConfig) ResetRetryCount() {
	s.Metadata.IssueRetryCount = 0
}
