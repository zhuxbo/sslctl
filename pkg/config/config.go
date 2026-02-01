// Package config 提供统一配置管理
package config

import "time"

// Config 统一配置结构（config.json）
type Config struct {
	Version      string         `json:"version"`
	API          APIConfig      `json:"api"`
	Schedule     ScheduleConfig `json:"schedule"`
	Certificates []CertConfig   `json:"certificates"`
	Metadata     ConfigMetadata `json:"metadata,omitempty"`
}

// ConfigMetadata 配置元数据
type ConfigMetadata struct {
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastCheckAt time.Time `json:"last_check_at,omitempty"`
}

// CertConfig 证书配置
type CertConfig struct {
	CertName string        `json:"cert_name"` // 证书名称（如 order-12345）
	OrderID  int           `json:"order_id"`  // 订单 ID
	Enabled  bool          `json:"enabled"`   // 是否启用
	Domains  []string      `json:"domains"`   // 证书域名列表
	Bindings []SiteBinding `json:"bindings"`  // 站点绑定
	Metadata CertMetadata  `json:"metadata,omitempty"`
}

// CertMetadata 证书元数据
type CertMetadata struct {
	LastDeployAt  time.Time `json:"last_deploy_at,omitempty"`
	CertExpiresAt time.Time `json:"cert_expires_at,omitempty"`
	CertSerial    string    `json:"cert_serial,omitempty"`
	// 本地私钥续签的状态信息
	CSRSubmittedAt  time.Time `json:"csr_submitted_at,omitempty"`
	LastCSRHash     string    `json:"last_csr_hash,omitempty"`
	LastIssueState  string    `json:"last_issue_state,omitempty"`
	IssueRetryCount int       `json:"issue_retry_count,omitempty"`
}

// SiteBinding 站点绑定配置
type SiteBinding struct {
	SiteName   string       `json:"site_name"`        // 站点名称
	ServerType string       `json:"server_type"`      // nginx, apache, docker-nginx, docker-apache
	Enabled    bool         `json:"enabled"`          // 是否启用
	Paths      BindingPaths `json:"paths"`            // 路径配置
	Reload     ReloadConfig `json:"reload,omitempty"` // 重载配置
	Docker     *DockerInfo  `json:"docker,omitempty"` // Docker 配置（仅 docker-* 类型）
}

// BindingPaths 绑定路径配置
type BindingPaths struct {
	Certificate string `json:"certificate"`           // 证书文件路径
	PrivateKey  string `json:"private_key"`           // 私钥文件路径
	ChainFile   string `json:"chain_file,omitempty"`  // 证书链文件路径（Apache）
	ConfigFile  string `json:"config_file,omitempty"` // 配置文件路径
}

// DockerInfo Docker 部署信息
type DockerInfo struct {
	ContainerName string `json:"container_name,omitempty"` // 容器名称
	DeployMode    string `json:"deploy_mode,omitempty"`    // volume | copy
}

// ServerType 常量
const (
	ServerTypeNginx        = "nginx"
	ServerTypeApache       = "apache"
	ServerTypeDockerNginx  = "docker-nginx"
	ServerTypeDockerApache = "docker-apache"
)

// MatchType 匹配类型
type MatchType string

const (
	MatchTypeFull    MatchType = "full"    // 完全匹配
	MatchTypePartial MatchType = "partial" // 部分匹配
	MatchTypeNone    MatchType = "none"    // 不匹配
)

// MatchResult 域名匹配结果
type MatchResult struct {
	Type           MatchType // 匹配类型
	MatchedDomains []string  // 匹配的域名
	MissedDomains  []string  // 未匹配的域名
}

// DaysUntilExpiry 计算证书到期剩余天数
func (c *CertConfig) DaysUntilExpiry() int {
	if c.Metadata.CertExpiresAt.IsZero() {
		return 999
	}
	duration := time.Until(c.Metadata.CertExpiresAt)
	return int(duration.Hours() / 24)
}

// NeedsRenewal 判断是否需要续期
func (c *CertConfig) NeedsRenewal(schedule *ScheduleConfig) bool {
	days := c.DaysUntilExpiry()
	mode := schedule.RenewMode
	if mode == "" {
		mode = RenewModePull
	}
	// 本地私钥模式：避免与服务端自动续签冲突
	if mode == RenewModeLocal {
		localRenewDays := schedule.RenewBeforeDays
		if localRenewDays == 0 {
			localRenewDays = LocalRenewDefaultDay
		}
		if c.Metadata.IssueRetryCount > 0 {
			return days <= localRenewDays
		}
		return days > ServerAutoRenewDays && days <= localRenewDays
	}

	renewDays := schedule.RenewBeforeDays
	if renewDays == 0 {
		renewDays = PullRenewDefaultDay
	}
	return days <= renewDays
}

// GetCertDir 获取证书存储目录
func GetCertDir(siteName string) string {
	return "/opt/cert-deploy/certs/" + siteName
}

// GetDefaultCertPath 获取默认证书路径
func GetDefaultCertPath(siteName string) string {
	return GetCertDir(siteName) + "/cert.pem"
}

// GetDefaultKeyPath 获取默认私钥路径
func GetDefaultKeyPath(siteName string) string {
	return GetCertDir(siteName) + "/key.pem"
}

// GetDefaultChainPath 获取默认证书链路径（Apache）
func GetDefaultChainPath(siteName string) string {
	return GetCertDir(siteName) + "/chain.pem"
}
