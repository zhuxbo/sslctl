// Package testutil 测试辅助工具
package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfig 测试用配置结构（简化版，避免循环导入）
type TestConfig struct {
	API          TestAPIConfig       `json:"api"`
	Schedule     TestScheduleConfig  `json:"schedule"`
	Certificates []TestCertConfig    `json:"certificates"`
	Metadata     TestConfigMetadata  `json:"metadata,omitempty"`
}

// TestAPIConfig 测试用 API 配置
type TestAPIConfig struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	CallbackURL string `json:"callback_url,omitempty"`
}

// TestScheduleConfig 测试用调度配置
type TestScheduleConfig struct {
	CheckIntervalHours int    `json:"check_interval_hours"`
	RenewBeforeDays    int    `json:"renew_before_days"`
	RenewMode          string `json:"renew_mode,omitempty"`
}

// TestCertConfig 测试用证书配置
type TestCertConfig struct {
	CertName string           `json:"cert_name"`
	OrderID  int              `json:"order_id"`
	Enabled  bool             `json:"enabled"`
	Domains  []string         `json:"domains"`
	Bindings []TestSiteBinding `json:"bindings"`
}

// TestSiteBinding 测试用站点绑定
type TestSiteBinding struct {
	SiteName   string `json:"site_name"`
	ServerType string `json:"server_type"`
	Enabled    bool   `json:"enabled"`
}

// TestConfigMetadata 测试用配置元数据
type TestConfigMetadata struct {
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastCheckAt time.Time `json:"last_check_at,omitempty"`
}

// DefaultTestConfig 默认测试配置
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		API: TestAPIConfig{
			URL:   "https://api.test.com",
			Token: "test-token",
		},
		Schedule: TestScheduleConfig{
			CheckIntervalHours: 6,
			RenewBeforeDays:    13,
			RenewMode:          "pull",
		},
		Certificates: []TestCertConfig{},
	}
}

// ConfigWithCerts 创建包含证书的测试配置
func ConfigWithCerts(certs ...TestCertConfig) *TestConfig {
	cfg := DefaultTestConfig()
	cfg.Certificates = certs
	return cfg
}

// WriteConfigFile 写入配置文件
func WriteConfigFile(t *testing.T, dir string, cfg *TestConfig) string {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	return configPath
}

// WriteInvalidConfigFile 写入无效的配置文件
func WriteInvalidConfigFile(t *testing.T, dir string) string {
	t.Helper()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"api": invalid}`), 0600); err != nil {
		t.Fatalf("failed to write invalid config file: %v", err)
	}
	return configPath
}

// SetupConfigDir 创建配置目录结构
func SetupConfigDir(t *testing.T, td *TempDir) string {
	t.Helper()
	dirs := []string{"certs", "logs", "backup"}
	for _, d := range dirs {
		td.MkdirAll(d, 0700)
	}
	return td.Path()
}

// TestCertConfigBuilder 证书配置构建器
type TestCertConfigBuilder struct {
	config TestCertConfig
}

// NewTestCertConfig 创建证书配置构建器
func NewTestCertConfig(name string, orderID int) *TestCertConfigBuilder {
	return &TestCertConfigBuilder{
		config: TestCertConfig{
			CertName: name,
			OrderID:  orderID,
			Enabled:  true,
			Domains:  []string{},
			Bindings: []TestSiteBinding{},
		},
	}
}

// WithDomains 设置域名
func (b *TestCertConfigBuilder) WithDomains(domains ...string) *TestCertConfigBuilder {
	b.config.Domains = domains
	return b
}

// WithEnabled 设置启用状态
func (b *TestCertConfigBuilder) WithEnabled(enabled bool) *TestCertConfigBuilder {
	b.config.Enabled = enabled
	return b
}

// WithBinding 添加站点绑定
func (b *TestCertConfigBuilder) WithBinding(siteName, serverType string, enabled bool) *TestCertConfigBuilder {
	b.config.Bindings = append(b.config.Bindings, TestSiteBinding{
		SiteName:   siteName,
		ServerType: serverType,
		Enabled:    enabled,
	})
	return b
}

// Build 构建配置
func (b *TestCertConfigBuilder) Build() TestCertConfig {
	return b.config
}
