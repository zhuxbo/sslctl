// Package config 提供基础配置结构
package config

import (
	"os"
	"strings"

	"github.com/cnssl/cert-deploy/pkg/errors"
)

// KeyConfig 私钥配置
type KeyConfig struct {
	Type  string `json:"type"`  // rsa|ecdsa
	Size  int    `json:"size"`  // 2048|4096
	Curve string `json:"curve"` // prime256v1|secp384r1|secp521r1
}

// CSRConfig CSR 配置（支持 OV 字段）
type CSRConfig struct {
	Organization string `json:"organization"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	Email        string `json:"email"`
}

// APIConfig API 配置
type APIConfig struct {
	URL     string `json:"url"`      // 证书 API 地址
	ReferID string `json:"refer_id"` // 引用 ID (Bearer Token)
}

// PathsConfig 路径配置
type PathsConfig struct {
	Certificate string `json:"certificate"` // 证书文件路径
	PrivateKey  string `json:"private_key"` // 私钥文件路径
	CA          string `json:"ca"`          // CA 证书路径
	Webroot     string `json:"webroot"`     // 网站根目录（用于 file 验证）
}

// ReloadConfig 重载配置
type ReloadConfig struct {
	TestCommand   string `json:"test_command"`   // 配置测试命令
	ReloadCommand string `json:"reload_command"` // 重载命令
}

// BackupConfig 备份配置
type BackupConfig struct {
	Enabled      bool `json:"enabled"`
	KeepVersions int  `json:"keep_versions"`
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	Method               string `json:"method"` // dns|file|http
	IgnoreDomainMismatch bool   `json:"ignore_domain_mismatch"`
}

// ScheduleConfig 调度配置
type ScheduleConfig struct {
	CheckIntervalHours int `json:"check_interval_hours"` // 检查间隔（小时）
	RenewalDaysBefore  int `json:"renewal_days_before"`  // 到期前多少天续期
	MinImproveDays     int `json:"min_improve_days"`     // 最小改进天数
}

// GetEnvWithDefault 获取环境变量，提供默认值
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ValidateLogLevel 验证日志级别
func ValidateLogLevel(level string) error {
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[strings.ToLower(level)] {
		return errors.NewConfigError(
			"invalid log level: "+level+" (must be debug|info|warn|error)",
			nil,
		)
	}
	return nil
}
