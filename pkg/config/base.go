// Package config 提供基础配置结构
package config

import (
	"net"
	"os"
	"strings"

	"github.com/zhuxbo/sslctl/pkg/errors"
)

// KeyConfig 私钥配置
type KeyConfig struct {
	Type  string `json:"type"`            // rsa|ecdsa
	Size  int    `json:"size,omitempty"`  // RSA: 2048|4096
	Curve string `json:"curve,omitempty"` // ECDSA: prime256v1|secp384r1|secp521r1
}

// CSRConfig CSR 配置（支持 OV 字段）
type CSRConfig struct {
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	State        string `json:"state,omitempty"`
	Locality     string `json:"locality,omitempty"`
	Email        string `json:"email,omitempty"`
}

// APIConfig API 配置
type APIConfig struct {
	URL         string `json:"url"`                    // 证书 API 基础地址
	Token       string `json:"token"`                  // API 认证 Token (Bearer Token)
	CallbackURL string `json:"callback_url,omitempty"` // 部署完成回调地址
}

// PathsConfig 路径配置
type PathsConfig struct {
	Certificate string `json:"certificate"`          // 证书文件路径 (fullchain for nginx, cert for apache)
	PrivateKey  string `json:"private_key"`          // 私钥文件路径
	ChainFile   string `json:"chain_file,omitempty"` // 中间证书链文件路径 (apache only)
	ConfigFile  string `json:"config_file"`          // 配置文件路径
	Webroot     string `json:"webroot,omitempty"`    // Web 根目录(用于文件验证)
}

// ReloadConfig 重载配置
type ReloadConfig struct {
	TestCommand   string `json:"test_command"`   // 测试命令, 如 "nginx -t"
	ReloadCommand string `json:"reload_command"` // 重载命令, 如 "systemctl reload nginx"
}

// BackupConfig 备份配置
type BackupConfig struct {
	Enabled      bool `json:"enabled"`       // 是否启用备份
	KeepVersions int  `json:"keep_versions"` // 保留版本数
}

// ValidationConfig 验证配置
type ValidationConfig struct {
	VerifyDomain         bool   `json:"verify_domain"`          // 是否验证域名
	TestHTTPS            bool   `json:"test_https"`             // 是否测试 HTTPS 访问
	TestURL              string `json:"test_url"`               // 测试 URL
	IgnoreDomainMismatch bool   `json:"ignore_domain_mismatch"` // 忽略域名不匹配
	Method               string `json:"method,omitempty"`       // 验证方式: txt|file|admin|...
}

// RenewMode 续签模式常量
const (
	RenewModeLocal = "local" // 本地私钥模式：本地生成私钥和 CSR，发起签发
	RenewModePull  = "pull"  // 拉取模式：从服务端拉取已签发的证书
)

// ValidationMethod 验证方法常量
const (
	ValidationMethodFile       = "file"       // 文件验证 (HTTP-01)
	ValidationMethodDelegation = "delegation" // 委托验证 (DNS-01)
)

// ValidateValidationMethod 校验域名与验证方法的兼容性
// 返回错误信息，如果兼容则返回空字符串
func ValidateValidationMethod(domain string, method string) string {
	if method == "" {
		return ""
	}

	// 检查是否是 IP 地址（使用 net.ParseIP 准确判断）
	isIP := net.ParseIP(domain) != nil

	// 检查是否是通配符域名
	isWildcard := len(domain) > 2 && domain[0] == '*' && domain[1] == '.'

	if isIP && method == ValidationMethodDelegation {
		return "IP 地址不支持委托验证"
	}

	if isWildcard && method == ValidationMethodFile {
		return "通配符域名不支持文件验证"
	}

	return ""
}

// 续签时间限制常量
const (
	ServerAutoRenewDays  = 14 // 服务端自动续签天数（到期前 14 天）
	LocalRenewDefaultDay = 15 // 本地私钥模式默认值
	PullRenewDefaultDay  = 13 // 拉取模式默认值
)

// 定时任务常量
const (
	DefaultCheckIntervalHours = 6 // 默认检查间隔（小时）
)

// 文件大小限制常量
const (
	MaxPrivateKeySize = 16 * 1024 // 16KB - 足够 RSA-8192 私钥
	MaxCertFileSize   = 1 << 20   // 1MB - 证书文件大小限制
)

// 环境变量常量
const (
	EnvAPIToken = "SSLCTL_API_TOKEN" // API Token 环境变量名 // #nosec G101 -- 非硬编码凭据，仅为环境变量名
	EnvAPIURL   = "SSLCTL_API_URL"   // API URL 环境变量
)

// ScheduleConfig 调度配置
type ScheduleConfig struct {
	CheckIntervalHours int    `json:"check_interval_hours"`       // 检查间隔(小时)
	RenewBeforeDays    int    `json:"renew_before_days"`          // 提前续期天数
	MinImproveDays     int    `json:"min_improve_days,omitempty"` // 最小改进天数
	RenewMode          string `json:"renew_mode,omitempty"`       // 续签模式: local | pull，默认 pull
}

// ValidateSchedule 验证调度配置
func ValidateSchedule(schedule *ScheduleConfig) error {
	mode := schedule.RenewMode
	if mode == "" {
		mode = RenewModePull // 默认拉取模式
	}

	// 如果 RenewBeforeDays 为 0，使用默认值，跳过验证
	if schedule.RenewBeforeDays == 0 {
		return nil
	}

	switch mode {
	case RenewModeLocal:
		// 本地私钥模式：RenewBeforeDays 必须 > 14
		if schedule.RenewBeforeDays <= ServerAutoRenewDays {
			return errors.NewConfigError(
				"本地私钥模式(local)的 renew_before_days 必须 > 14（服务端在到期前 14 天自动续签）",
				nil,
			)
		}
	case RenewModePull:
		// 拉取模式：RenewBeforeDays 必须 < 14
		if schedule.RenewBeforeDays >= ServerAutoRenewDays {
			return errors.NewConfigError(
				"拉取模式(pull)的 renew_before_days 必须 < 14（等待服务端在到期前 14 天完成续签）",
				nil,
			)
		}
	default:
		return errors.NewConfigError(
			"无效的 renew_mode: "+mode+"（必须是 local 或 pull）",
			nil,
		)
	}

	return nil
}

// DockerConfig Docker 部署配置
type DockerConfig struct {
	Enabled       bool   `json:"enabled"`                  // 是否启用 Docker 模式
	ContainerID   string `json:"container_id,omitempty"`   // 容器 ID
	ContainerName string `json:"container_name,omitempty"` // 容器名称

	// 自动发现配置
	AutoDiscover bool   `json:"auto_discover,omitempty"` // 自动发现 Nginx 容器
	ImageFilter  string `json:"image_filter,omitempty"`  // 镜像名过滤

	// 部署模式
	DeployMode string `json:"deploy_mode,omitempty"` // volume | copy | auto

	// Compose 配置
	ComposeFile string `json:"compose_file,omitempty"` // docker-compose.yml 路径
	ServiceName string `json:"service_name,omitempty"` // compose 服务名

	// 容器内路径
	ContainerPaths ContainerPathsConfig `json:"container_paths,omitempty"`
}

// ContainerPathsConfig 容器内路径配置
type ContainerPathsConfig struct {
	Certificate string `json:"certificate,omitempty"`  // 容器内证书路径
	PrivateKey  string `json:"private_key,omitempty"`  // 容器内私钥路径
	ConfigFile  string `json:"config_file,omitempty"`  // 容器内配置文件路径
	Webroot     string `json:"webroot,omitempty"`      // 容器内 Web 根目录
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
