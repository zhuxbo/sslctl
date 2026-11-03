// Package config 提供统一配置管理
package config

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// Config 统一配置结构（config.json）
type Config struct {
	ReleaseURL     string         `json:"release_url,omitempty"`
	UpgradeChannel string         `json:"upgrade_channel,omitempty"` // 升级通道: main/dev，空值跟随当前版本号自动判断
	Schedule       ScheduleConfig `json:"schedule"`
	Certificates   []CertConfig   `json:"certificates"`
	Metadata       ConfigMetadata `json:"metadata,omitempty"`
}

// ConfigMetadata 配置元数据
type ConfigMetadata struct {
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	LastCheckAt time.Time `json:"last_check_at,omitempty"`
}

// CertConfig 证书配置
type CertConfig struct {
	CertName         string        `json:"cert_name"`                   // 证书名称（如 example.com-12345）
	OrderID          int           `json:"order_id"`                    // 订单 ID
	Enabled          bool          `json:"enabled"`                     // 是否启用
	Domains          []string      `json:"domains"`                     // 证书域名列表
	RenewMode        string        `json:"renew_mode,omitempty"`        // 续签模式: local | pull（优先于全局配置）
	ValidationMethod string        `json:"validation_method,omitempty"` // 验证方法: file | delegation
	API              APIConfig     `json:"api"`                         // 证书级别的 API 配置
	Bindings         []SiteBinding `json:"bindings"`                    // 站点绑定
	Metadata         CertMetadata  `json:"metadata,omitempty"`
}

// GetAPI 获取 API 配置（环境变量优先覆盖所有证书）
// log 可为 nil，此时校验失败静默降级
func (c *CertConfig) GetAPI(log *logger.Logger) APIConfig {
	api := c.API

	if envToken := os.Getenv(EnvAPIToken); envToken != "" {
		if err := validateToken(envToken); err != nil {
			if log != nil {
				log.Warn("环境变量 %s 校验失败: %v，使用证书配置", EnvAPIToken, err)
			}
		} else {
			api.Token = envToken
		}
	}
	if envURL := os.Getenv(EnvAPIURL); envURL != "" {
		if err := validateAPIURL(envURL); err != nil {
			if log != nil {
				log.Warn("环境变量 %s 校验失败: %v，使用证书配置", EnvAPIURL, err)
			}
		} else {
			api.URL = envURL
		}
	}

	return api
}

// CertMetadata 证书元数据
type CertMetadata struct {
	LastDeployAt  time.Time `json:"last_deploy_at,omitempty"`
	CertExpiresAt time.Time `json:"cert_expires_at,omitempty"`
	CertSerial    string    `json:"cert_serial,omitempty"`
	// 本地私钥续签的状态信息
	CSRSubmittedAt time.Time `json:"csr_submitted_at,omitempty"`
	LastCSRHash    string    `json:"last_csr_hash,omitempty"`
	// LastIssueState 签发/生命周期状态：
	// "" / processing / CAPPED（触顶静默）/ EXPIRED（已过期静默）/ policy_blocked_needs_setup（非法 IP 配置）/ active（秒签待部署）/ 其他异常
	LastIssueState string `json:"last_issue_state,omitempty"`
	// IssueRetryCount 签发尝试计数（CSR 提交），>= 10 触顶
	IssueRetryCount int `json:"issue_retry_count,omitempty"`
	// DeployAttemptCount 部署尝试计数，>= 10 触顶；与签发计数分离，不从旧混合计数推断
	DeployAttemptCount int `json:"deploy_attempt_count,omitempty"`
	// DeployStartedAt 部署尝试崩溃安全标记：置位表示已持久化一个部署意图但结果未落盘，
	// 重启时据此复验并重放同一尝试，不再重复递增 DeployAttemptCount（deploy-spec §5.1）
	DeployStartedAt time.Time `json:"deploy_started_at,omitempty"`
	// CappedPhase 触顶阶段：issue / deploy / stalled / legacy（仅 LastIssueState==CAPPED 时有意义）
	CappedPhase string `json:"capped_phase,omitempty"`
	// LastOrderStatus 服务端最近一次返回的订单状态，**展示专用、不参与任何门禁判定**。
	// 与 LastIssueState 分离（deploy-spec §3.4）：后者的真实作用是区分「有无在途订单」，
	// 把 cancelled 这类订单终态写进去会让两个概念混在一个字段里，
	// 而 pull 模式从不 POST、根本不需要该区分。
	LastOrderStatus string `json:"last_order_status,omitempty"`
	// LastDeployBlockReason 最近一次环境阻断的原因（Web 配置本就损坏等非本次部署导致的失败）。
	// 环境恢复时清空。用于边沿触发上报：原因未变化时不重复上报。
	LastDeployBlockReason string `json:"last_deploy_block_reason,omitempty"`
	// LastDeployBlockAt 最近一次环境阻断的时间
	LastDeployBlockAt time.Time `json:"last_deploy_block_at,omitempty"`
	// BlockReportCount 环境阻断上报累计次数，>= 10 后转静默（deploy-spec §2.8）。
	// 阻断不递增 DeployAttemptCount（修好即自动恢复、无需人工解除 CAPPED），
	// 故若无此上限，整条阻断回调路径就没有任何边界。环境恢复时清零。
	BlockReportCount int `json:"block_report_count,omitempty"`
	// UnchangedCertRounds 服务端连续返回同一张证书（序列号未变）的轮数（平台扩展字段）。
	// 部署"成功"会清零全部计数，若服务端一直不换证，三重边界同时失效：
	// 计数每轮清零永不触顶、部署发生算进展使无进展计时也清零、到期闸门要等真过期。
	// 每轮还会真实改写证书文件并 reload Web 服务，服务端看到的却是一切正常。
	UnchangedCertRounds int `json:"unchanged_cert_rounds,omitempty"`
	// NoProgressSince 首次「本轮只查询、无任何进展」的时间（deploy-spec §3.2）。
	// 锚定首次、不滑动：每轮刷新等于永远达不到时限，那正是要修的问题。
	// 纯 GET 轮询不递增任何尝试计数，而到期闸门在 CertExpiresAt 为空时整段失效
	// （新证书默认为空，只有部署成功才回填），故需要这条与计数正交的绝对边界。
	NoProgressSince time.Time `json:"no_progress_since,omitempty"`
	// 部署失败的绑定列表（ServerName），下次检查时重试
	FailedBindings   []string  `json:"failed_bindings,omitempty"`
	FailedBindingsAt time.Time `json:"failed_bindings_at,omitempty"` // 首次记录失败绑定的时间
	// RetryAttemptCount 失败绑定重试计数（平台扩展字段，deploy-spec §1.6）。
	// 与证书级 DeployAttemptCount 分离：绑定级重试是规范未建模的平台扩展，
	// 共用公共计数会让单个坏站点把整张证书打进 CAPPED，健康站点跟着过期。
	RetryAttemptCount int `json:"retry_attempt_count,omitempty"`
	// NoBindingBlockedAt 零启用绑定阻断标记（平台扩展字段，deploy-spec §1.6）。
	// 证书 enabled 但无任何启用绑定时置位：退出自动流程、不发请求、不回调，等待人工处理；
	// 绑定恢复后自动清除。不占用公共字段 last_issue_state，避免覆盖在途签发状态。
	NoBindingBlockedAt time.Time `json:"no_binding_blocked_at,omitempty"`
	// StaleBindings 长期未部署成功的绑定（平台扩展字段）：语义为"该绑定当前未持有本证书的最新证书"。
	StaleBindings []string  `json:"stale_bindings,omitempty"`
	StaleSince    time.Time `json:"stale_since,omitempty"`
	// 文件验证相关
	ValidationFiles []string `json:"validation_files,omitempty"` // 已写入的验证文件路径（部署成功后清理）
}

// SiteBinding 站点绑定配置
type SiteBinding struct {
	ServerName string       `json:"server_name"`      // 站点名称（域名）
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
	Webroot     string `json:"webroot,omitempty"`     // Web 根目录(用于文件验证)
}

// DockerInfo Docker 部署信息
type DockerInfo struct {
	ContainerName string `json:"container_name,omitempty"` // 容器名称
	DeployMode    string `json:"deploy_mode,omitempty"`    // volume | copy
}

// ServerType 常量
// 注意：这些值必须与 pkg/webserver/types.go 中的定义保持一致
const (
	ServerTypeNginx        = string(webserver.TypeNginx)
	ServerTypeApache       = string(webserver.TypeApache)
	ServerTypeDockerNginx  = string(webserver.TypeDockerNginx)
	ServerTypeDockerApache = string(webserver.TypeDockerApache)
)

// IsDockerType 判断服务器类型是否为 Docker 变体（docker-nginx / docker-apache）
func IsDockerType(serverType string) bool {
	return serverType == ServerTypeDockerNginx || serverType == ServerTypeDockerApache
}

// IsDockerCopyBinding 表示需要在容器内读写证书的 Nginx 绑定。
func IsDockerCopyBinding(binding *SiteBinding) bool {
	return binding != nil && binding.ServerType == ServerTypeDockerNginx && binding.Docker != nil && binding.Docker.DeployMode == "copy"
}

// ValidateDockerBinding 校验 Docker 绑定的路径模式和容器检查/重载命令。
// volume 使用宿主机映射路径；Nginx copy 使用容器专用部署流程。
// 非 Docker 类型返回 nil。
func ValidateDockerBinding(binding *SiteBinding) error {
	if !IsDockerType(binding.ServerType) {
		return nil
	}
	if IsDockerCopyBinding(binding) {
		name := binding.Docker.ContainerName
		if !executor.IsValidDockerContainerName(name) {
			return fmt.Errorf("站点 %s 的 Docker 容器名称无效", binding.ServerName)
		}
		certPath, keyPath := binding.Paths.Certificate, binding.Paths.PrivateKey
		if !path.IsAbs(certPath) || !path.IsAbs(keyPath) || path.Clean(certPath) != certPath || path.Clean(keyPath) != keyPath || certPath == keyPath {
			return fmt.Errorf("站点 %s 的 Docker copy 模式需要已有 HTTPS 的独立证书、私钥绝对路径", binding.ServerName)
		}
		if binding.Reload.TestCommand != "docker exec "+name+" nginx -t" || binding.Reload.ReloadCommand != "docker exec "+name+" nginx -s reload" {
			return fmt.Errorf("站点 %s 的 Docker copy 模式需要匹配目标容器的 nginx 测试和重载命令，请重新 setup", binding.ServerName)
		}
		return nil
	}
	if binding.Docker == nil || binding.Docker.DeployMode != "volume" {
		return fmt.Errorf("站点 %s 的 Docker 证书目录未挂载为宿主机卷（copy 模式），通用部署路径无法安全写入，跳过部署", binding.ServerName)
	}
	if binding.Reload.ReloadCommand == "" {
		return fmt.Errorf("站点 %s 缺少 Docker 容器重载命令（未能确定容器名），跳过部署", binding.ServerName)
	}
	if binding.Paths.Certificate == "" {
		return fmt.Errorf("站点 %s 的 Docker 证书宿主机路径为空（挂载映射解析失败），跳过部署", binding.ServerName)
	}
	if binding.Paths.PrivateKey == "" {
		return fmt.Errorf("站点 %s 的 Docker 私钥宿主机路径为空（挂载映射解析失败），跳过部署", binding.ServerName)
	}
	return nil
}

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

// DaysUntilExpiry 计算证书到期剩余天数（展示用；判定请用 IsExpired/NeedsRenewal）
func (c *CertConfig) DaysUntilExpiry() int {
	if c.Metadata.CertExpiresAt.IsZero() {
		return 999
	}
	duration := time.Until(c.Metadata.CertExpiresAt)
	return int(duration.Hours() / 24)
}

// IsExpired 证书是否已过期（按时间点比较，避免整数天截断使"已过期"判定偏移约 24 小时）
// 到期时间未知（零值）不视为已过期，由调用方先回填元数据
func (c *CertConfig) IsExpired() bool {
	if c.Metadata.CertExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.Metadata.CertExpiresAt)
}

// GetRenewMode 获取续签模式（证书级别优先，否则使用全局配置）
func (c *CertConfig) GetRenewMode(schedule *ScheduleConfig) string {
	// 优先使用证书级别的配置
	if c.RenewMode != "" {
		return c.RenewMode
	}
	// 否则使用全局配置
	if schedule != nil && schedule.RenewMode != "" {
		return schedule.RenewMode
	}
	return RenewModePull
}

// IsIllegalIPConfig 判断是否为非法 IP 证书配置（deploy-spec §5.2）。
// SAN 含 IP 的证书必须 local + file；若为 pull 模式或 delegation 验证即非法，
// 应进入 policy_blocked_needs_setup 等待重新 setup（不自动改配置、不计数、不回调）。
func (c *CertConfig) IsIllegalIPConfig(schedule *ScheduleConfig) bool {
	if !ContainsIPDomain(c.Domains) {
		return false
	}
	if c.GetRenewMode(schedule) != RenewModeLocal {
		return true // IP + pull
	}
	if c.ValidationMethod == ValidationMethodDelegation {
		return true // IP + delegation
	}
	return false
}

// HasEnabledBinding 是否存在启用的站点绑定。
// 证书 enabled 但零启用绑定属配置异常（站点被改绑到其它证书、人工禁用等）：
// 无部署目标，不应进入自动续签/部署流程，更不应向服务端上报"部署成功"。
func (c *CertConfig) HasEnabledBinding() bool {
	for i := range c.Bindings {
		if c.Bindings[i].Enabled {
			return true
		}
	}
	return false
}

// NeedsRenewal 判断是否需要续期
// 到期时间未知（零值）返回 false：语义为"未知需处理"，由续签检查先查询 API 回填元数据后再判定
// 已过期证书不再触发续签（按时间点判定，过期不足 24 小时也算已过期）
func (c *CertConfig) NeedsRenewal(schedule *ScheduleConfig) bool {
	if c.Metadata.CertExpiresAt.IsZero() {
		return false
	}
	if c.IsExpired() {
		return false
	}
	renewDays := schedule.RenewBeforeDays
	if renewDays <= 0 {
		renewDays = DefaultRenewBeforeDays
	}
	return c.DaysUntilExpiry() <= renewDays
}

// GetCertDir 获取证书存储目录
func GetCertDir(siteName string) string {
	return "/opt/sslctl/certs/" + siteName
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
