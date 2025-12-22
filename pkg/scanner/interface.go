// Package scanner 定义扫描器接口
package scanner

// SSLSite 通用 SSL 站点信息
type SSLSite struct {
	ServerName      string   // 域名
	CertificatePath string   // 证书路径
	PrivateKeyPath  string   // 私钥路径
	ChainPath       string   // 证书链路径（可选，Apache 使用）
	ConfigFile      string   // 配置文件路径
	ListenPorts     []string // 监听端口
	Webroot         string   // Web 根目录（用于文件验证）
}

// Scanner 扫描器接口
type Scanner interface {
	// Scan 扫描所有 SSL 站点
	Scan() ([]*SSLSite, error)

	// FindByDomain 根据域名查找站点
	FindByDomain(domain string) (*SSLSite, error)
}
