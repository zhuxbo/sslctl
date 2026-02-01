// Package webserver Web 服务器抽象层
package webserver

// ServerType 服务器类型
type ServerType string

const (
	TypeNginx        ServerType = "nginx"
	TypeApache       ServerType = "apache"
	TypeDockerNginx  ServerType = "docker-nginx"
	TypeDockerApache ServerType = "docker-apache"
	TypeUnknown      ServerType = "unknown"
)

// Site 站点信息
type Site struct {
	Name            string     // 站点名称
	ServerName      string     // 主域名
	ServerAlias     []string   // 域名别名
	ConfigFile      string     // 配置文件路径
	ListenPorts     []string   // 监听端口
	CertificatePath string     // 证书路径
	PrivateKeyPath  string     // 私钥路径
	ChainFile       string     // 证书链路径（Apache）
	ServerType      ServerType // 服务器类型
	ContainerID     string     // Docker 容器 ID
	ContainerName   string     // Docker 容器名
	HostCertPath    string     // 宿主机证书路径
	HostKeyPath     string     // 宿主机私钥路径
	VolumeMode      bool       // 是否挂载卷模式
}

// Scanner 扫描器接口
type Scanner interface {
	// ScanLocal 扫描本地站点
	ScanLocal() ([]Site, error)
	// ScanDocker 扫描 Docker 站点
	ScanDocker() ([]Site, error)
	// ServerType 返回支持的服务器类型
	ServerType() ServerType
}

// Deployer 部署器接口
type Deployer interface {
	// Deploy 部署证书
	Deploy(cert, chain, key string) error
	// Reload 重载服务
	Reload() error
	// Test 测试配置
	Test() error
}
