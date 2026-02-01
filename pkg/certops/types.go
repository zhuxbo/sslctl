// Package certops 证书操作服务层
package certops

import (
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/config"
)

// ScanOptions 扫描选项
type ScanOptions struct {
	SSLOnly   bool   // 仅扫描 SSL 站点
	ServerType string // 指定服务器类型：nginx, apache, auto
}

// ScanResult 扫描结果
type ScanResult struct {
	ScanTime    time.Time     `json:"scan_time"`
	Environment string        `json:"environment"` // local | docker | mixed
	Sites       []ScannedSite `json:"sites"`
}

// ScannedSite 扫描到的站点
type ScannedSite struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Source          string   `json:"source"` // local | docker
	ContainerID     string   `json:"container_id,omitempty"`
	ContainerName   string   `json:"container_name,omitempty"`
	ConfigFile      string   `json:"config_file"`
	ServerName      string   `json:"server_name"`
	ServerAlias     []string `json:"server_alias,omitempty"`
	ListenPorts     []string `json:"listen_ports"`
	CertificatePath string   `json:"certificate_path"`
	PrivateKeyPath  string   `json:"private_key_path"`
	HostCertPath    string   `json:"host_cert_path,omitempty"`
	HostKeyPath     string   `json:"host_key_path,omitempty"`
	VolumeMode      bool     `json:"volume_mode,omitempty"`
}

// DeployOptions 部署选项
type DeployOptions struct {
	CertName string // 证书名称
	All      bool   // 部署所有证书
	DryRun   bool   // 仅测试，不实际部署
}

// DeployResult 部署结果
type DeployResult struct {
	CertName   string
	Success    bool
	Error      error
	BackupPath string
}

// RenewOptions 续签选项
type RenewOptions struct {
	Force bool // 强制续签，忽略有效期检查
}

// RenewResult 续签结果
type RenewResult struct {
	CertName    string
	Mode        string // local | pull
	Status      string // success | pending | failed
	Error       error
	DeployCount int
}

// toScannedSite 将 config.ScannedSite 转换为 certops.ScannedSite
func toScannedSite(s *config.ScannedSite) ScannedSite {
	return ScannedSite{
		ID:              s.ID,
		Name:            s.Name,
		Source:          s.Source,
		ContainerID:     s.ContainerID,
		ContainerName:   s.ContainerName,
		ConfigFile:      s.ConfigFile,
		ServerName:      s.ServerName,
		ServerAlias:     s.ServerAlias,
		ListenPorts:     s.ListenPorts,
		CertificatePath: s.CertificatePath,
		PrivateKeyPath:  s.PrivateKeyPath,
		HostCertPath:    s.HostCertPath,
		HostKeyPath:     s.HostKeyPath,
		VolumeMode:      s.VolumeMode,
	}
}
