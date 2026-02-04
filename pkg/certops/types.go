// Package certops 证书操作服务层
package certops

import (
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
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

// ScannedSite 扫描到的站点（类型别名，统一使用 config.ScannedSite）
type ScannedSite = config.ScannedSite

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

