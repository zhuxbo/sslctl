// Package config 扫描结果存储
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// ScanResult 扫描结果
type ScanResult struct {
	ScanTime    time.Time     `json:"scan_time"`
	Environment string        `json:"environment"` // local | docker | mixed
	Sites       []ScannedSite `json:"sites"`
}

// ScannedSite 扫描到的站点
type ScannedSite struct {
	// 站点标识
	ID   string `json:"id"`   // 使用域名（ServerName），可能为 _
	Name string `json:"name"` // 显示名称（容器名或本地）

	// 来源信息
	Source         string `json:"source"`                    // local | docker
	ContainerID    string `json:"container_id,omitempty"`    // Docker 容器 ID
	ContainerName  string `json:"container_name,omitempty"`  // Docker 容器名
	ComposeService string `json:"compose_service,omitempty"` // Compose 服务名

	// 配置信息
	ConfigFile  string   `json:"config_file"`            // 配置文件路径
	ServerName  string   `json:"server_name"`            // 主域名，可能为 _
	ServerAlias []string `json:"server_alias,omitempty"` // 域名别名
	ListenPorts []string `json:"listen_ports"`           // 监听端口
	Webroot     string   `json:"webroot,omitempty"`      // Web 根目录

	// 证书路径（容器内路径或本地路径）
	CertificatePath string `json:"certificate_path"` // 证书路径
	PrivateKeyPath  string `json:"private_key_path"` // 私钥路径

	// Docker 特有（宿主机路径）
	HostCertPath string `json:"host_cert_path,omitempty"` // 宿主机证书路径
	HostKeyPath  string `json:"host_key_path,omitempty"`  // 宿主机私钥路径
	VolumeMode   bool   `json:"volume_mode,omitempty"`    // 是否挂载卷模式
}

// getWorkDir 获取工作目录
func getWorkDir() string {
	if os.PathSeparator == '\\' {
		return `C:\cert-deploy`
	}
	return "/opt/cert-deploy"
}

// GetScanResultPath 获取扫描结果文件路径
func GetScanResultPath() string {
	return filepath.Join(getWorkDir(), "scan-result.json")
}

// SaveScanResult 保存扫描结果
func SaveScanResult(result *ScanResult) error {
	result.ScanTime = time.Now()

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(GetScanResultPath(), data, 0644)
}

// LoadScanResult 加载扫描结果
func LoadScanResult() (*ScanResult, error) {
	data, err := os.ReadFile(GetScanResultPath())
	if err != nil {
		return nil, err
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// FindSiteByID 根据 ID 查找站点
func (r *ScanResult) FindSiteByID(id string) *ScannedSite {
	for i := range r.Sites {
		if r.Sites[i].ID == id {
			return &r.Sites[i]
		}
	}
	return nil
}

// FindSiteByIndex 根据索引查找站点（1-based）
func (r *ScanResult) FindSiteByIndex(index int) *ScannedSite {
	if index < 1 || index > len(r.Sites) {
		return nil
	}
	return &r.Sites[index-1]
}
