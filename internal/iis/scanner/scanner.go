// Package scanner 扫描 IIS SSL 站点
package scanner

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cnssl/cert-deploy/internal/iis/powershell"
)

// SSLSite IIS SSL 站点信息
type SSLSite struct {
	SiteName       string    // IIS 站点名称
	HostName       string    // 主机名（域名）
	Port           string    // 端口
	CertThumbprint string    // 证书指纹
	CertExpires    time.Time // 证书过期时间
	CertSubject    string    // 证书主题
	PhysicalPath   string    // 站点物理路径 (Web 根目录)
}

// HTTPSite IIS HTTP 站点信息（未启用 HTTPS）
type HTTPSite struct {
	SiteName     string // IIS 站点名称
	HostName     string // 主机名（域名）
	Port         string // 端口
	PhysicalPath string // 站点物理路径
}

// Scanner IIS SSL 站点扫描器
type Scanner struct {
	psRunner *powershell.Runner
}

// New 创建扫描器
func New() *Scanner {
	return &Scanner{
		psRunner: powershell.NewRunner(),
	}
}

// Scan 扫描所有 IIS SSL 站点
func (s *Scanner) Scan() ([]*SSLSite, error) {
	// 调用 PowerShell 获取站点列表
	output, err := s.psRunner.ListSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list IIS sites: %w", err)
	}

	// 解析 JSON 输出
	return s.parseOutput(output)
}

// psSSLSite PowerShell 返回的站点结构
type psSSLSite struct {
	SiteName       string `json:"SiteName"`
	HostName       string `json:"HostName"`
	Port           string `json:"Port"`
	CertThumbprint string `json:"CertThumbprint"`
	CertExpires    string `json:"CertExpires"`
	CertSubject    string `json:"CertSubject"`
	PhysicalPath   string `json:"PhysicalPath"`
}

// parseOutput 解析 PowerShell 输出
func (s *Scanner) parseOutput(output string) ([]*SSLSite, error) {
	if output == "" {
		return nil, nil
	}

	// PowerShell 可能返回单个对象或数组
	var sites []*SSLSite

	// 尝试解析为数组
	var psSites []psSSLSite
	if err := json.Unmarshal([]byte(output), &psSites); err != nil {
		// 尝试解析为单个对象
		var psSite psSSLSite
		if err := json.Unmarshal([]byte(output), &psSite); err != nil {
			return nil, fmt.Errorf("failed to parse PowerShell output: %w", err)
		}
		psSites = []psSSLSite{psSite}
	}

	for _, ps := range psSites {
		site := &SSLSite{
			SiteName:       ps.SiteName,
			HostName:       ps.HostName,
			Port:           ps.Port,
			CertThumbprint: ps.CertThumbprint,
			CertSubject:    ps.CertSubject,
			PhysicalPath:   ps.PhysicalPath,
		}

		// 解析过期时间
		if ps.CertExpires != "" && ps.CertExpires != "N/A" {
			if t, err := time.Parse("2006-01-02 15:04:05", ps.CertExpires); err == nil {
				site.CertExpires = t
			}
		}

		sites = append(sites, site)
	}

	return sites, nil
}

// FindBySiteName 根据站点名称查找
func (s *Scanner) FindBySiteName(siteName string) (*SSLSite, error) {
	sites, err := s.Scan()
	if err != nil {
		return nil, err
	}

	for _, site := range sites {
		if site.SiteName == siteName {
			return site, nil
		}
	}

	return nil, nil
}

// FindByHostName 根据主机名（域名）查找
func (s *Scanner) FindByHostName(hostName string) (*SSLSite, error) {
	sites, err := s.Scan()
	if err != nil {
		return nil, err
	}

	for _, site := range sites {
		if site.HostName == hostName {
			return site, nil
		}
	}

	return nil, nil
}

// ValidateIIS 验证 IIS 是否可用
func (s *Scanner) ValidateIIS() error {
	command := `
Import-Module WebAdministration -ErrorAction Stop
Write-Output "IIS module loaded successfully"
`
	_, err := s.psRunner.Run(command)
	if err != nil {
		return fmt.Errorf("IIS WebAdministration module not available: %w", err)
	}
	return nil
}

// ScanHTTPSites 扫描仅有 HTTP 绑定的站点（无 HTTPS 绑定）
func (s *Scanner) ScanHTTPSites() ([]*HTTPSite, error) {
	output, err := s.psRunner.ListHTTPSites()
	if err != nil {
		return nil, fmt.Errorf("failed to list HTTP sites: %w", err)
	}

	return s.parseHTTPOutput(output)
}

// psHTTPSite PowerShell 返回的 HTTP 站点结构
type psHTTPSite struct {
	SiteName     string `json:"SiteName"`
	HostName     string `json:"HostName"`
	Port         string `json:"Port"`
	PhysicalPath string `json:"PhysicalPath"`
}

// parseHTTPOutput 解析 HTTP 站点 PowerShell 输出
func (s *Scanner) parseHTTPOutput(output string) ([]*HTTPSite, error) {
	if output == "" {
		return nil, nil
	}

	var sites []*HTTPSite

	// 尝试解析为数组
	var psSites []psHTTPSite
	if err := json.Unmarshal([]byte(output), &psSites); err != nil {
		// 尝试解析为单个对象
		var psSite psHTTPSite
		if err := json.Unmarshal([]byte(output), &psSite); err != nil {
			return nil, fmt.Errorf("failed to parse HTTP sites output: %w", err)
		}
		psSites = []psHTTPSite{psSite}
	}

	for _, ps := range psSites {
		site := &HTTPSite{
			SiteName:     ps.SiteName,
			HostName:     ps.HostName,
			Port:         ps.Port,
			PhysicalPath: ps.PhysicalPath,
		}
		sites = append(sites, site)
	}

	return sites, nil
}
