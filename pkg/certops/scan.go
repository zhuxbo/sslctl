// Package certops 站点扫描逻辑
package certops

import (
	"context"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// ScanSites 扫描站点
func (s *Service) ScanSites(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		ScanTime: time.Now(),
		Sites:    []ScannedSite{},
	}

	// 通过抽象层创建扫描器
	scanner, err := webserver.NewScanner(webserver.TypeNginx)
	if err != nil {
		s.log.Warn("创建扫描器失败: %v", err)
		return result, nil
	}

	// 使用统一的 Scan 方法扫描所有站点（本地 + Docker）
	sites, err := scanner.Scan()
	if err != nil {
		s.log.Warn("扫描站点失败: %v", err)
	} else {
		for _, site := range sites {
			// 如果仅 SSL，过滤非 SSL 站点
			if opts.SSLOnly && site.CertificatePath == "" {
				continue
			}
			result.Sites = append(result.Sites, ScannedSite{
				ID:              site.ServerName,
				Name:            site.ServerName,
				Source:          "local",
				ConfigFile:      site.ConfigFile,
				ServerName:      site.ServerName,
				ServerAlias:     site.ServerAlias,
				ListenPorts:     site.ListenPorts,
				CertificatePath: site.CertificatePath,
				PrivateKeyPath:  site.PrivateKeyPath,
			})
		}
	}

	// 确定环境
	result.Environment = "local"

	// 保存扫描结果
	configResult := &config.ScanResult{
		ScanTime:    result.ScanTime,
		Environment: result.Environment,
		Sites:       make([]config.ScannedSite, len(result.Sites)),
	}
	for i, site := range result.Sites {
		configResult.Sites[i] = config.ScannedSite{
			ID:              site.ID,
			Name:            site.Name,
			Source:          site.Source,
			ContainerID:     site.ContainerID,
			ContainerName:   site.ContainerName,
			ConfigFile:      site.ConfigFile,
			ServerName:      site.ServerName,
			ServerAlias:     site.ServerAlias,
			ListenPorts:     site.ListenPorts,
			CertificatePath: site.CertificatePath,
			PrivateKeyPath:  site.PrivateKeyPath,
			HostCertPath:    site.HostCertPath,
			HostKeyPath:     site.HostKeyPath,
			VolumeMode:      site.VolumeMode,
		}
	}
	if err := config.SaveScanResult(configResult); err != nil {
		s.log.Warn("保存扫描结果失败: %v", err)
	}

	return result, nil
}
