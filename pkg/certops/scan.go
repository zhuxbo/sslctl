// Package certops 站点扫描逻辑
package certops

import (
	"context"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/webserver"
)

// ScanSites 扫描站点（支持 Nginx 和 Apache）
func (s *Service) ScanSites(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		ScanTime: time.Now(),
		Sites:    []ScannedSite{},
	}

	// 扫描所有支持的服务器类型
	serverTypes := []webserver.ServerType{webserver.TypeNginx, webserver.TypeApache}

	for _, serverType := range serverTypes {
		scanner, err := webserver.NewScanner(serverType)
		if err != nil {
			s.log.Debug("创建 %s 扫描器失败: %v", serverType, err)
			continue
		}

		sites, err := scanner.Scan()
		if err != nil {
			s.log.Debug("扫描 %s 站点失败: %v", serverType, err)
			continue
		}

		for _, site := range sites {
			// 如果仅 SSL，过滤非 SSL 站点
			if opts.SSLOnly && site.CertificatePath == "" {
				continue
			}
			result.Sites = append(result.Sites, ScannedSite{
				Source:          "local",
				ServerName:      site.ServerName,
				ServerAlias:     site.ServerAlias,
				ListenPorts:     site.ListenPorts,
				ConfigFile:      site.ConfigFile,
				CertificatePath: site.CertificatePath,
				PrivateKeyPath:  site.PrivateKeyPath,
				ChainFilePath:   site.ChainFile,
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
			Source:          site.Source,
			ContainerID:     site.ContainerID,
			ContainerName:   site.ContainerName,
			ServerName:      site.ServerName,
			ServerAlias:     site.ServerAlias,
			ListenPorts:     site.ListenPorts,
			ConfigFile:      site.ConfigFile,
			CertificatePath: site.CertificatePath,
			PrivateKeyPath:  site.PrivateKeyPath,
			ChainFilePath:   site.ChainFilePath,
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
