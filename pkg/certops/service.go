// Package certops 证书操作服务层
package certops

import (
	"time"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// Service 证书服务
type Service struct {
	cfgManager *config.ConfigManager
	fetcher    *fetcher.Fetcher
	backupMgr  *backup.Manager
	log        *logger.Logger
}

// NewService 创建证书服务
func NewService(cfgManager *config.ConfigManager, log *logger.Logger) *Service {
	return &Service{
		cfgManager: cfgManager,
		fetcher:    fetcher.New(30 * time.Second),
		backupMgr:  backup.NewManager(cfgManager.GetBackupDir(), 5),
		log:        log,
	}
}

// CheckExpiry 检查证书过期时间并输出告警日志
// 距过期不足 7 天且续签失败 → Error 级别
// 距过期不足 14 天 → Warn 级别
func (s *Service) CheckExpiry() {
	cfg, err := s.cfgManager.Load()
	if err != nil {
		s.log.Warn("加载配置失败，跳过过期检查: %v", err)
		return
	}

	now := time.Now()
	for _, cert := range cfg.Certificates {
		if !cert.Enabled || cert.Metadata.CertExpiresAt.IsZero() {
			continue
		}

		remaining := cert.Metadata.CertExpiresAt.Sub(now)

		if remaining < 7*24*time.Hour {
			s.log.Error("证书 %s 即将过期! 剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		} else if remaining < 14*24*time.Hour {
			s.log.Warn("证书 %s 即将过期，剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		}
	}
}
