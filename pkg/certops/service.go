// Package certops 证书操作服务层
package certops

import (
	"context"
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

// GetConfigManager 获取配置管理器
func (s *Service) GetConfigManager() *config.ConfigManager {
	return s.cfgManager
}

// GetFetcher 获取 API 客户端
func (s *Service) GetFetcher() *fetcher.Fetcher {
	return s.fetcher
}

// GetBackupManager 获取备份管理器
func (s *Service) GetBackupManager() *backup.Manager {
	return s.backupMgr
}

// GetLogger 获取日志记录器
func (s *Service) GetLogger() *logger.Logger {
	return s.log
}

// Deploy 部署指定证书
func (s *Service) Deploy(ctx context.Context, certName string) (*DeployResult, error) {
	return s.DeployOne(ctx, certName)
}

// DeployAll 部署所有证书
func (s *Service) DeployAll(ctx context.Context) ([]*DeployResult, error) {
	return s.DeployAllCerts(ctx)
}

// CheckAndRenew 检查并续签证书
func (s *Service) CheckAndRenew(ctx context.Context) ([]*RenewResult, error) {
	return s.CheckAndRenewAll(ctx)
}

// Scan 扫描站点
func (s *Service) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	return s.ScanSites(ctx, opts)
}
