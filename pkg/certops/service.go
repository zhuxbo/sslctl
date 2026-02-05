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

// Getter 方法 - 用于测试和外部访问内部组件
// 设计说明：这些 Getter 方法是有意保留的，用于：
// 1. 单元测试中验证 Service 正确初始化
// 2. 允许外部代码在特殊场景下访问内部组件（如自定义部署流程）
// Go 惯例允许简单 Getter，因为它们不增加复杂性且提供了测试便利性
//
// Deprecated: 仅用于测试，新代码应优先使用行为测试替代直接访问内部组件。

// GetConfigManager 获取配置管理器
//
// Deprecated: 仅用于测试
func (s *Service) GetConfigManager() *config.ConfigManager { return s.cfgManager }

// GetFetcher 获取 API 客户端
//
// Deprecated: 仅用于测试
func (s *Service) GetFetcher() *fetcher.Fetcher { return s.fetcher }

// GetBackupManager 获取备份管理器
//
// Deprecated: 仅用于测试
func (s *Service) GetBackupManager() *backup.Manager { return s.backupMgr }

// GetLogger 获取日志记录器
//
// Deprecated: 仅用于测试
func (s *Service) GetLogger() *logger.Logger { return s.log }

// 便捷方法 - 提供简洁的公共 API
//
// Deprecated: 这些别名方法将在未来版本中移除，请直接使用 DeployOne/DeployAllCerts/CheckAndRenewAll/ScanSites。

// Deploy 部署指定证书（DeployOne 的别名）
//
// Deprecated: 请使用 DeployOne
func (s *Service) Deploy(ctx context.Context, certName string) (*DeployResult, error) {
	return s.DeployOne(ctx, certName)
}

// DeployAll 部署所有证书（DeployAllCerts 的别名）
//
// Deprecated: 请使用 DeployAllCerts
func (s *Service) DeployAll(ctx context.Context) ([]*DeployResult, error) {
	return s.DeployAllCerts(ctx)
}

// CheckAndRenew 检查并续签证书（CheckAndRenewAll 的别名）
//
// Deprecated: 请使用 CheckAndRenewAll
func (s *Service) CheckAndRenew(ctx context.Context) ([]*RenewResult, error) {
	return s.CheckAndRenewAll(ctx)
}

// Scan 扫描站点（ScanSites 的别名）
//
// Deprecated: 请使用 ScanSites
func (s *Service) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	return s.ScanSites(ctx, opts)
}
