// Package certops 证书操作服务层
package certops

import (
	"context"
	"fmt"
	"strings"
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

// sendCallback 统一发送回调
// 非关键路径，失败仅记录日志
// 返回服务端下发的 renewBeforeDays（失败时返回 0）
func (s *Service) sendCallback(ctx context.Context, api config.APIConfig, req *fetcher.CallbackRequest) int {
	if api.URL == "" || api.Token == "" {
		return 0
	}

	renewBeforeDays, err := s.fetcher.CallbackNew(ctx, api.URL, api.Token, req)

	if err != nil {
		s.log.Warn("回调发送失败（不影响结果）: %v", err)
		return 0
	}
	s.log.Debug("回调成功: order=%d status=%s", req.OrderID, req.Status)
	return renewBeforeDays
}

// syncOrderID 同步 API 返回的订单号到本地配置
// 订单续费后 API 会返回新的订单号，需要及时更新 order_id 和 cert_name
func (s *Service) syncOrderID(cert *config.CertConfig, certData *fetcher.CertData) {
	if certData.OrderID > 0 && certData.OrderID != cert.OrderID {
		s.log.Info("证书 %s 订单已续费，订单号更新: %d -> %d", cert.CertName, cert.OrderID, certData.OrderID)
		cert.OrderID = certData.OrderID
	}
	// 修正 cert_name 使其与 order_id 一致
	s.fixCertName(cert)
}

// fixCertName 修正 cert_name 中的订单号后缀，使其与 order_id 一致
// cert_name 格式: {domain}-{order_id}
func (s *Service) fixCertName(cert *config.CertConfig) {
	idx := strings.LastIndex(cert.CertName, "-")
	if idx < 0 {
		return
	}
	expectedName := fmt.Sprintf("%s-%d", cert.CertName[:idx], cert.OrderID)
	if expectedName == cert.CertName {
		return
	}
	oldName := cert.CertName
	cert.CertName = expectedName
	s.log.Info("证书名称修正: %s -> %s", oldName, expectedName)
	if err := s.cfgManager.RenameCert(oldName, cert); err != nil {
		s.log.Warn("重命名证书配置失败: %v", err)
	}
}

// fillCertMetadata 填充回调请求中的证书元数据（预留扩展）
func fillCertMetadata(_ *fetcher.CallbackRequest, _ *config.CertConfig) {
}

// CheckExpiry 检查证书过期时间并输出告警日志
// 距过期不足 7 天 → Error 级别
// 距过期不足 13 天 → Warn 级别
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

		if remaining < 0 {
			days := int(-remaining.Hours() / 24)
			s.log.Error("证书 %s 已过期 %d 天! (过期时间: %s)",
				cert.CertName, days, cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		} else if remaining < 7*24*time.Hour {
			s.log.Error("证书 %s 即将过期! 剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		} else if remaining < 13*24*time.Hour {
			s.log.Warn("证书 %s 即将过期，剩余 %d 天 (过期时间: %s)",
				cert.CertName, int(remaining.Hours()/24), cert.Metadata.CertExpiresAt.Format("2006-01-02"))
		}
	}
}
