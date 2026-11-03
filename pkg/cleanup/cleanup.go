// Package cleanup 清理 sslctl 管理状态，但不改动已部署的证书。
package cleanup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// Result 描述一次清理移除的管理状态。
type Result struct {
	RemovedBindings     int
	RemovedCertificates int
}

// Service 清理证书和站点管理状态。
type Service struct {
	config cleanupConfig
	backup backupCleaner
}

type cleanupConfig interface {
	RemoveSite(string) (*config.RemoveSiteResult, error)
	RemoveCertificate(string) ([]config.CertConfig, error)
	ListCerts() ([]config.CertConfig, error)
	GetWorkDir() string
}

type backupCleaner interface {
	DeleteAllBackups(string) error
}

// New 使用配置的 sslctl 工作目录创建清理服务。
func New(configManager *config.ConfigManager) *Service {
	return &Service{
		config: configManager,
		backup: backup.NewManager(configManager.GetBackupDir(), 5),
	}
}

// RemoveSite 解除站点管理并删除 sslctl 专用备份数据。
// 已部署的证书文件和 Web 服务器配置始终保留。
func (s *Service) RemoveSite(siteName string) (*Result, error) {
	removed, err := s.config.RemoveSite(siteName)
	if err != nil {
		return nil, err
	}

	result := &Result{
		RemovedBindings:     removed.RemovedBindings,
		RemovedCertificates: len(removed.RemovedCertificates),
	}
	var cleanupErrors []error
	if err := s.backup.DeleteAllBackups(siteName); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("清理站点备份失败: %w", err))
	}
	for i := range removed.RemovedCertificates {
		if err := s.removePendingKeys(removed.RemovedCertificates[i].CertName); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return result, errors.Join(cleanupErrors...)
}

// RemoveCertificate 解除证书管理并删除 sslctl 专用状态。
// 已部署的证书文件、验证文件和 Web 服务器配置始终保留。
func (s *Service) RemoveCertificate(certName string) (*Result, error) {
	certs, err := s.config.RemoveCertificate(certName)
	if err != nil {
		return nil, err
	}

	result := &Result{RemovedCertificates: len(certs)}
	var cleanupErrors []error
	remainingCerts, listErr := s.config.ListCerts()
	if listErr != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("复检剩余站点绑定失败: %w", listErr))
	}
	remainingSites := make(map[string]struct{})
	for i := range remainingCerts {
		for j := range remainingCerts[i].Bindings {
			remainingSites[remainingCerts[i].Bindings[j].ServerName] = struct{}{}
		}
	}
	seenSites := make(map[string]struct{})
	for i := range certs {
		result.RemovedBindings += len(certs[i].Bindings)
		for j := range certs[i].Bindings {
			siteName := certs[i].Bindings[j].ServerName
			if _, seen := seenSites[siteName]; seen {
				continue
			}
			seenSites[siteName] = struct{}{}
			if _, stillManaged := remainingSites[siteName]; stillManaged || listErr != nil {
				continue
			}
			if err := s.backup.DeleteAllBackups(siteName); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("清理站点 %s 的备份失败: %w", siteName, err))
			}
		}
	}
	if err := s.removePendingKeys(certName); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	return result, errors.Join(cleanupErrors...)
}

func (s *Service) removePendingKeys(certName string) error {
	pendingRoot := filepath.Join(s.config.GetWorkDir(), "pending-keys")
	pendingDir, err := util.JoinUnderDir(pendingRoot, certName)
	if err != nil {
		return fmt.Errorf("清理证书 %s 的 pending 私钥失败: %w", certName, err)
	}
	if err := os.RemoveAll(pendingDir); err != nil {
		return fmt.Errorf("清理证书 %s 的 pending 私钥失败: %w", certName, err)
	}
	return nil
}
