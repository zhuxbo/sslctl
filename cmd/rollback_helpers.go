// 辅助函数：用于回滚后的证书元数据更新与解析
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/util"
)

// parseRollbackCert 解析证书文件（不校验证书有效期）
func parseRollbackCert(certPath string) (*x509.Certificate, error) {
	data, err := util.SafeReadFile(certPath, config.MaxCertFileSize)
	if err != nil {
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("证书格式无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}
	return cert, nil
}

// applyRollbackMetadata 根据站点名更新证书元数据，返回被更新的证书列表
func applyRollbackMetadata(cfg *config.Config, siteName string, cert *x509.Certificate, meta *backup.Metadata, now time.Time) []*config.CertConfig {
	var updated []*config.CertConfig

	// 优先使用证书解析结果，否则回退到备份元数据
	var (
		expiresAt time.Time
		serial    string
	)
	if cert != nil {
		expiresAt = cert.NotAfter
		if cert.SerialNumber != nil {
			serial = fmt.Sprintf("%X", cert.SerialNumber)
		}
	} else if meta != nil && !meta.CertInfo.NotAfter.IsZero() {
		expiresAt = meta.CertInfo.NotAfter
		serial = meta.CertInfo.Serial
	}

	for i := range cfg.Certificates {
		certCfg := &cfg.Certificates[i]
		if !certHasSite(certCfg, siteName) {
			continue
		}

		// 标记回滚后的当前状态
		certCfg.Metadata.LastDeployAt = now
		if !expiresAt.IsZero() {
			certCfg.Metadata.CertExpiresAt = expiresAt
		}
		if serial != "" {
			certCfg.Metadata.CertSerial = serial
		}

		// 回滚视为一次部署成功，清理本地续签状态
		certCfg.Metadata.CSRSubmittedAt = time.Time{}
		certCfg.Metadata.LastCSRHash = ""
		certCfg.Metadata.LastIssueState = ""
		certCfg.Metadata.IssueRetryCount = 0

		updated = append(updated, certCfg)
	}

	return updated
}

// certHasSite 判断证书配置是否包含指定站点绑定
func certHasSite(cert *config.CertConfig, siteName string) bool {
	for _, binding := range cert.Bindings {
		if binding.SiteName == siteName {
			return true
		}
	}
	return false
}
