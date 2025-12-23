// Package issuer 负责证书签发流程
package issuer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cnssl/cert-deploy/pkg/config"
	"github.com/cnssl/cert-deploy/pkg/csr"
	"github.com/cnssl/cert-deploy/pkg/fetcher"
	"github.com/cnssl/cert-deploy/pkg/logger"
	"github.com/cnssl/cert-deploy/pkg/util"
)

// IssueResult 签发结果
type IssueResult struct {
	CertData   *fetcher.CertData // 证书数据
	PrivateKey string            // 本地生成的私钥
	CSRHash    string            // CSR 哈希
}

// IssueOptions 签发选项
type IssueOptions struct {
	Webroot          string        // Web 根目录（用于 file 验证）
	ValidationMethod string        // 验证方式: file, txt
	MaxWait          time.Duration // 最大等待时间
	CheckInterval    time.Duration // 检查间隔
}

// DefaultIssueOptions 默认签发选项
var DefaultIssueOptions = IssueOptions{
	MaxWait:       5 * time.Minute,
	CheckInterval: 10 * time.Second,
}

// Issuer 证书签发器
type Issuer struct {
	fetcher *fetcher.Fetcher
	logger  *logger.Logger
}

// New 创建签发器
func New(log *logger.Logger) *Issuer {
	return &Issuer{
		fetcher: fetcher.New(30 * time.Second),
		logger:  log,
	}
}

// Issue 发起证书签发
// 流程：
// 1. 生成私钥和 CSR
// 2. 调用 API 提交 CSR
// 3. 如果需要 file 验证，放置验证文件并等待
// 4. 轮询等待证书签发完成
// 5. 返回证书和私钥
func (i *Issuer) Issue(ctx context.Context, site *config.SiteConfig, opts IssueOptions) (*IssueResult, error) {
	// 合并默认选项
	if opts.MaxWait == 0 {
		opts.MaxWait = DefaultIssueOptions.MaxWait
	}
	if opts.CheckInterval == 0 {
		opts.CheckInterval = DefaultIssueOptions.CheckInterval
	}

	// 1. 生成私钥和 CSR
	keyOpts := csr.KeyOptions{
		Type:  site.Key.Type,
		Size:  site.Key.Size,
		Curve: site.Key.Curve,
	}

	// CommonName 优先使用配置，否则使用第一个域名
	commonName := site.CSR.CommonName
	if commonName == "" && len(site.Domains) > 0 {
		commonName = site.Domains[0]
	}

	csrOpts := csr.CSROptions{
		CommonName:   commonName,
		Organization: site.CSR.Organization,
		Country:      site.CSR.Country,
		State:        site.CSR.State,
		Locality:     site.CSR.Locality,
		Email:        site.CSR.Email,
	}

	i.log("生成私钥和 CSR: CN=%s", commonName)

	privateKey, csrPEM, csrHash, err := csr.GenerateKeyAndCSR(keyOpts, csrOpts)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// 2. 提交 CSR 到 API
	i.log("提交 CSR 到 API: %s", site.API.URL)

	certData, err := i.fetcher.StartOrUpdate(ctx, site.API.URL, site.API.ReferID, csrPEM, opts.ValidationMethod)
	if err != nil {
		return nil, fmt.Errorf("提交 CSR 失败: %w", err)
	}

	// 3. 处理 file 验证
	if certData.Status == "processing" && certData.File != nil {
		certData, err = i.handleFileValidation(ctx, site, certData, opts)
		if err != nil {
			return nil, err
		}
	}

	// 4. 等待证书签发完成（如果还在 processing 状态）
	if certData.Status == "processing" {
		certData, err = i.waitForCert(ctx, site, opts)
		if err != nil {
			return nil, err
		}
	}

	// 5. 检查最终状态
	if certData.Status != "active" || certData.Cert == "" {
		return nil, fmt.Errorf("证书未签发成功: status=%s", certData.Status)
	}

	return &IssueResult{
		CertData:   certData,
		PrivateKey: privateKey,
		CSRHash:    csrHash,
	}, nil
}

// handleFileValidation 处理 file 验证
func (i *Issuer) handleFileValidation(ctx context.Context, site *config.SiteConfig, certData *fetcher.CertData, opts IssueOptions) (*fetcher.CertData, error) {
	if opts.Webroot == "" {
		return nil, fmt.Errorf("证书需要 file 验证，但未提供 webroot 路径")
	}

	// 写入验证文件
	validationPath, err := util.JoinUnderDir(opts.Webroot, certData.File.Path)
	if err != nil {
		return nil, fmt.Errorf("验证文件路径无效: %w", err)
	}
	validationDir := filepath.Dir(validationPath)

	if err := os.MkdirAll(validationDir, 0755); err != nil {
		return nil, fmt.Errorf("创建验证文件目录失败: %w", err)
	}

	if err := os.WriteFile(validationPath, []byte(certData.File.Content), 0644); err != nil {
		return nil, fmt.Errorf("写入验证文件失败: %w", err)
	}

	i.log("验证文件已放置: %s", validationPath)

	// 确保清理验证文件
	defer func() {
		os.Remove(validationPath)
		i.log("验证文件已清理: %s", validationPath)
	}()

	// 等待证书签发完成
	return i.waitForCert(ctx, site, opts)
}

// waitForCert 等待证书签发完成
func (i *Issuer) waitForCert(ctx context.Context, site *config.SiteConfig, opts IssueOptions) (*fetcher.CertData, error) {
	deadline := time.Now().Add(opts.MaxWait)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(opts.CheckInterval):
			certData, err := i.fetcher.Info(ctx, site.API.URL, site.API.ReferID)
			if err != nil {
				i.log("检查证书状态失败: %v", err)
				continue
			}

			if certData.Status == "active" && certData.Cert != "" {
				i.log("证书签发完成")
				return certData, nil
			}

			i.log("证书状态: %s，继续等待...", certData.Status)
		}
	}

	return nil, fmt.Errorf("等待证书签发超时")
}

// log 记录日志
func (i *Issuer) log(format string, args ...interface{}) {
	if i.logger != nil {
		i.logger.Info(format, args...)
	}
}
