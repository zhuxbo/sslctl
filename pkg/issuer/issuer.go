// Package issuer 负责证书签发流程
package issuer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
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

	certData, err := i.fetcher.StartOrUpdate(ctx, site.API.URL, site.API.Token, csrPEM, opts.ValidationMethod)
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
		_ = os.Remove(validationPath)
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
			certData, err := i.fetcher.Info(ctx, site.API.URL, site.API.Token)
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

// IssueAction 签发动作
const (
	ActionSkip      = "skip"      // 跳过（processing 状态）
	ActionDeployed  = "deployed"  // 已部署
	ActionSubmitted = "submitted" // 已提交 CSR，等待下次
	ActionError     = "error"     // 错误
)

// CheckAndIssueResult CheckAndIssue 的返回结果
type CheckAndIssueResult struct {
	CertData   *fetcher.CertData // 证书数据（仅 deployed 时有效）
	PrivateKey string            // 私钥（仅 deployed 时有效）
	Action     string            // 动作: skip, deployed, submitted, error
	OrderID    int               // 订单 ID（submitted 时需要保存）
}

// CheckAndIssue 检查订单状态并决定下一步操作（用于本地私钥模式）
// 流程:
//   - OrderID > 0: 查询订单状态
//     - processing: return skip
//     - active: handleActiveCert
//     - 失败/其他: submitNewCSR
//   - OrderID == 0: submitNewCSR
func (i *Issuer) CheckAndIssue(ctx context.Context, site *config.SiteConfig, keyPath string, opts IssueOptions) (*CheckAndIssueResult, error) {
	// 合并默认选项
	if opts.MaxWait == 0 {
		opts.MaxWait = DefaultIssueOptions.MaxWait
	}
	if opts.CheckInterval == 0 {
		opts.CheckInterval = DefaultIssueOptions.CheckInterval
	}

	orderID := site.Metadata.OrderID

	// 如果有订单 ID，先查询状态
	if orderID > 0 {
		i.log("查询订单状态: OrderID=%d", orderID)
		certData, err := i.fetcher.QueryOrder(ctx, site.API.URL, site.API.Token, orderID)
		if err != nil {
			i.log("查询订单失败: %v，将重新提交 CSR", err)
			return i.submitNewCSR(ctx, site, keyPath, opts)
		}

		switch certData.Status {
		case "processing":
			i.log("订单仍在处理中，跳过")
			return &CheckAndIssueResult{Action: ActionSkip}, nil
		case "active":
			return i.handleActiveCert(ctx, site, certData, keyPath, opts)
		default:
			i.log("订单状态异常: %s，将重新提交 CSR", certData.Status)
			return i.submitNewCSR(ctx, site, keyPath, opts)
		}
	}

	// 没有订单 ID，提交新 CSR
	return i.submitNewCSR(ctx, site, keyPath, opts)
}

// handleActiveCert 处理已签发的证书
func (i *Issuer) handleActiveCert(ctx context.Context, site *config.SiteConfig, certData *fetcher.CertData, keyPath string, opts IssueOptions) (*CheckAndIssueResult, error) {
	i.log("证书已签发，检查私钥")

	// API 返回了私钥，直接使用
	if certData.PrivateKey != "" {
		i.log("使用 API 返回的私钥")
		return &CheckAndIssueResult{
			CertData:   certData,
			PrivateKey: certData.PrivateKey,
			Action:     ActionDeployed,
			OrderID:    certData.OrderID,
		}, nil
	}

	// 尝试读取本地私钥
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		i.log("本地私钥不存在，将重新提交 CSR: %v", err)
		return i.submitNewCSR(ctx, site, keyPath, opts)
	}

	privateKey := string(keyBytes)

	// 验证私钥与证书是否匹配
	if !i.validateKeyPair(certData.Cert, privateKey) {
		i.log("本地私钥与证书不匹配，删除旧私钥并重新提交 CSR")
		_ = os.Remove(keyPath)
		return i.submitNewCSR(ctx, site, keyPath, opts)
	}

	i.log("本地私钥与证书匹配")
	return &CheckAndIssueResult{
		CertData:   certData,
		PrivateKey: privateKey,
		Action:     ActionDeployed,
		OrderID:    certData.OrderID,
	}, nil
}

// submitNewCSR 生成新的 CSR 并提交
func (i *Issuer) submitNewCSR(ctx context.Context, site *config.SiteConfig, keyPath string, opts IssueOptions) (*CheckAndIssueResult, error) {
	// 生成私钥和 CSR
	keyOpts := csr.KeyOptions{
		Type:  site.Key.Type,
		Size:  site.Key.Size,
		Curve: site.Key.Curve,
	}

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

	// 保存私钥到本地
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return nil, fmt.Errorf("创建私钥目录失败: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(privateKey), 0600); err != nil {
		return nil, fmt.Errorf("保存私钥失败: %w", err)
	}
	i.log("私钥已保存: %s", keyPath)

	// 提交 CSR 到 API（通过 POST 部署接口）
	// 传入现有 order_id 用于重签/续费场景，首次提交时 order_id 为 0
	i.log("提交 CSR 到 API: %s (OrderID=%d)", site.API.URL, site.Metadata.OrderID)

	certData, err := i.fetcher.Update(ctx, site.API.URL, site.API.Token,
		site.Metadata.OrderID,
		csrPEM,
		strings.Join(site.Domains, ","),
		opts.ValidationMethod)
	if err != nil {
		return nil, fmt.Errorf("提交 CSR 失败: %w", err)
	}

	// 更新元数据
	site.Metadata.CSRSubmittedAt = time.Now()
	site.Metadata.LastCSRHash = csrHash
	site.Metadata.LastIssueState = certData.Status
	site.Metadata.OrderID = certData.OrderID

	// 处理 file 验证
	if certData.Status == "processing" && certData.File != nil {
		certData, err = i.handleFileValidation(ctx, site, certData, opts)
		if err != nil {
			return &CheckAndIssueResult{
				Action:  ActionSubmitted,
				OrderID: site.Metadata.OrderID,
			}, nil // file 验证失败不算致命错误，等待下次
		}
	}

	// 如果还在 processing 状态，等待下次
	if certData.Status == "processing" {
		i.log("CSR 已提交，等待签发: OrderID=%d", certData.OrderID)
		return &CheckAndIssueResult{
			Action:  ActionSubmitted,
			OrderID: certData.OrderID,
		}, nil
	}

	// 证书已签发
	if certData.Status == "active" && certData.Cert != "" {
		i.log("证书签发完成")
		return &CheckAndIssueResult{
			CertData:   certData,
			PrivateKey: privateKey,
			Action:     ActionDeployed,
			OrderID:    certData.OrderID,
		}, nil
	}

	return nil, fmt.Errorf("证书签发状态异常: status=%s", certData.Status)
}

// validateKeyPair 验证私钥与证书是否匹配
func (i *Issuer) validateKeyPair(certPEM, keyPEM string) bool {
	v := validator.New("")
	return v.ValidateCertKeyPair(certPEM, keyPEM) == nil
}
