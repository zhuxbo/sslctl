// Package fetcher 负责从 API 获取证书
package fetcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// API 响应状态码
const (
	APICodeSuccess = 1 // API 成功响应码
)

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries  int           // 最大重试次数
	InitialWait time.Duration // 初始等待时间
	MaxWait     time.Duration // 最大等待时间
	Multiplier  float64       // 退避乘数
}

// DefaultRetryConfig 默认重试配置（指数退避：1s, 2s, 4s）
var DefaultRetryConfig = RetryConfig{
	MaxRetries:  3,
	InitialWait: 1 * time.Second,
	MaxWait:     4 * time.Second,
	Multiplier:  2.0,
}

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据
type CertData struct {
	OrderID          int            `json:"order_id"`
	Status           string         `json:"status"`
	Domains          string         `json:"domains"`
	Cert             string         `json:"certificate"`
	IntermediateCert string         `json:"ca_certificate"`
	PrivateKey       string         `json:"private_key"`
	IssuedAt         string         `json:"issued_at"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

// APIResponse API 响应结构
type APIResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"msg"` // API 使用 msg 字段
	Data    json.RawMessage `json:"data"`
}

// ParseData 解析 Data 字段，支持单个对象或数组格式
func (r *APIResponse) ParseData() (*CertData, error) {
	if len(r.Data) == 0 {
		return nil, fmt.Errorf("empty data field")
	}
	// 尝试解析为单个对象
	var single CertData
	if err := json.Unmarshal(r.Data, &single); err == nil {
		return &single, nil
	}
	// 尝试解析为数组
	var list []CertData
	if err := json.Unmarshal(r.Data, &list); err != nil {
		return nil, fmt.Errorf("failed to parse data: not object or array")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("empty data array")
	}
	return &list[0], nil
}

// PaginatedResponse 批量查询分页响应结构
type PaginatedResponse struct {
	Total           int        `json:"total"`
	CurrentPage     int        `json:"page"`
	PageSize        int        `json:"page_size"`
	RenewBeforeDays int        `json:"renew_before_days"`
	Data            []CertData `json:"data"`
}

// ParsePaginatedData 解析批量查询的分页响应
// 批量响应格式: {"total": N, "page": 1, "page_size": 100, "renew_before_days": 14, "data": [...]}
// 兼容单对象格式: 包装成单元素切片返回
// 返回: (certs, total, renewBeforeDays, error)
func (r *APIResponse) ParsePaginatedData() ([]CertData, int, int, error) {
	if len(r.Data) == 0 {
		return nil, 0, 0, fmt.Errorf("empty data field")
	}
	// 尝试解析为分页响应
	var paginated PaginatedResponse
	if err := json.Unmarshal(r.Data, &paginated); err == nil && paginated.Data != nil {
		return paginated.Data, paginated.Total, paginated.RenewBeforeDays, nil
	}
	// 兼容：尝试解析为单个对象
	var single CertData
	if err := json.Unmarshal(r.Data, &single); err == nil && single.OrderID != 0 {
		return []CertData{single}, 1, 0, nil
	}
	// 兼容：尝试解析为数组
	var list []CertData
	if err := json.Unmarshal(r.Data, &list); err == nil {
		return list, len(list), 0, nil
	}
	return nil, 0, 0, fmt.Errorf("failed to parse paginated data")
}

// UpdateRequest 更新/续费证书请求

type UpdateRequest struct {
	OrderID          int    `json:"order_id,omitempty"`
	CSR              string `json:"csr,omitempty"`
	Domains          string `json:"domains,omitempty"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
	OrderID    int    `json:"order_id"`
	Status     string `json:"status"` // success, failure
	DeployedAt string `json:"deployed_at"`
}

// UpdateResponse update 接口的 data 字段结构
// 服务端格式：{"order_id": ..., "status": ..., ..., "renew_before_days": 14}
type UpdateResponse struct {
	CertData
	RenewBeforeDays int `json:"renew_before_days"`
}

// CallbackResponse 回调响应
type CallbackResponse struct {
	Code            int    `json:"code"`
	Message         string `json:"msg"`
	RenewBeforeDays int    `json:"renew_before_days"`
}

// Fetcher 证书获取器
type Fetcher struct {
	client      *http.Client
	postTimeout time.Duration // POST 请求超时（默认 60s），GET 使用 client.Timeout（默认 30s）
	retryConfig RetryConfig
}

// New 创建新的 Fetcher
// - 强制 TLS >= 1.2
// - 连接池复用与 HTTP/2
// - 合理的连接/空闲超时
// - DNS Rebinding 防护：在 TCP 连接时二次校验目标 IP
func New(timeout time.Duration) *Fetcher {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         makeSSRFSafeDialContext(dialer),
		ForceAttemptHTTP2:   true,
	}
	return &Fetcher{
		client:      &http.Client{Timeout: timeout, Transport: transport},
		postTimeout: 60 * time.Second,
		retryConfig: DefaultRetryConfig,
	}
}

// makeSSRFSafeDialContext 创建带 SSRF 防护的 DialContext
// 在 TCP 连接时二次校验目标 IP，防止 DNS Rebinding 攻击
func makeSSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %w", addr, err)
		}

		// 检查是否为本地地址（允许 HTTP）
		isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if isLocal {
			return dialer.DialContext(ctx, network, addr)
		}

		// 手动解析 DNS 并校验每个 IP
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}

		// 筛选安全的 IP 并尝试连接
		var lastErr error
		for _, ip := range ips {
			if err := validateIPForSSRF(ip); err != nil {
				lastErr = err
				continue
			}

			// 使用已验证的 IP 直接连接，绕过 DNS 重新解析
			targetAddr := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}

		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no valid IP address found for %s", host)
	}
}

// validateIPForSSRF 校验 IP 是否安全（非内网、非回环、非云元数据）
func validateIPForSSRF(ip net.IP) error {
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address not allowed: %s", ip)
	}
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address not allowed: %s", ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("private IP not allowed: %s", ip)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local address not allowed: %s", ip)
	}
	if ip.String() == "169.254.169.254" {
		return fmt.Errorf("cloud metadata endpoint not allowed")
	}
	return nil
}

// NewWithRetry 创建带自定义重试配置的 Fetcher
func NewWithRetry(timeout time.Duration, retryConfig RetryConfig) *Fetcher {
	f := New(timeout)
	f.retryConfig = retryConfig
	return f
}

// defaultMaxResponseSize API 响应体最大大小（512KB 足够承载证书链）
const defaultMaxResponseSize = 512 * 1024

// batchMaxResponseSize 批量查询响应体最大大小（5MB，100 条证书约 500-800KB）
const batchMaxResponseSize = 5 * 1024 * 1024

// isRetryable 判断错误是否可重试
func isRetryable(err error, statusCode int) bool {
	// 网络错误可重试，但 SSRF 防护拒绝的请求除外
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not allowed") || strings.Contains(msg, "cloud metadata endpoint") {
			return false
		}
		return true
	}
	// 5xx 服务器错误可重试
	if statusCode >= 500 && statusCode < 600 {
		return true
	}
	// 429 Too Many Requests 可重试
	if statusCode == http.StatusTooManyRequests {
		return true
	}
	return false
}

// doWithRetry 带重试的 HTTP 请求
func (f *Fetcher) doWithRetry(ctx context.Context, newRequest func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= f.retryConfig.MaxRetries; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}

		// POST 请求使用更长超时（spec: GET 30s, POST 60s）
		if req.Method == http.MethodPost && f.postTimeout > 0 {
			if _, hasDeadline := req.Context().Deadline(); !hasDeadline {
				postCtx, cancel := context.WithTimeout(req.Context(), f.postTimeout)
				req = req.WithContext(postCtx)
				defer cancel()
			}
		}

		resp, err := f.client.Do(req)

		// 请求成功且不需要重试，返回响应（由调用者关闭 Body）
		if err == nil && !isRetryable(nil, resp.StatusCode) {
			return resp, nil
		}

		// 记录错误并确保关闭响应体
		var statusCode int
		if err != nil {
			// 网络错误：Go http.Client.Do 规范保证 err != nil 时 resp == nil
			lastErr = err
		} else {
			// HTTP 错误但需要重试（5xx、429 等）
			statusCode = resp.StatusCode
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close() // 必须关闭，防止连接泄漏
			if len(body) > 0 {
				lastErr = fmt.Errorf("HTTP %d: %s", statusCode, string(body))
			} else {
				lastErr = fmt.Errorf("HTTP %d", statusCode)
			}
		}

		// 最后一次尝试不等待
		if attempt == f.retryConfig.MaxRetries {
			break
		}

		// 检查是否可重试
		if !isRetryable(err, statusCode) {
			break
		}

		// 指数退避 + 抖动：InitialWait * Multiplier^attempt * (0.75~1.25)
		multiplier := f.retryConfig.Multiplier
		if multiplier < 1.0 {
			multiplier = 2.0
		}
		wait := float64(f.retryConfig.InitialWait)
		for i := 0; i < attempt; i++ {
			wait *= multiplier
		}
		// ±25% 随机抖动，防止多实例同时重试的惊群效应
		jitter := 0.75 + rand.Float64()*0.5 // [0.75, 1.25)
		sleepTime := time.Duration(wait * jitter)
		if sleepTime > f.retryConfig.MaxWait {
			sleepTime = f.retryConfig.MaxWait
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleepTime):
		}
	}

	return nil, lastErr
}

// doAPICallBatch 批量查询的 API 调用流程，返回证书列表、总数和 renewBeforeDays
func (f *Fetcher) doAPICallBatch(ctx context.Context, newRequest func() (*http.Request, error), errMsg string) ([]CertData, int, int, error) {
	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return nil, 0, 0, errors.NewNetworkError(errMsg, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, 0, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, batchMaxResponseSize))
	if err != nil {
		return nil, 0, 0, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, 0, 0, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, 0, 0, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParsePaginatedData()
}

// mustValidURL 校验 URL 是否有效。
// 仅 localhost/127.0.0.1 允许 HTTP，其他必须使用 HTTPS。
// 同时检查 SSRF 风险，阻止访问内网 IP 和云元数据地址。
// 委托给 validator.ValidateAPIURL 实现，避免代码重复。
func mustValidURL(apiURL string) error {
	return validator.ValidateAPIURL(apiURL)
}

// Callback 调用回调接口通知部署结果
// 返回：(renewBeforeDays, error)
func (f *Fetcher) Callback(ctx context.Context, callbackURL, token string, callbackReq *CallbackRequest) (int, error) {
	if err := mustValidURL(callbackURL); err != nil {
		return 0, errors.NewNetworkError("invalid callback URL", err)
	}
	bodyData, err := json.Marshal(callbackReq)
	if err != nil {
		return 0, errors.NewNetworkError("failed to marshal callback request", err)
	}

	newRequest := func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)
		return httpReq, nil
	}

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return 0, errors.NewNetworkError("failed to send callback", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, errors.NewNetworkError(fmt.Sprintf("callback returned unexpected status: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 64 * 1024 // 64KB 足够回调响应
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return 0, errors.NewNetworkError("failed to read callback response", err)
	}
	var callbackResp CallbackResponse
	if err := json.Unmarshal(body, &callbackResp); err != nil {
		return 0, errors.NewNetworkError("failed to parse callback response", err)
	}
	if callbackResp.Code != APICodeSuccess {
		return 0, errors.NewNetworkError(fmt.Sprintf("callback failed: %s", callbackResp.Message), nil)
	}
	return callbackResp.RenewBeforeDays, nil
}

// buildAPIURL 构建 API URL
// 如果 baseURL 已包含路径（如 /api/deploy），直接使用
// 如果只有 host，自动拼接 /api/deploy
func buildAPIURL(baseURL, path string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}
	// 如果已有路径，直接拼接
	if u.Path != "" && u.Path != "/" {
		return baseURL + path
	}
	// 否则使用默认的 /api/deploy 路径
	return baseURL + "/api/deploy" + path
}

// Query 查询证书（新 API：GET {baseURL}/api/deploy?order=xxx）
// API 返回分页格式，取第一条结果
// 返回: (certData, renewBeforeDays, error)
func (f *Fetcher) Query(ctx context.Context, baseURL, token, domain string) (*CertData, int, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	// 构建带 order 参数的 URL
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}
	q := u.Query()
	q.Set("order", domain)
	u.RawQuery = q.Encode()
	fullURL := u.String()

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	certs, _, renewBeforeDays, err := f.doAPICallBatch(ctx, newRequest, "failed to query certificate")
	if err != nil {
		return nil, 0, err
	}
	if len(certs) == 0 {
		return nil, 0, errors.NewNetworkError("no certificate found", nil)
	}
	return &certs[0], renewBeforeDays, nil
}

// Update 更新/续费证书（新 API：POST {baseURL}/api/deploy）
// 返回：(certData, renewBeforeDays, error)
func (f *Fetcher) Update(ctx context.Context, baseURL, token string, orderID int, csr, domains, method string) (*CertData, int, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	reqBody := UpdateRequest{
		OrderID:          orderID,
		CSR:              csr,
		Domains:          domains,
		ValidationMethod: method,
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, errors.NewNetworkError("failed to marshal request", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return nil, 0, errors.NewNetworkError("failed to update certificate", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseSize))
	if err != nil {
		return nil, 0, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, 0, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, 0, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	// update 响应 data 字段为单条，同层包含 renew_before_days
	var updateResp UpdateResponse
	if err := json.Unmarshal(apiResp.Data, &updateResp); err != nil {
		// 兼容旧格式（data 为数组）
		certData, parseErr := apiResp.ParseData()
		if parseErr != nil {
			return nil, 0, errors.NewNetworkError("failed to parse update response", err)
		}
		return certData, 0, nil
	}
	return &updateResp.CertData, updateResp.RenewBeforeDays, nil
}

// CallbackNew 调用新的回调接口（POST {baseURL}/api/deploy/callback）
// 返回：(renewBeforeDays, error)
func (f *Fetcher) CallbackNew(ctx context.Context, baseURL, token string, callbackReq *CallbackRequest) (int, error) {
	callbackURL := buildAPIURL(baseURL, "/callback")
	return f.Callback(ctx, callbackURL, token, callbackReq)
}

// QueryOrder 按 OrderID 查询订单状态
// GET {baseURL}/api/deploy?order=xxx
// API 返回分页格式，取第一条结果
// 返回: (certData, renewBeforeDays, error)
func (f *Fetcher) QueryOrder(ctx context.Context, baseURL, token string, orderID int) (*CertData, int, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	// 构建带 order 参数的 URL
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}
	q := u.Query()
	q.Set("order", fmt.Sprintf("%d", orderID))
	u.RawQuery = q.Encode()
	fullURL := u.String()

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	certs, _, renewBeforeDays, err := f.doAPICallBatch(ctx, newRequest, "failed to query order")
	if err != nil {
		return nil, 0, err
	}
	if len(certs) == 0 {
		return nil, 0, errors.NewNetworkError("order not found", nil)
	}
	return &certs[0], renewBeforeDays, nil
}

// ToggleAutoReissueRequest toggleAutoReissue 请求体
type ToggleAutoReissueRequest struct {
	OrderID     int  `json:"order_id"`
	AutoReissue bool `json:"auto_reissue"`
}

// ToggleAutoReissue 通知服务端是否自动续签
// POST {baseURL}/api/deploy/auto-reissue
// 此为非关键路径，调用失败返回 error 由调用方决定是否记录日志
func (f *Fetcher) ToggleAutoReissue(ctx context.Context, baseURL, token string, orderID int, autoReissue bool) error {
	apiURL := buildAPIURL(baseURL, "/auto-reissue")
	if err := mustValidURL(apiURL); err != nil {
		return errors.NewNetworkError("invalid API URL", err)
	}

	reqBody := ToggleAutoReissueRequest{
		OrderID:     orderID,
		AutoReissue: autoReissue,
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return errors.NewNetworkError("failed to marshal request", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return errors.NewNetworkError("failed to toggle auto reissue", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseSize))
	if err != nil {
		return errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return nil
}

// QueryBatch 批量查询证书
// query 非空时: GET {baseURL}/api/deploy?order={query}
// query 为空时: GET {baseURL}/api/deploy（返回最新 100 条 active 证书）
// 自动处理分页，返回全部结果
// 返回: (certs, renewBeforeDays, error)，renewBeforeDays 取最后一页的值
func (f *Fetcher) QueryBatch(ctx context.Context, baseURL, token, query string) ([]CertData, int, error) {
	// 规范 2.3：批量查询上限 100
	if query != "" {
		if parts := strings.Split(query, ","); len(parts) > 100 {
			return nil, 0, errors.NewNetworkError(
				fmt.Sprintf("批量查询超过上限: %d（最大 100）", len(parts)), nil)
		}
	}

	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, errors.NewNetworkError("invalid API URL", err)
	}

	const pageSize = 100
	var allCerts []CertData
	var lastRenewBeforeDays int

	for page := 1; ; page++ {
		q := u.Query()
		if query != "" {
			q.Set("order", query)
		}
		q.Set("page_size", fmt.Sprintf("%d", pageSize))
		q.Set("page", fmt.Sprintf("%d", page))
		u.RawQuery = q.Encode()
		fullURL := u.String()

		newRequest := func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			return req, nil
		}

		certs, total, renewBeforeDays, err := f.doAPICallBatch(ctx, newRequest, "failed to batch query")
		if err != nil {
			return nil, 0, err
		}

		allCerts = append(allCerts, certs...)
		if renewBeforeDays > 0 {
			lastRenewBeforeDays = renewBeforeDays
		}

		// 已获取全部或无更多页
		if len(allCerts) >= total || len(certs) == 0 {
			break
		}
	}

	return allCerts, lastRenewBeforeDays, nil
}
