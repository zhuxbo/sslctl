// Package fetcher 负责从 API 获取证书
package fetcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/errors"
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

// DefaultRetryConfig 默认重试配置（线性退避：1s, 2s, 3s）
var DefaultRetryConfig = RetryConfig{
	MaxRetries:  3,
	InitialWait: 1 * time.Second,
	MaxWait:     3 * time.Second,
	Multiplier:  1.0,
}

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据
type CertData struct {
	OrderID          int            `json:"order_id"`
	Status           string         `json:"status"`
	CommonName       string         `json:"common_name"`
	Domain           string         `json:"domain"`
	Domains          string         `json:"domains"`
	Cert             string         `json:"certificate"`
	IntermediateCert string         `json:"ca_certificate"`
	PrivateKey       string         `json:"private_key"`
	ExpiresAt        string         `json:"expires_at"`
	CreatedAt        string         `json:"created_at"`
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

// PostRequest POST 参数（兼容旧接口）
type PostRequest struct {
	CSR              string `json:"csr"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// UpdateRequest 更新/续费证书请求（新 API）
type UpdateRequest struct {
	OrderID          int    `json:"order_id,omitempty"`
	CSR              string `json:"csr,omitempty"`
	Domains          string `json:"domains,omitempty"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
	OrderID       int    `json:"order_id"`
	Domain        string `json:"domain"`
	Status        string `json:"status"` // success, failure
	DeployedAt    string `json:"deployed_at"`
	CertExpiresAt string `json:"cert_expires_at,omitempty"`
	CertSerial    string `json:"cert_serial,omitempty"`
	ServerType    string `json:"server_type,omitempty"` // nginx, apache
	Message       string `json:"message,omitempty"`
}

// CallbackResponse 回调响应
type CallbackResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

// Fetcher 证书获取器
type Fetcher struct {
	client      *http.Client
	retryConfig RetryConfig
}

// New 创建新的 Fetcher
// - 强制 TLS >= 1.2
// - 连接池复用与 HTTP/2
// - 合理的连接/空闲超时
func New(timeout time.Duration) *Fetcher {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}
	return &Fetcher{
		client:      &http.Client{Timeout: timeout, Transport: transport},
		retryConfig: DefaultRetryConfig,
	}
}

// NewWithRetry 创建带自定义重试配置的 Fetcher
func NewWithRetry(timeout time.Duration, retryConfig RetryConfig) *Fetcher {
	f := New(timeout)
	f.retryConfig = retryConfig
	return f
}

// isRetryable 判断错误是否可重试
func isRetryable(err error, statusCode int) bool {
	// 网络错误可重试
	if err != nil {
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

		resp, err := f.client.Do(req)
		if err == nil && !isRetryable(nil, resp.StatusCode) {
			return resp, nil
		}

		// 记录错误
		if err != nil {
			lastErr = err
			// 当 err != nil 但 resp != nil 时，关闭响应体防止连接泄漏
			if resp != nil {
				resp.Body.Close()
			}
		} else {
			// 尝试读取错误详情
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if len(body) > 0 {
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			} else {
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}

		// 最后一次尝试不等待
		if attempt == f.retryConfig.MaxRetries {
			break
		}

		// 检查是否可重试
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		if !isRetryable(err, statusCode) {
			break
		}

		// 线性退避：1s, 2s, 3s（attempt 从 0 开始）
		sleepTime := f.retryConfig.InitialWait + time.Duration(attempt)*time.Second
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

// mustValidURL 校验 URL 是否有效。
// 仅 localhost/127.0.0.1 允许 HTTP，其他必须使用 HTTPS。
func mustValidURL(apiURL string) error {
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("API URL must use HTTP or HTTPS, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("API URL must have a valid host")
	}

	// HTTP 仅允许 localhost
	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme == "http" && !isLocal {
		return fmt.Errorf("HTTP only allowed for localhost, use HTTPS for remote servers")
	}
	return nil
}

// Info 调用 GET 获取证书信息（兼容旧接口）
// 自动处理 URL 路径：如果 apiURL 只有 host，会自动添加 /api/deploy
func (f *Fetcher) Info(ctx context.Context, apiURL, token string) (*CertData, error) {
	fullURL := buildAPIURL(apiURL, "")
	if err := mustValidURL(fullURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	}

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return nil, errors.NewNetworkError("failed to get certificate info", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	// 限制响应体大小，防止不合理的大包造成内存压力
	const maxResponseSize = 512 * 1024 // 512KB 足够承载证书链
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParseData()
}

// StartOrUpdate 调用 POST 提交 CSR 发起/更新签发（兼容旧接口）
// 自动处理 URL 路径：如果 apiURL 只有 host，会自动添加 /api/deploy
func (f *Fetcher) StartOrUpdate(ctx context.Context, apiURL, token, csrPEM, validationMethod string) (*CertData, error) {
	fullURL := buildAPIURL(apiURL, "")
	if err := mustValidURL(fullURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}
	reqBody := PostRequest{CSR: csrPEM}
	if validationMethod != "" {
		reqBody.ValidationMethod = validationMethod
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.NewNetworkError("failed to marshal request", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(bodyData))
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
		return nil, errors.NewNetworkError("failed to post CSR", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParseData()
}

// Callback 调用回调接口通知部署结果
func (f *Fetcher) Callback(ctx context.Context, callbackURL, token string, callbackReq *CallbackRequest) error {
	if err := mustValidURL(callbackURL); err != nil {
		return errors.NewNetworkError("invalid callback URL", err)
	}
	bodyData, err := json.Marshal(callbackReq)
	if err != nil {
		return errors.NewNetworkError("failed to marshal callback request", err)
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
		return errors.NewNetworkError("failed to send callback", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.NewNetworkError(fmt.Sprintf("callback returned unexpected status: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 64 * 1024 // 64KB 足够回调响应
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return errors.NewNetworkError("failed to read callback response", err)
	}
	var callbackResp CallbackResponse
	if err := json.Unmarshal(body, &callbackResp); err != nil {
		return errors.NewNetworkError("failed to parse callback response", err)
	}
	if callbackResp.Code != APICodeSuccess {
		return errors.NewNetworkError(fmt.Sprintf("callback failed: %s", callbackResp.Message), nil)
	}
	return nil
}

// buildAPIURL 构建 API URL（支持新旧格式）
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

// Query 查询证书（新 API：GET {baseURL}/api/deploy?domain=xxx）
func (f *Fetcher) Query(ctx context.Context, baseURL, token, domain string) (*CertData, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}

	// 构建带 domain 参数的 URL
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}
	q := u.Query()
	q.Set("domain", domain)
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

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return nil, errors.NewNetworkError("failed to query certificate", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParseData()
}

// Update 更新/续费证书（新 API：POST {baseURL}/api/deploy）
func (f *Fetcher) Update(ctx context.Context, baseURL, token string, orderID int, csr, domains, method string) (*CertData, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}

	reqBody := UpdateRequest{
		OrderID:          orderID,
		CSR:              csr,
		Domains:          domains,
		ValidationMethod: method,
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.NewNetworkError("failed to marshal request", err)
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
		return nil, errors.NewNetworkError("failed to update certificate", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParseData()
}

// CallbackNew 调用新的回调接口（POST {baseURL}/api/deploy/callback）
func (f *Fetcher) CallbackNew(ctx context.Context, baseURL, token string, callbackReq *CallbackRequest) error {
	callbackURL := buildAPIURL(baseURL, "/callback")
	return f.Callback(ctx, callbackURL, token, callbackReq)
}

// QueryOrder 按 OrderID 查询订单状态
// GET {baseURL}/api/deploy?order_id=xxx
func (f *Fetcher) QueryOrder(ctx context.Context, baseURL, token string, orderID int) (*CertData, error) {
	apiURL := buildAPIURL(baseURL, "")
	if err := mustValidURL(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}

	// 构建带 order_id 参数的 URL
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}
	q := u.Query()
	q.Set("order_id", fmt.Sprintf("%d", orderID))
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

	resp, err := f.doWithRetry(ctx, newRequest)
	if err != nil {
		return nil, errors.NewNetworkError("failed to query order", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewNetworkError(fmt.Sprintf("unexpected status code: %d", resp.StatusCode), nil)
	}
	const maxResponseSize = 512 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, errors.NewNetworkError("failed to read response body", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, errors.NewNetworkError("failed to parse JSON response", err)
	}
	if apiResp.Code != APICodeSuccess {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return apiResp.ParseData()
}
