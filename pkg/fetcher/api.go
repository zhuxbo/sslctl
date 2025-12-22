// Package fetcher 负责从 API 获取证书
package fetcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cnssl/cert-deploy/pkg/errors"
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

// DefaultRetryConfig 默认重试配置
var DefaultRetryConfig = RetryConfig{
	MaxRetries:  3,
	InitialWait: 1 * time.Second,
	MaxWait:     30 * time.Second,
	Multiplier:  2.0,
}

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据
type CertData struct {
	Status           string         `json:"status"`
	CommonName       string         `json:"common_name"`
	Cert             string         `json:"cert"`
	IntermediateCert string         `json:"intermediate_cert"`
	PrivateKey       string         `json:"private_key"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

// APIResponse API 响应结构
type APIResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"msg"` // API 使用 msg 字段
	Data    CertData `json:"data"`
}

// PostRequest POST 参数
type PostRequest struct {
	CSR              string `json:"csr"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
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
	wait := f.retryConfig.InitialWait

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
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
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

		// 指数退避 + 随机抖动
		jitter := time.Duration(rand.Int63n(int64(wait / 2)))
		sleepTime := wait + jitter
		if sleepTime > f.retryConfig.MaxWait {
			sleepTime = f.retryConfig.MaxWait
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleepTime):
		}

		wait = time.Duration(float64(wait) * f.retryConfig.Multiplier)
	}

	return nil, lastErr
}

// mustValidURL 校验 URL 是否有效。
// 生产环境应使用 HTTPS，HTTP 仅用于本地测试。
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
	return nil
}

// Info 调用 GET 获取证书信息
func (f *Fetcher) Info(ctx context.Context, apiURL, referID string) (*CertData, error) {
	if err := mustValidURL(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}

	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+referID)
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
	return &apiResp.Data, nil
}

// StartOrUpdate 调用 POST 提交 CSR 发起/更新签发
func (f *Fetcher) StartOrUpdate(ctx context.Context, apiURL, referID, csrPEM, validationMethod string) (*CertData, error) {
	if err := mustValidURL(apiURL); err != nil {
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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+referID)
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
	return &apiResp.Data, nil
}

// Callback 调用回调接口通知部署结果
func (f *Fetcher) Callback(ctx context.Context, callbackURL, referID string, callbackReq *CallbackRequest) error {
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
		httpReq.Header.Set("Authorization", "Bearer "+referID)
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
