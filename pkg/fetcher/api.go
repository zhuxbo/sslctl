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

	"github.com/cnssl/cert-deploy/pkg/errors"
)

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据（不再包含私钥）
type CertData struct {
	Status           string         `json:"status"`
	CommonName       string         `json:"common_name"`
	Cert             string         `json:"cert"`
	IntermediateCert string         `json:"intermediate_cert"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

// APIResponse API 响应结构
type APIResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Data    CertData `json:"data"`
}

// PostRequest POST 参数
type PostRequest struct {
	CSR              string `json:"csr"`
	CommonName       string `json:"common_name"`
	ValidationMethod string `json:"validation_method,omitempty"`
}

// Fetcher 证书获取器
type Fetcher struct {
	client *http.Client
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
		client: &http.Client{Timeout: timeout, Transport: transport},
	}
}

// mustHTTPS 校验 URL 必须为 HTTPS，且 host 合法。
func mustHTTPS(apiURL string) error {
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("API URL must use HTTPS, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("API URL must have a valid host")
	}
	return nil
}

// Info 调用 GET 获取证书信息
func (f *Fetcher) Info(ctx context.Context, apiURL, referID string) (*CertData, error) {
	if err := mustHTTPS(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, errors.NewNetworkError("failed to create request", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+referID)

	resp, err := f.client.Do(req)
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
	if apiResp.Code != 1 {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return &apiResp.Data, nil
}

// StartOrUpdate 调用 POST 提交 CSR 发起/更新签发
func (f *Fetcher) StartOrUpdate(ctx context.Context, apiURL, referID, csrPEM, commonName, validationMethod string) (*CertData, error) {
	if err := mustHTTPS(apiURL); err != nil {
		return nil, errors.NewNetworkError("invalid API URL", err)
	}
	reqBody := PostRequest{CSR: csrPEM, CommonName: commonName}
	if validationMethod != "" {
		reqBody.ValidationMethod = validationMethod
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.NewNetworkError("failed to marshal request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyData))
	if err != nil {
		return nil, errors.NewNetworkError("failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+referID)

	resp, err := f.client.Do(req)
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
	if apiResp.Code != 1 {
		return nil, errors.NewNetworkError(fmt.Sprintf("API error: %s", apiResp.Message), nil)
	}
	return &apiResp.Data, nil
}
