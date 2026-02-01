// Package testutil 测试辅助工具
package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockAPIResponse 模拟 API 响应结构
type MockAPIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// MockCertData 模拟证书数据
type MockCertData struct {
	OrderID          int    `json:"order_id"`
	Status           string `json:"status"`
	CommonName       string `json:"common_name"`
	Domain           string `json:"domain"`
	Domains          string `json:"domains"`
	Cert             string `json:"certificate"`
	IntermediateCert string `json:"ca_certificate"`
	PrivateKey       string `json:"private_key"`
	ExpiresAt        string `json:"expires_at"`
	CreatedAt        string `json:"created_at"`
}

// NewMockAPIServer 创建 Mock API 服务器
func NewMockAPIServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// NewMockTLSServer 创建 Mock HTTPS 服务器
func NewMockTLSServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

// SuccessHandler 返回成功响应的处理器
func SuccessHandler(data interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := MockAPIResponse{
			Code:    1,
			Message: "success",
			Data:    data,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ErrorHandler 返回错误响应的处理器
func ErrorHandler(code int, message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := MockAPIResponse{
			Code:    code,
			Message: message,
			Data:    nil,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// StatusHandler 返回指定 HTTP 状态码的处理器
func StatusHandler(statusCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
	}
}

// TimeoutHandler 模拟超时的处理器（不响应）
func TimeoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 阻塞，等待客户端超时
		select {}
	}
}

// RequestRecorder 记录请求的处理器包装
type RequestRecorder struct {
	Requests []*http.Request
	Handler  http.HandlerFunc
}

// NewRequestRecorder 创建请求记录器
func NewRequestRecorder(handler http.HandlerFunc) *RequestRecorder {
	return &RequestRecorder{
		Requests: make([]*http.Request, 0),
		Handler:  handler,
	}
}

// ServeHTTP 实现 http.Handler 接口
func (r *RequestRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Requests = append(r.Requests, req)
	if r.Handler != nil {
		r.Handler(w, req)
	}
}

// DefaultMockCertData 默认测试证书数据
var DefaultMockCertData = MockCertData{
	OrderID:          12345,
	Status:           "issued",
	CommonName:       "example.com",
	Domain:           "example.com",
	Domains:          "example.com,*.example.com",
	Cert:             "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpA...\n-----END CERTIFICATE-----",
	IntermediateCert: "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpB...\n-----END CERTIFICATE-----",
	PrivateKey:       "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----",
	ExpiresAt:        "2025-12-31T23:59:59Z",
	CreatedAt:        "2024-01-01T00:00:00Z",
}

// RetryCountHandler 返回一个计数重试次数的处理器
// 前 failCount 次返回 500，之后返回成功
func RetryCountHandler(failCount int, successData interface{}) http.HandlerFunc {
	count := 0
	return func(w http.ResponseWriter, r *http.Request) {
		count++
		if count <= failCount {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		SuccessHandler(successData)(w, r)
	}
}

// AuthCheckHandler 验证 Authorization 头的处理器
func AuthCheckHandler(expectedToken string, successData interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + expectedToken
		if auth != expected {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(MockAPIResponse{Code: 0, Message: "unauthorized"})
			return
		}
		SuccessHandler(successData)(w, r)
	}
}
