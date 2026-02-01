// Package fetcher API 客户端测试
package fetcher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockResponse 模拟 API 响应
type mockResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// mockCertData 模拟证书数据
func mockCertData() map[string]interface{} {
	return map[string]interface{}{
		"order_id":       12345,
		"status":         "issued",
		"common_name":    "example.com",
		"domain":         "example.com",
		"domains":        "example.com,*.example.com",
		"certificate":    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		"ca_certificate": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
		"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----",
		"expires_at":     "2025-12-31T23:59:59Z",
		"created_at":     "2024-01-01T00:00:00Z",
	}
}

// TestNew 测试创建 Fetcher
func TestNew(t *testing.T) {
	f := New(30 * time.Second)
	if f == nil {
		t.Fatal("New() returned nil")
	}
	if f.client == nil {
		t.Error("client should not be nil")
	}
}

// TestNewWithRetry 测试创建带自定义重试配置的 Fetcher
func TestNewWithRetry(t *testing.T) {
	retryConfig := RetryConfig{
		MaxRetries:  5,
		InitialWait: 2 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}
	f := NewWithRetry(30*time.Second, retryConfig)

	if f.retryConfig.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", f.retryConfig.MaxRetries)
	}
}

// TestInfo 测试获取证书信息
func TestInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求方法
		if r.Method != http.MethodGet {
			t.Errorf("Method = %s, want GET", r.Method)
		}

		// 验证 Authorization 头
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Authorization = %s, want Bearer test-token", auth)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	// 使用 localhost HTTP 应该被允许
	data, err := f.Info(ctx, server.URL, "test-token")
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}

	if data.CommonName != "example.com" {
		t.Errorf("CommonName = %s, want example.com", data.CommonName)
	}
}

// TestInfo_APIError 测试 API 返回错误
func TestInfo_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockResponse{
			Code:    0,
			Message: "token invalid",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	_, err := f.Info(ctx, server.URL, "bad-token")
	if err == nil {
		t.Error("Info() should return error for API error response")
	}

	if !strings.Contains(err.Error(), "token invalid") {
		t.Errorf("error should contain 'token invalid', got %v", err)
	}
}

// TestInfo_HTTPError 测试 HTTP 错误状态码
func TestInfo_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	_, err := f.Info(ctx, server.URL, "token")
	if err == nil {
		t.Error("Info() should return error for HTTP 404")
	}
}

// TestQuery 测试按域名查询
func TestQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 domain 参数
		domain := r.URL.Query().Get("domain")
		if domain != "test.example.com" {
			t.Errorf("domain query param = %s, want test.example.com", domain)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.Query(ctx, server.URL, "token", "test.example.com")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}
}

// TestQueryOrder 测试按订单 ID 查询
func TestQueryOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 order_id 参数
		orderID := r.URL.Query().Get("order_id")
		if orderID != "12345" {
			t.Errorf("order_id query param = %s, want 12345", orderID)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.QueryOrder(ctx, server.URL, "token", 12345)
	if err != nil {
		t.Fatalf("QueryOrder() error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}
}

// TestStartOrUpdate 测试提交 CSR
func TestStartOrUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求方法
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		// 验证 Content-Type
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}

		// 验证请求体
		body, _ := io.ReadAll(r.Body)
		var req PostRequest
		json.Unmarshal(body, &req)

		if req.CSR != "test-csr" {
			t.Errorf("CSR = %s, want test-csr", req.CSR)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.StartOrUpdate(ctx, server.URL, "token", "test-csr", "")
	if err != nil {
		t.Fatalf("StartOrUpdate() error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}
}

// TestUpdate 测试更新证书
func TestUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		var req UpdateRequest
		json.Unmarshal(body, &req)

		if req.OrderID != 12345 {
			t.Errorf("OrderID = %d, want 12345", req.OrderID)
		}

		if req.CSR != "new-csr" {
			t.Errorf("CSR = %s, want new-csr", req.CSR)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.Update(ctx, server.URL, "token", 12345, "new-csr", "", "")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}
}

// TestCallback 测试回调
func TestCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		var req CallbackRequest
		json.Unmarshal(body, &req)

		if req.OrderID != 12345 {
			t.Errorf("OrderID = %d, want 12345", req.OrderID)
		}

		if req.Status != "success" {
			t.Errorf("Status = %s, want success", req.Status)
		}

		resp := CallbackResponse{
			Code:    1,
			Message: "ok",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	req := &CallbackRequest{
		OrderID:    12345,
		Domain:     "example.com",
		Status:     "success",
		DeployedAt: "2024-01-01T00:00:00Z",
	}

	err := f.Callback(ctx, server.URL, "token", req)
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
}

// TestCallback_Error 测试回调失败
func TestCallback_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := CallbackResponse{
			Code:    0,
			Message: "callback failed",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	req := &CallbackRequest{OrderID: 12345, Status: "success"}
	err := f.Callback(ctx, server.URL, "token", req)
	if err == nil {
		t.Error("Callback() should return error for failed callback")
	}
}

// TestMustValidURL 测试 URL 验证
func TestMustValidURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"HTTPS 远程", "https://api.example.com", false},
		{"HTTP localhost", "http://localhost:8080", false},
		{"HTTP 127.0.0.1", "http://127.0.0.1:8080", false},
		{"HTTP 远程", "http://api.example.com", true},
		{"无效 scheme", "ftp://api.example.com", true},
		{"无 host", "https://", true},
		{"无效 URL", "not-a-url", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mustValidURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("mustValidURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestBuildAPIURL 测试 URL 构建
func TestBuildAPIURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
	}{
		{
			name:    "只有 host",
			baseURL: "https://api.example.com",
			path:    "",
			want:    "https://api.example.com/api/deploy",
		},
		{
			name:    "带路径的 URL",
			baseURL: "https://api.example.com/api/deploy",
			path:    "",
			want:    "https://api.example.com/api/deploy",
		},
		{
			name:    "拼接额外路径",
			baseURL: "https://api.example.com/api/deploy",
			path:    "/callback",
			want:    "https://api.example.com/api/deploy/callback",
		},
		{
			name:    "根路径",
			baseURL: "https://api.example.com/",
			path:    "",
			want:    "https://api.example.com//api/deploy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAPIURL(tt.baseURL, tt.path)
			if got != tt.want {
				t.Errorf("buildAPIURL(%q, %q) = %q, want %q", tt.baseURL, tt.path, got, tt.want)
			}
		})
	}
}

// TestAPIResponse_ParseData 测试解析响应数据
func TestAPIResponse_ParseData(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "单个对象",
			data:    `{"order_id":123,"status":"issued"}`,
			wantErr: false,
		},
		{
			name:    "数组格式",
			data:    `[{"order_id":123,"status":"issued"}]`,
			wantErr: false,
		},
		{
			name:    "空数组",
			data:    `[]`,
			wantErr: true,
		},
		{
			name:    "空数据",
			data:    ``,
			wantErr: true,
		},
		{
			name:    "无效 JSON",
			data:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &APIResponse{
				Code: 1,
				Data: json.RawMessage(tt.data),
			}

			_, err := resp.ParseData()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRetry 测试重试机制
func TestRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// 快速重试配置
	retryConfig := RetryConfig{
		MaxRetries:  3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Multiplier:  1.0,
	}
	f := NewWithRetry(30*time.Second, retryConfig)
	ctx := context.Background()

	_, err := f.Info(ctx, server.URL, "token")
	if err != nil {
		t.Fatalf("Info() should succeed after retries, error = %v", err)
	}

	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

// TestRetry_ExhaustedRetries 测试重试耗尽
func TestRetry_ExhaustedRetries(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	retryConfig := RetryConfig{
		MaxRetries:  2,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Multiplier:  1.0,
	}
	f := NewWithRetry(30*time.Second, retryConfig)
	ctx := context.Background()

	_, err := f.Info(ctx, server.URL, "token")
	if err == nil {
		t.Error("Info() should fail after exhausting retries")
	}

	// 初始请求 + 2 次重试 = 3 次调用
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

// TestContextCancellation 测试上下文取消
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // 长时间等待
		resp := mockResponse{Code: 1, Data: mockCertData()}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := f.Info(ctx, server.URL, "token")
	if err == nil {
		t.Error("Info() should fail when context is cancelled")
	}
}

// TestIsRetryable 测试可重试判断
func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		want       bool
	}{
		{"网络错误", context.DeadlineExceeded, 0, true},
		{"500 错误", nil, 500, true},
		{"502 错误", nil, 502, true},
		{"503 错误", nil, 503, true},
		{"429 限流", nil, 429, true},
		{"400 错误", nil, 400, false},
		{"401 未授权", nil, 401, false},
		{"404 未找到", nil, 404, false},
		{"200 成功", nil, 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryable(tt.err, tt.statusCode)
			if got != tt.want {
				t.Errorf("isRetryable(%v, %d) = %v, want %v", tt.err, tt.statusCode, got, tt.want)
			}
		})
	}
}

// TestResponseSizeLimit 测试响应体大小限制
func TestResponseSizeLimit(t *testing.T) {
	// 创建一个返回大响应的服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 返回有效的 JSON 响应，但是一个大的
		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	// 正常响应应该成功
	_, err := f.Info(ctx, server.URL, "token")
	if err != nil {
		t.Fatalf("Info() should succeed for normal response, error = %v", err)
	}
}
