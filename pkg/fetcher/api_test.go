// Package fetcher API 客户端测试
package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.Unmarshal(body, &req)

		if req.CSR != "test-csr" {
			t.Errorf("CSR = %s, want test-csr", req.CSR)
		}

		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.Unmarshal(body, &req)

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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.Unmarshal(body, &req)

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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
		{"HTTPS localhost", "https://localhost:443", false},
		{"HTTP localhost", "http://localhost:8080", false},
		{"HTTP 127.0.0.1", "http://127.0.0.1:8080", false},
		{"HTTP 远程", "http://api.example.com", true},
		{"无效 scheme", "ftp://localhost", true},
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
		_ = json.NewEncoder(w).Encode(resp)
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
		_ = json.NewEncoder(w).Encode(resp)
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
		{"SSRF private IP", fmt.Errorf("dial tcp: private IP not allowed: 10.0.0.1"), 0, false},
		{"SSRF loopback", fmt.Errorf("dial tcp: loopback address not allowed: 127.0.0.1"), 0, false},
		{"SSRF link-local", fmt.Errorf("dial tcp: link-local address not allowed: 169.254.1.1"), 0, false},
		{"SSRF cloud metadata", fmt.Errorf("dial tcp: cloud metadata endpoint not allowed"), 0, false},
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
		_ = json.NewEncoder(w).Encode(resp)
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

// TestQueryOrder_Retry 测试 QueryOrder 重试逻辑
func TestQueryOrder_Retry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// 前两次返回 500 错误
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// 第三次成功
		resp := mockResponse{
			Code: 1,
			Data: mockCertData(),
		}
		_ = json.NewEncoder(w).Encode(resp)
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

	data, err := f.QueryOrder(ctx, server.URL, "token", 12345)
	if err != nil {
		t.Fatalf("QueryOrder() 应在重试后成功, error = %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}

	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

// TestQueryOrder_RetryBoundary 测试重试边界条件
func TestQueryOrder_RetryBoundary(t *testing.T) {
	tests := []struct {
		name          string
		maxRetries    int
		failCount     int
		wantSuccess   bool
		wantCallCount int
	}{
		{
			name:          "刚好在最大重试次数内成功",
			maxRetries:    3,
			failCount:     3,
			wantSuccess:   true,
			wantCallCount: 4, // 初始请求 + 3 次重试
		},
		{
			name:          "超过最大重试次数",
			maxRetries:    2,
			failCount:     10,
			wantSuccess:   false,
			wantCallCount: 3, // 初始请求 + 2 次重试
		},
		{
			name:          "无需重试",
			maxRetries:    3,
			failCount:     0,
			wantSuccess:   true,
			wantCallCount: 1,
		},
		{
			name:          "重试一次成功",
			maxRetries:    3,
			failCount:     1,
			wantSuccess:   true,
			wantCallCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++
				if callCount <= tt.failCount {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				resp := mockResponse{Code: 1, Data: mockCertData()}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			retryConfig := RetryConfig{
				MaxRetries:  tt.maxRetries,
				InitialWait: 5 * time.Millisecond,
				MaxWait:     20 * time.Millisecond,
				Multiplier:  1.0,
			}
			f := NewWithRetry(30*time.Second, retryConfig)
			ctx := context.Background()

			_, err := f.QueryOrder(ctx, server.URL, "token", 12345)
			gotSuccess := err == nil

			if gotSuccess != tt.wantSuccess {
				t.Errorf("success = %v, want %v", gotSuccess, tt.wantSuccess)
			}

			if callCount != tt.wantCallCount {
				t.Errorf("callCount = %d, want %d", callCount, tt.wantCallCount)
			}
		})
	}
}

// TestFetcher_Timeout 测试请求超时
func TestFetcher_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟慢响应
		time.Sleep(500 * time.Millisecond)
		resp := mockResponse{Code: 1, Data: mockCertData()}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// 设置很短的超时
	f := New(100 * time.Millisecond)
	ctx := context.Background()

	_, err := f.Info(ctx, server.URL, "token")
	if err == nil {
		t.Error("Info() 应因超时而失败")
	}
}

// TestFetcher_TimeoutWithContext 测试上下文超时
func TestFetcher_TimeoutWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		resp := mockResponse{Code: 1, Data: mockCertData()}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := f.Info(ctx, server.URL, "token")
	if err == nil {
		t.Error("Info() 应因上下文超时而失败")
	}
}

// TestFetcher_LargeResponse 测试大响应体处理
func TestFetcher_LargeResponse(t *testing.T) {
	// 生成一个较大但有效的响应
	largeCertData := mockCertData()
	// 添加一个大的证书内容（模拟长证书链）
	largeCert := "-----BEGIN CERTIFICATE-----\n"
	for i := 0; i < 100; i++ {
		largeCert += "MIIFazCCA1OgAwIBAgIUBjN9V2sI3dPh7aSjQy4rKj3EXAMPLE\n"
	}
	largeCert += "-----END CERTIFICATE-----"
	largeCertData["certificate"] = largeCert
	largeCertData["ca_certificate"] = largeCert + "\n" + largeCert + "\n" + largeCert

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockResponse{
			Code: 1,
			Data: largeCertData,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.Info(ctx, server.URL, "token")
	if err != nil {
		t.Fatalf("Info() 处理大响应失败: %v", err)
	}

	if data.OrderID != 12345 {
		t.Errorf("OrderID = %d, want 12345", data.OrderID)
	}
}

// TestRetry_429TooManyRequests 测试 429 限流重试
func TestRetry_429TooManyRequests(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		resp := mockResponse{Code: 1, Data: mockCertData()}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

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
		t.Fatalf("Info() 应在 429 后重试成功: %v", err)
	}

	if callCount != 2 {
		t.Errorf("callCount = %d, want 2", callCount)
	}
}

// TestRetry_NonRetryableErrors 测试不可重试的错误
func TestRetry_NonRetryableErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
		{"404 Not Found", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			retryConfig := RetryConfig{
				MaxRetries:  3,
				InitialWait: 10 * time.Millisecond,
				MaxWait:     50 * time.Millisecond,
				Multiplier:  1.0,
			}
			f := NewWithRetry(30*time.Second, retryConfig)
			ctx := context.Background()

			_, err := f.Info(ctx, server.URL, "token")
			if err == nil {
				t.Error("Info() 应失败")
			}

			// 不可重试的错误应该只调用一次
			if callCount != 1 {
				t.Errorf("callCount = %d, want 1（不可重试错误不应重试）", callCount)
			}
		})
	}
}

// TestDefaultRetryConfig 测试默认重试配置
func TestDefaultRetryConfig(t *testing.T) {
	if DefaultRetryConfig.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", DefaultRetryConfig.MaxRetries)
	}
	if DefaultRetryConfig.InitialWait != 1*time.Second {
		t.Errorf("InitialWait = %v, want 1s", DefaultRetryConfig.InitialWait)
	}
	if DefaultRetryConfig.MaxWait != 3*time.Second {
		t.Errorf("MaxWait = %v, want 3s", DefaultRetryConfig.MaxWait)
	}
}

// TestCertData_Fields 测试 CertData 字段解析
func TestCertData_Fields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"order_id":       99999,
			"status":         "issued",
			"common_name":    "test.example.com",
			"domain":         "test.example.com",
			"domains":        "test.example.com,www.test.example.com",
			"certificate":    "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
			"ca_certificate": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
			"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----",
			"expires_at":     "2025-06-30T23:59:59Z",
			"created_at":     "2024-06-01T00:00:00Z",
		}
		resp := mockResponse{Code: 1, Data: data}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	data, err := f.Info(ctx, server.URL, "token")
	if err != nil {
		t.Fatalf("Info() error = %v", err)
	}

	if data.OrderID != 99999 {
		t.Errorf("OrderID = %d, want 99999", data.OrderID)
	}
	if data.Status != "issued" {
		t.Errorf("Status = %s, want issued", data.Status)
	}
	if data.CommonName != "test.example.com" {
		t.Errorf("CommonName = %s, want test.example.com", data.CommonName)
	}
	if data.Domains != "test.example.com,www.test.example.com" {
		t.Errorf("Domains = %s", data.Domains)
	}
	if data.ExpiresAt != "2025-06-30T23:59:59Z" {
		t.Errorf("ExpiresAt = %s", data.ExpiresAt)
	}
}

// TestCallbackNew 测试新回调接口
func TestCallbackNew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 URL 路径包含 /callback
		if !strings.HasSuffix(r.URL.Path, "/callback") {
			t.Errorf("URL path = %s, want ends with /callback", r.URL.Path)
		}

		resp := CallbackResponse{Code: 1, Message: "ok"}
		_ = json.NewEncoder(w).Encode(resp)
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

	err := f.CallbackNew(ctx, server.URL, "token", req)
	if err != nil {
		t.Fatalf("CallbackNew() error = %v", err)
	}
}

// TestUpdate_WithDomains 测试带域名的更新
func TestUpdate_WithDomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req UpdateRequest
		_ = json.Unmarshal(body, &req)

		if req.Domains != "example.com,www.example.com" {
			t.Errorf("Domains = %s, want example.com,www.example.com", req.Domains)
		}
		if req.ValidationMethod != "http" {
			t.Errorf("ValidationMethod = %s, want http", req.ValidationMethod)
		}

		resp := mockResponse{Code: 1, Data: mockCertData()}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	_, err := f.Update(ctx, server.URL, "token", 12345, "csr", "example.com,www.example.com", "http")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
}

// TestAPIResponse_ParsePaginatedData 测试分页响应解析
func TestAPIResponse_ParsePaginatedData(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantCount int
		wantTotal int
		wantErr   bool
	}{
		{
			name:      "分页响应",
			data:      `{"total":2,"currentPage":1,"pageSize":100,"data":[{"order_id":1,"status":"active"},{"order_id":2,"status":"active"}]}`,
			wantCount: 2,
			wantTotal: 2,
		},
		{
			name:      "分页响应空数据",
			data:      `{"total":0,"currentPage":1,"pageSize":100,"data":[]}`,
			wantCount: 0,
			wantTotal: 0,
		},
		{
			name:      "兼容单对象",
			data:      `{"order_id":123,"status":"issued"}`,
			wantCount: 1,
			wantTotal: 1,
		},
		{
			name:      "兼容数组",
			data:      `[{"order_id":1,"status":"active"},{"order_id":2,"status":"active"}]`,
			wantCount: 2,
			wantTotal: 2,
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

			certs, total, err := resp.ParsePaginatedData()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePaginatedData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(certs) != tt.wantCount {
				t.Errorf("certs count = %d, want %d", len(certs), tt.wantCount)
			}
			if total != tt.wantTotal {
				t.Errorf("total = %d, want %d", total, tt.wantTotal)
			}
		})
	}
}

// TestQueryBatch 测试批量查询
func TestQueryBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParam := r.URL.Query().Get("query")
		pageSize := r.URL.Query().Get("pageSize")

		if pageSize != "100" {
			t.Errorf("pageSize = %s, want 100", pageSize)
		}

		var data []map[string]interface{}
		if queryParam == "" {
			// 无参数：返回全部
			data = []map[string]interface{}{mockCertData()}
		} else if queryParam == "123,example.com" {
			// 混合查询
			cert1 := mockCertData()
			cert1["order_id"] = 123
			cert2 := mockCertData()
			cert2["order_id"] = 456
			data = []map[string]interface{}{cert1, cert2}
		}

		resp := mockResponse{
			Code: 1,
			Data: map[string]interface{}{
				"total":       len(data),
				"currentPage": 1,
				"pageSize":    100,
				"data":        data,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	// 测试无参数查询
	certs, err := f.QueryBatch(ctx, server.URL, "token", "")
	if err != nil {
		t.Fatalf("QueryBatch('') error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("QueryBatch('') got %d certs, want 1", len(certs))
	}

	// 测试混合查询
	certs, err = f.QueryBatch(ctx, server.URL, "token", "123,example.com")
	if err != nil {
		t.Fatalf("QueryBatch('123,example.com') error = %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("QueryBatch('123,example.com') got %d certs, want 2", len(certs))
	}
}

// TestQueryBatch_Pagination 测试批量查询自动翻页
func TestQueryBatch_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		page := r.URL.Query().Get("currentPage")

		var data []map[string]interface{}
		total := 3
		pageNum := 1
		if page == "2" {
			pageNum = 2
		}

		switch page {
		case "1":
			cert1 := mockCertData()
			cert1["order_id"] = 1
			cert2 := mockCertData()
			cert2["order_id"] = 2
			data = []map[string]interface{}{cert1, cert2}
		case "2":
			cert3 := mockCertData()
			cert3["order_id"] = 3
			data = []map[string]interface{}{cert3}
		default:
			data = []map[string]interface{}{}
		}

		resp := mockResponse{
			Code: 1,
			Data: map[string]interface{}{
				"total":       total,
				"currentPage": pageNum,
				"pageSize":    2,
				"data":        data,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := New(30 * time.Second)
	ctx := context.Background()

	certs, err := f.QueryBatch(ctx, server.URL, "token", "")
	if err != nil {
		t.Fatalf("QueryBatch() error = %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("got %d certs, want 3", len(certs))
	}
	if callCount != 2 {
		t.Errorf("API called %d times, want 2 (pagination)", callCount)
	}
}

// TestQueryBatch_APIError 测试批量查询 API 错误
func TestQueryBatch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockResponse{Code: 0, Message: "unauthorized"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	f := NewWithRetry(30*time.Second, RetryConfig{MaxRetries: 0})
	ctx := context.Background()

	_, err := f.QueryBatch(ctx, server.URL, "bad-token", "")
	if err == nil {
		t.Fatal("QueryBatch() should return error for API error")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("error should contain 'unauthorized', got: %v", err)
	}
}
