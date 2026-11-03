// Package certops 补充测试
package certops

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestFillCertMetadata 测试 fillCertMetadata 不 panic
func TestFillCertMetadata(t *testing.T) {
	req := &fetcher.CallbackRequest{
		OrderID: 123,
		Status:  "success",
	}
	cert := &config.CertConfig{
		CertName: "test-cert",
		OrderID:  123,
	}

	// fillCertMetadata 当前是空函数（预留扩展），调用不应 panic
	fillCertMetadata(req, cert)

	// 验证 req 和 cert 未被意外修改
	if req.OrderID != 123 {
		t.Errorf("OrderID 不应被修改: %d", req.OrderID)
	}
	if cert.CertName != "test-cert" {
		t.Errorf("CertName 不应被修改: %s", cert.CertName)
	}
}

// TestFillCertMetadata_NilFields 测试空字段不 panic
func TestFillCertMetadata_NilFields(t *testing.T) {
	req := &fetcher.CallbackRequest{}
	cert := &config.CertConfig{}

	// 不应 panic
	fillCertMetadata(req, cert)
}

// TestSendCallback_EmptyAPI 测试空 API 配置时返回 0
func TestSendCallback_EmptyAPI(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	tests := []struct {
		name string
		api  config.APIConfig
	}{
		{"URL 为空", config.APIConfig{URL: "", Token: "test-token"}},
		{"Token 为空", config.APIConfig{URL: "http://example.com", Token: ""}},
		{"都为空", config.APIConfig{URL: "", Token: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &fetcher.CallbackRequest{
				OrderID: 123,
				Status:  "success",
			}
			result := svc.sendCallback(t.Context(), tt.api, req)
			if result != 0 {
				t.Errorf("空 API 配置应返回 0，实际: %d", result)
			}
		})
	}
}

// TestRetryFailedBindings_CapParksToStale 重试触顶停车：不消耗证书级配额、不 CAP 整张证书，
// 未发生部署的出口静默停车（deploy-spec §2.8:297 触顶路径不发送任何回调）。
func TestRetryFailedBindings_CapParksToStale(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	staleSince := time.Now().Add(-8 * 24 * time.Hour)
	cert := &config.CertConfig{
		CertName: "capped-retry-cert",
		OrderID:  123,
		Enabled:  true,
		API:      config.APIConfig{URL: "http://127.0.0.1:1", Token: "test-token"},
		Metadata: config.CertMetadata{
			FailedBindings:   []string{"site1.com"},
			FailedBindingsAt: staleSince,
			// 本轮入口递增后恰好达到上限
			RetryAttemptCount:  MaxRetryAttemptCount - 1,
			DeployAttemptCount: 3, // 证书级配额基线，重试路径全程不得触碰
		},
		Bindings: []config.SiteBinding{{ServerName: "site1.com", ServerType: config.ServerTypeNginx, Enabled: true}},
	}
	_ = cm.AddCert(cert)

	svc := NewService(cm, logger.NewNopLogger())
	// 保留默认重试次数；此处验证失败状态，不等待生产环境的秒级退避。
	retry := fetcher.DefaultRetryConfig
	retry.InitialWait = time.Millisecond
	retry.MaxWait = 4 * time.Millisecond
	svc.fetcher = fetcher.NewWithRetry(retry)
	certCopy, _ := cm.GetCert("capped-retry-cert")

	result := svc.retryFailedBindings(t.Context(), certCopy, cert.API)

	// API 不可达属"未发生部署"：触顶时静默停车，不上报回调
	if result != nil {
		t.Fatalf("触顶且未发生部署时应静默停车（返回 nil），实际: %+v", result)
	}

	updated, _ := cm.GetCert("capped-retry-cert")
	if len(updated.Metadata.FailedBindings) != 0 {
		t.Errorf("停车后 FailedBindings 应被清空，实际: %v", updated.Metadata.FailedBindings)
	}
	if !updated.Metadata.FailedBindingsAt.IsZero() {
		t.Errorf("停车后 FailedBindingsAt 应被清零，实际: %v", updated.Metadata.FailedBindingsAt)
	}
	if updated.Metadata.RetryAttemptCount != 0 {
		t.Errorf("停车后重试计数应复位，实际: %d", updated.Metadata.RetryAttemptCount)
	}
	// 关键不变式：绑定级重试绝不能消耗证书级部署配额，
	// 否则一个坏站点或一次 API 宕机就会把整张证书打进 CAPPED、健康站点跟着过期
	if updated.Metadata.DeployAttemptCount != 3 {
		t.Errorf("重试路径不得触碰证书级 DeployAttemptCount，实际: %d", updated.Metadata.DeployAttemptCount)
	}
	if updated.Metadata.LastIssueState != "" {
		t.Errorf("重试触顶不得把整张证书打进终止态，实际: %q", updated.Metadata.LastIssueState)
	}
	if len(updated.Metadata.StaleBindings) != 1 || updated.Metadata.StaleBindings[0] != "site1.com" {
		t.Errorf("停车后绑定应转入 StaleBindings，实际: %v", updated.Metadata.StaleBindings)
	}
	if updated.Metadata.StaleSince.Sub(staleSince) > time.Second || staleSince.Sub(updated.Metadata.StaleSince) > time.Second {
		t.Errorf("StaleSince 应取首次失败时间，实际: %v", updated.Metadata.StaleSince)
	}
}

// TestRetryFailedBindings_APIFail 测试 API 失败分支
func TestRetryFailedBindings_APIFail(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "api-fail-cert",
		OrderID:  456,
		Enabled:  true,
		API:      config.APIConfig{URL: "http://127.0.0.1:1", Token: "test-token"},
		Metadata: config.CertMetadata{
			FailedBindings:   []string{"site1.com"},
			FailedBindingsAt: time.Now().Add(-1 * time.Hour), // 1 小时前
		},
		// 失败绑定必须仍在启用绑定中，否则被前置预检判为幽灵条目直接清理
		Bindings: []config.SiteBinding{{ServerName: "site1.com", ServerType: config.ServerTypeNginx, Enabled: true}},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)
	// 保留默认重试次数；此处验证失败状态，不等待生产环境的秒级退避。
	retry := fetcher.DefaultRetryConfig
	retry.InitialWait = time.Millisecond
	retry.MaxWait = 4 * time.Millisecond
	svc.fetcher = fetcher.NewWithRetry(retry)

	certCopy, _ := cm.GetCert("api-fail-cert")

	// 使用不可达的 API 地址
	result := svc.retryFailedBindings(t.Context(), certCopy, config.APIConfig{
		URL:   "http://127.0.0.1:1",
		Token: "test-token",
	})

	if result == nil {
		t.Fatal("结果不应为 nil")
	}
	if result.Status != "failure" {
		t.Errorf("API 失败应返回 failure，实际: %s", result.Status)
	}
	if result.Error == nil {
		t.Error("API 失败应返回错误")
	}
}

// TestTryUpdateRenewBeforeDays_Zero 测试 renewBeforeDays <= 0 时跳过
func TestTryUpdateRenewBeforeDays_Zero(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 写入初始配置
	writeTestConfig(t, dir, &config.Config{
		Schedule: config.ScheduleConfig{RenewBeforeDays: 14},
	})

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	// renewBeforeDays = 0 应跳过
	svc.tryUpdateRenewBeforeDays(0)

	// 验证未被修改
	cfg, _ := cm.Load()
	if cfg.Schedule.RenewBeforeDays != 14 {
		t.Errorf("renewBeforeDays 不应被修改: %d", cfg.Schedule.RenewBeforeDays)
	}

	// renewBeforeDays = -1 也应跳过
	svc.tryUpdateRenewBeforeDays(-1)
	cfg, _ = cm.Load()
	if cfg.Schedule.RenewBeforeDays != 14 {
		t.Errorf("renewBeforeDays 不应被修改: %d", cfg.Schedule.RenewBeforeDays)
	}
}

// newMockAPIServer 创建一个返回指定证书数据的 mock API 服务器
// 响应格式与 fetcher.QueryOrder 期望的一致
func newMockAPIServer(t *testing.T, certData map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/callback") {
			// 回调请求返回成功
			_, _ = w.Write([]byte(`{"code":1,"msg":"ok"}`))
			return
		}

		// QueryOrder 请求
		resp := map[string]interface{}{
			"code": 1,
			"msg":  "ok",
			"data": certData,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// TestRetryFailedBindings_CertNotReady 测试证书未就绪分支
func TestRetryFailedBindings_CertNotReady(t *testing.T) {
	// Mock API 返回 processing 状态
	server := newMockAPIServer(t, map[string]interface{}{
		"order_id":       456,
		"status":         "processing",
		"certificate":    "",
		"ca_certificate": "",
	})
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "not-ready-cert",
		OrderID:  456,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			FailedBindings:    []string{"site1.com"},
			FailedBindingsAt:  time.Now().Add(-1 * time.Hour),
			RetryAttemptCount: 5,
		},
		Bindings: []config.SiteBinding{{ServerName: "site1.com", ServerType: config.ServerTypeNginx, Enabled: true}},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	certCopy, _ := cm.GetCert("not-ready-cert")

	result := svc.retryFailedBindings(t.Context(), certCopy, config.APIConfig{
		URL:   server.URL,
		Token: "test-token",
	})

	if result == nil {
		t.Fatal("结果不应为 nil")
	}
	if result.Status != "pending" {
		t.Errorf("证书未就绪应返回 pending，实际: %s", result.Status)
	}
	// 服务端仍在签发（合法在途状态）：既非部署尝试也非部署结果，不得计入重试配额，
	// 否则合法 processing 满 10 轮会清空 FailedBindings，证书真正签发后反而不再重试
	if certCopy.Metadata.RetryAttemptCount != 5 {
		t.Errorf("未就绪分支不应计入重试配额，实际 RetryAttemptCount = %d", certCopy.Metadata.RetryAttemptCount)
	}
	// syncOrderID 会把 cert_name 修正为 {domain}-{order_id}，按修正后的名字回读
	updated, err := cm.GetCert(certCopy.CertName)
	if err != nil {
		t.Fatalf("读取证书 %s 失败: %v", certCopy.CertName, err)
	}
	if updated.Metadata.RetryAttemptCount != 5 {
		t.Errorf("回滚后的重试计数应已落盘，实际 %d", updated.Metadata.RetryAttemptCount)
	}
	if len(updated.Metadata.FailedBindings) != 1 {
		t.Errorf("未就绪不应清空失败绑定，实际: %v", updated.Metadata.FailedBindings)
	}
}

// TestDeployOne_CertNotActive 测试 DeployOne 在证书未就绪时的行为
func TestDeployOne_CertNotActive(t *testing.T) {
	// Mock API 返回 processing 状态
	server := newMockAPIServer(t, map[string]interface{}{
		"order_id":       789,
		"status":         "processing",
		"certificate":    "",
		"ca_certificate": "",
	})
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 确保 API 环境变量未设置
	_ = os.Unsetenv(config.EnvAPIToken)
	_ = os.Unsetenv(config.EnvAPIURL)

	cert := &config.CertConfig{
		CertName: "processing-cert",
		OrderID:  789,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Bindings: []config.SiteBinding{
			{
				ServerName: "test.com",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(dir, "cert.pem"),
					PrivateKey:  filepath.Join(dir, "key.pem"),
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	result, err := svc.DeployOne(t.Context(), "processing-cert")
	if err == nil {
		t.Fatal("证书未就绪时应返回错误")
	}
	if !strings.Contains(err.Error(), "证书未就绪") {
		t.Errorf("错误信息应包含'证书未就绪'，实际: %v", err)
	}
	if result != nil {
		t.Error("result 应为 nil")
	}
}

// TestDeployOne_EmptyIntermediateCert 测试中间证书为空时的行为
func TestDeployOne_EmptyIntermediateCert(t *testing.T) {
	// Mock API 返回 active 但中间证书为空
	server := newMockAPIServer(t, map[string]interface{}{
		"order_id":       101,
		"status":         "active",
		"certificate":    "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		"ca_certificate": "",
		"private_key":    "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
	})
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	_ = os.Unsetenv(config.EnvAPIToken)
	_ = os.Unsetenv(config.EnvAPIURL)

	cert := &config.CertConfig{
		CertName: "no-ca-cert",
		OrderID:  101,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Bindings: []config.SiteBinding{
			{
				ServerName: "test.com",
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(dir, "cert.pem"),
					PrivateKey:  filepath.Join(dir, "key.pem"),
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	result, err := svc.DeployOne(t.Context(), "no-ca-cert")
	if err == nil {
		t.Fatal("中间证书为空时应返回错误")
	}
	if !strings.Contains(err.Error(), "中间证书为空") {
		t.Errorf("错误信息应包含'中间证书为空'，实际: %v", err)
	}
	if result != nil {
		t.Error("result 应为 nil")
	}
}

// TestDeployAllCerts_WithMockAPI ���试有证书但 API 返回处理中的场景
func TestDeployAllCerts_WithMockAPI(t *testing.T) {
	// Mock API 返回 processing 状态
	server := newMockAPIServer(t, map[string]interface{}{
		"order_id":       999,
		"status":         "processing",
		"certificate":    "",
		"ca_certificate": "",
	})
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	_ = os.Unsetenv(config.EnvAPIToken)
	_ = os.Unsetenv(config.EnvAPIURL)

	cert := &config.CertConfig{
		CertName: "deploy-all-cert",
		OrderID:  999,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Bindings: []config.SiteBinding{
			{
				ServerName: "test.com",
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(dir, "cert.pem"),
					PrivateKey:  filepath.Join(dir, "key.pem"),
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	results, err := svc.DeployAllCerts(t.Context())
	if err != nil {
		t.Errorf("DeployAllCerts 不应返回顶层错误: %v", err)
	}

	// 应有一个结果（部署失败）
	if len(results) != 1 {
		t.Fatalf("期望 1 个结果，实际: %d", len(results))
	}
	if results[0].Success {
		t.Error("证书未就绪时 Success 应为 false")
	}
}

// TestSendCallback_WithServer 测试 sendCallback 有效 API 的完整路径
func TestSendCallback_WithServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":1,"msg":"ok","renew_before_days":7}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	req := &fetcher.CallbackRequest{
		OrderID: 123,
		Status:  "success",
	}

	result := svc.sendCallback(t.Context(), config.APIConfig{
		URL:   server.URL,
		Token: "test-token",
	}, req)

	if result != 7 {
		t.Errorf("sendCallback 应返回 renew_before_days=7，实际: %d", result)
	}
}

// TestSendCallback_ServerError 测试 sendCallback 服务端错误时返回 0
func TestSendCallback_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	req := &fetcher.CallbackRequest{
		OrderID: 123,
		Status:  "failure",
	}

	result := svc.sendCallback(t.Context(), config.APIConfig{
		URL:   server.URL,
		Token: "test-token",
	}, req)

	if result != 0 {
		t.Errorf("服务端错��时应返回 0，实际: %d", result)
	}
}
