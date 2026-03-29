// Package certops 回调测试公共辅助函数
package certops

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newCallbackTestServer 返回本地回调服务，避免真实 DNS/HTTP 请求导致测试不稳定。
func newCallbackTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 始终返回成功，避免回调重试造成测试耗时。
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok"}`))
	}))
}

// newRenewBeforeDaysCallbackServer 返回本地回调服务，响应中包含指定的 renew_before_days。
func newRenewBeforeDaysCallbackServer(t *testing.T, renewBeforeDays int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":1,"msg":"ok","renew_before_days":%d}`, renewBeforeDays)
	}))
}
