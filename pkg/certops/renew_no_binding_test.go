// Package certops 零启用绑定闸门测试
package certops

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// countingAPI 记录收到的请求数，用于断言"零绑定证书零 API 请求"
type countingAPI struct {
	hits atomic.Int32
	resp string
}

func (a *countingAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if a.resp == "" {
			_, _ = w.Write([]byte(`{"code":1,"msg":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(a.resp))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestZeroBinding_NoRequestNoCallbackNoCount 零启用绑定证书必须完全退出自动流程：
// 不发任何 API 请求、不产生结果、不上报回调、不消耗部署配额，只落阻断标记。
// 修复前实测：pull 与 local 两种模式都会连发 10 次 success 回调，服务端以为部署成功，
// 第 11 轮起静默 CAPPED —— 实际一个站点都没部署。
func TestZeroBinding_NoRequestNoCallbackNoCount(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renewMode string
		bindings  []config.SiteBinding
	}{
		{name: "pull/无绑定", renewMode: config.RenewModePull},
		{name: "pull/绑定全禁用", renewMode: config.RenewModePull, bindings: []config.SiteBinding{
			{ServerName: "off", ServerType: config.ServerTypeNginx, Enabled: false},
		}},
		{name: "local/绑定全禁用", renewMode: config.RenewModeLocal, bindings: []config.SiteBinding{
			{ServerName: "off", ServerType: config.ServerTypeNginx, Enabled: false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())

			api := &countingAPI{}
			server := api.server(t)

			cert := &config.CertConfig{
				CertName:  "gone.example.com-950",
				OrderID:   950,
				Enabled:   true,
				RenewMode: tc.renewMode,
				Domains:   []string{"gone.example.com"},
				API:       config.APIConfig{URL: server.URL, Token: "test-token"},
				Metadata: config.CertMetadata{
					CertExpiresAt:      time.Now().Add(3 * 24 * time.Hour), // 临期，需要续签
					DeployAttemptCount: 2,                                  // 基线：闸门不得推进它
				},
				Bindings: tc.bindings,
			}
			if err := cm.AddCert(cert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			for round := 1; round <= 3; round++ {
				results, err := svc.CheckAndRenewAll(t.Context())
				if err != nil {
					t.Fatalf("第 %d 轮失败: %v", round, err)
				}
				if len(results) != 0 {
					t.Fatalf("第 %d 轮不应产生续签结果: %+v", round, results)
				}
			}

			if hits := api.hits.Load(); hits != 0 {
				t.Errorf("零绑定证书不应发起任何 API 请求，实际 %d 次", hits)
			}

			updated, err := cm.GetCert("gone.example.com-950")
			if err != nil {
				t.Fatalf("读取证书失败: %v", err)
			}
			if updated.Metadata.NoBindingBlockedAt.IsZero() {
				t.Error("应落阻断标记 no_binding_blocked_at")
			}
			if updated.Metadata.DeployAttemptCount != 2 {
				t.Errorf("闸门不得消耗部署配额，实际 DeployAttemptCount = %d", updated.Metadata.DeployAttemptCount)
			}
			if updated.Metadata.LastIssueState != "" {
				t.Errorf("阻断标记不得占用公共字段 last_issue_state，实际 %q", updated.Metadata.LastIssueState)
			}
		})
	}
}

// TestZeroBinding_ZeroExpiryStillBlockedWithoutRequest 零到期时间 + 零绑定 + API 不可达：
// 仍必须拿到阻断标记且零请求。闸门若放在元数据回填之后，这类证书会每天发一次注定失败的查询、
// 却永远拿不到标记，`sslctl status` 也看不出异常。
func TestZeroBinding_ZeroExpiryStillBlockedWithoutRequest(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	api := &countingAPI{}
	server := api.server(t)

	cert := &config.CertConfig{
		CertName: "zeroexp.example.com-960",
		OrderID:  960,
		Enabled:  true,
		Domains:  []string{"zeroexp.example.com"},
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		// CertExpiresAt 零值 + 无绑定
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
		t.Fatalf("CheckAndRenewAll 失败: %v", err)
	}

	if hits := api.hits.Load(); hits != 0 {
		t.Errorf("零绑定证书不应发起回填查询，实际 %d 次", hits)
	}
	updated, err := cm.GetCert("zeroexp.example.com-960")
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if updated.Metadata.NoBindingBlockedAt.IsZero() {
		t.Error("零到期 + 零绑定同样应落阻断标记")
	}
}

// TestZeroBinding_KeepsInFlightIssueState 在途保护：零绑定闸门不得碰 last_issue_state
// 与 pending 私钥。早期方案把阻断态写进 last_issue_state，自愈清空后
// prepareLocalRenew 会因 entryState 为空重新生成 CSR、覆盖与已签发证书配对的 pending 私钥，
// 并旁路 MaxIssueRetryCount 停机保护（实测 issue_retry_count 1→2、多一次 POST）。
func TestZeroBinding_KeepsInFlightIssueState(t *testing.T) {
	for _, state := range []string{config.IssueStateProcessing, config.IssueStateActive} {
		t.Run(state, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())

			api := &countingAPI{}
			server := api.server(t)

			const certName = "inflight.example.com-970"
			keyPEM := "-----BEGIN RSA PRIVATE KEY-----\ninflight\n-----END RSA PRIVATE KEY-----"
			if err := savePendingKey(cm.GetWorkDir(), certName, keyPEM); err != nil {
				t.Fatalf("保存 pending 私钥失败: %v", err)
			}

			cert := &config.CertConfig{
				CertName:  certName,
				OrderID:   970,
				Enabled:   true,
				RenewMode: config.RenewModeLocal,
				Domains:   []string{"inflight.example.com"},
				API:       config.APIConfig{URL: server.URL, Token: "test-token"},
				Metadata: config.CertMetadata{
					CertExpiresAt:   time.Now().Add(3 * 24 * time.Hour),
					LastIssueState:  state,
					IssueRetryCount: 1,
				},
			}
			if err := cm.AddCert(cert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			// 第 1 轮：阻断
			if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
				t.Fatalf("阻断轮失败: %v", err)
			}
			blocked, _ := cm.GetCert(certName)
			if blocked.Metadata.LastIssueState != state {
				t.Fatalf("在途状态被覆盖: %q -> %q", state, blocked.Metadata.LastIssueState)
			}

			// 第 2 轮：人工恢复绑定后自愈
			blocked.Bindings = []config.SiteBinding{{
				ServerName: "inflight.example.com",
				ServerType: config.ServerTypeNginx,
				Enabled:    true,
				Paths: config.BindingPaths{
					Certificate: filepath.Join(tmpDir, "site", "cert.pem"),
					PrivateKey:  filepath.Join(tmpDir, "site", "key.pem"),
				},
			}}
			if err := cm.UpdateCert(blocked); err != nil {
				t.Fatalf("恢复绑定失败: %v", err)
			}
			hitsBefore := api.hits.Load()
			if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
				t.Fatalf("自愈轮失败: %v", err)
			}

			healed, _ := cm.GetCert(certName)
			if healed.Metadata.LastIssueState != state {
				t.Errorf("自愈后在途状态应保持 %q，实际 %q", state, healed.Metadata.LastIssueState)
			}
			if healed.Metadata.IssueRetryCount != 1 {
				t.Errorf("自愈不得复位签发计数（会旁路停机保护），实际 %d", healed.Metadata.IssueRetryCount)
			}
			if !healed.Metadata.NoBindingBlockedAt.IsZero() {
				t.Error("恢复绑定后应清除阻断标记")
			}
			got, err := readPendingKey(cm.GetWorkDir(), certName)
			if err != nil || got != keyPEM {
				t.Errorf("pending 私钥不应被改动: err=%v", err)
			}
			// 自愈轮只允许走查询路径（GET），不得重新提交 CSR
			if delta := api.hits.Load() - hitsBefore; delta == 0 {
				t.Error("自愈后应恢复正常续签流程（至少一次查询）")
			}
		})
	}
}

// TestZeroBinding_TerminalStatesTakePrecedence 闸门内部先跑纯本地判定：
// 已过期 → EXPIRED、部署触顶 → CAPPED(deploy)，保住 deploy-spec §3.2 的状态转移，
// 且这两个判定都是纯函数、零 API 请求。
func TestZeroBinding_TerminalStatesTakePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		meta      config.CertMetadata
		wantState string
		wantPhase string
	}{
		{
			name:      "零绑定且已过期",
			meta:      config.CertMetadata{CertExpiresAt: time.Now().Add(-time.Hour)},
			wantState: config.IssueStateExpired,
		},
		{
			name: "零绑定且部署触顶",
			meta: config.CertMetadata{
				CertExpiresAt:      time.Now().Add(3 * 24 * time.Hour),
				DeployAttemptCount: MaxDeployAttemptCount,
			},
			wantState: config.IssueStateCapped,
			wantPhase: config.CappedPhaseDeploy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())

			api := &countingAPI{}
			server := api.server(t)

			cert := &config.CertConfig{
				CertName: "term.example.com-980",
				OrderID:  980,
				Enabled:  true,
				Domains:  []string{"term.example.com"},
				API:      config.APIConfig{URL: server.URL, Token: "test-token"},
				Metadata: tc.meta,
			}
			if err := cm.AddCert(cert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			if _, err := svc.CheckAndRenewAll(t.Context()); err != nil {
				t.Fatalf("CheckAndRenewAll 失败: %v", err)
			}

			if hits := api.hits.Load(); hits != 0 {
				t.Errorf("终止态判定是纯本地计算，不应发请求，实际 %d 次", hits)
			}
			updated, _ := cm.GetCert("term.example.com-980")
			if updated.Metadata.LastIssueState != tc.wantState {
				t.Errorf("LastIssueState = %q, want %q", updated.Metadata.LastIssueState, tc.wantState)
			}
			if tc.wantPhase != "" && updated.Metadata.CappedPhase != tc.wantPhase {
				t.Errorf("CappedPhase = %q, want %q", updated.Metadata.CappedPhase, tc.wantPhase)
			}
			if !updated.Metadata.NoBindingBlockedAt.IsZero() {
				t.Error("已进入规范终止态的证书不应再落零绑定标记")
			}
		})
	}
}

// TestMarkNoBindingBlocked_SkipsWhenBindingRestoredConcurrently 并发窗口：
// 落盘前若绑定已被补齐（锁创建失败降级、人工编辑 config.json），
// 必须放弃写入。整条覆盖会把刚补齐的绑定连同标记一起抹掉，
// 且此后自愈条件（有启用绑定）永远不成立。
func TestMarkNoBindingBlocked_SkipsWhenBindingRestoredConcurrently(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	const certName = "race.example.com-990"
	if err := cm.AddCert(&config.CertConfig{
		CertName: certName,
		OrderID:  990,
		Enabled:  true,
		Bindings: []config.SiteBinding{{ServerName: "race.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// 模拟陈旧快照：内存副本无绑定，盘上已被补齐
	stale := &config.CertConfig{CertName: certName, OrderID: 990, Enabled: true}
	svc.markNoBindingBlocked(stale)

	updated, err := cm.GetCert(certName)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	if !updated.Metadata.NoBindingBlockedAt.IsZero() {
		t.Error("盘上已有启用绑定时不应写入阻断标记")
	}
	if !updated.HasEnabledBinding() {
		t.Error("绝不能用陈旧快照整条覆盖掉已补齐的绑定")
	}
}

// TestZeroBinding_BlockSurvivesReload 阻断标记必须跨一次完整的 Load()/迁移读回仍在。
func TestZeroBinding_BlockSurvivesReload(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	const certName = "reload.example.com-991"
	if err := cm.AddCert(&config.CertConfig{
		CertName: certName,
		OrderID:  991,
		Enabled:  true,
		Metadata: config.CertMetadata{CertExpiresAt: time.Now().Add(3 * 24 * time.Hour)},
	}); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	cert, _ := cm.GetCert(certName)
	svc.markNoBindingBlocked(cert)

	// 新建管理器强制重新读盘（含迁移路径）
	reopened, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("重新打开配置失败: %v", err)
	}
	got, err := reopened.GetCert(certName)
	if err != nil {
		t.Fatalf("重新读取证书失败: %v", err)
	}
	if got.Metadata.NoBindingBlockedAt.IsZero() {
		t.Error("阻断标记应跨 Load()/迁移保留")
	}
	if got.Metadata.LastIssueState != "" {
		t.Errorf("不占用 last_issue_state，迁移也不应把它改写，实际 %q", got.Metadata.LastIssueState)
	}
}

// TestSplitRetryTargets_GhostClasses 两类幽灵分别处置：
// 仍在 Bindings 但被禁用 → 可转入 stale 等恢复；已不在 Bindings → 直接丢弃。
// 若一律转入 stale，本证书永远不会再部署该站点，ClearStaleBinding 的调用点也永远不会
// 以它为入参，每日 Error 将永远关不掉。
func TestSplitRetryTargets_GhostClasses(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{ServerName: "live", Enabled: true},
			{ServerName: "disabled", Enabled: false},
		},
		Metadata: config.CertMetadata{FailedBindings: []string{"live", "disabled", "moved"}},
	}

	retryable, ghosts := splitRetryTargets(cert)
	if len(retryable) != 1 || retryable[0] != "live" {
		t.Fatalf("retryable = %v, want [live]", retryable)
	}
	if len(ghosts) != 2 {
		t.Fatalf("ghosts = %v, want 2 项", ghosts)
	}

	migrateToStale(cert, ghosts, time.Now())
	if len(cert.Metadata.StaleBindings) != 1 || cert.Metadata.StaleBindings[0] != "disabled" {
		t.Errorf("只有仍在 Bindings 中的幽灵可转入 stale，实际: %v", cert.Metadata.StaleBindings)
	}

	ClearStaleBinding(cert, "disabled")
	if len(cert.Metadata.StaleBindings) != 0 || !cert.Metadata.StaleSince.IsZero() {
		t.Errorf("清空后应一并清除 StaleSince，实际: %v / %v", cert.Metadata.StaleBindings, cert.Metadata.StaleSince)
	}
}

// TestRetryFailedBindings_AllGhostsNoCallback 幽灵条目全无可重试目标时：
// 不发请求、不报 success、不更新 LastDeployAt，返回 nil 让上层不上报回调。
// 修复前该路径会报 success 并向服务端谎报"已修复"。
func TestRetryFailedBindings_AllGhostsNoCallback(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	api := &countingAPI{}
	server := api.server(t)

	lastDeploy := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	cert := &config.CertConfig{
		CertName: "ghost.example.com-901",
		OrderID:  901,
		Enabled:  true,
		API:      config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			CertExpiresAt:    time.Now().Add(60 * 24 * time.Hour),
			LastDeployAt:     lastDeploy,
			FailedBindings:   []string{"ghost-site"},
			FailedBindingsAt: time.Now().Add(-time.Hour),
		},
		Bindings: []config.SiteBinding{{ServerName: "ghost-site", ServerType: config.ServerTypeNginx, Enabled: false}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	certCopy, _ := cm.GetCert(cert.CertName)
	result := svc.retryFailedBindings(t.Context(), certCopy, cert.API)
	if result != nil {
		t.Fatalf("幽灵条目不应产生可上报结果，实际: %+v", result)
	}
	if hits := api.hits.Load(); hits != 0 {
		t.Errorf("纯记账清理不应发起 API 请求，实际 %d 次", hits)
	}

	updated, _ := cm.GetCert(cert.CertName)
	if len(updated.Metadata.FailedBindings) != 0 {
		t.Errorf("幽灵条目应被清理，实际: %v", updated.Metadata.FailedBindings)
	}
	if !updated.Metadata.LastDeployAt.Equal(lastDeploy) {
		t.Error("一个绑定都没重试，不得更新 LastDeployAt")
	}
	if len(updated.Metadata.StaleBindings) != 1 {
		t.Errorf("被禁用的幽灵应转入 stale 等待恢复，实际: %v", updated.Metadata.StaleBindings)
	}
	if updated.Metadata.RetryAttemptCount != 0 {
		t.Errorf("预检早退不应消耗重试配额，实际 %d", updated.Metadata.RetryAttemptCount)
	}
}

// TestRetryFailedBindings_FrontFailuresTerminate 四条非成功出口都必须在 10 轮内停车。
// 计数点若放在部署循环之前的任何一次早退之后，持久性前置故障（API 宕机、私钥不可读）
// 会产生无上限的每日 failure 回调，永不停车 —— 这是对现状的净回归。
func TestRetryFailedBindings_FrontFailuresTerminate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resp    string
		apiDown bool
	}{
		{name: "API 宕机", apiDown: true},
		{name: "证书未就绪但配额外", resp: `{"code":1,"msg":"ok","data":{"order_id":902,"status":"processing"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(tmpDir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}
			svc := NewService(cm, logger.NewNopLogger())
			// 本用例检查轮次配额，保留传输重试次数，但无需等待真实秒级退避。
			retry := fetcher.DefaultRetryConfig
			retry.InitialWait = time.Millisecond
			retry.MaxWait = 4 * time.Millisecond
			svc.fetcher = fetcher.NewWithRetry(retry)

			apiURL := "http://127.0.0.1:1"
			if !tc.apiDown {
				api := &countingAPI{resp: tc.resp}
				apiURL = api.server(t).URL
			}

			cert := &config.CertConfig{
				CertName: "front.example.com-902",
				OrderID:  902,
				Enabled:  true,
				API:      config.APIConfig{URL: apiURL, Token: "test-token"},
				Metadata: config.CertMetadata{
					CertExpiresAt:      time.Now().Add(60 * 24 * time.Hour),
					FailedBindings:     []string{"front-site"},
					FailedBindingsAt:   time.Now().Add(-time.Hour),
					DeployAttemptCount: 4, // 证书级配额基线
				},
				Bindings: []config.SiteBinding{{ServerName: "front-site", ServerType: config.ServerTypeNginx, Enabled: true}},
			}
			if err := cm.AddCert(cert); err != nil {
				t.Fatalf("添加证书失败: %v", err)
			}

			var parkedRound int
			for round := 1; round <= 15; round++ {
				certCopy, err := cm.GetCert(cert.CertName)
				if err != nil {
					t.Fatalf("第 %d 轮读取证书失败: %v", round, err)
				}
				if len(certCopy.Metadata.FailedBindings) == 0 {
					parkedRound = round - 1
					break
				}
				svc.retryFailedBindings(t.Context(), certCopy, cert.API)
			}

			updated, _ := cm.GetCert(cert.CertName)
			switch {
			case tc.apiDown:
				if parkedRound == 0 || parkedRound > MaxRetryAttemptCount {
					t.Fatalf("API 宕机应在 %d 轮内停车，实际第 %d 轮", MaxRetryAttemptCount, parkedRound)
				}
				if len(updated.Metadata.StaleBindings) != 1 {
					t.Errorf("停车后应转入 stale，实际: %v", updated.Metadata.StaleBindings)
				}
			default:
				// processing 是上游合法在途状态：不计配额、不停车，等签发完成自愈
				if parkedRound != 0 {
					t.Fatalf("证书签发中不应停车，实际第 %d 轮停车", parkedRound)
				}
				if updated.Metadata.RetryAttemptCount != 0 {
					t.Errorf("签发中不应消耗重试配额，实际 %d", updated.Metadata.RetryAttemptCount)
				}
				if len(updated.Metadata.FailedBindings) != 1 {
					t.Errorf("签发中不应清空失败绑定，实际: %v", updated.Metadata.FailedBindings)
				}
			}
			// 任何情况下都不得消耗证书级配额，否则一次 API 宕机就会让整张证书 CAPPED
			if updated.Metadata.DeployAttemptCount != 4 {
				t.Errorf("重试路径不得触碰 DeployAttemptCount，实际 %d", updated.Metadata.DeployAttemptCount)
			}
			if updated.Metadata.LastIssueState != "" {
				t.Errorf("重试路径不得把整张证书打进终止态，实际 %q", updated.Metadata.LastIssueState)
			}
		})
	}
}
