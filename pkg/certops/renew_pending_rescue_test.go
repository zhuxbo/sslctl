// Package certops 续签部署全失败后 pending 私钥可重试可补救测试
package certops

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
	certs "github.com/zhuxbo/sslctl/testdata/certs"
)

// TestRenew_AllBindingsFail_SelfHealsNextRound 复现并验证死锁链的修复：
// local 续签 active 配对通过进入部署，当日全部绑定失败 → pending 不转正；
// 若此时 CertExpiresAt 被更新为新证书日期，下轮 NeedsRenewal=false 只走 retryFailedBindings，
// 而重试链读不到 pending，旧钥与新证书配对必败，7 天后放弃，站点走向真实过期。
// 修复后：全失败不更新元数据，下轮走完整 prepare→读 pending→部署 自愈成功。
func TestRenew_AllBindingsFail_SelfHealsNextRound(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	newCert, err := certs.GenerateValidCert("heal.example.com", []string{"heal.example.com"})
	if err != nil {
		t.Fatalf("生成新证书失败: %v", err)
	}
	oldCert, err := certs.GenerateValidCert("heal.example.com", []string{"heal.example.com"})
	if err != nil {
		t.Fatalf("生成旧证书失败: %v", err)
	}
	intermediate, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成中间证书失败: %v", err)
	}

	certPath := filepath.Join(tmpDir, "site", "cert.pem")
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	// 线上为旧证书+旧私钥
	if err := os.WriteFile(certPath, []byte(oldCert.CertPEM), 0644); err != nil {
		t.Fatalf("写入线上证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(oldCert.KeyPEM), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}
	// pending 为新私钥（CSR 已提交、服务端已签发）
	if err := savePendingKey(cm.GetWorkDir(), "heal.example.com-2000", newCert.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 2000, "active", newCert.CertPEM, intermediate.CertPEM)
	defer server.Close()

	oldExpiry := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)
	cert := &config.CertConfig{
		CertName:  "heal.example.com-2000",
		OrderID:   2000,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"heal.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			LastIssueState: "processing",
			CertExpiresAt:  oldExpiry, // 旧证书临期
		},
		Bindings: []config.SiteBinding{{
			ServerName: "heal-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	// === 第一轮：部署全部失败（把 cert.pem 变成目录使 mock 部署器写入失败）===
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("移除证书文件失败: %v", err)
	}
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("制造部署障碍失败: %v", err)
	}

	certData, privateKey, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("第一轮 prepare 应成功（active+pending 配对）: %v", err)
	}
	if privateKey != newCert.KeyPEM {
		t.Fatal("应使用 pending 私钥")
	}
	deployCount, _, deployErr := svc.deployCertToBindings(t.Context(), cert, certData, privateKey)
	if deployCount != 0 || deployErr == nil {
		t.Fatalf("第一轮部署应全部失败: count=%d err=%v", deployCount, deployErr)
	}

	// 死锁不变式校验：元数据未被新证书污染，自愈条件保持
	if !cert.Metadata.CertExpiresAt.Equal(oldExpiry) {
		t.Error("全失败后 CertExpiresAt 不应更新（否则下轮 NeedsRenewal=false 进入死锁）")
	}
	if cert.Metadata.LastIssueState != "processing" {
		t.Errorf("全失败后 LastIssueState 应保持 processing，实际 %q", cert.Metadata.LastIssueState)
	}
	if !cert.NeedsRenewal(&config.ScheduleConfig{RenewBeforeDays: 14}) {
		t.Error("全失败后 NeedsRenewal 应仍为 true（走完整自愈循环）")
	}
	if _, err := readPendingKey(cm.GetWorkDir(), "heal.example.com-2000"); err != nil {
		t.Errorf("全失败后 pending 私钥应保留: %v", err)
	}

	// === 第二轮：障碍解除，完整自愈 ===
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("清除部署障碍失败: %v", err)
	}

	certData2, privateKey2, err := svc.prepareLocalRenew(t.Context(), cert, cert.API)
	if err != nil {
		t.Fatalf("第二轮 prepare 应成功: %v", err)
	}
	deployCount2, _, deployErr2 := svc.deployCertToBindings(t.Context(), cert, certData2, privateKey2)
	if deployCount2 != 1 || deployErr2 != nil {
		t.Fatalf("第二轮部署应成功: count=%d err=%v", deployCount2, deployErr2)
	}

	// 自愈完成：线上为新证书+新私钥，pending 已转正，元数据已更新
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != newCert.KeyPEM {
		t.Error("自愈后线上私钥应为新私钥")
	}
	if _, err := os.Lstat(getPendingKeyPath(cm.GetWorkDir(), "heal.example.com-2000")); !os.IsNotExist(err) {
		t.Error("自愈后 pending 私钥应已转正清理")
	}
	if cert.Metadata.CertExpiresAt.Equal(oldExpiry) || cert.Metadata.LastIssueState != "" {
		t.Error("自愈后元数据应更新、CSR 状态应清零")
	}
}

// TestGetPrivateKeyForCert_PendingRescue 验证正式私钥与目标证书不配对时回退 pending 私钥
// （配对校验通过才用）——覆盖"全部失败→手动 deploy 用 pending 补救"的取钥环节。
func TestGetPrivateKeyForCert_PendingRescue(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	newCert, _ := certs.GenerateValidCert("rescue.example.com", []string{"rescue.example.com"})
	oldCert, _ := certs.GenerateValidCert("rescue.example.com", []string{"rescue.example.com"})

	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	// 正式位置是旧私钥（与新证书不配对）
	if err := os.WriteFile(keyPath, []byte(oldCert.KeyPEM), 0600); err != nil {
		t.Fatalf("写入旧私钥失败: %v", err)
	}
	// pending 是新私钥
	if err := savePendingKey(cm.GetWorkDir(), "rescue.example.com-2100", newCert.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "rescue.example.com-2100",
		Bindings: []config.SiteBinding{{
			ServerName: "rescue-site",
			Enabled:    true,
			Paths:      config.BindingPaths{PrivateKey: keyPath},
		}},
	}

	// 目标为新证书：正式钥不配对 → 应回退 pending
	key, err := GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, newCert.CertPEM, "", nil)
	if err != nil {
		t.Fatalf("应回退到 pending 私钥补救: %v", err)
	}
	if key != newCert.KeyPEM {
		t.Error("应返回 pending 私钥（与目标证书配对）")
	}

	// 部署成功后补转正
	CommitPendingKeyIfMatches(cm.GetWorkDir(), cert, key, nil)
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != newCert.KeyPEM {
		t.Error("转正后正式位置应为新私钥")
	}
	if _, err := os.Lstat(getPendingKeyPath(cm.GetWorkDir(), "rescue.example.com-2100")); !os.IsNotExist(err) {
		t.Error("转正后 pending 文件应清理")
	}
}

// TestGetPrivateKeyForCert_Degradation 退化场景：行为与原实现一致。
func TestGetPrivateKeyForCert_Degradation(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	pair, _ := certs.GenerateValidCert("deg.example.com", []string{"deg.example.com"})
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(pair.KeyPEM), 0600); err != nil {
		t.Fatalf("写入私钥失败: %v", err)
	}

	cert := &config.CertConfig{
		CertName: "deg.example.com-2200",
		Bindings: []config.SiteBinding{{
			ServerName: "deg-site",
			Enabled:    true,
			Paths:      config.BindingPaths{PrivateKey: keyPath},
		}},
	}

	// API 私钥优先（原行为）
	key, err := GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, pair.CertPEM, "api-key", nil)
	if err != nil || key != "api-key" {
		t.Errorf("API 私钥应优先: key=%q err=%v", key, err)
	}

	// pending 缺失 + 正式钥配对 → 返回正式钥（原行为）
	key, err = GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, pair.CertPEM, "", nil)
	if err != nil || key != pair.KeyPEM {
		t.Errorf("正式钥配对时应直接使用: err=%v", err)
	}

	// certPEM 为空 → 退化为不校验直接读正式钥（原行为）
	key, err = GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, "", "", nil)
	if err != nil || key != pair.KeyPEM {
		t.Errorf("无证书内容时应退化为原行为: err=%v", err)
	}

	// 正式钥不配对且无 pending → 明确错误
	other, _ := certs.GenerateValidCert("other.example.com", []string{"other.example.com"})
	if _, err := GetPrivateKeyForCert(t.Context(), cm.GetWorkDir(), cert, other.CertPEM, "", nil); err == nil {
		t.Error("不配对且无 pending 时应返回错误")
	}
}

// TestRetryFailedBindings_RescuesWithPendingKey 验证失败绑定重试链能用 pending 私钥补救
// （修复前 retry 只读正式位置，旧钥与新证书配对必败，7 天后放弃走向真实过期）。
func TestRetryFailedBindings_RescuesWithPendingKey(t *testing.T) {
	tmpDir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}
	svc := NewService(cm, logger.NewNopLogger())

	newCert, _ := certs.GenerateValidCert("retryheal.example.com", []string{"retryheal.example.com"})
	oldCert, _ := certs.GenerateValidCert("retryheal.example.com", []string{"retryheal.example.com"})
	intermediate, _ := certs.GenerateValidCert("Test CA", nil)

	certPath := filepath.Join(tmpDir, "site", "cert.pem")
	keyPath := filepath.Join(tmpDir, "site", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(oldCert.CertPEM), 0644); err != nil {
		t.Fatalf("写入线上证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(oldCert.KeyPEM), 0600); err != nil {
		t.Fatalf("写入线上私钥失败: %v", err)
	}
	if err := savePendingKey(cm.GetWorkDir(), "retryheal.example.com-2300", newCert.KeyPEM); err != nil {
		t.Fatalf("保存 pending 私钥失败: %v", err)
	}

	server := newQueryOrderServer(t, 2300, "active", newCert.CertPEM, intermediate.CertPEM)
	defer server.Close()

	cert := &config.CertConfig{
		CertName:  "retryheal.example.com-2300",
		OrderID:   2300,
		Enabled:   true,
		RenewMode: config.RenewModeLocal,
		Domains:   []string{"retryheal.example.com"},
		API:       config.APIConfig{URL: server.URL, Token: "test-token"},
		Metadata: config.CertMetadata{
			FailedBindings:   []string{"retryheal-site"},
			FailedBindingsAt: time.Now(),
		},
		Bindings: []config.SiteBinding{{
			ServerName: "retryheal-site",
			ServerType: config.ServerTypeNginx,
			Enabled:    true,
			Paths:      config.BindingPaths{Certificate: certPath, PrivateKey: keyPath},
		}},
	}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("添加证书失败: %v", err)
	}

	result := svc.retryFailedBindings(t.Context(), cert, cert.API)
	if result.Status != "success" || result.DeployCount != 1 {
		t.Fatalf("重试应用 pending 私钥补救成功: %+v (err=%v)", result, result.Error)
	}

	// pending 已转正、线上为新私钥
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != newCert.KeyPEM {
		t.Error("重试成功后线上私钥应为新私钥")
	}
	if _, err := os.Lstat(getPendingKeyPath(cm.GetWorkDir(), "retryheal.example.com-2300")); !os.IsNotExist(err) {
		t.Error("重试成功后 pending 私钥应已转正清理")
	}
}
