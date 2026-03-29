package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateConfig_NoChange 当前格式不触发迁移
func TestMigrateConfig_NoChange(t *testing.T) {
	cfg := `{
		"schedule": {"renew_before_days": 14, "renew_mode": "pull"},
		"certificates": [{
			"cert_name": "test",
			"order_id": 123,
			"api": {"url": "https://api.example.com", "token": "tok"},
			"bindings": [{"server_name": "example.com", "server_type": "nginx"}]
		}]
	}`
	_, changed, err := migrateConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if changed {
		t.Error("当前格式不应触发迁移")
	}
}

// TestMigrateConfig_GlobalAPIToCert 全局 API 迁移到证书级别
func TestMigrateConfig_GlobalAPIToCert(t *testing.T) {
	oldCfg := `{
		"api": {"url": "https://api.example.com", "token": "global-token"},
		"certificates": [
			{"cert_name": "cert1", "order_id": 1},
			{"cert_name": "cert2", "order_id": 2, "api": {"url": "https://custom.com", "token": "custom-token"}}
		]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("应检测到全局 API 并触发迁移")
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("解析迁移结果失败: %v", err)
	}

	// 顶层 api 应被删除
	if _, has := raw["api"]; has {
		t.Error("迁移后顶层 api 应被删除")
	}

	// cert1 应继承全局 API
	certs := raw["certificates"].([]interface{})
	cert1 := certs[0].(map[string]interface{})
	cert1API := cert1["api"].(map[string]interface{})
	if cert1API["url"] != "https://api.example.com" {
		t.Errorf("cert1 api.url = %v, 期望 https://api.example.com", cert1API["url"])
	}
	if cert1API["token"] != "global-token" {
		t.Errorf("cert1 api.token = %v, 期望 global-token", cert1API["token"])
	}

	// cert2 应保留自己的 API
	cert2 := certs[1].(map[string]interface{})
	cert2API := cert2["api"].(map[string]interface{})
	if cert2API["url"] != "https://custom.com" {
		t.Errorf("cert2 api.url = %v, 期望 https://custom.com", cert2API["url"])
	}
}

// TestMigrateConfig_GlobalAPI_PartialCertAPI 全局 API 补全证书缺失字段
func TestMigrateConfig_GlobalAPI_PartialCertAPI(t *testing.T) {
	oldCfg := `{
		"api": {"url": "https://global.com", "token": "global-token"},
		"certificates": [
			{"cert_name": "cert1", "order_id": 1, "api": {"url": "https://custom.com"}}
		]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("应触发迁移")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	certs := raw["certificates"].([]interface{})
	cert1API := certs[0].(map[string]interface{})["api"].(map[string]interface{})

	// url 保留证书自己的，token 从全局补全
	if cert1API["url"] != "https://custom.com" {
		t.Errorf("url = %v, 期望保留证书自己的 https://custom.com", cert1API["url"])
	}
	if cert1API["token"] != "global-token" {
		t.Errorf("token = %v, 期望从全局补全 global-token", cert1API["token"])
	}
}

// TestMigrateConfig_SiteNameToServerName 站点字段重命名
func TestMigrateConfig_SiteNameToServerName(t *testing.T) {
	oldCfg := `{
		"certificates": [{
			"cert_name": "test",
			"order_id": 1,
			"api": {"url": "https://api.example.com", "token": "tok"},
			"bindings": [
				{"site_name": "old.example.com", "server_type": "nginx"},
				{"server_name": "new.example.com", "server_type": "nginx"}
			]
		}]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("应检测到 site_name 并触发迁移")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	certs := raw["certificates"].([]interface{})
	bindings := certs[0].(map[string]interface{})["bindings"].([]interface{})

	// 第一个 binding: site_name → server_name
	b0 := bindings[0].(map[string]interface{})
	if _, has := b0["site_name"]; has {
		t.Error("迁移后不应保留 site_name")
	}
	if b0["server_name"] != "old.example.com" {
		t.Errorf("server_name = %v, 期望 old.example.com", b0["server_name"])
	}

	// 第二个 binding: 已是新格式，不变
	b1 := bindings[1].(map[string]interface{})
	if b1["server_name"] != "new.example.com" {
		t.Errorf("server_name = %v, 期望 new.example.com", b1["server_name"])
	}
}

// TestMigrateConfig_RemoveCallbackURL 移除废弃的 callback_url
func TestMigrateConfig_RemoveCallbackURL(t *testing.T) {
	oldCfg := `{
		"certificates": [{
			"cert_name": "test",
			"order_id": 1,
			"api": {"url": "https://api.example.com", "token": "tok", "callback_url": "https://old-callback.com"},
			"bindings": [{"server_name": "example.com", "server_type": "nginx"}]
		}]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("应检测到 callback_url 并触发迁移")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	certs := raw["certificates"].([]interface{})
	certAPI := certs[0].(map[string]interface{})["api"].(map[string]interface{})

	if _, has := certAPI["callback_url"]; has {
		t.Error("迁移后不应保留 callback_url")
	}
	// 其他字段应保留
	if certAPI["url"] != "https://api.example.com" {
		t.Errorf("url = %v, 期望保留", certAPI["url"])
	}
}

// TestMigrateConfig_CrossVersion 跨版本升级：同时包含多种旧格式
func TestMigrateConfig_CrossVersion(t *testing.T) {
	oldCfg := `{
		"api": {"url": "https://global.com", "token": "tok", "callback_url": "https://old.com/callback"},
		"certificates": [{
			"cert_name": "test",
			"order_id": 1,
			"bindings": [{"site_name": "example.com", "server_type": "nginx"}]
		}]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("跨版本旧配置应触发迁移")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)

	// 全局 api 删除
	if _, has := raw["api"]; has {
		t.Error("顶层 api 应被删除")
	}

	certs := raw["certificates"].([]interface{})
	cert := certs[0].(map[string]interface{})

	// API 已继承到证书，且 callback_url 已移除
	certAPI := cert["api"].(map[string]interface{})
	if certAPI["url"] != "https://global.com" {
		t.Errorf("api.url = %v, 期望从全局继承", certAPI["url"])
	}
	if _, has := certAPI["callback_url"]; has {
		t.Error("callback_url 应被移除")
	}

	// site_name → server_name
	bindings := cert["bindings"].([]interface{})
	b := bindings[0].(map[string]interface{})
	if b["server_name"] != "example.com" {
		t.Errorf("server_name = %v, 期望 example.com", b["server_name"])
	}
	if _, has := b["site_name"]; has {
		t.Error("site_name 应被移除")
	}
}

// TestMigrateConfig_Idempotent 迁移是幂等的：迁移后再迁移不产生变化
func TestMigrateConfig_Idempotent(t *testing.T) {
	oldCfg := `{
		"api": {"url": "https://global.com", "token": "tok", "callback_url": "https://old.com"},
		"certificates": [{
			"cert_name": "test",
			"order_id": 1,
			"bindings": [{"site_name": "example.com", "server_type": "nginx"}]
		}]
	}`

	// 第一次迁移
	data1, changed1, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("第一次迁移失败: %v", err)
	}
	if !changed1 {
		t.Fatal("第一次应触发迁移")
	}

	// 第二次迁移
	_, changed2, err := migrateConfig(data1)
	if err != nil {
		t.Fatalf("第二次迁移失败: %v", err)
	}
	if changed2 {
		t.Error("第二次迁移不应产生变化（幂等性）")
	}
}

// TestMigrateConfig_InvalidJSON 无效 JSON 返回错误
func TestMigrateConfig_InvalidJSON(t *testing.T) {
	_, _, err := migrateConfig([]byte("not json"))
	if err == nil {
		t.Error("无效 JSON 应返回错误")
	}
}

// TestMigrateConfig_EmptyConfig 空配置触发默认值填充
func TestMigrateConfig_EmptyConfig(t *testing.T) {
	data, changed, err := migrateConfig([]byte(`{}`))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Error("空配置应触发默认值填充")
	}
	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	if _, has := raw["schedule"]; !has {
		t.Error("schedule 应被自动补齐")
	}
}

// TestMigrateConfig_Integration 集成测试：迁移后能正确加载为 Config 结构
func TestMigrateConfig_Integration(t *testing.T) {
	oldCfg := `{
		"api": {"url": "https://api.example.com", "token": "test-token"},
		"schedule": {"renew_before_days": 7, "renew_mode": "pull"},
		"certificates": [{
			"cert_name": "example.com-123",
			"order_id": 123,
			"enabled": true,
			"domains": ["example.com"],
			"bindings": [{
				"site_name": "example.com",
				"server_type": "nginx",
				"enabled": true,
				"paths": {"certificate": "/etc/ssl/cert.pem", "private_key": "/etc/ssl/key.pem"}
			}]
		}]
	}`

	// 写入临时文件
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(oldCfg), 0600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}

	// 通过 ConfigManager 加载（触发迁移）
	cm, err := NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建 ConfigManager 失败: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 验证迁移结果
	if len(cfg.Certificates) != 1 {
		t.Fatalf("证书数量 = %d, 期望 1", len(cfg.Certificates))
	}

	cert := cfg.Certificates[0]
	if cert.API.URL != "https://api.example.com" {
		t.Errorf("证书 API URL = %s, 期望从全局继承", cert.API.URL)
	}
	if cert.API.Token != "test-token" {
		t.Errorf("证书 API Token = %s, 期望从全局继承", cert.API.Token)
	}
	if len(cert.Bindings) != 1 {
		t.Fatalf("绑定数量 = %d, 期望 1", len(cert.Bindings))
	}
	if cert.Bindings[0].ServerName != "example.com" {
		t.Errorf("ServerName = %s, 期望 example.com（从 site_name 迁移）", cert.Bindings[0].ServerName)
	}

	// 验证迁移后的文件已持久化
	savedData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读取迁移后配置失败: %v", err)
	}
	var savedRaw map[string]interface{}
	_ = json.Unmarshal(savedData, &savedRaw)
	if _, has := savedRaw["api"]; has {
		t.Error("持久化的配置中不应有顶层 api")
	}
}

// TestResolvePath 测试路径解析引擎
func TestResolvePath(t *testing.T) {
	raw := map[string]interface{}{
		"schedule": map[string]interface{}{"renew_before_days": float64(14)},
		"certificates": []interface{}{
			map[string]interface{}{
				"cert_name": "cert1",
				"bindings": []interface{}{
					map[string]interface{}{"server_name": "a.com"},
					map[string]interface{}{"server_name": "b.com"},
				},
			},
			map[string]interface{}{
				"cert_name": "cert2",
				"bindings": []interface{}{
					map[string]interface{}{"server_name": "c.com"},
				},
			},
		},
	}

	tests := []struct {
		path      string
		wantCount int
	}{
		{".", 1},                              // 根节点
		{"certificates[]", 2},                 // 2 个证书
		{"certificates[].bindings[]", 3},      // 3 个绑定
		{"schedule", 1},                       // 子 map
		{"nonexistent[]", 0},                  // 不存在的路径
		{"certificates[].nonexistent[]", 0},   // 嵌套不存在
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			nodes := resolvePath(raw, tt.path)
			if len(nodes) != tt.wantCount {
				t.Errorf("resolvePath(%q) 返回 %d 个节点, 期望 %d", tt.path, len(nodes), tt.wantCount)
			}
		})
	}
}

// TestSplitTargetPath 测试目标路径拆分
func TestSplitTargetPath(t *testing.T) {
	tests := []struct {
		target     string
		wantParent string
		wantField  string
	}{
		{"certificates[].api", "certificates[]", "api"},
		{"api", ".", "api"},
		{"a[].b[].c", "a[].b[]", "c"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			parent, field := splitTargetPath(tt.target)
			if parent != tt.wantParent || field != tt.wantField {
				t.Errorf("splitTargetPath(%q) = (%q, %q), 期望 (%q, %q)",
					tt.target, parent, field, tt.wantParent, tt.wantField)
			}
		})
	}
}

// TestApplyRename_Generic 测试通用 rename 操作
func TestApplyRename_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"old_key": "v1", "keep": true},
			map[string]interface{}{"new_key": "v2"},
			map[string]interface{}{"old_key": "v3", "new_key": "existing"},
		},
	}

	changed := applyRename(raw, "items[]", "old_key", "new_key")
	if !changed {
		t.Fatal("应有变更")
	}

	items := raw["items"].([]interface{})
	// 第一个：old_key→new_key
	if items[0].(map[string]interface{})["new_key"] != "v1" {
		t.Error("第一个元素应重命名")
	}
	if _, has := items[0].(map[string]interface{})["old_key"]; has {
		t.Error("旧键应删除")
	}
	// 第二个：已有 new_key，无变化
	if items[1].(map[string]interface{})["new_key"] != "v2" {
		t.Error("第二个元素不应变化")
	}
	// 第三个：已有 new_key，old_key 删除但不覆盖
	if items[2].(map[string]interface{})["new_key"] != "existing" {
		t.Error("已有 new_key 不应被覆盖")
	}
}

// TestApplyDelete_Generic 测试通用 delete 操作
func TestApplyDelete_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"keep": "v1", "remove": "x"},
			map[string]interface{}{"keep": "v2"},
		},
	}

	changed := applyDelete(raw, "items[]", "remove")
	if !changed {
		t.Fatal("应有变更")
	}
	item0 := raw["items"].([]interface{})[0].(map[string]interface{})
	if _, has := item0["remove"]; has {
		t.Error("字段应被删除")
	}
	if item0["keep"] != "v1" {
		t.Error("其他字段应保留")
	}
}

// TestApplySpread_Generic 测试通用 spread 操作
func TestApplySpread_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"defaults": map[string]interface{}{"a": "1", "b": "2"},
		"items": []interface{}{
			map[string]interface{}{"name": "x"},                                         // 无 cfg，完整继承
			map[string]interface{}{"name": "y", "cfg": map[string]interface{}{"a": "override"}}, // 部分，补全 b
			map[string]interface{}{"name": "z", "cfg": map[string]interface{}{"a": "1", "b": "2"}}, // 完整，不变
		},
	}

	changed := applySpread(raw, "defaults", "items[].cfg")
	if !changed {
		t.Fatal("应有变更")
	}
	if _, has := raw["defaults"]; has {
		t.Error("源字段应被删除")
	}

	items := raw["items"].([]interface{})
	// x: 完整继承
	cfg0 := items[0].(map[string]interface{})["cfg"].(map[string]interface{})
	if cfg0["a"] != "1" || cfg0["b"] != "2" {
		t.Errorf("x 应完整继承, got a=%v b=%v", cfg0["a"], cfg0["b"])
	}
	// y: a 保留 override，b 补全
	cfg1 := items[1].(map[string]interface{})["cfg"].(map[string]interface{})
	if cfg1["a"] != "override" {
		t.Errorf("y.a 应保留 override, got %v", cfg1["a"])
	}
	if cfg1["b"] != "2" {
		t.Errorf("y.b 应补全为 2, got %v", cfg1["b"])
	}
	// z: 不变
	cfg2 := items[2].(map[string]interface{})["cfg"].(map[string]interface{})
	if cfg2["a"] != "1" || cfg2["b"] != "2" {
		t.Error("z 不应变化")
	}
}

// TestApplyMove_Generic 测试通用 move 操作
func TestApplyMove_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"api_url":   "https://example.com",
		"api_token": "tok123",
	}

	// 移入不存在的子对象
	changed := applyMove(raw, ".", "api_url", "api")
	if !changed {
		t.Fatal("应有变更")
	}
	if _, has := raw["api_url"]; has {
		t.Error("源字段应被删除")
	}
	api := raw["api"].(map[string]interface{})
	if api["api_url"] != "https://example.com" {
		t.Errorf("api.api_url = %v, 期望 https://example.com", api["api_url"])
	}

	// 移入已有的子对象，不覆盖
	raw["api_token_new"] = "new_value"
	api["api_token_new"] = "existing"
	applyMove(raw, ".", "api_token_new", "api")
	if api["api_token_new"] != "existing" {
		t.Error("已有键不应被覆盖")
	}
}

// TestFillDefaults_Schedule 测试默认值填充
func TestFillDefaults_Schedule(t *testing.T) {
	// 完全缺失 schedule
	raw := map[string]interface{}{
		"certificates": []interface{}{},
	}
	changed := fillDefaults(raw)
	if !changed {
		t.Fatal("缺失 schedule 应触发填充")
	}
	schedule, ok := raw["schedule"].(map[string]interface{})
	if !ok {
		t.Fatal("schedule 应被创建")
	}
	if schedule["renew_before_days"] != float64(DefaultRenewBeforeDays) {
		t.Errorf("renew_before_days = %v, 期望 %d", schedule["renew_before_days"], DefaultRenewBeforeDays)
	}
	if schedule["renew_mode"] != RenewModePull {
		t.Errorf("renew_mode = %v, 期望 %s", schedule["renew_mode"], RenewModePull)
	}
}

// TestFillDefaults_PartialSchedule 已有部分 schedule 字段时仅补齐缺失
func TestFillDefaults_PartialSchedule(t *testing.T) {
	raw := map[string]interface{}{
		"schedule": map[string]interface{}{
			"renew_before_days": float64(7),
		},
	}
	changed := fillDefaults(raw)
	if !changed {
		t.Fatal("缺失 renew_mode 应触发填充")
	}
	schedule := raw["schedule"].(map[string]interface{})
	// 已有值不覆盖
	if schedule["renew_before_days"] != float64(7) {
		t.Errorf("renew_before_days 不应被覆盖, got %v", schedule["renew_before_days"])
	}
	// 缺失值补齐
	if schedule["renew_mode"] != RenewModePull {
		t.Errorf("renew_mode = %v, 期望 %s", schedule["renew_mode"], RenewModePull)
	}
}

// TestFillDefaults_NoChange 完整配置不触发变更
func TestFillDefaults_NoChange(t *testing.T) {
	raw := map[string]interface{}{
		"schedule": map[string]interface{}{
			"renew_before_days": float64(14),
			"renew_mode":        "pull",
		},
	}
	changed := fillDefaults(raw)
	if changed {
		t.Error("完整配置不应触发变更")
	}
}

// TestMigrateConfig_FillsDefaults 集成测试：迁移时自动补齐默认值
func TestMigrateConfig_FillsDefaults(t *testing.T) {
	// 旧配置没有 schedule
	oldCfg := `{"certificates": []}`
	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("缺失 schedule 应触发迁移")
	}
	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	schedule, ok := raw["schedule"].(map[string]interface{})
	if !ok {
		t.Fatal("schedule 应被创建")
	}
	if schedule["renew_before_days"] != float64(DefaultRenewBeforeDays) {
		t.Errorf("renew_before_days = %v, 期望 %v", schedule["renew_before_days"], float64(DefaultRenewBeforeDays))
	}
}

// TestMigrateConfig_GlobalAPI_EmptyAPI 空全局 API 直接删除
func TestMigrateConfig_GlobalAPI_EmptyAPI(t *testing.T) {
	oldCfg := `{
		"api": {},
		"certificates": [{"cert_name": "test", "order_id": 1}]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("空全局 api 应被清理")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	if _, has := raw["api"]; has {
		t.Error("空全局 api 应被删除")
	}
}
