// Package config 统一配置管理器测试
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestNewConfigManagerWithDir 测试自定义目录创建
func TestNewConfigManagerWithDir(t *testing.T) {
	dir := t.TempDir()

	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}

	// 验证目录创建
	dirs := []string{
		cm.GetWorkDir(),
		cm.GetCertsDir(),
		cm.GetLogsDir(),
		cm.GetBackupDir(),
	}

	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("directory %s not created: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}

	// 验证路径正确
	if cm.GetWorkDir() != dir {
		t.Errorf("GetWorkDir() = %s, want %s", cm.GetWorkDir(), dir)
	}

	if cm.GetConfigPath() != filepath.Join(dir, "config.json") {
		t.Errorf("GetConfigPath() = %s, want %s", cm.GetConfigPath(), filepath.Join(dir, "config.json"))
	}
}

// TestConfigManager_LoadDefault 测试加载默认配置
func TestConfigManager_LoadDefault(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 配置文件不存在时应返回默认配置
	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Version != "2.0" {
		t.Errorf("default config Version = %s, want 2.0", cfg.Version)
	}

	if cfg.Schedule.RenewMode != RenewModePull {
		t.Errorf("default RenewMode = %s, want %s", cfg.Schedule.RenewMode, RenewModePull)
	}

	if len(cfg.Certificates) != 0 {
		t.Errorf("default Certificates length = %d, want 0", len(cfg.Certificates))
	}
}

// TestConfigManager_SaveAndLoad 测试保存和加载配置
func TestConfigManager_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 创建测试配置
	cfg := &Config{
		Version: "2.0",
		API: APIConfig{
			URL:   "https://api.example.com",
			Token: "test-token",
		},
		Schedule: ScheduleConfig{
			CheckIntervalHours: 12,
			RenewBeforeDays:    7,
			RenewMode:          RenewModePull,
		},
		Certificates: []CertConfig{
			{
				CertName: "order-12345",
				OrderID:  12345,
				Enabled:  true,
				Domains:  []string{"example.com", "*.example.com"},
			},
		},
	}

	// 保存配置
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// 验证文件存在
	if !cm.ConfigExists() {
		t.Error("ConfigExists() = false after Save")
	}

	// 重新加载验证
	cm2, _ := NewConfigManagerWithDir(dir)
	loaded, err := cm2.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.API.URL != cfg.API.URL {
		t.Errorf("loaded API.URL = %s, want %s", loaded.API.URL, cfg.API.URL)
	}

	if loaded.API.Token != cfg.API.Token {
		t.Errorf("loaded API.Token = %s, want %s", loaded.API.Token, cfg.API.Token)
	}

	if len(loaded.Certificates) != 1 {
		t.Fatalf("loaded Certificates length = %d, want 1", len(loaded.Certificates))
	}

	if loaded.Certificates[0].CertName != "order-12345" {
		t.Errorf("loaded CertName = %s, want order-12345", loaded.Certificates[0].CertName)
	}
}

// TestConfigManager_Reload 测试重新加载配置
func TestConfigManager_Reload(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 先加载默认配置
	cfg1, _ := cm.Load()
	cfg1.API.Token = "token1"
	cm.Save(cfg1)

	// 外部修改配置文件
	cm2, _ := NewConfigManagerWithDir(dir)
	cfg2, _ := cm2.Load()
	cfg2.API.Token = "token2"
	cm2.Save(cfg2)

	// 原 cm 重新加载
	reloaded, err := cm.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if reloaded.API.Token != "token2" {
		t.Errorf("reloaded Token = %s, want token2", reloaded.API.Token)
	}
}

// TestConfigManager_CertCRUD 测试证书 CRUD 操作
func TestConfigManager_CertCRUD(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 添加证书
	cert := &CertConfig{
		CertName: "order-001",
		OrderID:  1,
		Enabled:  true,
		Domains:  []string{"example.com"},
	}

	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	// 获取证书
	got, err := cm.GetCert("order-001")
	if err != nil {
		t.Fatalf("GetCert() error = %v", err)
	}
	if got.OrderID != 1 {
		t.Errorf("got OrderID = %d, want 1", got.OrderID)
	}

	// 根据订单 ID 获取
	got2, err := cm.GetCertByOrderID(1)
	if err != nil {
		t.Fatalf("GetCertByOrderID() error = %v", err)
	}
	if got2.CertName != "order-001" {
		t.Errorf("got CertName = %s, want order-001", got2.CertName)
	}

	// 更新证书
	cert.Enabled = false
	if err := cm.UpdateCert(cert); err != nil {
		t.Fatalf("UpdateCert() error = %v", err)
	}

	got3, _ := cm.GetCert("order-001")
	if got3.Enabled != false {
		t.Error("UpdateCert() did not update Enabled field")
	}

	// 列出证书
	certs, err := cm.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("ListCerts() length = %d, want 1", len(certs))
	}

	// 列出启用的证书（现在应该是 0）
	enabled, _ := cm.ListEnabledCerts()
	if len(enabled) != 0 {
		t.Errorf("ListEnabledCerts() length = %d, want 0", len(enabled))
	}

	// 删除证书
	if err := cm.DeleteCert("order-001"); err != nil {
		t.Fatalf("DeleteCert() error = %v", err)
	}

	_, err = cm.GetCert("order-001")
	if err == nil {
		t.Error("GetCert() should return error after delete")
	}
}

// TestConfigManager_AddCertUpdate 测试添加证书时更新已存在的证书
func TestConfigManager_AddCertUpdate(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cert1 := &CertConfig{CertName: "order-001", Enabled: true}
	cm.AddCert(cert1)

	// 再次添加同名证书应更新
	cert2 := &CertConfig{CertName: "order-001", Enabled: false}
	cm.AddCert(cert2)

	got, _ := cm.GetCert("order-001")
	if got.Enabled != false {
		t.Error("AddCert should update existing cert")
	}

	certs, _ := cm.ListCerts()
	if len(certs) != 1 {
		t.Errorf("should have 1 cert, got %d", len(certs))
	}
}

// TestConfigManager_SetAPI 测试设置 API 配置
func TestConfigManager_SetAPI(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	api := APIConfig{
		URL:   "https://new-api.example.com",
		Token: "new-token",
	}

	if err := cm.SetAPI(api); err != nil {
		t.Fatalf("SetAPI() error = %v", err)
	}

	cfg, _ := cm.Load()
	if cfg.API.URL != api.URL {
		t.Errorf("API.URL = %s, want %s", cfg.API.URL, api.URL)
	}
}

// TestConfigManager_InitConfig 测试初始化配置
func TestConfigManager_InitConfig(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	if err := cm.InitConfig("https://api.test.com", "init-token"); err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}

	cfg, _ := cm.Load()
	if cfg.API.URL != "https://api.test.com" {
		t.Errorf("API.URL = %s, want https://api.test.com", cfg.API.URL)
	}
	if cfg.API.Token != "init-token" {
		t.Errorf("API.Token = %s, want init-token", cfg.API.Token)
	}
}

// TestConfigManager_EnvOverride 测试环境变量覆盖
func TestConfigManager_EnvOverride(t *testing.T) {
	dir := t.TempDir()

	// 先保存一个配置
	cfg := &Config{
		Version: "2.0",
		API: APIConfig{
			URL:   "https://file-api.com",
			Token: "file-token",
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(filepath.Join(dir, "config.json"), data, 0600)

	// 设置环境变量
	os.Setenv(EnvAPIToken, "env-token")
	os.Setenv(EnvAPIURL, "https://env-api.com")
	defer func() {
		os.Unsetenv(EnvAPIToken)
		os.Unsetenv(EnvAPIURL)
	}()

	cm, _ := NewConfigManagerWithDir(dir)
	loaded, _ := cm.Load()

	// 环境变量应该覆盖文件配置
	if loaded.API.Token != "env-token" {
		t.Errorf("API.Token = %s, want env-token (from env)", loaded.API.Token)
	}
	if loaded.API.URL != "https://env-api.com" {
		t.Errorf("API.URL = %s, want https://env-api.com (from env)", loaded.API.URL)
	}
}

// TestConfigManager_Metadata 测试元数据自动更新
func TestConfigManager_Metadata(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cfg := &Config{Version: "2.0"}
	before := time.Now()

	if err := cm.Save(cfg); err != nil {
		t.Fatal(err)
	}

	after := time.Now()

	loaded, _ := cm.Reload()

	if loaded.Metadata.CreatedAt.Before(before) || loaded.Metadata.CreatedAt.After(after) {
		t.Error("CreatedAt should be set to current time")
	}

	if loaded.Metadata.UpdatedAt.Before(before) || loaded.Metadata.UpdatedAt.After(after) {
		t.Error("UpdatedAt should be set to current time")
	}
}

// TestConfigManager_GetSiteCertsDir 测试站点证书目录
func TestConfigManager_GetSiteCertsDir(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	siteCertsDir := cm.GetSiteCertsDir("example.com")
	expected := filepath.Join(dir, "certs", "example.com")

	if siteCertsDir != expected {
		t.Errorf("GetSiteCertsDir() = %s, want %s", siteCertsDir, expected)
	}
}

// TestConfigManager_EnsureSiteCertsDir 测试确保站点证书目录存在
func TestConfigManager_EnsureSiteCertsDir(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	siteCertsDir, err := cm.EnsureSiteCertsDir("example.com")
	if err != nil {
		t.Fatalf("EnsureSiteCertsDir() error = %v", err)
	}

	info, err := os.Stat(siteCertsDir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("created path is not a directory")
	}
}

// TestConfigManager_InvalidJSON 测试无效 JSON 配置
func TestConfigManager_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	// 写入无效 JSON
	invalidJSON := []byte(`{"version": "2.0", invalid json}`)
	os.WriteFile(filepath.Join(dir, "config.json"), invalidJSON, 0600)

	cm, _ := NewConfigManagerWithDir(dir)
	_, err := cm.Load()

	if err == nil {
		t.Error("Load() should return error for invalid JSON")
	}
}

// TestConfigManager_NotFoundErrors 测试查找不存在的证书
func TestConfigManager_NotFoundErrors(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 获取不存在的证书
	_, err := cm.GetCert("nonexistent")
	if err == nil {
		t.Error("GetCert() should return error for nonexistent cert")
	}

	// 根据订单 ID 获取不存在的证书
	_, err = cm.GetCertByOrderID(99999)
	if err == nil {
		t.Error("GetCertByOrderID() should return error for nonexistent order")
	}

	// 更新不存在的证书
	err = cm.UpdateCert(&CertConfig{CertName: "nonexistent"})
	if err == nil {
		t.Error("UpdateCert() should return error for nonexistent cert")
	}

	// 删除不存在的证书
	err = cm.DeleteCert("nonexistent")
	if err == nil {
		t.Error("DeleteCert() should return error for nonexistent cert")
	}
}

// TestConfigManager_ConcurrentAccess 测试并发访问
func TestConfigManager_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	// 并发读取（读取操作应该是安全的）
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cm.Load()
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent access error: %v", err)
	}

	// 顺序写入（避免竞态条件）
	for i := 0; i < 5; i++ {
		cert := &CertConfig{
			CertName: "seq-cert-" + string(rune('A'+i)),
			OrderID:  i,
		}
		if err := cm.AddCert(cert); err != nil {
			t.Errorf("sequential AddCert error: %v", err)
		}
	}
}

// TestConfigManager_LoadCaching 测试配置加载缓存
func TestConfigManager_LoadCaching(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 首次加载
	cfg1, _ := cm.Load()
	cfg1.API.Token = "cached"

	// 第二次加载应返回相同对象（从缓存）
	cfg2, _ := cm.Load()

	// 由于返回的是缓存的同一对象，修改会反映
	if cfg2.API.Token != "cached" {
		t.Error("Load() should return cached config")
	}
}
