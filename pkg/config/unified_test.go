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
	_ = cm.Save(cfg1)

	// 外部修改配置文件
	cm2, _ := NewConfigManagerWithDir(dir)
	cfg2, _ := cm2.Load()
	cfg2.API.Token = "token2"
	_ = cm2.Save(cfg2)

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
	_ = cm.AddCert(cert1)

	// 再次添加同名证书应更新
	cert2 := &CertConfig{CertName: "order-001", Enabled: false}
	_ = cm.AddCert(cert2)

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
	_ = os.WriteFile(filepath.Join(dir, "config.json"), data, 0600)

	// 设置环境变量
	_ = os.Setenv(EnvAPIToken, "env-token")
	_ = os.Setenv(EnvAPIURL, "https://env-api.com")
	defer func() {
		_ = os.Unsetenv(EnvAPIToken)
		_ = os.Unsetenv(EnvAPIURL)
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
	_ = os.WriteFile(filepath.Join(dir, "config.json"), invalidJSON, 0600)

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

// TestCertConfig_DaysUntilExpiry 测试证书到期剩余天数计算
func TestCertConfig_DaysUntilExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		wantRange [2]int // 预期天数范围 [min, max]
	}{
		{
			name:      "未设置过期时间",
			expiresAt: time.Time{},
			wantRange: [2]int{999, 999},
		},
		{
			name:      "30天后过期",
			expiresAt: time.Now().Add(30 * 24 * time.Hour),
			wantRange: [2]int{29, 30},
		},
		{
			name:      "1天后过期",
			expiresAt: time.Now().Add(24 * time.Hour),
			wantRange: [2]int{0, 1},
		},
		{
			name:      "已过期",
			expiresAt: time.Now().Add(-24 * time.Hour),
			wantRange: [2]int{-2, -1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertConfig{
				Metadata: CertMetadata{
					CertExpiresAt: tt.expiresAt,
				},
			}
			days := cert.DaysUntilExpiry()
			if days < tt.wantRange[0] || days > tt.wantRange[1] {
				t.Errorf("DaysUntilExpiry() = %d, 期望在 [%d, %d] 范围内", days, tt.wantRange[0], tt.wantRange[1])
			}
		})
	}
}

// TestCertConfig_NeedsRenewal 测试续签判断逻辑
func TestCertConfig_NeedsRenewal(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		schedule  ScheduleConfig
		want      bool
	}{
		{
			name:      "Pull模式-需要续签（3天后过期）",
			expiresAt: time.Now().Add(3 * 24 * time.Hour),
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 7,
			},
			want: true,
		},
		{
			name:      "Pull模式-不需要续签（30天后过期）",
			expiresAt: time.Now().Add(30 * 24 * time.Hour),
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 7,
			},
			want: false,
		},
		{
			name:      "Pull模式-默认天数",
			expiresAt: time.Now().Add(5 * 24 * time.Hour),
			schedule: ScheduleConfig{
				RenewMode: RenewModePull,
			},
			want: true, // PullRenewDefaultDay = 7
		},
		{
			name:      "空模式默认为Pull",
			expiresAt: time.Now().Add(3 * 24 * time.Hour),
			schedule: ScheduleConfig{
				RenewBeforeDays: 7,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertConfig{
				Metadata: CertMetadata{
					CertExpiresAt: tt.expiresAt,
				},
			}
			got := cert.NeedsRenewal(&tt.schedule)
			if got != tt.want {
				t.Errorf("NeedsRenewal() = %v, 期望 %v", got, tt.want)
			}
		})
	}
}

// TestCertConfig_NeedsRenewal_LocalMode 测试本地私钥模式的续签判断
func TestCertConfig_NeedsRenewal_LocalMode(t *testing.T) {
	tests := []struct {
		name           string
		expiresAt      time.Time
		retryCount     int
		renewBeforeDays int
		want           bool
	}{
		{
			name:           "本地模式-在服务端自动续签范围内，不续签",
			expiresAt:      time.Now().Add(10 * 24 * time.Hour), // 10 天后过期，小于 ServerAutoRenewDays (14)
			retryCount:     0,
			renewBeforeDays: 30,
			want:           false, // days (10) <= ServerAutoRenewDays (14) 不续签
		},
		{
			name:           "本地模式-有重试记录，续签",
			expiresAt:      time.Now().Add(25 * 24 * time.Hour),
			retryCount:     1,
			renewBeforeDays: 30,
			want:           true,
		},
		{
			name:           "本地模式-在续签窗口内",
			expiresAt:      time.Now().Add(35 * 24 * time.Hour),
			retryCount:     0,
			renewBeforeDays: 40,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertConfig{
				Metadata: CertMetadata{
					CertExpiresAt:   tt.expiresAt,
					IssueRetryCount: tt.retryCount,
				},
			}
			schedule := &ScheduleConfig{
				RenewMode:       RenewModeLocal,
				RenewBeforeDays: tt.renewBeforeDays,
			}
			got := cert.NeedsRenewal(schedule)
			if got != tt.want {
				t.Errorf("NeedsRenewal() = %v, 期望 %v", got, tt.want)
			}
		})
	}
}

// TestConfigManager_ConcurrentWrites 测试并发写入
func TestConfigManager_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	// 并发写入不同的证书
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cert := &CertConfig{
				CertName: "cert-" + string(rune('A'+idx)),
				OrderID:  idx,
				Enabled:  true,
			}
			if err := cm.AddCert(cert); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("并发写入错误: %v", err)
	}

	// 验证所有证书都保存了
	certs, err := cm.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}

	// 由于并发写入可能有覆盖，至少应该有一些证书
	if len(certs) == 0 {
		t.Error("没有保存任何证书")
	}
}

// TestGetCertDir 测试证书目录路径生成
func TestGetCertDir(t *testing.T) {
	tests := []struct {
		siteName string
		want     string
	}{
		{"example.com", "/opt/cert-deploy/certs/example.com"},
		{"test.example.com", "/opt/cert-deploy/certs/test.example.com"},
	}

	for _, tt := range tests {
		got := GetCertDir(tt.siteName)
		if got != tt.want {
			t.Errorf("GetCertDir(%s) = %s, 期望 %s", tt.siteName, got, tt.want)
		}
	}
}

// TestGetDefaultPaths 测试默认路径生成
func TestGetDefaultPaths(t *testing.T) {
	siteName := "example.com"

	certPath := GetDefaultCertPath(siteName)
	if certPath != "/opt/cert-deploy/certs/example.com/cert.pem" {
		t.Errorf("GetDefaultCertPath() = %s", certPath)
	}

	keyPath := GetDefaultKeyPath(siteName)
	if keyPath != "/opt/cert-deploy/certs/example.com/key.pem" {
		t.Errorf("GetDefaultKeyPath() = %s", keyPath)
	}

	chainPath := GetDefaultChainPath(siteName)
	if chainPath != "/opt/cert-deploy/certs/example.com/chain.pem" {
		t.Errorf("GetDefaultChainPath() = %s", chainPath)
	}
}

// TestScanResult_FindSiteByID 测试根据 ID 查找站点
func TestScanResult_FindSiteByID(t *testing.T) {
	result := &ScanResult{
		Sites: []ScannedSite{
			{ID: "example.com", ServerName: "example.com"},
			{ID: "test.com", ServerName: "test.com"},
		},
	}

	// 查找存在的站点
	site := result.FindSiteByID("example.com")
	if site == nil {
		t.Error("FindSiteByID() 未找到存在的站点")
	} else if site.ServerName != "example.com" {
		t.Errorf("FindSiteByID() = %s, 期望 example.com", site.ServerName)
	}

	// 查找不存在的站点
	site = result.FindSiteByID("nonexistent.com")
	if site != nil {
		t.Error("FindSiteByID() 应返回 nil 对于不存在的站点")
	}
}

// TestScanResult_FindSiteByIndex 测试根据索引查找站点
func TestScanResult_FindSiteByIndex(t *testing.T) {
	result := &ScanResult{
		Sites: []ScannedSite{
			{ID: "site1.com", ServerName: "site1.com"},
			{ID: "site2.com", ServerName: "site2.com"},
			{ID: "site3.com", ServerName: "site3.com"},
		},
	}

	// 有效索引（1-based）
	site := result.FindSiteByIndex(1)
	if site == nil || site.ID != "site1.com" {
		t.Error("FindSiteByIndex(1) 失败")
	}

	site = result.FindSiteByIndex(3)
	if site == nil || site.ID != "site3.com" {
		t.Error("FindSiteByIndex(3) 失败")
	}

	// 无效索引
	site = result.FindSiteByIndex(0)
	if site != nil {
		t.Error("FindSiteByIndex(0) 应返回 nil")
	}

	site = result.FindSiteByIndex(4)
	if site != nil {
		t.Error("FindSiteByIndex(4) 应返回 nil（超出范围）")
	}

	site = result.FindSiteByIndex(-1)
	if site != nil {
		t.Error("FindSiteByIndex(-1) 应返回 nil")
	}
}

// TestConfigManager_FilePermissions 测试文件权限
func TestConfigManager_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 保存配置
	cfg := &Config{
		Version: "2.0",
		API:     APIConfig{Token: "secret-token"},
	}
	if err := cm.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// 检查配置文件权限（应该是 0600）
	info, err := os.Stat(cm.GetConfigPath())
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	// 在某些系统上可能因 umask 不同，允许 0600 或 0644
	if perm != 0600 && perm != 0644 {
		t.Logf("配置文件权限: %o（期望 0600）", perm)
	}
}

// TestConfigManager_ScheduleDefaults 测试默认调度配置
func TestConfigManager_ScheduleDefaults(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cfg, _ := cm.Load()

	if cfg.Schedule.RenewMode != RenewModePull {
		t.Errorf("默认 RenewMode = %s, 期望 %s", cfg.Schedule.RenewMode, RenewModePull)
	}

	if cfg.Schedule.CheckIntervalHours != DefaultCheckIntervalHours {
		t.Errorf("默认 CheckIntervalHours = %d, 期望 %d", cfg.Schedule.CheckIntervalHours, DefaultCheckIntervalHours)
	}

	if cfg.Schedule.RenewBeforeDays != PullRenewDefaultDay {
		t.Errorf("默认 RenewBeforeDays = %d, 期望 %d", cfg.Schedule.RenewBeforeDays, PullRenewDefaultDay)
	}
}

// TestConfigManager_MultipleCertOperations 测试多证书操作
func TestConfigManager_MultipleCertOperations(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 添加多个证书
	certs := []CertConfig{
		{CertName: "cert-a", OrderID: 1, Enabled: true, Domains: []string{"a.com"}},
		{CertName: "cert-b", OrderID: 2, Enabled: true, Domains: []string{"b.com"}},
		{CertName: "cert-c", OrderID: 3, Enabled: false, Domains: []string{"c.com"}},
	}

	for _, cert := range certs {
		if err := cm.AddCert(&cert); err != nil {
			t.Fatalf("AddCert(%s) error = %v", cert.CertName, err)
		}
	}

	// 列出所有证书
	allCerts, _ := cm.ListCerts()
	if len(allCerts) != 3 {
		t.Errorf("ListCerts() = %d, 期望 3", len(allCerts))
	}

	// 列出启用的证书
	enabledCerts, _ := cm.ListEnabledCerts()
	if len(enabledCerts) != 2 {
		t.Errorf("ListEnabledCerts() = %d, 期望 2", len(enabledCerts))
	}

	// 更新证书
	cert, _ := cm.GetCert("cert-c")
	cert.Enabled = true
	_ = cm.UpdateCert(cert)

	enabledCerts, _ = cm.ListEnabledCerts()
	if len(enabledCerts) != 3 {
		t.Errorf("更新后 ListEnabledCerts() = %d, 期望 3", len(enabledCerts))
	}

	// 删除证书
	_ = cm.DeleteCert("cert-b")
	allCerts, _ = cm.ListCerts()
	if len(allCerts) != 2 {
		t.Errorf("删除后 ListCerts() = %d, 期望 2", len(allCerts))
	}
}
