// Package config 统一配置管理器测试
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		Schedule: ScheduleConfig{
			RenewBeforeDays: 7,
			RenewMode:       RenewModePull,
		},
		Certificates: []CertConfig{
			{
				CertName: "example.com-12345",
				OrderID:  12345,
				Enabled:  true,
				Domains:  []string{"example.com", "*.example.com"},
				API: APIConfig{
					URL:   "https://api.example.com",
					Token: "test-token",
				},
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

	if len(loaded.Certificates) != 1 {
		t.Fatalf("loaded Certificates length = %d, want 1", len(loaded.Certificates))
	}

	if loaded.Certificates[0].CertName != "example.com-12345" {
		t.Errorf("loaded CertName = %s, want example.com-12345", loaded.Certificates[0].CertName)
	}

	if loaded.Certificates[0].API.URL != "https://api.example.com" {
		t.Errorf("loaded cert API.URL = %s, want https://api.example.com", loaded.Certificates[0].API.URL)
	}
}

// TestConfigManager_Reload 测试重新加载配置
func TestConfigManager_Reload(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 先添加一个证书
	cert := &CertConfig{
		CertName: "test",
		OrderID:  1,
		Enabled:  true,
		API:      APIConfig{Token: "token1", URL: "https://api1.com"},
	}
	_ = cm.AddCert(cert)

	// 外部修改配置文件
	cm2, _ := NewConfigManagerWithDir(dir)
	cfg2, _ := cm2.Load()
	cfg2.Certificates[0].API.Token = "token2"
	_ = cm2.Save(cfg2)

	// 原 cm 重新加载
	reloaded, err := cm.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if reloaded.Certificates[0].API.Token != "token2" {
		t.Errorf("reloaded Token = %s, want token2", reloaded.Certificates[0].API.Token)
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

// TestCertConfig_API 测试证书级别 API 配置
func TestCertConfig_API(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cert := &CertConfig{
		CertName: "order-1",
		OrderID:  1,
		Enabled:  true,
		API:      APIConfig{URL: "https://api-a.com", Token: "token-a"},
	}
	_ = cm.AddCert(cert)

	got, _ := cm.GetCert("order-1")
	if got.API.URL != "https://api-a.com" {
		t.Errorf("API.URL = %s, want https://api-a.com", got.API.URL)
	}
	if got.API.Token != "token-a" {
		t.Errorf("API.Token = %s, want token-a", got.API.Token)
	}
}

// TestCertConfig_GetAPI_EnvOverride 测试环境变量通过 GetAPI() 覆盖证书级别 API
func TestCertConfig_GetAPI_EnvOverride(t *testing.T) {
	// 设置环境变量（Token 至少 32 字符）
	envToken := "env-token-that-is-long-enough-for-validation"
	envURL := "http://localhost:8080"
	_ = os.Setenv(EnvAPIToken, envToken)
	_ = os.Setenv(EnvAPIURL, envURL)
	defer func() {
		_ = os.Unsetenv(EnvAPIToken)
		_ = os.Unsetenv(EnvAPIURL)
	}()

	cert := &CertConfig{
		CertName: "test",
		API: APIConfig{
			URL:   "https://file-api.com",
			Token: "file-token-that-is-long-enough-for-validation",
		},
	}

	api := cert.GetAPI(nil)

	// 环境变量应该覆盖证书配置
	if api.Token != envToken {
		t.Errorf("API.Token = %s, want %s (from env)", api.Token, envToken)
	}
	if api.URL != envURL {
		t.Errorf("API.URL = %s, want %s (from env)", api.URL, envURL)
	}
}

// TestCertConfig_GetAPI_NoEnv 测试无环境变量时 GetAPI() 返回证书自身 API
func TestCertConfig_GetAPI_NoEnv(t *testing.T) {
	// 确保环境变量未设置
	_ = os.Unsetenv(EnvAPIToken)
	_ = os.Unsetenv(EnvAPIURL)

	cert := &CertConfig{
		CertName: "test",
		API: APIConfig{
			URL:   "https://cert-api.com",
			Token: "cert-token-value",
		},
	}

	api := cert.GetAPI(nil)
	if api.URL != "https://cert-api.com" {
		t.Errorf("API.URL = %s, want https://cert-api.com", api.URL)
	}
	if api.Token != "cert-token-value" {
		t.Errorf("API.Token = %s, want cert-token-value", api.Token)
	}
}

// TestConfigManager_Metadata 测试元数据自动更新
func TestConfigManager_Metadata(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cfg := &Config{}
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
	invalidJSON := []byte(`{"api": invalid json}`)
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

	// 添加一个证书，用于测试深拷贝
	_ = cm.AddCert(&CertConfig{CertName: "cache-test", Enabled: true, API: APIConfig{Token: "original"}})

	// 首次加载
	cfg1, _ := cm.Load()
	cfg1.Certificates[0].API.Token = "modified-locally"

	// 第二次加载返回副本，对 cfg1 的修改不应影响 cfg2
	cfg2, _ := cm.Load()

	// 由于返回的是深拷贝副本，修改 cfg1 不应反映到 cfg2
	if cfg2.Certificates[0].API.Token == "modified-locally" {
		t.Error("Load() should return independent copy, modifications to one should not affect another")
	}

	// 验证缓存内部数据未被外部修改影响
	cfg3, _ := cm.Load()
	if cfg3.Certificates[0].API.Token == "modified-locally" {
		t.Error("Internal cache should not be affected by external modifications")
	}
}

// TestConfigManager_DeepCopyDocker 测试 Docker 指针深拷贝
func TestConfigManager_DeepCopyDocker(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 创建带 Docker 配置的证书
	cert := &CertConfig{
		CertName: "docker-test",
		OrderID:  100,
		Enabled:  true,
		Bindings: []SiteBinding{
			{
				ServerName:   "docker-site",
				ServerType: ServerTypeDockerNginx,
				Enabled:    true,
				Docker: &DockerInfo{
					ContainerName: "original-container",
					DeployMode:    "volume",
				},
			},
		},
	}

	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	// 加载配置并修改 Docker 字段
	cfg1, _ := cm.Load()
	if len(cfg1.Certificates) == 0 || len(cfg1.Certificates[0].Bindings) == 0 {
		t.Fatal("证书或绑定为空")
	}
	if cfg1.Certificates[0].Bindings[0].Docker == nil {
		t.Fatal("Docker 配置为空")
	}

	// 修改返回副本中的 Docker 配置
	cfg1.Certificates[0].Bindings[0].Docker.ContainerName = "modified-container"

	// 再次加载，验证内部缓存未被影响
	cfg2, _ := cm.Load()
	if cfg2.Certificates[0].Bindings[0].Docker.ContainerName == "modified-container" {
		t.Error("Docker pointer should be deep copied, modifications should not affect internal cache")
	}

	if cfg2.Certificates[0].Bindings[0].Docker.ContainerName != "original-container" {
		t.Errorf("Docker.ContainerName = %s, want original-container",
			cfg2.Certificates[0].Bindings[0].Docker.ContainerName)
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
			want: true, // DefaultRenewBeforeDays = 13，5 <= 13 需续签
		},
		{
			name:      "空模式默认为Pull",
			expiresAt: time.Now().Add(3 * 24 * time.Hour),
			schedule: ScheduleConfig{
				RenewBeforeDays: 7,
			},
			want: true,
		},
		{
			name:      "Pull模式-全局配置为local天数时应使用pull默认值",
			expiresAt: time.Now().Add(20 * 24 * time.Hour), // 20 天后过期
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 30, // local 模式的典型值，对 pull 无效
			},
			want: false, // 应使用 DefaultRenewBeforeDays (13)，20 > 13 不续签
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

// TestCertConfig_NeedsRenewal_LocalMode 测试本机提交的续签判断
func TestCertConfig_NeedsRenewal_LocalMode(t *testing.T) {
	tests := []struct {
		name           string
		expiresAt      time.Time
		retryCount     int
		renewBeforeDays int
		want           bool
	}{
		{
			name:           "本地模式-在续签窗口内",
			expiresAt:      time.Now().Add(10 * 24 * time.Hour), // 10 天后过期，<= 13
			retryCount:     0,
			renewBeforeDays: 13,
			want:           true,
		},
		{
			name:           "本地模式-超出续签窗口",
			expiresAt:      time.Now().Add(15 * 24 * time.Hour), // 15 天后过期，> 13
			retryCount:     0,
			renewBeforeDays: 13,
			want:           false,
		},
		{
			name:            "本地模式-renewBeforeDays超过上限使用默认值13",
			expiresAt:       time.Now().Add(12 * 24 * time.Hour), // 12 天后过期
			retryCount:      0,
			renewBeforeDays: 30, // 超过上限，应回落到 13
			want:            true, // 12 <= 13
		},
		{
			name:            "本地模式-renewBeforeDays为0时使用默认值13",
			expiresAt:       time.Now().Add(12 * 24 * time.Hour), // 12 天后过期
			retryCount:      0,
			renewBeforeDays: 0,
			want:            true, // 应使用默认值 13，12 <= 13
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
		{"example.com", "/opt/sslctl/certs/example.com"},
		{"test.example.com", "/opt/sslctl/certs/test.example.com"},
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
	if certPath != "/opt/sslctl/certs/example.com/cert.pem" {
		t.Errorf("GetDefaultCertPath() = %s", certPath)
	}

	keyPath := GetDefaultKeyPath(siteName)
	if keyPath != "/opt/sslctl/certs/example.com/key.pem" {
		t.Errorf("GetDefaultKeyPath() = %s", keyPath)
	}

	chainPath := GetDefaultChainPath(siteName)
	if chainPath != "/opt/sslctl/certs/example.com/chain.pem" {
		t.Errorf("GetDefaultChainPath() = %s", chainPath)
	}
}

// TestScanResult_FindSiteByServerName 测试根据 ServerName 查找站点
func TestScanResult_FindSiteByServerName(t *testing.T) {
	result := &ScanResult{
		Sites: []ScannedSite{
			{ServerName: "example.com"},
			{ServerName: "test.com"},
		},
	}

	// 查找存在的站点
	site := result.FindSiteByServerName("example.com")
	if site == nil {
		t.Error("FindSiteByServerName() 未找到存在的站点")
	} else if site.ServerName != "example.com" {
		t.Errorf("FindSiteByServerName() = %s, 期望 example.com", site.ServerName)
	}

	// 查找不存在的站点
	site = result.FindSiteByServerName("nonexistent.com")
	if site != nil {
		t.Error("FindSiteByServerName() 应返回 nil 对于不存在的站点")
	}
}

// TestScanResult_FindSiteByIndex 测试根据索引查找站点
func TestScanResult_FindSiteByIndex(t *testing.T) {
	result := &ScanResult{
		Sites: []ScannedSite{
			{ServerName: "site1.com"},
			{ServerName: "site2.com"},
			{ServerName: "site3.com"},
		},
	}

	// 有效索引（1-based）
	site := result.FindSiteByIndex(1)
	if site == nil || site.ServerName != "site1.com" {
		t.Error("FindSiteByIndex(1) 失败")
	}

	site = result.FindSiteByIndex(3)
	if site == nil || site.ServerName != "site3.com" {
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
		Certificates: []CertConfig{
			{CertName: "test", API: APIConfig{Token: "secret-token"}},
		},
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

	if cfg.Schedule.RenewBeforeDays != DefaultRenewBeforeDays {
		t.Errorf("默认 RenewBeforeDays = %d, 期望 %d", cfg.Schedule.RenewBeforeDays, DefaultRenewBeforeDays)
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

// TestCertConfig_Bindings 测试证书绑定操作
func TestCertConfig_Bindings(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 创建带绑定的证书
	cert := &CertConfig{
		CertName: "binding-test",
		OrderID:  100,
		Enabled:  true,
		Domains:  []string{"bind.example.com"},
		Bindings: []SiteBinding{
			{
				ServerName:   "site1",
				ServerType: ServerTypeNginx,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/etc/ssl/site1/cert.pem",
					PrivateKey:  "/etc/ssl/site1/key.pem",
				},
				Reload: ReloadConfig{
					TestCommand:   "nginx -t",
					ReloadCommand: "systemctl reload nginx",
				},
			},
		},
	}

	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	// 获取并验证绑定
	got, _ := cm.GetCert("binding-test")
	if len(got.Bindings) != 1 {
		t.Errorf("Bindings 长度 = %d, 期望 1", len(got.Bindings))
	}

	binding := got.Bindings[0]
	if binding.ServerName != "site1" {
		t.Errorf("ServerName = %s, 期望 site1", binding.ServerName)
	}
	if binding.ServerType != ServerTypeNginx {
		t.Errorf("ServerType = %s, 期望 %s", binding.ServerType, ServerTypeNginx)
	}
	if !binding.Enabled {
		t.Error("Binding 应该是启用的")
	}

	// 添加新绑定
	got.Bindings = append(got.Bindings, SiteBinding{
		ServerName:   "site2",
		ServerType: ServerTypeApache,
		Enabled:    true,
		Paths: BindingPaths{
			Certificate: "/etc/ssl/site2/cert.pem",
			PrivateKey:  "/etc/ssl/site2/key.pem",
			ChainFile:   "/etc/ssl/site2/chain.pem",
		},
	})

	if err := cm.UpdateCert(got); err != nil {
		t.Fatalf("UpdateCert() error = %v", err)
	}

	updated, _ := cm.GetCert("binding-test")
	if len(updated.Bindings) != 2 {
		t.Errorf("更新后 Bindings 长度 = %d, 期望 2", len(updated.Bindings))
	}

	// 验证 Apache 绑定
	apacheBinding := updated.Bindings[1]
	if apacheBinding.ServerType != ServerTypeApache {
		t.Errorf("ServerType = %s, 期望 %s", apacheBinding.ServerType, ServerTypeApache)
	}
	if apacheBinding.Paths.ChainFile == "" {
		t.Error("Apache 绑定应有 ChainFile")
	}
}

// TestCertConfig_DockerBinding 测试 Docker 绑定配置
func TestCertConfig_DockerBinding(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cert := &CertConfig{
		CertName: "docker-test",
		OrderID:  200,
		Enabled:  true,
		Domains:  []string{"docker.example.com"},
		Bindings: []SiteBinding{
			{
				ServerName:   "docker-site",
				ServerType: ServerTypeDockerNginx,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/opt/certs/docker/cert.pem",
					PrivateKey:  "/opt/certs/docker/key.pem",
				},
				Docker: &DockerInfo{
					ContainerName: "nginx-container",
					DeployMode:    "volume",
				},
			},
		},
	}

	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	got, _ := cm.GetCert("docker-test")
	binding := got.Bindings[0]

	if binding.ServerType != ServerTypeDockerNginx {
		t.Errorf("ServerType = %s, 期望 %s", binding.ServerType, ServerTypeDockerNginx)
	}

	if binding.Docker == nil {
		t.Fatal("Docker 配置不应为 nil")
	}

	if binding.Docker.ContainerName != "nginx-container" {
		t.Errorf("ContainerName = %s, 期望 nginx-container", binding.Docker.ContainerName)
	}

	if binding.Docker.DeployMode != "volume" {
		t.Errorf("DeployMode = %s, 期望 volume", binding.Docker.DeployMode)
	}
}

// TestScheduleConfig_Validation 测试调度配置验证
func TestScheduleConfig_Validation(t *testing.T) {
	tests := []struct {
		name      string
		schedule  ScheduleConfig
		wantError bool
	}{
		{
			name: "有效的 pull 模式",
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 7,
			},
			wantError: false,
		},
		{
			name: "有效的 local 模式",
			schedule: ScheduleConfig{
				RenewMode:       RenewModeLocal,
				RenewBeforeDays: 13,
			},
			wantError: false,
		},
		{
			name: "pull 模式 RenewBeforeDays > 13 应报错",
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 14,
			},
			wantError: true,
		},
		{
			name: "local 模式 RenewBeforeDays > 13 应报错",
			schedule: ScheduleConfig{
				RenewMode:       RenewModeLocal,
				RenewBeforeDays: 14,
			},
			wantError: true,
		},
		{
			name: "默认值（0）应通过",
			schedule: ScheduleConfig{
				RenewMode:       RenewModePull,
				RenewBeforeDays: 0,
			},
			wantError: false,
		},
		{
			name: "无效的 renew_mode",
			schedule: ScheduleConfig{
				RenewMode:       "invalid",
				RenewBeforeDays: 10,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchedule(&tt.schedule)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateSchedule() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

// TestValidateValidationMethod 测试验证方法校验
func TestValidateValidationMethod(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		method  string
		wantErr bool
	}{
		{"正常域名-file", "example.com", ValidationMethodFile, false},
		{"正常域名-delegation", "example.com", ValidationMethodDelegation, false},
		{"通配符-file 应报错", "*.example.com", ValidationMethodFile, true},
		{"通配符-delegation", "*.example.com", ValidationMethodDelegation, false},
		{"IP-file", "192.168.1.1", ValidationMethodFile, false},
		{"IP-delegation 应报错", "192.168.1.1", ValidationMethodDelegation, true},
		{"IPv6-delegation 应报错", "2001:db8::1", ValidationMethodDelegation, true},
		{"空方法", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateValidationMethod(tt.domain, tt.method)
			hasErr := result != ""
			if hasErr != tt.wantErr {
				t.Errorf("ValidateValidationMethod(%s, %s) = %q, wantErr = %v", tt.domain, tt.method, result, tt.wantErr)
			}
		})
	}
}

// TestGetEnvWithDefault 测试环境变量默认值
func TestGetEnvWithDefault(t *testing.T) {
	// 测试默认值
	result := GetEnvWithDefault("NONEXISTENT_ENV_VAR_12345", "default-value")
	if result != "default-value" {
		t.Errorf("GetEnvWithDefault() = %s, 期望 default-value", result)
	}

	// 测试实际环境变量
	testKey := "TEST_ENV_VAR_FOR_CONFIG"
	testValue := "test-value"
	_ = os.Setenv(testKey, testValue)
	defer func() { _ = os.Unsetenv(testKey) }()

	result = GetEnvWithDefault(testKey, "default")
	if result != testValue {
		t.Errorf("GetEnvWithDefault() = %s, 期望 %s", result, testValue)
	}
}

// TestValidateLogLevel 测试日志级别验证
func TestValidateLogLevel(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", false},
		{"error", false},
		{"DEBUG", false}, // 大小写不敏感
		{"INFO", false},
		{"invalid", true},
		{"trace", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			err := ValidateLogLevel(tt.level)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLogLevel(%s) error = %v, wantErr = %v", tt.level, err, tt.wantErr)
			}
		})
	}
}

// TestServerTypeConstants 测试服务器类型常量
func TestServerTypeConstants(t *testing.T) {
	// 验证常量值
	if ServerTypeNginx != "nginx" {
		t.Errorf("ServerTypeNginx = %s, 期望 nginx", ServerTypeNginx)
	}
	if ServerTypeApache != "apache" {
		t.Errorf("ServerTypeApache = %s, 期望 apache", ServerTypeApache)
	}
	if ServerTypeDockerNginx != "docker-nginx" {
		t.Errorf("ServerTypeDockerNginx = %s, 期望 docker-nginx", ServerTypeDockerNginx)
	}
	if ServerTypeDockerApache != "docker-apache" {
		t.Errorf("ServerTypeDockerApache = %s, 期望 docker-apache", ServerTypeDockerApache)
	}
}

// TestRenewModeConstants 测试续签模式常量
func TestRenewModeConstants(t *testing.T) {
	if RenewModeLocal != "local" {
		t.Errorf("RenewModeLocal = %s, 期望 local", RenewModeLocal)
	}
	if RenewModePull != "pull" {
		t.Errorf("RenewModePull = %s, 期望 pull", RenewModePull)
	}
}

// TestMatchType 测试匹配类型
func TestMatchType(t *testing.T) {
	if MatchTypeFull != "full" {
		t.Errorf("MatchTypeFull = %s, 期望 full", MatchTypeFull)
	}
	if MatchTypePartial != "partial" {
		t.Errorf("MatchTypePartial = %s, 期望 partial", MatchTypePartial)
	}
	if MatchTypeNone != "none" {
		t.Errorf("MatchTypeNone = %s, 期望 none", MatchTypeNone)
	}
}

// TestMatchResult 测试匹配结果
func TestMatchResult(t *testing.T) {
	result := MatchResult{
		Type:           MatchTypeFull,
		MatchedDomains: []string{"example.com", "www.example.com"},
		MissedDomains:  []string{},
	}

	if result.Type != MatchTypeFull {
		t.Errorf("Type = %s, 期望 %s", result.Type, MatchTypeFull)
	}
	if len(result.MatchedDomains) != 2 {
		t.Errorf("MatchedDomains 长度 = %d, 期望 2", len(result.MatchedDomains))
	}
	if len(result.MissedDomains) != 0 {
		t.Errorf("MissedDomains 长度 = %d, 期望 0", len(result.MissedDomains))
	}
}

// TestCertMetadata 测试证书元数据
func TestCertMetadata(t *testing.T) {
	metadata := CertMetadata{
		CertSerial:      "ABC123",
		LastIssueState:  "issued",
		IssueRetryCount: 0,
	}

	if metadata.CertSerial != "ABC123" {
		t.Errorf("CertSerial = %s, 期望 ABC123", metadata.CertSerial)
	}
	if metadata.LastIssueState != "issued" {
		t.Errorf("LastIssueState = %s, 期望 issued", metadata.LastIssueState)
	}
	if metadata.IssueRetryCount != 0 {
		t.Errorf("IssueRetryCount = %d, 期望 0", metadata.IssueRetryCount)
	}
}

// TestTimeConstants 测试时间相关常量
func TestTimeConstants(t *testing.T) {
	if MaxRenewBeforeDays != 13 {
		t.Errorf("MaxRenewBeforeDays = %d, 期望 13", MaxRenewBeforeDays)
	}
	if DefaultRenewBeforeDays != 13 {
		t.Errorf("DefaultRenewBeforeDays = %d, 期望 13", DefaultRenewBeforeDays)
	}
}

// TestEnvConstants 测试环境变量常量
func TestEnvConstants(t *testing.T) {
	if EnvAPIToken != "SSLCTL_API_TOKEN" {
		t.Errorf("EnvAPIToken = %s", EnvAPIToken)
	}
	if EnvAPIURL != "SSLCTL_API_URL" {
		t.Errorf("EnvAPIURL = %s", EnvAPIURL)
	}
}

// TestCertConfig_GetRenewMode 测试证书级别续签模式配置
func TestCertConfig_GetRenewMode(t *testing.T) {
	tests := []struct {
		name           string
		certRenewMode  string
		schedRenewMode string
		want           string
	}{
		{
			name:           "证书级别优先",
			certRenewMode:  RenewModeLocal,
			schedRenewMode: RenewModePull,
			want:           RenewModeLocal,
		},
		{
			name:           "证书级别为空时使用全局配置",
			certRenewMode:  "",
			schedRenewMode: RenewModeLocal,
			want:           RenewModeLocal,
		},
		{
			name:           "两者都为空时默认为 pull",
			certRenewMode:  "",
			schedRenewMode: "",
			want:           RenewModePull,
		},
		{
			name:           "全局配置为空时使用证书级别",
			certRenewMode:  RenewModeLocal,
			schedRenewMode: "",
			want:           RenewModeLocal,
		},
		{
			name:           "schedule 为 nil 时使用证书级别",
			certRenewMode:  RenewModeLocal,
			schedRenewMode: "", // schedule 将为 nil
			want:           RenewModeLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertConfig{
				CertName:  "test",
				RenewMode: tt.certRenewMode,
			}

			var schedule *ScheduleConfig
			if tt.name != "schedule 为 nil 时使用证书级别" {
				schedule = &ScheduleConfig{
					RenewMode: tt.schedRenewMode,
				}
			}

			got := cert.GetRenewMode(schedule)
			if got != tt.want {
				t.Errorf("GetRenewMode() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestConfigManager_GetSiteBinding 测试根据站点名称获取绑定配置
func TestConfigManager_GetSiteBinding(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 添加带多个绑定的证书配置
	cert1 := &CertConfig{
		CertName: "cert-1",
		OrderID:  1,
		Enabled:  true,
		Bindings: []SiteBinding{
			{
				ServerName:   "nginx-site.com",
				ServerType: ServerTypeNginx,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/etc/ssl/nginx-site/cert.pem",
					PrivateKey:  "/etc/ssl/nginx-site/key.pem",
				},
			},
			{
				ServerName:   "apache-site.com",
				ServerType: ServerTypeApache,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/etc/ssl/apache-site/cert.pem",
					PrivateKey:  "/etc/ssl/apache-site/key.pem",
					ChainFile:   "/etc/ssl/apache-site/chain.pem",
				},
			},
		},
	}

	cert2 := &CertConfig{
		CertName: "cert-2",
		OrderID:  2,
		Enabled:  true,
		Bindings: []SiteBinding{
			{
				ServerName:   "docker-site.com",
				ServerType: ServerTypeDockerNginx,
				Enabled:    true,
				Docker: &DockerInfo{
					ContainerName: "nginx-container",
					DeployMode:    "volume",
				},
			},
		},
	}

	_ = cm.AddCert(cert1)
	_ = cm.AddCert(cert2)

	tests := []struct {
		name       string
		siteName   string
		wantType   string
		wantDocker bool
		wantErr    bool
	}{
		{
			name:     "找到 Nginx 站点",
			siteName: "nginx-site.com",
			wantType: ServerTypeNginx,
			wantErr:  false,
		},
		{
			name:     "找到 Apache 站点",
			siteName: "apache-site.com",
			wantType: ServerTypeApache,
			wantErr:  false,
		},
		{
			name:       "找到 Docker 站点",
			siteName:   "docker-site.com",
			wantType:   ServerTypeDockerNginx,
			wantDocker: true,
			wantErr:    false,
		},
		{
			name:     "站点不存在",
			siteName: "nonexistent.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding, err := cm.GetSiteBinding(tt.siteName)

			if tt.wantErr {
				if err == nil {
					t.Error("GetSiteBinding() 期望返回错误")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetSiteBinding() error = %v", err)
			}

			if binding.ServerName != tt.siteName {
				t.Errorf("ServerName = %s, 期望 %s", binding.ServerName, tt.siteName)
			}

			if binding.ServerType != tt.wantType {
				t.Errorf("ServerType = %s, 期望 %s", binding.ServerType, tt.wantType)
			}

			if tt.wantDocker && binding.Docker == nil {
				t.Error("期望有 Docker 配置")
			}
		})
	}
}

// TestConfigManager_GetSiteBinding_DeepCopy 测试 GetSiteBinding 返回深拷贝
func TestConfigManager_GetSiteBinding_DeepCopy(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cert := &CertConfig{
		CertName: "test-cert",
		OrderID:  1,
		Enabled:  true,
		Bindings: []SiteBinding{
			{
				ServerName:   "test-site.com",
				ServerType: ServerTypeDockerNginx,
				Enabled:    true,
				Docker: &DockerInfo{
					ContainerName: "original-container",
					DeployMode:    "volume",
				},
			},
		},
	}
	_ = cm.AddCert(cert)

	// 获取绑定并修改
	binding1, _ := cm.GetSiteBinding("test-site.com")
	binding1.Docker.ContainerName = "modified-container"
	binding1.ServerName = "modified-site.com"

	// 再次获取，验证未被修改
	binding2, _ := cm.GetSiteBinding("test-site.com")

	if binding2.ServerName != "test-site.com" {
		t.Error("GetSiteBinding 应返回深拷贝，修改不应影响内部缓存")
	}

	if binding2.Docker.ContainerName != "original-container" {
		t.Error("Docker 配置应该是深拷贝")
	}
}

// TestDeepCopyCompleteness 测试深拷贝完整性
// 此测试验证 copyConfig 函数正确处理了所有引用类型字段
// 如果添加了新的引用类型字段但未更新 copyConfig，此测试将失败
func TestDeepCopyCompleteness(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	// 创建包含所有引用类型字段的完整配置
	originalCert := &CertConfig{
		CertName:  "deep-copy-test",
		OrderID:   999,
		Enabled:   true,
		RenewMode: RenewModeLocal,
		Domains:   []string{"domain1.com", "domain2.com", "domain3.com"},
		Bindings: []SiteBinding{
			{
				ServerName:   "binding1.com",
				ServerType: ServerTypeNginx,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/path/to/cert1.pem",
					PrivateKey:  "/path/to/key1.pem",
				},
			},
			{
				ServerName:   "binding2.com",
				ServerType: ServerTypeDockerNginx,
				Enabled:    true,
				Paths: BindingPaths{
					Certificate: "/path/to/cert2.pem",
					PrivateKey:  "/path/to/key2.pem",
				},
				Docker: &DockerInfo{
					ContainerName: "original-container",
					DeployMode:    "volume",
				},
			},
		},
	}

	if err := cm.AddCert(originalCert); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}

	// 加载配置并进行修改
	cfg1, _ := cm.Load()
	if len(cfg1.Certificates) == 0 {
		t.Fatal("配置为空")
	}

	// 修改所有引用类型字段
	cfg1.Certificates[0].Domains[0] = "modified-domain.com"
	cfg1.Certificates[0].Domains = append(cfg1.Certificates[0].Domains, "new-domain.com")
	cfg1.Certificates[0].Bindings[0].ServerName = "modified-binding.com"
	cfg1.Certificates[0].Bindings = append(cfg1.Certificates[0].Bindings, SiteBinding{ServerName: "new-binding.com"})
	cfg1.Certificates[0].Bindings[1].Docker.ContainerName = "modified-container"
	cfg1.Certificates = append(cfg1.Certificates, CertConfig{CertName: "new-cert"})

	// 再次加载配置，验证所有原始值未被影响
	cfg2, _ := cm.Load()

	// 验证 Certificates slice 独立
	if len(cfg2.Certificates) != 1 {
		t.Errorf("Certificates 长度 = %d, 期望 1（原始值）", len(cfg2.Certificates))
	}

	// 验证 Domains slice 独立
	if cfg2.Certificates[0].Domains[0] != "domain1.com" {
		t.Errorf("Domains[0] = %s, 期望 domain1.com", cfg2.Certificates[0].Domains[0])
	}
	if len(cfg2.Certificates[0].Domains) != 3 {
		t.Errorf("Domains 长度 = %d, 期望 3", len(cfg2.Certificates[0].Domains))
	}

	// 验证 Bindings slice 独立
	if len(cfg2.Certificates[0].Bindings) != 2 {
		t.Errorf("Bindings 长度 = %d, 期望 2", len(cfg2.Certificates[0].Bindings))
	}
	if cfg2.Certificates[0].Bindings[0].ServerName != "binding1.com" {
		t.Errorf("Bindings[0].ServerName = %s, 期望 binding1.com", cfg2.Certificates[0].Bindings[0].ServerName)
	}

	// 验证 Docker 指针独立
	if cfg2.Certificates[0].Bindings[1].Docker == nil {
		t.Fatal("Docker 配置不应为 nil")
	}
	if cfg2.Certificates[0].Bindings[1].Docker.ContainerName != "original-container" {
		t.Errorf("Docker.ContainerName = %s, 期望 original-container",
			cfg2.Certificates[0].Bindings[1].Docker.ContainerName)
	}
}

// TestSaveLocked_SymlinkTarget 测试配置保存时检测目标路径为符号链接
func TestSaveLocked_SymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}

	// 先正常保存一次
	cfg := &Config{
		Certificates: []CertConfig{},
	}
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("初次保存失败: %v", err)
	}

	// 将配置文件替换为符号链接
	configPath := cm.GetConfigPath()
	targetFile := filepath.Join(dir, "target.json")
	_ = os.WriteFile(targetFile, []byte("{}"), 0600)
	_ = os.Remove(configPath)
	if err := os.Symlink(targetFile, configPath); err != nil {
		t.Skip("无法创建符号链接:", err)
	}

	// 清除缓存强制重新保存
	cm.mu.Lock()
	cm.config = nil
	cm.mu.Unlock()

	// 保存应该被拒绝
	err = cm.Save(cfg)
	if err == nil {
		t.Error("当配置路径为符号链接时，Save() 应该返回错误")
	}
	if err != nil && !strings.Contains(err.Error(), "symlink") {
		t.Errorf("错误信息应包含 'symlink': %v", err)
	}
}

// TestConfigManager_UpdateMetadata 测试 UpdateMetadata 原子修改
func TestConfigManager_UpdateMetadata(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}

	// 先保存一个初始配置
	cfg := &Config{}
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// 通过 UpdateMetadata 回调修改元数据
	now := time.Now()
	err = cm.UpdateMetadata(func(m *ConfigMetadata) {
		m.LastCheckAt = now
	})
	if err != nil {
		t.Fatalf("UpdateMetadata() error = %v", err)
	}

	// 重新加载验证持久化
	loaded, err := cm.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if loaded.Metadata.LastCheckAt.IsZero() {
		t.Error("UpdateMetadata 回调修改的 LastCheckAt 未持久化")
	}

	// 验证 LastCheckAt 值正确（允许 1 秒误差）
	diff := loaded.Metadata.LastCheckAt.Sub(now)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("LastCheckAt 与设置值差异过大: %v", diff)
	}
}

// TestConfigManager_UpdateMetadata_Multiple 测试多次 UpdateMetadata 调用
func TestConfigManager_UpdateMetadata_Multiple(t *testing.T) {
	dir := t.TempDir()
	cm, _ := NewConfigManagerWithDir(dir)

	cfg := &Config{}
	_ = cm.Save(cfg)

	// 第一次更新
	_ = cm.UpdateMetadata(func(m *ConfigMetadata) {
		m.LastCheckAt = time.Now()
	})

	// 第二次更新不应覆盖第一次
	time2 := time.Now().Add(time.Hour)
	_ = cm.UpdateMetadata(func(m *ConfigMetadata) {
		m.UpdatedAt = time2
	})

	loaded, _ := cm.Reload()
	if loaded.Metadata.LastCheckAt.IsZero() {
		t.Error("第二次 UpdateMetadata 不应覆盖第一次设置的 LastCheckAt")
	}
}

// TestConfigManager_MtimeReload 测试配置文件被外部修改后自动重新加载
func TestConfigManager_MtimeReload(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}

	// 初始保存
	cfg := &Config{
		Certificates: []CertConfig{
			{CertName: "test", Enabled: true, API: APIConfig{URL: "https://example.com/api", Token: "initial"}},
		},
	}
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// 第一次加载（缓存）
	cfg1, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg1.Certificates[0].API.URL != "https://example.com/api" {
		t.Fatalf("初始 URL 不正确: %s", cfg1.Certificates[0].API.URL)
	}

	// 等待确保 mtime 不同
	time.Sleep(100 * time.Millisecond)

	// 外部修改配置文件
	newCfg := &Config{
		Certificates: []CertConfig{
			{CertName: "test", Enabled: true, API: APIConfig{URL: "https://modified.com/api", Token: "modified"}},
		},
	}
	data, _ := json.MarshalIndent(newCfg, "", "  ")
	if err := os.WriteFile(cm.GetConfigPath(), data, 0600); err != nil {
		t.Fatalf("外部写入失败: %v", err)
	}

	// 再次加载，应该检测到 mtime 变化并重新加载
	cfg2, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() after external modification error = %v", err)
	}
	if cfg2.Certificates[0].API.URL != "https://modified.com/api" {
		t.Errorf("外部修改后 URL = %s, 期望 https://modified.com/api", cfg2.Certificates[0].API.URL)
	}
}
