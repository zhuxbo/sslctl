// Package config 站点配置管理测试
package config

import (
	"testing"
	"time"
)

// TestSiteConfig_DaysUntilExpiry 测试证书到期剩余天数计算
func TestSiteConfig_DaysUntilExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		minDays   int
		maxDays   int
	}{
		{
			name:      "未设置过期时间",
			expiresAt: time.Time{},
			minDays:   999,
			maxDays:   999,
		},
		{
			name:      "30天后过期",
			expiresAt: time.Now().Add(30 * 24 * time.Hour),
			minDays:   29, // 可能有时间偏差
			maxDays:   31,
		},
		{
			name:      "已过期",
			expiresAt: time.Now().Add(-10 * 24 * time.Hour),
			minDays:   -11,
			maxDays:   -9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SiteConfig{
				Metadata: MetadataConfig{
					CertExpiresAt: tt.expiresAt,
				},
			}

			days := cfg.DaysUntilExpiry()
			if days < tt.minDays || days > tt.maxDays {
				t.Errorf("DaysUntilExpiry() = %d, 期望在 [%d, %d] 范围内",
					days, tt.minDays, tt.maxDays)
			}
		})
	}
}

// TestSiteConfig_NeedsRenewal 测试是否需要续期判断
func TestSiteConfig_NeedsRenewal(t *testing.T) {
	tests := []struct {
		name            string
		expiresAt       time.Time
		renewBeforeDays int
		expected        bool
	}{
		{
			name:            "未设置过期时间",
			expiresAt:       time.Time{},
			renewBeforeDays: 14,
			expected:        false, // 999 天 > 14 天
		},
		{
			name:            "剩余30天，阈值14天，不需要续期",
			expiresAt:       time.Now().Add(30 * 24 * time.Hour),
			renewBeforeDays: 14,
			expected:        false,
		},
		{
			name:            "剩余10天，阈值14天，需要续期",
			expiresAt:       time.Now().Add(10 * 24 * time.Hour),
			renewBeforeDays: 14,
			expected:        true,
		},
		{
			name:            "已过期，需要续期",
			expiresAt:       time.Now().Add(-5 * 24 * time.Hour),
			renewBeforeDays: 14,
			expected:        true,
		},
		{
			name:            "刚好等于阈值天数",
			expiresAt:       time.Now().Add(14 * 24 * time.Hour),
			renewBeforeDays: 14,
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SiteConfig{
				Metadata: MetadataConfig{
					CertExpiresAt: tt.expiresAt,
				},
				Schedule: ScheduleConfig{
					RenewBeforeDays: tt.renewBeforeDays,
				},
			}

			got := cfg.NeedsRenewal()
			if got != tt.expected {
				t.Errorf("NeedsRenewal() = %v, 期望 %v", got, tt.expected)
			}
		})
	}
}

// TestSiteConfig_Struct 测试配置结构体字段
func TestSiteConfig_Struct(t *testing.T) {
	cfg := &SiteConfig{
		Version:    "1.0",
		SiteName:   "test-site",
		Enabled:    true,
		ServerType: "nginx",
		API: APIConfig{
			URL:   "https://api.example.com",
			Token: "test-token",
		},
		Domains: []string{"example.com", "www.example.com"},
		Paths: PathsConfig{
			Certificate: "/etc/ssl/cert.pem",
			PrivateKey:  "/etc/ssl/key.pem",
			ConfigFile:  "/etc/nginx/nginx.conf",
		},
		Reload: ReloadConfig{
			TestCommand:   "nginx -t",
			ReloadCommand: "systemctl reload nginx",
		},
		Schedule: ScheduleConfig{
			CheckIntervalHours: 6,
			RenewBeforeDays:    14,
		},
		Validation: ValidationConfig{
			VerifyDomain: true,
			TestHTTPS:    true,
		},
		Key: KeyConfig{
			Type: "rsa",
			Size: 2048,
		},
		Backup: BackupConfig{
			Enabled:      true,
			KeepVersions: 5,
		},
	}

	// 验证基本字段
	if cfg.SiteName != "test-site" {
		t.Errorf("SiteName = %s", cfg.SiteName)
	}
	if !cfg.Enabled {
		t.Error("Enabled 应为 true")
	}
	if cfg.ServerType != "nginx" {
		t.Errorf("ServerType = %s", cfg.ServerType)
	}
	if len(cfg.Domains) != 2 {
		t.Errorf("Domains 数量 = %d", len(cfg.Domains))
	}
}

// TestAPIConfig 测试 API 配置结构
func TestAPIConfig(t *testing.T) {
	api := APIConfig{
		URL:   "https://api.example.com/deploy",
		Token: "secret-token",
	}

	if api.URL == "" {
		t.Error("URL 不应为空")
	}
	if api.Token == "" {
		t.Error("Token 不应为空")
	}
}

// TestPathsConfig 测试路径配置结构
func TestPathsConfig(t *testing.T) {
	paths := PathsConfig{
		Certificate: "/etc/ssl/cert.pem",
		PrivateKey:  "/etc/ssl/key.pem",
		ChainFile:   "/etc/ssl/chain.pem",
		ConfigFile:  "/etc/nginx/nginx.conf",
		Webroot:     "/var/www/html",
	}

	if paths.Certificate == "" {
		t.Error("Certificate 不应为空")
	}
	if paths.PrivateKey == "" {
		t.Error("PrivateKey 不应为空")
	}
}

// TestReloadConfig 测试重载配置结构
func TestReloadConfig(t *testing.T) {
	reload := ReloadConfig{
		TestCommand:   "nginx -t",
		ReloadCommand: "systemctl reload nginx",
	}

	if reload.TestCommand == "" {
		t.Error("TestCommand 不应为空")
	}
	if reload.ReloadCommand == "" {
		t.Error("ReloadCommand 不应为空")
	}
}

// TestScheduleConfig 测试调度配置结构
func TestScheduleConfig(t *testing.T) {
	schedule := ScheduleConfig{
		CheckIntervalHours: 6,
		RenewBeforeDays:    14,
		MinImproveDays:     7,
	}

	if schedule.CheckIntervalHours <= 0 {
		t.Error("CheckIntervalHours 应大于 0")
	}
	if schedule.RenewBeforeDays <= 0 {
		t.Error("RenewBeforeDays 应大于 0")
	}
}

// TestKeyConfig 测试私钥配置结构
func TestKeyConfig(t *testing.T) {
	rsaKey := KeyConfig{
		Type: "rsa",
		Size: 2048,
	}

	if rsaKey.Type != "rsa" {
		t.Errorf("Type = %s", rsaKey.Type)
	}

	ecKey := KeyConfig{
		Type:  "ecdsa",
		Curve: "prime256v1",
	}

	if ecKey.Type != "ecdsa" {
		t.Errorf("Type = %s", ecKey.Type)
	}
}

// TestBackupConfig 测试备份配置结构
func TestBackupConfig(t *testing.T) {
	backup := BackupConfig{
		Enabled:      true,
		KeepVersions: 5,
	}

	if !backup.Enabled {
		t.Error("Enabled 应为 true")
	}
	if backup.KeepVersions <= 0 {
		t.Error("KeepVersions 应大于 0")
	}
}

// TestMetadataConfig 测试元数据配置结构
func TestMetadataConfig(t *testing.T) {
	now := time.Now()
	metadata := MetadataConfig{
		CreatedAt:     now,
		LastDeployAt:  now,
		LastCheckAt:   now,
		CertExpiresAt: now.Add(90 * 24 * time.Hour),
		CertSerial:    "ABC123",
		AutoScanned:   true,
	}

	if metadata.CreatedAt.IsZero() {
		t.Error("CreatedAt 不应为零值")
	}
	if metadata.CertSerial == "" {
		t.Error("CertSerial 不应为空")
	}
}
