// Package certops 证书操作服务层测试
package certops

import (
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

// TestNewService 测试服务创建
func TestNewService(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()
	svc := NewService(cm, log)

	if svc == nil {
		t.Fatal("NewService 返回 nil")
	}

	if svc.GetConfigManager() != cm {
		t.Error("GetConfigManager 返回值不正确")
	}

	if svc.GetFetcher() == nil {
		t.Error("GetFetcher 返回 nil")
	}

	if svc.GetBackupManager() == nil {
		t.Error("GetBackupManager 返回 nil")
	}

	if svc.GetLogger() != log {
		t.Error("GetLogger 返回值不正确")
	}
}

// TestGetRenewMode 测试获取续签模式
func TestGetRenewMode(t *testing.T) {
	tests := []struct {
		name     string
		schedule config.ScheduleConfig
		want     string
	}{
		{
			name:     "空模式默认为 pull",
			schedule: config.ScheduleConfig{},
			want:     config.RenewModePull,
		},
		{
			name:     "显式 pull 模式",
			schedule: config.ScheduleConfig{RenewMode: config.RenewModePull},
			want:     config.RenewModePull,
		},
		{
			name:     "显式 local 模式",
			schedule: config.ScheduleConfig{RenewMode: config.RenewModeLocal},
			want:     config.RenewModeLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRenewMode(&tt.schedule)
			if got != tt.want {
				t.Errorf("getRenewMode() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

// TestPickKeyPath 测试选择私钥路径
func TestPickKeyPath(t *testing.T) {
	tests := []struct {
		name string
		cert config.CertConfig
		want string
	}{
		{
			name: "无绑定",
			cert: config.CertConfig{},
			want: "",
		},
		{
			name: "单个启用的绑定",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: true,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/key.pem",
						},
					},
				},
			},
			want: "/path/to/key.pem",
		},
		{
			name: "多个绑定，优先启用的",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/disabled.pem",
						},
					},
					{
						Enabled: true,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/enabled.pem",
						},
					},
				},
			},
			want: "/path/to/enabled.pem",
		},
		{
			name: "所有绑定禁用，使用第一个",
			cert: config.CertConfig{
				Bindings: []config.SiteBinding{
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/first.pem",
						},
					},
					{
						Enabled: false,
						Paths: config.BindingPaths{
							PrivateKey: "/path/to/second.pem",
						},
					},
				},
			},
			want: "/path/to/first.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickKeyPath(&tt.cert)
			if got != tt.want {
				t.Errorf("pickKeyPath() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

// TestToScannedSite 测试站点类型转换
func TestToScannedSite(t *testing.T) {
	configSite := &config.ScannedSite{
		ID:              "example.com",
		Name:            "Example Site",
		Source:          "local",
		ConfigFile:      "/etc/nginx/sites-enabled/example.conf",
		ServerName:      "example.com",
		ServerAlias:     []string{"www.example.com"},
		ListenPorts:     []string{"443 ssl"},
		CertificatePath: "/etc/ssl/cert.pem",
		PrivateKeyPath:  "/etc/ssl/key.pem",
	}

	result := toScannedSite(configSite)

	if result.ID != configSite.ID {
		t.Errorf("ID = %s, 期望 %s", result.ID, configSite.ID)
	}
	if result.ServerName != configSite.ServerName {
		t.Errorf("ServerName = %s, 期望 %s", result.ServerName, configSite.ServerName)
	}
	if result.Source != configSite.Source {
		t.Errorf("Source = %s, 期望 %s", result.Source, configSite.Source)
	}
	if len(result.ServerAlias) != len(configSite.ServerAlias) {
		t.Errorf("ServerAlias 长度 = %d, 期望 %d", len(result.ServerAlias), len(configSite.ServerAlias))
	}
}
