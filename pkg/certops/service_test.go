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

	// 验证内部组件已正确初始化
	if svc.cfgManager != cm {
		t.Error("cfgManager 未正确初始化")
	}
	if svc.fetcher == nil {
		t.Error("fetcher 未正确初始化")
	}
	if svc.backupMgr == nil {
		t.Error("backupMgr 未正确初始化")
	}
	if svc.log != log {
		t.Error("log 未正确初始化")
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

