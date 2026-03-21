// Package certops 证书操作服务层测试
package certops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// writeTestConfig 写入测试配置文件
func writeTestConfig(t *testing.T, dir string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// captureLogger 创建一个可以捕获日志输出的 Logger（写入文件后读取）
func captureLogger(t *testing.T, dir string) (*logger.Logger, func() string) {
	t.Helper()
	logDir := filepath.Join(dir, "logs")
	log, err := logger.New(logDir, "test")
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	log.SetLevel(logger.LevelDebug)

	readLogs := func() string {
		_ = log.Close()
		entries, _ := os.ReadDir(logDir)
		var buf strings.Builder
		for _, e := range entries {
			data, _ := os.ReadFile(filepath.Join(logDir, e.Name()))
			buf.Write(data)
		}
		return buf.String()
	}
	return log, readLogs
}

// TestCheckExpiry 测试证书过期告警逻辑
func TestCheckExpiry(t *testing.T) {
	tests := []struct {
		name       string
		certs      []config.CertConfig
		wantLevel  string // "ERROR", "WARN", "" (无告警)
		wantAbsent string // 不应出现的内容
	}{
		{
			name:      "证书已过期",
			wantLevel: "ERROR",
			certs: []config.CertConfig{
				{
					CertName: "expired-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(-24 * time.Hour),
					},
				},
			},
		},
		{
			name:      "7天内过期",
			wantLevel: "ERROR",
			certs: []config.CertConfig{
				{
					CertName: "soon-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(3 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:      "7-13天过期",
			wantLevel: "WARN",
			certs: []config.CertConfig{
				{
					CertName: "warn-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(10 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:       "13天以上无告警",
			wantLevel:  "",
			wantAbsent: "warn-cert",
			certs: []config.CertConfig{
				{
					CertName: "ok-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(30 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:       "禁用证书跳过",
			wantLevel:  "",
			wantAbsent: "disabled-cert",
			certs: []config.CertConfig{
				{
					CertName: "disabled-cert",
					Enabled:  false,
					Metadata: config.CertMetadata{
						CertExpiresAt: time.Now().Add(1 * 24 * time.Hour),
					},
				},
			},
		},
		{
			name:       "CertExpiresAt零值跳过",
			wantLevel:  "",
			wantAbsent: "zero-cert",
			certs: []config.CertConfig{
				{
					CertName: "zero-cert",
					Enabled:  true,
					Metadata: config.CertMetadata{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cm, err := config.NewConfigManagerWithDir(dir)
			if err != nil {
				t.Fatalf("创建配置管理器失败: %v", err)
			}

			cfg := &config.Config{
				Certificates: tt.certs,
			}
			writeTestConfig(t, dir, cfg)

			log, readLogs := captureLogger(t, dir)
			svc := NewService(cm, log)
			svc.CheckExpiry()

			output := readLogs()

			if tt.wantLevel == "ERROR" {
				if !strings.Contains(output, "[ERROR]") {
					t.Errorf("期望 ERROR 日志，实际输出:\n%s", output)
				}
			} else if tt.wantLevel == "WARN" {
				if !strings.Contains(output, "[WARN]") {
					t.Errorf("期望 WARN 日志，实际输出:\n%s", output)
				}
			}

			if tt.wantAbsent != "" && strings.Contains(output, tt.wantAbsent) {
				t.Errorf("不应出现 %q，实际输出:\n%s", tt.wantAbsent, output)
			}
		})
	}
}

// TestCheckExpiry_LoadFail 测试配置加载失败时不 panic
func TestCheckExpiry_LoadFail(t *testing.T) {
	dir := t.TempDir()
	cm, err := config.NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	// 写入无效 JSON
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	log, readLogs := captureLogger(t, dir)
	svc := NewService(cm, log)

	// 不应 panic
	svc.CheckExpiry()

	output := readLogs()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("配置加载失败时应输出 WARN 日志，实际输出:\n%s", output)
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

