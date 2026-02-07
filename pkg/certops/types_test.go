// Package certops 类型定义测试
package certops

import (
	"testing"
	"time"
)

// TestScanOptions 测试扫描选项
func TestScanOptions(t *testing.T) {
	opts := ScanOptions{
		SSLOnly:    true,
		ServerType: "nginx",
	}

	if !opts.SSLOnly {
		t.Error("SSLOnly 应为 true")
	}
	if opts.ServerType != "nginx" {
		t.Errorf("ServerType = %s, 期望 nginx", opts.ServerType)
	}
}

// TestScanResult 测试扫描结果
func TestScanResult(t *testing.T) {
	now := time.Now()
	result := ScanResult{
		ScanTime:    now,
		Environment: "local",
		Sites: []ScannedSite{
			{
				ID:         "example.com",
				ServerName: "example.com",
				Source:     "local",
			},
		},
	}

	if result.ScanTime != now {
		t.Error("ScanTime 不匹配")
	}
	if result.Environment != "local" {
		t.Errorf("Environment = %s, 期望 local", result.Environment)
	}
	if len(result.Sites) != 1 {
		t.Errorf("Sites 长度 = %d, 期望 1", len(result.Sites))
	}
}

// TestScannedSite 测试扫描站点结构
func TestScannedSite(t *testing.T) {
	site := ScannedSite{
		ID:              "example.com",
		Name:            "Example",
		Source:          "docker",
		ContainerID:     "abc123",
		ContainerName:   "nginx-container",
		ConfigFile:      "/etc/nginx/nginx.conf",
		ServerName:      "example.com",
		ServerAlias:     []string{"www.example.com", "api.example.com"},
		ListenPorts:     []string{"80", "443 ssl"},
		CertificatePath: "/etc/ssl/cert.pem",
		PrivateKeyPath:  "/etc/ssl/key.pem",
		HostCertPath:    "/opt/certs/cert.pem",
		HostKeyPath:     "/opt/certs/key.pem",
		VolumeMode:      true,
	}

	if site.ID != "example.com" {
		t.Errorf("ID = %s, 期望 example.com", site.ID)
	}
	if site.Source != "docker" {
		t.Errorf("Source = %s, 期望 docker", site.Source)
	}
	if !site.VolumeMode {
		t.Error("VolumeMode 应为 true")
	}
	if len(site.ServerAlias) != 2 {
		t.Errorf("ServerAlias 长度 = %d, 期望 2", len(site.ServerAlias))
	}
	if len(site.ListenPorts) != 2 {
		t.Errorf("ListenPorts 长度 = %d, 期望 2", len(site.ListenPorts))
	}
}

// TestDeployOptions 测试部署选项
func TestDeployOptions(t *testing.T) {
	tests := []struct {
		name     string
		opts     DeployOptions
		wantAll  bool
		wantDry  bool
		wantCert string
	}{
		{
			name:     "部署指定证书",
			opts:     DeployOptions{CertName: "order-123"},
			wantCert: "order-123",
		},
		{
			name:    "部署所有证书",
			opts:    DeployOptions{All: true},
			wantAll: true,
		},
		{
			name:     "干运行模式",
			opts:     DeployOptions{CertName: "test", DryRun: true},
			wantDry:  true,
			wantCert: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.All != tt.wantAll {
				t.Errorf("All = %v, 期望 %v", tt.opts.All, tt.wantAll)
			}
			if tt.opts.DryRun != tt.wantDry {
				t.Errorf("DryRun = %v, 期望 %v", tt.opts.DryRun, tt.wantDry)
			}
			if tt.opts.CertName != tt.wantCert {
				t.Errorf("CertName = %s, 期望 %s", tt.opts.CertName, tt.wantCert)
			}
		})
	}
}

// TestDeployResult 测试部署结果
func TestDeployResult(t *testing.T) {
	result := DeployResult{
		CertName:   "order-123",
		Success:    true,
		BackupPath: "/opt/backup/20240101",
	}

	if result.CertName != "order-123" {
		t.Errorf("CertName = %s, 期望 order-123", result.CertName)
	}
	if !result.Success {
		t.Error("Success 应为 true")
	}
	if result.Error != nil {
		t.Error("Error 应为 nil")
	}
}

// TestRenewOptions 测试续签选项
func TestRenewOptions(t *testing.T) {
	opts := RenewOptions{Force: true}
	if !opts.Force {
		t.Error("Force 应为 true")
	}
}

// TestRenewResult 测试续签结果
func TestRenewResult(t *testing.T) {
	tests := []struct {
		name   string
		result RenewResult
	}{
		{
			name: "成功续签",
			result: RenewResult{
				CertName:    "order-123",
				Mode:        "pull",
				Status:      "success",
				DeployCount: 2,
			},
		},
		{
			name: "等待签发",
			result: RenewResult{
				CertName: "order-456",
				Mode:     "local",
				Status:   "pending",
			},
		},
		{
			name: "续签失败",
			result: RenewResult{
				CertName: "order-789",
				Mode:     "pull",
				Status:   "failure",
				Error:    nil, // 实际应有错误
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.CertName == "" {
				t.Error("CertName 不应为空")
			}
			if tt.result.Mode != "pull" && tt.result.Mode != "local" {
				t.Errorf("Mode = %s, 应为 pull 或 local", tt.result.Mode)
			}
		})
	}
}
