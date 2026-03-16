// Package certops 类型定义测试
package certops

import (
	"fmt"
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

// TestRenewResult_StatusValues 测试续签结果状态枚举
func TestRenewResult_StatusValues(t *testing.T) {
	// 验证状态枚举值是否与 API 回调中使用的值一致
	validStatuses := map[string]bool{
		"success": true,
		"pending": true,
		"failure": true,
	}

	tests := []struct {
		name   string
		result RenewResult
	}{
		{
			name: "成功续签应有部署计数",
			result: RenewResult{
				CertName:    "order-123",
				Mode:        "pull",
				Status:      "success",
				DeployCount: 2,
			},
		},
		{
			name: "等待签发无错误",
			result: RenewResult{
				CertName: "order-456",
				Mode:     "local",
				Status:   "pending",
			},
		},
		{
			name: "续签失败应有错误",
			result: RenewResult{
				CertName: "order-789",
				Mode:     "pull",
				Status:   "failure",
				Error:    fmt.Errorf("API error"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !validStatuses[tt.result.Status] {
				t.Errorf("Status %q 不是有效的状态枚举值", tt.result.Status)
			}

			// 成功时应有部署计数
			if tt.result.Status == "success" && tt.result.DeployCount == 0 {
				t.Error("成功续签时 DeployCount 应 > 0")
			}

			// 失败时应有错误
			if tt.result.Status == "failure" && tt.result.Error == nil {
				t.Error("失败续签时 Error 不应为 nil")
			}

			// pending 时不应有错误
			if tt.result.Status == "pending" && tt.result.Error != nil {
				t.Error("pending 时 Error 应为 nil")
			}
		})
	}
}
