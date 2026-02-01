// Package daemon 守护进程模式测试
package daemon

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/certops"
	"github.com/zhuxbo/cert-deploy/pkg/config"
	"github.com/zhuxbo/cert-deploy/pkg/logger"
)

// TestCheckAndDeploy_Success 测试成功检查部署
func TestCheckAndDeploy_Success(t *testing.T) {
	// 这个测试验证 checkAndDeploy 函数的日志输出逻辑
	// 由于 checkAndDeploy 依赖 certops.Service，我们测试其行为模式

	tmpDir := t.TempDir()
	cfgManager, err := config.NewConfigManagerWithDir(tmpDir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	log := logger.NewNopLogger()

	// 创建服务
	svc := certops.NewService(cfgManager, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 调用 checkAndDeploy（无证书配置时应该正常返回）
	checkAndDeploy(ctx, svc, log)
}

// TestCheckAndDeploy_WithContext 测试带上下文的检查
func TestCheckAndDeploy_WithContext(t *testing.T) {
	tmpDir := t.TempDir()
	cfgManager, _ := config.NewConfigManagerWithDir(tmpDir)
	log := logger.NewNopLogger()
	svc := certops.NewService(cfgManager, log)

	// 使用已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 应该能够处理取消的上下文
	checkAndDeploy(ctx, svc, log)
}

// TestDaemonInterval 测试守护进程间隔配置
func TestDaemonInterval(t *testing.T) {
	tests := []struct {
		name          string
		intervalHours int
		wantHours     int
	}{
		{
			name:          "默认间隔",
			intervalHours: 0,
			wantHours:     config.DefaultCheckIntervalHours,
		},
		{
			name:          "自定义间隔",
			intervalHours: 12,
			wantHours:     12,
		},
		{
			name:          "最小间隔",
			intervalHours: 1,
			wantHours:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interval := time.Duration(tt.intervalHours) * time.Hour
			if interval == 0 {
				interval = time.Duration(config.DefaultCheckIntervalHours) * time.Hour
			}

			gotHours := int(interval.Hours())
			if gotHours != tt.wantHours {
				t.Errorf("interval = %d hours, want %d hours", gotHours, tt.wantHours)
			}
		})
	}
}

// TestRenewResultStats 测试续签结果统计
func TestRenewResultStats(t *testing.T) {
	results := []certops.RenewResult{
		{CertName: "cert1", Status: "success", DeployCount: 2},
		{CertName: "cert2", Status: "success", DeployCount: 1},
		{CertName: "cert3", Status: "failed", Error: fmt.Errorf("API error")},
		{CertName: "cert4", Status: "pending"},
		{CertName: "cert5", Status: "pending"},
	}

	var successCount, failedCount, pendingCount int
	for _, r := range results {
		switch r.Status {
		case "success":
			successCount++
		case "failed":
			failedCount++
		case "pending":
			pendingCount++
		}
	}

	if successCount != 2 {
		t.Errorf("successCount = %d, want 2", successCount)
	}
	if failedCount != 1 {
		t.Errorf("failedCount = %d, want 1", failedCount)
	}
	if pendingCount != 2 {
		t.Errorf("pendingCount = %d, want 2", pendingCount)
	}
}

// TestContextTimeout 测试上下文超时
func TestContextTimeout(t *testing.T) {
	parentCtx := context.Background()

	// 模拟 checkAndDeploy 中的超时设置
	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Minute)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("上下文应该有截止时间")
	}

	// 验证截止时间在 30 分钟后（允许几秒误差）
	expected := time.Now().Add(30 * time.Minute)
	diff := deadline.Sub(expected)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("截止时间不正确: diff = %v", diff)
	}
}
