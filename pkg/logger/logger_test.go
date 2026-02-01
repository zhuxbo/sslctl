// Package logger 日志记录器测试
package logger

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLevel_String 测试日志级别字符串转换
func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(100), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Level.String() = %s, 期望 %s", got, tt.expected)
			}
		})
	}
}

// TestParseLevel 测试日志级别解析
func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"WARNING", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"unknown", LevelInfo}, // 默认返回 Info
		{"", LevelInfo},        // 空字符串默认返回 Info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseLevel(tt.input); got != tt.expected {
				t.Errorf("ParseLevel(%q) = %v, 期望 %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestNew 测试创建日志记录器
func TestNew(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := New(tmpDir, "test-site")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer logger.Close()

	if logger == nil {
		t.Error("New() 返回 nil")
	}
}

// TestNew_CreateDir 测试自动创建目录
func TestNew_CreateDir(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs", "subdir")

	logger, err := New(logDir, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer logger.Close()

	// 验证目录已创建
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Error("日志目录未创建")
	}
}

// TestLogger_SetLevel 测试设置日志级别
func TestLogger_SetLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.SetLevel(LevelError)
	if logger.minLevel != LevelError {
		t.Errorf("SetLevel() 后 minLevel = %v, 期望 %v", logger.minLevel, LevelError)
	}

	logger.SetLevel(LevelDebug)
	if logger.minLevel != LevelDebug {
		t.Errorf("SetLevel() 后 minLevel = %v, 期望 %v", logger.minLevel, LevelDebug)
	}
}

// TestLogger_LogMethods 测试日志方法
func TestLogger_LogMethods(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.SetLevel(LevelDebug)

	// 这些方法不应 panic
	logger.Debug("debug message %d", 1)
	logger.Info("info message %s", "test")
	logger.Warn("warn message")
	logger.Error("error message")
}

// TestLogger_LogDeployment 测试部署日志
func TestLogger_LogDeployment(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功部署
	logger.LogDeployment("example.com", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", true, nil)

	// 失败部署
	logger.LogDeployment("example.com", "/etc/ssl/cert.pem", "/etc/ssl/key.pem", false, os.ErrPermission)
}

// TestLogger_LogBackup 测试备份日志
func TestLogger_LogBackup(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功备份
	logger.LogBackup("/etc/ssl/cert.pem", "/backup/cert.pem", true, nil)

	// 失败备份
	logger.LogBackup("/etc/ssl/cert.pem", "/backup/cert.pem", false, os.ErrNotExist)
}

// TestLogger_LogReload 测试重载日志
func TestLogger_LogReload(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 成功重载
	logger.LogReload("nginx -s reload", true, "", nil)

	// 失败重载
	logger.LogReload("nginx -s reload", false, "config error", os.ErrInvalid)
}

// TestLogger_LogScan 测试扫描日志
func TestLogger_LogScan(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	logger.LogScan("/etc/nginx/nginx.conf", 5)
}

// TestNewNopLogger 测试空日志记录器
func TestNewNopLogger(t *testing.T) {
	logger := NewNopLogger()

	if logger == nil {
		t.Error("NewNopLogger() 返回 nil")
	}

	// 空日志记录器不应输出任何内容，也不应 panic
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
}

// TestLogger_Close 测试关闭日志记录器
func TestLogger_Close(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")

	// 关闭应该不报错
	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// 多次关闭不应 panic
	_ = logger.Close()
}

// TestLogger_Close_NilFile 测试关闭空文件的日志记录器
func TestLogger_Close_NilFile(t *testing.T) {
	logger := NewNopLogger()

	err := logger.Close()
	if err != nil {
		t.Errorf("Close() 空文件时应返回 nil，实际: %v", err)
	}
}

// TestLevelConstants 测试日志级别常量
func TestLevelConstants(t *testing.T) {
	// 验证级别顺序
	if LevelDebug >= LevelInfo {
		t.Error("LevelDebug 应小于 LevelInfo")
	}
	if LevelInfo >= LevelWarn {
		t.Error("LevelInfo 应小于 LevelWarn")
	}
	if LevelWarn >= LevelError {
		t.Error("LevelWarn 应小于 LevelError")
	}
}

// TestLogRotationConstants 测试日志轮转常量
func TestLogRotationConstants(t *testing.T) {
	if MaxLogAgeDays <= 0 {
		t.Error("MaxLogAgeDays 应大于 0")
	}
	if MaxLogBackups <= 0 {
		t.Error("MaxLogBackups 应大于 0")
	}
}

// TestLogger_LevelFiltering 测试日志级别过滤
func TestLogger_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	logger, _ := New(tmpDir, "test")
	defer logger.Close()

	// 设置为 Error 级别，Debug/Info/Warn 应被过滤
	logger.SetLevel(LevelError)

	// 这些应该被过滤（不输出）
	logger.Debug("should not appear")
	logger.Info("should not appear")
	logger.Warn("should not appear")

	// 这个应该输出
	logger.Error("should appear")
}
