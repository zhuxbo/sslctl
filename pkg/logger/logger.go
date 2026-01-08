// Package logger 日志记录器
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level 日志级别
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel 从字符串解析日志级别
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG":
		return LevelDebug
	case "info", "INFO":
		return LevelInfo
	case "warn", "WARN", "warning", "WARNING":
		return LevelWarn
	case "error", "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// getLevelFromEnv 从环境变量获取日志级别
func getLevelFromEnv() Level {
	levelStr := os.Getenv("LOG_LEVEL")
	if levelStr == "" {
		return LevelInfo
	}
	return ParseLevel(levelStr)
}

// Logger 日志记录器
type Logger struct {
	logDir   string
	siteName string
	mu       sync.Mutex
	file     *os.File
	minLevel Level
}

// New 创建日志记录器
// 日志级别通过 LOG_LEVEL 环境变量配置，支持: debug, info, warn, error
func New(logDir, siteName string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	l := &Logger{
		logDir:   logDir,
		siteName: siteName,
		minLevel: getLevelFromEnv(),
	}

	if err := l.openLogFile(); err != nil {
		return nil, err
	}

	return l, nil
}

// openLogFile 打开或创建日志文件
func (l *Logger) openLogFile() error {
	// 按日期命名日志文件
	date := time.Now().Format("2006-01-02")
	filename := fmt.Sprintf("%s-%s.log", l.siteName, date)
	logPath := filepath.Join(l.logDir, filename)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.file = file
	return nil
}

// SetLevel 设置最小日志级别
func (l *Logger) SetLevel(level Level) {
	l.minLevel = level
}

// log 写入日志
func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.minLevel {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 检查是否需要切换日志文件（日期变化）
	date := time.Now().Format("2006-01-02")
	expectedFilename := fmt.Sprintf("%s-%s.log", l.siteName, date)
	if l.file != nil {
		currentFilename := filepath.Base(l.file.Name())
		if currentFilename != expectedFilename {
			_ = l.file.Close()
			_ = l.openLogFile()
		}
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("[%s] [%s] %s\n", timestamp, level.String(), message)

	// 写入文件
	if l.file != nil {
		_, _ = l.file.WriteString(logLine)
	}

	// 同时输出到控制台
	fmt.Print(logLine)
}

// Debug 调试日志
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Info 信息日志
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warn 警告日志
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Error 错误日志
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Close 关闭日志文件
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// LogDeployment 记录部署操作
func (l *Logger) LogDeployment(domain, certPath, keyPath string, success bool, err error) {
	if success {
		l.Info("证书部署成功: domain=%s, cert=%s, key=%s", domain, certPath, keyPath)
	} else {
		l.Error("证书部署失败: domain=%s, cert=%s, key=%s, error=%v", domain, certPath, keyPath, err)
	}
}

// LogBackup 记录备份操作
func (l *Logger) LogBackup(srcPath, backupPath string, success bool, err error) {
	if success {
		l.Info("证书备份成功: src=%s, backup=%s", srcPath, backupPath)
	} else {
		l.Error("证书备份失败: src=%s, backup=%s, error=%v", srcPath, backupPath, err)
	}
}

// LogReload 记录重载操作
func (l *Logger) LogReload(command string, success bool, output string, err error) {
	if success {
		l.Info("服务重载成功: command=%s", command)
	} else {
		l.Error("服务重载失败: command=%s, output=%s, error=%v", command, output, err)
	}
}

// LogScan 记录扫描操作
func (l *Logger) LogScan(configPath string, sitesFound int) {
	l.Info("配置扫描完成: path=%s, sites_found=%d", configPath, sitesFound)
}
