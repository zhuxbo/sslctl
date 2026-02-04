// Package logger 日志记录器
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// 敏感信息过滤正则表达式
var (
	// 匹配 PEM 格式的私钥
	privateKeyRegex = regexp.MustCompile(`-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----`)
	// 匹配 API Token（Bearer token 格式）
	bearerTokenRegex = regexp.MustCompile(`Bearer\s+[A-Za-z0-9\-_\.]+`)
	// 匹配常见的 token/secret 参数
	tokenParamRegex = regexp.MustCompile(`(token|secret|password|api_key|apikey)=["']?[^"'\s&]+["']?`)
)

// sanitize 过滤敏感信息
func sanitize(msg string) string {
	// 过滤私钥
	msg = privateKeyRegex.ReplaceAllString(msg, "***REDACTED PRIVATE KEY***")
	// 过滤 Bearer token
	msg = bearerTokenRegex.ReplaceAllString(msg, "Bearer ***REDACTED***")
	// 过滤 token/secret 参数
	msg = tokenParamRegex.ReplaceAllStringFunc(msg, func(match string) string {
		// 保留参数名，只隐藏值
		idx := 0
		for i, c := range match {
			if c == '=' {
				idx = i
				break
			}
		}
		return match[:idx+1] + "***REDACTED***"
	})
	return msg
}

// Level 日志级别
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// 日志轮转配置
const (
	MaxLogAgeDays = 30 // 保留 30 天
	MaxLogBackups = 10 // 最多保留 10 个日志文件
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
	if err := os.MkdirAll(logDir, 0700); err != nil {
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

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
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
			oldFile := l.file
			l.file = nil
			_ = oldFile.Close()
			if err := l.openLogFile(); err != nil {
				// 打开新文件失败，尝试恢复旧文件或在控制台输出警告
				fmt.Printf("[WARN] 切换日志文件失败: %v，后续日志仅输出到控制台\n", err)
			}
			// 日期切换时清理旧日志
			l.cleanOldLogs()
		}
	} else if l.logDir != "" {
		// 如果文件为空但日志目录存在，尝试重新打开
		_ = l.openLogFile()
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	// 过滤敏感信息
	message = sanitize(message)
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

// NewNopLogger 创建一个不输出任何内容的日志记录器（用于测试）
func NewNopLogger() *Logger {
	return &Logger{
		minLevel: LevelError + 1, // 高于所有级别，不输出任何日志
	}
}

// cleanOldLogs 清理旧日志文件
func (l *Logger) cleanOldLogs() {
	pattern := filepath.Join(l.logDir, l.siteName+"-*.log")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) < MaxLogBackups {
		return
	}

	// 获取文件信息并按修改时间排序（最新在前）
	type fileInfo struct {
		path    string
		modTime time.Time
	}
	fileInfos := make([]fileInfo, 0, len(files))
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, fileInfo{path: f, modTime: info.ModTime()})
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].modTime.After(fileInfos[j].modTime)
	})

	// 删除超出保留数量的旧文件
	for i := MaxLogBackups; i < len(fileInfos); i++ {
		_ = os.Remove(fileInfos[i].path)
	}
}
