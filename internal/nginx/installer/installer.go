// Package installer 为 Nginx 站点安装 HTTPS 配置
package installer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
)

// NginxInstaller Nginx HTTPS 安装器
type NginxInstaller struct {
	configPath  string // 站点配置文件路径
	certPath    string // 证书路径
	keyPath     string // 私钥路径
	serverName  string // 服务器名称
	testCommand string // 测试命令
}

// NewNginxInstaller 创建 Nginx 安装器
func NewNginxInstaller(configPath, certPath, keyPath, serverName, testCommand string) *NginxInstaller {
	return &NginxInstaller{
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		serverName:  serverName,
		testCommand: testCommand,
	}
}

// InstallResult 安装结果
type InstallResult struct {
	BackupPath string // 备份路径
	Modified   bool   // 是否修改了配置
}

// Install 安装 HTTPS 配置
// 在现有 HTTP server 块中添加 SSL 配置
func (i *NginxInstaller) Install() (*InstallResult, error) {
	// 1. 读取配置文件
	content, err := os.ReadFile(i.configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	originalContent := string(content)

	// 2. 检查是否已配置 SSL
	if i.hasSSLConfig(originalContent) {
		return &InstallResult{Modified: false}, nil
	}

	// 3. 备份原配置
	backupPath, err := i.backup(originalContent)
	if err != nil {
		return nil, fmt.Errorf("备份配置失败: %w", err)
	}

	// 4. 生成新配置
	newContent, err := i.addSSLConfig(originalContent)
	if err != nil {
		return nil, fmt.Errorf("生成 SSL 配置失败: %w", err)
	}

	// 5. 写入新配置
	if err := os.WriteFile(i.configPath, []byte(newContent), 0600); err != nil {
		return nil, fmt.Errorf("写入配置失败: %w", err)
	}

	// 6. 测试配置
	if err := i.testConfig(); err != nil {
		// 回滚
		if rollbackErr := os.WriteFile(i.configPath, []byte(originalContent), 0600); rollbackErr != nil {
			return nil, fmt.Errorf("配置测试失败且回滚失败: test=%v, rollback=%v", err, rollbackErr)
		}
		return nil, fmt.Errorf("配置测试失败，已回滚: %w", err)
	}

	return &InstallResult{
		BackupPath: backupPath,
		Modified:   true,
	}, nil
}

// hasSSLConfig 检查目标 server 块是否已配置 SSL
// 只检查匹配 serverName 的 server 块，而不是整个文件
func (i *NginxInstaller) hasSSLConfig(content string) bool {
	lines := strings.Split(content, "\n")

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)

	inServerBlock := false
	braceCount := 0
	currentServerNames := []string{}
	hasSSLInBlock := false

	for _, line := range lines {
		// 跳过注释
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 检测 server 块开始
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			currentServerNames = nil
			hasSSLInBlock = false
			continue
		}

		if !inServerBlock {
			continue
		}

		// 统计大括号
		braceCount += strings.Count(line, "{") - strings.Count(line, "}")

		// 解析 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			currentServerNames = append(currentServerNames, names...)
		}

		// 检测 SSL 配置
		if sslCertRe.MatchString(line) {
			hasSSLInBlock = true
		}

		// server 块结束
		if braceCount <= 0 {
			// 检查这个 server 块是否是目标域名且已有 SSL
			for _, name := range currentServerNames {
				if name == i.serverName && hasSSLInBlock {
					return true
				}
			}
			inServerBlock = false
		}
	}

	return false
}

// backup 备份配置文件
func (i *NginxInstaller) backup(content string) (string, error) {
	backupDir := filepath.Dir(i.configPath)
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", filepath.Base(i.configPath), timestamp))

	if err := os.WriteFile(backupPath, []byte(content), 0600); err != nil {
		return "", err
	}

	return backupPath, nil
}

// addSSLConfig 添加 SSL 配置到 server 块
func (i *NginxInstaller) addSSLConfig(content string) (string, error) {
	lines := strings.Split(content, "\n")
	var result []string

	// 状态跟踪
	inServerBlock := false
	braceCount := 0
	hasListen80 := false
	listenLineIndex := -1

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	// 精确匹配端口 80：开头或冒号后是 80，后面是空格、分号或行尾
	listen80Re := regexp.MustCompile(`(?:^|[:\s])80(?:\s|;|$)`)

	for _, line := range lines {
		// 检测 server 块开始
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			hasListen80 = false
			listenLineIndex = -1
			result = append(result, line)
			continue
		}

		if inServerBlock {
			// 统计大括号
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			// 检查 listen 指令
			if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
				listenValue := strings.TrimSpace(matches[1])
				// 精确检查是否是 80 端口（避免误匹配 8080、18080 等）
				if listen80Re.MatchString(listenValue) && !strings.Contains(listenValue, "ssl") {
					hasListen80 = true
					listenLineIndex = len(result)
				}
			}

			// server 块结束
			if braceCount <= 0 {
				// 如果这个 server 块有 listen 80，添加 SSL 配置
				if hasListen80 && listenLineIndex >= 0 {
					// 在 listen 80 后面添加 listen 443 ssl
					result = i.insertSSLDirectives(result, listenLineIndex)
				}
				inServerBlock = false
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n"), nil
}

// insertSSLDirectives 在指定位置插入 SSL 指令
func (i *NginxInstaller) insertSSLDirectives(lines []string, afterIndex int) []string {
	// 获取缩进
	indent := i.getIndent(lines[afterIndex])

	// SSL 配置
	sslConfig := []string{
		fmt.Sprintf("%slisten 443 ssl;", indent),
		fmt.Sprintf("%slisten [::]:443 ssl;", indent),
		fmt.Sprintf("%sssl_certificate %s;", indent, i.certPath),
		fmt.Sprintf("%sssl_certificate_key %s;", indent, i.keyPath),
		fmt.Sprintf("%sssl_protocols TLSv1.2 TLSv1.3;", indent),
		fmt.Sprintf("%sssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;", indent),
		fmt.Sprintf("%sssl_prefer_server_ciphers off;", indent),
	}

	// 插入到 listen 80 之后
	newLines := make([]string, 0, len(lines)+len(sslConfig))
	newLines = append(newLines, lines[:afterIndex+1]...)
	newLines = append(newLines, sslConfig...)
	newLines = append(newLines, lines[afterIndex+1:]...)

	return newLines
}

// getIndent 获取行的缩进
func (i *NginxInstaller) getIndent(line string) string {
	for idx, ch := range line {
		if ch != ' ' && ch != '\t' {
			return line[:idx]
		}
	}
	return ""
}

// testConfig 测试 Nginx 配置
func (i *NginxInstaller) testConfig() error {
	if i.testCommand == "" {
		return nil
	}
	return executor.Run(i.testCommand)
}

// Rollback 回滚到备份
func (i *NginxInstaller) Rollback(backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("读取备份文件失败: %w", err)
	}

	if err := os.WriteFile(i.configPath, content, 0644); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	return nil
}

// FindHTTPServerBlock 查找 HTTP server 块的配置文件
func FindHTTPServerBlock(configPath, serverName string) (string, error) {
	// 递归查找包含指定 server_name 的配置文件
	return findConfigWithServerName(configPath, serverName)
}

// findConfigWithServerName 递归查找配置文件
func findConfigWithServerName(configPath, serverName string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	configDir := filepath.Dir(configPath)
	serverNameRe := regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)
	includeRe := regexp.MustCompile(`^\s*include\s+([^;]+);`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 检查 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name == serverName {
					return configPath, nil
				}
			}
		}

		// 检查 include
		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			pattern = strings.Trim(pattern, `"'`)

			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(configDir, pattern)
			}

			files, err := filepath.Glob(pattern)
			if err == nil {
				for _, f := range files {
					if result, err := findConfigWithServerName(f, serverName); err == nil && result != "" {
						return result, nil
					}
				}
			}
		}
	}

	return "", nil
}
