// Package installer 为 Apache 站点安装 HTTPS 配置
package installer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zhuxbo/cert-deploy/pkg/util"
)

// ApacheInstaller Apache HTTPS 安装器
type ApacheInstaller struct {
	configPath  string // 站点配置文件路径
	certPath    string // 证书路径
	keyPath     string // 私钥路径
	chainPath   string // 证书链路径
	serverName  string // 服务器名称
	testCommand string // 测试命令
}

// NewApacheInstaller 创建 Apache 安装器
func NewApacheInstaller(configPath, certPath, keyPath, chainPath, serverName, testCommand string) *ApacheInstaller {
	if testCommand == "" {
		testCommand = "apache2ctl -t"
	}
	return &ApacheInstaller{
		configPath:  configPath,
		certPath:    certPath,
		keyPath:     keyPath,
		chainPath:   chainPath,
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
// 基于现有 :80 VirtualHost 创建 :443 VirtualHost
func (i *ApacheInstaller) Install() (*InstallResult, error) {
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
	newContent, err := i.addSSLVirtualHost(originalContent)
	if err != nil {
		return nil, fmt.Errorf("生成 SSL 配置失败: %w", err)
	}

	// 5. 写入新配置
	if err := os.WriteFile(i.configPath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("写入配置失败: %w", err)
	}

	// 6. 测试配置
	if err := i.testConfig(); err != nil {
		// 回滚
		if rollbackErr := os.WriteFile(i.configPath, []byte(originalContent), 0644); rollbackErr != nil {
			return nil, fmt.Errorf("配置测试失败且回滚失败: test=%v, rollback=%v", err, rollbackErr)
		}
		return nil, fmt.Errorf("配置测试失败，已回滚: %w", err)
	}

	return &InstallResult{
		BackupPath: backupPath,
		Modified:   true,
	}, nil
}

// hasSSLConfig 检查目标 VirtualHost 是否已配置 SSL
// 只检查匹配 serverName 的 :443 VirtualHost，而不是整个文件
func (i *ApacheInstaller) hasSSLConfig(content string) bool {
	lines := strings.Split(content, "\n")

	// 正则表达式
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+[^>]*:443[^>]*>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	serverAliasRe := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)

	inVhost := false
	serverNames := []string{}

	for _, line := range lines {
		// 检测 :443 VirtualHost 开始
		if vhostStartRe.MatchString(line) {
			inVhost = true
			serverNames = nil
			continue
		}

		if !inVhost {
			continue
		}

		// 解析 ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			name := strings.TrimSpace(matches[1])
			name = strings.Trim(name, `"'`)
			serverNames = append(serverNames, name)
		}

		// 解析 ServerAlias
		if matches := serverAliasRe.FindStringSubmatch(line); len(matches) > 1 {
			aliases := strings.Fields(matches[1])
			for _, alias := range aliases {
				alias = strings.Trim(alias, `"'`)
				serverNames = append(serverNames, alias)
			}
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			// 检查这个 VirtualHost 是否包含目标域名
			for _, name := range serverNames {
				if name == i.serverName {
					return true
				}
			}
			inVhost = false
		}
	}

	return false
}

// backup 备份配置文件
func (i *ApacheInstaller) backup(content string) (string, error) {
	backupDir := filepath.Dir(i.configPath)
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", filepath.Base(i.configPath), timestamp))

	if err := os.WriteFile(backupPath, []byte(content), 0644); err != nil {
		return "", err
	}

	return backupPath, nil
}

// addSSLVirtualHost 添加 SSL VirtualHost
func (i *ApacheInstaller) addSSLVirtualHost(content string) (string, error) {
	// 查找 :80 VirtualHost
	vhost80, err := i.extractVirtualHost80(content)
	if err != nil {
		return "", err
	}

	if vhost80 == "" {
		return "", fmt.Errorf("未找到 :80 VirtualHost")
	}

	// 生成 :443 VirtualHost
	vhost443 := i.generateSSLVirtualHost(vhost80)

	// 在文件末尾添加
	return content + "\n" + vhost443, nil
}

// extractVirtualHost80 提取 :80 VirtualHost
func (i *ApacheInstaller) extractVirtualHost80(content string) (string, error) {
	lines := strings.Split(content, "\n")
	var result []string
	inVhost := false
	depth := 0

	// 精确匹配端口 80，避免误匹配 8080/180 等
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+[^>]*:80(?:[^0-9][^>]*)?>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)

	var currentVhost []string
	foundServerName := false

	for _, line := range lines {
		if vhostStartRe.MatchString(line) {
			inVhost = true
			depth = 1
			currentVhost = []string{line}
			foundServerName = false
			continue
		}

		if inVhost {
			currentVhost = append(currentVhost, line)

			// 检查嵌套
			if strings.Contains(line, "<") && !strings.Contains(line, "</") {
				depth++
			}
			if strings.Contains(line, "</") {
				depth--
			}

			// 检查 ServerName
			if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
				serverName := strings.TrimSpace(matches[1])
				serverName = strings.Trim(serverName, `"'`)
				if serverName == i.serverName {
					foundServerName = true
				}
			}

			// VirtualHost 结束
			if vhostEndRe.MatchString(line) {
				if foundServerName {
					result = currentVhost
					break
				}
				inVhost = false
				currentVhost = nil
			}
		}
	}

	return strings.Join(result, "\n"), nil
}

// generateSSLVirtualHost 生成 SSL VirtualHost
func (i *ApacheInstaller) generateSSLVirtualHost(vhost80 string) string {
	// 替换端口
	vhost443 := regexp.MustCompile(`(?i)(<VirtualHost\s+[^>]*):80([^>]*>)`).
		ReplaceAllString(vhost80, "${1}:443${2}")

	lines := strings.Split(vhost443, "\n")
	var result []string

	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost`)
	sslInserted := false

	for _, line := range lines {
		result = append(result, line)

		// 在 VirtualHost 开始后插入 SSL 配置
		if vhostStartRe.MatchString(line) && !sslInserted {
			indent := i.getIndent(line) + "    "
			sslConfig := []string{
				fmt.Sprintf("%sSSLEngine on", indent),
				fmt.Sprintf("%sSSLCertificateFile %s", indent, i.certPath),
				fmt.Sprintf("%sSSLCertificateKeyFile %s", indent, i.keyPath),
			}
			if i.chainPath != "" {
				sslConfig = append(sslConfig, fmt.Sprintf("%sSSLCertificateChainFile %s", indent, i.chainPath))
			}
			sslConfig = append(sslConfig,
				fmt.Sprintf("%sSSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", indent),
			)
			result = append(result, sslConfig...)
			sslInserted = true
		}
	}

	// 添加注释
	header := fmt.Sprintf("\n# SSL VirtualHost for %s - Generated by cert-deploy\n", i.serverName)

	return header + strings.Join(result, "\n")
}

// getIndent 获取行的缩进
func (i *ApacheInstaller) getIndent(line string) string {
	for idx, ch := range line {
		if ch != ' ' && ch != '\t' {
			return line[:idx]
		}
	}
	return ""
}

// testConfig 测试 Apache 配置
func (i *ApacheInstaller) testConfig() error {
	return util.RunCommand(i.testCommand)
}

// Rollback 回滚到备份
func (i *ApacheInstaller) Rollback(backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("读取备份文件失败: %w", err)
	}

	if err := os.WriteFile(i.configPath, content, 0644); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	return nil
}

// FindHTTPVirtualHost 查找 HTTP VirtualHost 的配置文件
func FindHTTPVirtualHost(configPath, serverName string) (string, error) {
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
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	includeRe := regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 检查 ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			name := strings.TrimSpace(matches[1])
			name = strings.Trim(name, `"'`)
			if name == serverName {
				return configPath, nil
			}
		}

		// 检查 Include
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
