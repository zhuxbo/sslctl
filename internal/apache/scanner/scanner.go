// Package scanner 扫描 Apache 配置文件提取 SSL 证书路径
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// SSLSite 扫描到的 SSL 站点信息
type SSLSite struct {
	ConfigFile      string   // 配置文件路径
	ServerName      string   // 服务器名称（主域名）
	ServerAlias     []string // 域名别名列表 (ServerAlias)
	CertificatePath string   // 证书路径 (SSLCertificateFile)
	PrivateKeyPath  string   // 私钥路径 (SSLCertificateKeyFile)
	ChainPath       string   // 证书链路径 (SSLCertificateChainFile)
	ListenPort      string   // 监听端口
	Webroot         string   // Web 根目录 (DocumentRoot)
}

// HTTPSite 扫描到的 HTTP 站点信息（未启用 SSL）
type HTTPSite struct {
	ConfigFile string // 配置文件路径
	ServerName string // 服务器名称（域名）
	ListenPort string // 监听端口
	Webroot    string // Web 根目录 (DocumentRoot)
}

// Scanner Apache 配置扫描器
type Scanner struct {
	mainConfigPath string          // 主配置文件路径
	serverRoot     string          // ServerRoot 路径
	scannedFiles   map[string]bool // 已扫描的文件（避免循环）
}

// New 创建扫描器（自动检测配置路径）
func New() *Scanner {
	return &Scanner{
		scannedFiles: make(map[string]bool),
	}
}

// NewWithConfig 使用指定配置文件创建扫描器
func NewWithConfig(configPath string) *Scanner {
	return &Scanner{
		mainConfigPath: configPath,
		scannedFiles:   make(map[string]bool),
	}
}

// DetectApache 检测 Apache 是否安装并获取配置路径
func DetectApache() (configPath string, serverRoot string, err error) {
	// 尝试不同的 Apache 命令
	commands := []string{"apache2ctl", "apachectl", "httpd"}

	for _, cmd := range commands {
		configPath, serverRoot, err = getApacheConfigFromCommand(cmd)
		if err == nil && configPath != "" {
			return configPath, serverRoot, nil
		}
	}

	// 尝试常见路径
	commonConfigs := getCommonApachePaths()
	for _, cfg := range commonConfigs {
		if _, err := os.Stat(cfg.configPath); err == nil {
			return cfg.configPath, cfg.serverRoot, nil
		}
	}

	return "", "", fmt.Errorf("无法检测 Apache 配置文件路径")
}

type apacheConfig struct {
	configPath string
	serverRoot string
}

// getApacheConfigFromCommand 通过命令获取 Apache 配置
func getApacheConfigFromCommand(cmdName string) (string, string, error) {
	// apache2ctl -V 或 httpd -V 输出:
	// -D SERVER_CONFIG_FILE="apache2.conf" 或 "conf/httpd.conf"
	// -D HTTPD_ROOT="/etc/apache2" 或 "/etc/httpd"
	cmd := exec.Command(cmdName, "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}

	var serverRoot, configFile string

	// 匹配 HTTPD_ROOT
	rootRe := regexp.MustCompile(`HTTPD_ROOT="([^"]+)"`)
	if matches := rootRe.FindSubmatch(output); len(matches) > 1 {
		serverRoot = string(matches[1])
	}

	// 匹配 SERVER_CONFIG_FILE
	configRe := regexp.MustCompile(`SERVER_CONFIG_FILE="([^"]+)"`)
	if matches := configRe.FindSubmatch(output); len(matches) > 1 {
		configFile = string(matches[1])
	}

	if configFile == "" {
		return "", "", fmt.Errorf("无法获取配置文件路径")
	}

	// 如果配置文件是相对路径，拼接 ServerRoot
	var configPath string
	if filepath.IsAbs(configFile) {
		configPath = configFile
	} else if serverRoot != "" {
		configPath = filepath.Join(serverRoot, configFile)
	} else {
		return "", "", fmt.Errorf("无法确定配置文件绝对路径")
	}

	// 验证文件存在
	if _, err := os.Stat(configPath); err != nil {
		return "", "", err
	}

	return configPath, serverRoot, nil
}

// getCommonApachePaths 获取常见的 Apache 配置路径
func getCommonApachePaths() []apacheConfig {
	if runtime.GOOS == "windows" {
		return []apacheConfig{
			{`C:\Apache24\conf\httpd.conf`, `C:\Apache24`},
			{`C:\Apache\conf\httpd.conf`, `C:\Apache`},
			{`C:\Program Files\Apache24\conf\httpd.conf`, `C:\Program Files\Apache24`},
		}
	}
	return []apacheConfig{
		// Debian/Ubuntu
		{"/etc/apache2/apache2.conf", "/etc/apache2"},
		// CentOS/RHEL/Fedora
		{"/etc/httpd/conf/httpd.conf", "/etc/httpd"},
		// macOS brew
		{"/usr/local/etc/httpd/httpd.conf", "/usr/local/etc/httpd"},
		{"/opt/homebrew/etc/httpd/httpd.conf", "/opt/homebrew/etc/httpd"},
		// 编译安装
		{"/usr/local/apache2/conf/httpd.conf", "/usr/local/apache2"},
	}
}

// Scan 扫描所有配置
func (s *Scanner) Scan() ([]*SSLSite, error) {
	// 如果没有指定配置路径，自动检测
	if s.mainConfigPath == "" {
		configPath, serverRoot, err := DetectApache()
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.serverRoot = serverRoot
	}

	// 从主配置文件开始递归扫描
	return s.scanConfigFile(s.mainConfigPath)
}

// ScanFile 扫描单个配置文件
func (s *Scanner) ScanFile(filePath string) ([]*SSLSite, error) {
	return s.parseConfigFile(filePath)
}

// scanConfigFile 扫描配置文件（递归处理 Include）
func (s *Scanner) scanConfigFile(configPath string) ([]*SSLSite, error) {
	// 避免重复扫描
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	if s.scannedFiles[absPath] {
		return nil, nil
	}
	s.scannedFiles[absPath] = true

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	var sites []*SSLSite

	// 解析当前文件
	fileSites, err := s.parseConfigFile(configPath)
	if err == nil {
		sites = append(sites, fileSites...)
	}

	// 查找 Include/IncludeOptional 指令
	includes, err := s.findIncludes(configPath)
	if err != nil {
		return sites, nil
	}

	// 递归扫描 include 的文件
	for _, inc := range includes {
		incSites, err := s.scanConfigFile(inc)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// findIncludes 查找配置文件中的 Include 指令
func (s *Scanner) findIncludes(configPath string) ([]string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	configDir := filepath.Dir(configPath)
	var includes []string

	// 匹配 Include 和 IncludeOptional 指令
	includeRe := regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			// 去除引号
			pattern = strings.Trim(pattern, `"'`)

			// 处理相对路径
			if !filepath.IsAbs(pattern) {
				// 优先使用 ServerRoot，其次使用配置目录
				if s.serverRoot != "" {
					pattern = filepath.Join(s.serverRoot, pattern)
				} else {
					pattern = filepath.Join(configDir, pattern)
				}
			}

			// 展开 glob 模式
			files, err := filepath.Glob(pattern)
			if err == nil && len(files) > 0 {
				includes = append(includes, files...)
			} else if err == nil {
				// 可能是精确路径
				if _, err := os.Stat(pattern); err == nil {
					includes = append(includes, pattern)
				}
			}
		}
	}

	return includes, scanner.Err()
}

// parseConfigFile 解析单个配置文件
func (s *Scanner) parseConfigFile(filePath string) ([]*SSLSite, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sites []*SSLSite
	var currentSite *SSLSite
	inVirtualHost := false
	depth := 0

	// 正则表达式
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+([^>]+)>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	serverAliasRe := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)
	sslCertRe := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(.+)$`)
	sslKeyRe := regexp.MustCompile(`(?i)^\s*SSLCertificateKeyFile\s+(.+)$`)
	sslChainRe := regexp.MustCompile(`(?i)^\s*SSLCertificateChainFile\s+(.+)$`)
	docRootRe := regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 检测 VirtualHost 开始
		if matches := vhostStartRe.FindStringSubmatch(line); len(matches) > 1 {
			inVirtualHost = true
			depth = 1
			currentSite = &SSLSite{
				ConfigFile: filePath,
				ListenPort: strings.TrimSpace(matches[1]),
			}
			continue
		}

		if !inVirtualHost {
			continue
		}

		// 检测嵌套标签
		if strings.Contains(line, "<") && !strings.Contains(line, "</") {
			depth++
		}
		if strings.Contains(line, "</") {
			depth--
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			if currentSite != nil && currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
				sites = append(sites, currentSite)
			}
			inVirtualHost = false
			currentSite = nil
			continue
		}

		// 解析 ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			serverName := strings.TrimSpace(matches[1])
			serverName = strings.Trim(serverName, `"'`)
			currentSite.ServerName = serverName
		}

		// 解析 ServerAlias（可能包含多个域名，空格分隔）
		if matches := serverAliasRe.FindStringSubmatch(line); len(matches) > 1 {
			aliases := strings.Fields(matches[1])
			for _, alias := range aliases {
				alias = strings.Trim(alias, `"'`)
				currentSite.ServerAlias = append(currentSite.ServerAlias, alias)
			}
		}

		// 解析 SSLCertificateFile
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			certPath = strings.Trim(certPath, `"'`)
			currentSite.CertificatePath = certPath
		}

		// 解析 SSLCertificateKeyFile
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			currentSite.PrivateKeyPath = keyPath
		}

		// 解析 SSLCertificateChainFile
		if matches := sslChainRe.FindStringSubmatch(line); len(matches) > 1 {
			chainPath := strings.TrimSpace(matches[1])
			chainPath = strings.Trim(chainPath, `"'`)
			currentSite.ChainPath = chainPath
		}

		// 解析 DocumentRoot
		if matches := docRootRe.FindStringSubmatch(line); len(matches) > 1 {
			docRoot := strings.TrimSpace(matches[1])
			docRoot = strings.Trim(docRoot, `"'`)
			currentSite.Webroot = docRoot
		}
	}

	// 处理最后一个 VirtualHost
	if currentSite != nil && currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
		sites = append(sites, currentSite)
	}

	return sites, scanner.Err()
}

// FindByDomain 根据域名查找站点
// 同时匹配 ServerName 和 ServerAlias
func (s *Scanner) FindByDomain(domain string) (*SSLSite, error) {
	sites, err := s.Scan()
	if err != nil {
		return nil, err
	}

	for _, site := range sites {
		// 检查主域名
		if site.ServerName == domain {
			return site, nil
		}

		// 检查别名
		for _, alias := range site.ServerAlias {
			if alias == domain {
				return site, nil
			}
			// 支持通配符匹配
			if strings.HasPrefix(alias, "*.") {
				suffix := alias[1:] // 去掉 *
				if strings.HasSuffix(domain, suffix) {
					return site, nil
				}
			}
		}

		// 支持主域名通配符匹配
		if strings.HasPrefix(site.ServerName, "*.") {
			suffix := site.ServerName[1:] // 去掉 *
			if strings.HasSuffix(domain, suffix) {
				return site, nil
			}
		}
	}

	return nil, nil
}

// GetConfigPath 获取检测到的主配置文件路径
func (s *Scanner) GetConfigPath() string {
	return s.mainConfigPath
}

// GetServerRoot 获取 ServerRoot 路径
func (s *Scanner) GetServerRoot() string {
	return s.serverRoot
}

// ScanHTTPSites 扫描未启用 SSL 的 HTTP 站点
func (s *Scanner) ScanHTTPSites() ([]*HTTPSite, error) {
	// 如果没有指定配置路径，自动检测
	if s.mainConfigPath == "" {
		configPath, serverRoot, err := DetectApache()
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.serverRoot = serverRoot
	}

	// 重置已扫描文件记录
	s.scannedFiles = make(map[string]bool)

	// 从主配置文件开始递归扫描
	return s.scanHTTPConfigFile(s.mainConfigPath)
}

// scanHTTPConfigFile 扫描配置文件中的 HTTP 站点（递归处理 Include）
func (s *Scanner) scanHTTPConfigFile(configPath string) ([]*HTTPSite, error) {
	// 避免重复扫描
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	if s.scannedFiles[absPath] {
		return nil, nil
	}
	s.scannedFiles[absPath] = true

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	var sites []*HTTPSite

	// 解析当前文件
	fileSites, err := s.parseHTTPConfigFile(configPath)
	if err == nil {
		sites = append(sites, fileSites...)
	}

	// 查找 Include/IncludeOptional 指令
	includes, err := s.findIncludes(configPath)
	if err != nil {
		return sites, nil
	}

	// 递归扫描 include 的文件
	for _, inc := range includes {
		incSites, err := s.scanHTTPConfigFile(inc)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// parseHTTPConfigFile 解析单个配置文件中的 HTTP 站点
func (s *Scanner) parseHTTPConfigFile(filePath string) ([]*HTTPSite, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sites []*HTTPSite
	var currentSite *HTTPSite
	inVirtualHost := false
	depth := 0
	hasSSL := false

	// 正则表达式
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+([^>]+)>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	sslEngineRe := regexp.MustCompile(`(?i)^\s*SSLEngine\s+on`)
	sslCertRe := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+`)
	docRootRe := regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 检测 VirtualHost 开始
		if matches := vhostStartRe.FindStringSubmatch(line); len(matches) > 1 {
			inVirtualHost = true
			depth = 1
			hasSSL = false
			listenPort := strings.TrimSpace(matches[1])
			// 检查端口是否为 443（通常是 SSL）
			if strings.Contains(listenPort, ":443") {
				hasSSL = true
			}
			currentSite = &HTTPSite{
				ConfigFile: filePath,
				ListenPort: listenPort,
			}
			continue
		}

		if !inVirtualHost {
			continue
		}

		// 检测嵌套标签
		if strings.Contains(line, "<") && !strings.Contains(line, "</") {
			depth++
		}
		if strings.Contains(line, "</") {
			depth--
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			// 只添加没有 SSL 配置的站点
			if currentSite != nil && !hasSSL && currentSite.ServerName != "" {
				sites = append(sites, currentSite)
			}
			inVirtualHost = false
			currentSite = nil
			continue
		}

		// 检测 SSL 配置
		if sslEngineRe.MatchString(line) || sslCertRe.MatchString(line) {
			hasSSL = true
		}

		// 解析 ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			serverName := strings.TrimSpace(matches[1])
			serverName = strings.Trim(serverName, `"'`)
			currentSite.ServerName = serverName
		}

		// 解析 DocumentRoot
		if matches := docRootRe.FindStringSubmatch(line); len(matches) > 1 {
			docRoot := strings.TrimSpace(matches[1])
			docRoot = strings.Trim(docRoot, `"'`)
			currentSite.Webroot = docRoot
		}
	}

	// 处理最后一个 VirtualHost
	if currentSite != nil && !hasSSL && currentSite.ServerName != "" {
		sites = append(sites, currentSite)
	}

	return sites, scanner.Err()
}

// HasSSLConfig 检查指定配置文件是否已有 SSL 配置
func (s *Scanner) HasSSLConfig(configPath string) bool {
	file, err := os.Open(configPath)
	if err != nil {
		return false
	}
	defer file.Close()

	sslEngineRe := regexp.MustCompile(`(?i)^\s*SSLEngine\s+on`)
	sslCertRe := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if sslEngineRe.MatchString(line) || sslCertRe.MatchString(line) {
			return true
		}
	}

	return false
}
