// Package scanner 扫描 Nginx 配置文件提取 SSL 证书路径
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
	ServerAlias     []string // 域名别名列表
	CertificatePath string   // 证书路径 (ssl_certificate)
	PrivateKeyPath  string   // 私钥路径 (ssl_certificate_key)
	ListenPorts     []string // 监听端口
	Webroot         string   // Web 根目录 (root)
}

// HTTPSite 扫描到的 HTTP 站点信息（未启用 SSL）
type HTTPSite struct {
	ConfigFile  string // 配置文件路径
	ServerName  string // 服务器名称（域名）
	ListenPort  string // 监听端口
	Webroot     string // Web 根目录 (root)
}

// Scanner Nginx 配置扫描器
type Scanner struct {
	mainConfigPath string   // 主配置文件路径
	configRoot     string   // 配置根目录
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
		configRoot:     filepath.Dir(configPath),
		scannedFiles:   make(map[string]bool),
	}
}

// DetectNginx 检测 Nginx 是否安装并获取配置路径
func DetectNginx() (configPath string, err error) {
	// 方法1: 通过 nginx -t 获取配置路径
	configPath, err = getNginxConfigFromTest()
	if err == nil && configPath != "" {
		return configPath, nil
	}

	// 方法2: 通过 nginx -V 获取编译时的默认路径
	configPath, err = getNginxConfigFromVersion()
	if err == nil && configPath != "" {
		return configPath, nil
	}

	// 方法3: 尝试常见路径
	commonPaths := getCommonNginxPaths()
	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("无法检测 Nginx 配置文件路径")
}

// getNginxConfigFromTest 通过 nginx -t 获取配置路径
func getNginxConfigFromTest() (string, error) {
	// nginx -t 输出: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
	cmd := exec.Command("nginx", "-t")
	output, _ := cmd.CombinedOutput() // 忽略错误，即使配置有问题也能获取路径

	// 匹配配置文件路径
	re := regexp.MustCompile(`configuration file (.+?) `)
	matches := re.FindSubmatch(output)
	if len(matches) > 1 {
		configPath := string(matches[1])
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("无法从 nginx -t 获取配置路径")
}

// getNginxConfigFromVersion 通过 nginx -V 获取配置路径
func getNginxConfigFromVersion() (string, error) {
	// nginx -V 输出包含: --conf-path=/etc/nginx/nginx.conf
	cmd := exec.Command("nginx", "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// 匹配 --conf-path
	re := regexp.MustCompile(`--conf-path=([^\s]+)`)
	matches := re.FindSubmatch(output)
	if len(matches) > 1 {
		configPath := string(matches[1])
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
	}

	// 匹配 --prefix 然后拼接 conf/nginx.conf
	re = regexp.MustCompile(`--prefix=([^\s]+)`)
	matches = re.FindSubmatch(output)
	if len(matches) > 1 {
		prefix := string(matches[1])
		configPath := filepath.Join(prefix, "conf", "nginx.conf")
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("无法从 nginx -V 获取配置路径")
}

// getCommonNginxPaths 获取常见的 Nginx 配置路径
func getCommonNginxPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\nginx\conf\nginx.conf`,
			`C:\Program Files\nginx\conf\nginx.conf`,
		}
	}
	return []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf", // macOS brew
		"/opt/nginx/conf/nginx.conf",
	}
}

// Scan 扫描所有配置目录
func (s *Scanner) Scan() ([]*SSLSite, error) {
	// 如果没有指定配置路径，自动检测
	if s.mainConfigPath == "" {
		configPath, err := DetectNginx()
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.configRoot = filepath.Dir(configPath)
	}

	// 从主配置文件开始递归扫描
	return s.scanConfigFile(s.mainConfigPath)
}

// ScanFile 扫描单个配置文件
func (s *Scanner) ScanFile(filePath string) ([]*SSLSite, error) {
	return s.parseConfigFile(filePath)
}

// scanConfigFile 扫描配置文件（递归处理 include）
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

	// 查找 include 指令
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

// findIncludes 查找配置文件中的 include 指令
func (s *Scanner) findIncludes(configPath string) ([]string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	configDir := filepath.Dir(configPath)
	var includes []string

	// 匹配 include 指令
	includeRe := regexp.MustCompile(`^\s*include\s+([^;]+);`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}

		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			// 去除引号
			pattern = strings.Trim(pattern, `"'`)

			// 处理相对路径
			if !filepath.IsAbs(pattern) {
				// 相对于配置根目录或当前配置目录
				pattern = filepath.Join(configDir, pattern)
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
	inServerBlock := false
	braceCount := 0
	inLocation := false       // 是否在 location 块内
	locationBraceCount := 0   // location 块的大括号计数

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+([^;]+);`)
	sslKeyRe := regexp.MustCompile(`^\s*ssl_certificate_key\s+([^;]+);`)
	rootRe := regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe := regexp.MustCompile(`^\s*location\s+`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 检测 server 块开始
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			currentSite = &SSLSite{
				ConfigFile: filePath,
			}
			continue
		}

		if !inServerBlock {
			continue
		}

		// 检测 location 块开始
		if locationRe.MatchString(line) && strings.Contains(line, "{") {
			inLocation = true
			locationBraceCount = 1
		}

		// 统计大括号
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")
		braceCount += openBraces - closeBraces

		// 跟踪 location 块的大括号（排除当前行已处理的）
		if inLocation && !locationRe.MatchString(line) {
			locationBraceCount += openBraces - closeBraces
			if locationBraceCount <= 0 {
				inLocation = false
				locationBraceCount = 0
			}
		}

		// server 块结束
		if braceCount <= 0 {
			if currentSite != nil && currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
				sites = append(sites, currentSite)
			}
			inServerBlock = false
			currentSite = nil
			continue
		}

		// 解析 server_name（保存所有域名别名）
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name == "_" {
					continue
				}
				// 第一个非通配符域名作为主域名
				if currentSite.ServerName == "" && !strings.HasPrefix(name, "*") {
					currentSite.ServerName = name
				} else {
					// 其他域名作为别名
					currentSite.ServerAlias = append(currentSite.ServerAlias, name)
				}
			}
			// 如果全是通配符，取第一个作为主域名
			if currentSite.ServerName == "" && len(names) > 0 {
				currentSite.ServerName = names[0]
			}
		}

		// 解析 listen
		if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
			port := strings.TrimSpace(matches[1])
			currentSite.ListenPorts = append(currentSite.ListenPorts, port)
		}

		// 解析 ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			// 去除引号
			certPath = strings.Trim(certPath, `"'`)
			currentSite.CertificatePath = certPath
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			// 去除引号
			keyPath = strings.Trim(keyPath, `"'`)
			currentSite.PrivateKeyPath = keyPath
		}

		// 解析 root（仅在 server 块级别，不在 location 块内）
		if !inLocation {
			if matches := rootRe.FindStringSubmatch(line); len(matches) > 1 {
				// 只取第一个 server 级别的 root 指令
				if currentSite.Webroot == "" {
					webroot := strings.TrimSpace(matches[1])
					webroot = strings.Trim(webroot, `"'`)
					currentSite.Webroot = webroot
				}
			}
		}
	}

	// 处理最后一个 server 块
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

// ScanHTTPSites 扫描未启用 SSL 的 HTTP 站点
func (s *Scanner) ScanHTTPSites() ([]*HTTPSite, error) {
	// 如果没有指定配置路径，自动检测
	if s.mainConfigPath == "" {
		configPath, err := DetectNginx()
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.configRoot = filepath.Dir(configPath)
	}

	// 重置已扫描文件记录
	s.scannedFiles = make(map[string]bool)

	// 从主配置文件开始递归扫描
	return s.scanHTTPConfigFile(s.mainConfigPath)
}

// scanHTTPConfigFile 扫描配置文件中的 HTTP 站点（递归处理 include）
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

	// 查找 include 指令
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
	inServerBlock := false
	braceCount := 0
	hasSSL := false
	inLocation := false       // 是否在 location 块内
	locationBraceCount := 0   // location 块的大括号计数

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)
	rootRe := regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe := regexp.MustCompile(`^\s*location\s+`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// 检测 server 块开始
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			hasSSL = false
			inLocation = false
			locationBraceCount = 0
			currentSite = &HTTPSite{
				ConfigFile: filePath,
			}
			continue
		}

		if !inServerBlock {
			continue
		}

		// 检测 location 块开始
		if locationRe.MatchString(line) && strings.Contains(line, "{") {
			inLocation = true
			locationBraceCount = 1
		}

		// 统计大括号
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")
		braceCount += openBraces - closeBraces

		// 跟踪 location 块的大括号
		if inLocation && !locationRe.MatchString(line) {
			locationBraceCount += openBraces - closeBraces
			if locationBraceCount <= 0 {
				inLocation = false
				locationBraceCount = 0
			}
		}

		// server 块结束
		if braceCount <= 0 {
			// 只添加没有 SSL 配置的站点
			if currentSite != nil && !hasSSL && currentSite.ServerName != "" {
				sites = append(sites, currentSite)
			}
			inServerBlock = false
			currentSite = nil
			continue
		}

		// 检测 SSL 配置
		if sslCertRe.MatchString(line) {
			hasSSL = true
		}

		// 检测 listen 指令中的 ssl 关键字
		if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
			listenValue := strings.TrimSpace(matches[1])
			if strings.Contains(listenValue, "ssl") {
				hasSSL = true
			}
			// 保存监听端口（取第一个非 SSL 的）
			if currentSite.ListenPort == "" && !strings.Contains(listenValue, "ssl") {
				// 提取端口号
				parts := strings.Fields(listenValue)
				if len(parts) > 0 {
					port := parts[0]
					// 处理 [::]:80 格式
					if strings.Contains(port, "]:") {
						port = strings.Split(port, "]:")[1]
					} else if strings.Contains(port, ":") {
						port = strings.Split(port, ":")[1]
					}
					currentSite.ListenPort = port
				}
			}
		}

		// 解析 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			if len(names) > 0 {
				// 取第一个非通配符域名
				for _, name := range names {
					if name != "_" && !strings.HasPrefix(name, "*") {
						currentSite.ServerName = name
						break
					}
				}
				if currentSite.ServerName == "" && len(names) > 0 {
					currentSite.ServerName = names[0]
				}
			}
		}

		// 解析 root（仅在 server 块级别，不在 location 块内）
		if !inLocation {
			if matches := rootRe.FindStringSubmatch(line); len(matches) > 1 {
				if currentSite.Webroot == "" {
					webroot := strings.TrimSpace(matches[1])
					webroot = strings.Trim(webroot, `"'`)
					currentSite.Webroot = webroot
				}
			}
		}
	}

	// 处理最后一个 server 块
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

	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)
	sslListenRe := regexp.MustCompile(`^\s*listen\s+.*ssl`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if sslCertRe.MatchString(line) || sslListenRe.MatchString(line) {
			return true
		}
	}

	return false
}
