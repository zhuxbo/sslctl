// Package scanner 扫描 Nginx 配置文件提取 SSL 证书路径
package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/zhuxbo/sslctl/internal/executor"
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

// Site 通用站点信息（合并 SSL 和非 SSL）
type Site struct {
	ConfigFile      string   `json:"config_file"`                // 配置文件路径
	ServerName      string   `json:"server_name"`                // 服务器名称（主域名）
	ServerAlias     []string `json:"server_alias,omitempty"`     // 域名别名列表
	ListenPorts     []string `json:"listen_ports"`               // 监听端口
	Webroot         string   `json:"webroot,omitempty"`          // Web 根目录 (root)
	HasSSL          bool     `json:"has_ssl"`                    // 是否配置了 SSL
	CertificatePath string   `json:"certificate_path,omitempty"` // 证书路径 (ssl_certificate)
	PrivateKeyPath  string   `json:"private_key_path,omitempty"` // 私钥路径 (ssl_certificate_key)
}

// maxScanDepth 最大扫描深度，防止符号链接环导致死循环
const maxScanDepth = 100

// Scanner Nginx 配置扫描器
type Scanner struct {
	mainConfigPath string            // 主配置文件路径
	configRoot     string            // 配置根目录
	scannedFiles   map[string]bool   // 已扫描的文件（避免循环）
	debug          bool              // 调试模式
	debugLog       func(string, ...interface{}) // 调试日志函数
}

// New 创建扫描器（自动检测配置路径）
func New() *Scanner {
	return &Scanner{
		scannedFiles: make(map[string]bool),
	}
}

// SetDebug 设置调试模式
func (s *Scanner) SetDebug(debug bool, logFn func(string, ...interface{})) {
	s.debug = debug
	s.debugLog = logFn
}

func (s *Scanner) logDebug(format string, args ...interface{}) {
	if s.debug && s.debugLog != nil {
		s.debugLog(format, args...)
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
	output, _ := executor.RunOutput("nginx -t") // 忽略错误，即使配置有问题也能获取路径

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
	output, err := executor.RunOutput("nginx -V")
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

// GetMergedConfig 使用 nginx -T 获取合并后的完整配置
// 返回配置内容和各配置文件的位置映射
func GetMergedConfig() (string, map[int]string, error) {
	output, err := executor.RunOutput("nginx -T")
	if err != nil {
		// 即使有警告也可能输出配置，检查是否有内容
		if len(output) == 0 {
			return "", nil, fmt.Errorf("nginx -T 执行失败: %w", err)
		}
	}

	content := string(output)

	// 解析配置文件位置映射
	// 格式: # configuration file /path/to/file:
	fileMap := make(map[int]string)
	configFileRe := regexp.MustCompile(`# configuration file ([^:]+):`)
	lines := strings.Split(content, "\n")
	currentFile := ""

	for i, line := range lines {
		if matches := configFileRe.FindStringSubmatch(line); len(matches) > 1 {
			currentFile = matches[1]
		}
		if currentFile != "" {
			fileMap[i] = currentFile
		}
	}

	return content, fileMap, nil
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
	return s.scanConfigFile(s.mainConfigPath, 0)
}

// ScanFile 扫描单个配置文件
func (s *Scanner) ScanFile(filePath string) ([]*SSLSite, error) {
	return s.parseConfigFile(filePath)
}

// scanConfigFile 扫描配置文件（递归处理 include）
func (s *Scanner) scanConfigFile(configPath string, depth int) ([]*SSLSite, error) {
	// 检查扫描深度限制
	if depth > maxScanDepth {
		s.logDebug("扫描深度超过限制 (%d)，跳过: %s", maxScanDepth, configPath)
		return nil, nil
	}

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
		incSites, err := s.scanConfigFile(inc, depth+1)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// findIncludes 查找配置文件中的 include 指令
func (s *Scanner) findIncludes(configPath string) ([]string, error) {
	// 使用 ReadFile 一次性读取，避免递归扫描时文件句柄长时间占用
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	configDir := filepath.Dir(configPath)
	var includes []string

	// 匹配 include 指令（支持行内注释之前的内容）
	includeRe := regexp.MustCompile(`^\s*include\s+([^;#]+);`)

	lineScanner := bufio.NewScanner(bytes.NewReader(data))
	for lineScanner.Scan() {
		line := lineScanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			// 去除引号
			pattern = strings.Trim(pattern, `"'`)

			originalPattern := pattern

			// 处理相对路径（始终基于当前配置文件目录）
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(configDir, pattern)
			}

			// 展开 glob 模式
			files, err := filepath.Glob(pattern)
			if err == nil && len(files) > 0 {
				s.logDebug("include %s => %d files", originalPattern, len(files))
				includes = append(includes, files...)
			} else if err == nil {
				// 可能是精确路径
				if _, err := os.Stat(pattern); err == nil {
					s.logDebug("include %s => 1 file (exact)", originalPattern)
					includes = append(includes, pattern)
				} else {
					s.logDebug("include %s => no match (pattern: %s)", originalPattern, pattern)
				}
			} else {
				s.logDebug("include %s => glob error: %v", originalPattern, err)
			}
		}
	}

	return includes, lineScanner.Err()
}

// parseConfigFile 解析单个配置文件
func (s *Scanner) parseConfigFile(filePath string) ([]*SSLSite, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var sites []*SSLSite
	var currentSite *SSLSite
	inServerBlock := false
	braceCount := 0
	inLocation := false       // 是否在 location 块内
	locationBraceCount := 0   // location 块的大括号计数
	pendingServer := false    // 是否有待处理的 server 关键字

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe := regexp.MustCompile(`^\s*server\s*$`)
	openBraceOnlyRe := regexp.MustCompile(`^\s*\{\s*$`)
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

		// 检测 server 块开始 - 方式1: server { 同一行
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &SSLSite{
				ConfigFile: filePath,
			}
			continue
		}

		// 检测 server 块开始 - 方式2: server 单独一行
		if serverOnlyRe.MatchString(line) {
			pendingServer = true
			continue
		}

		// 检测 server 块开始 - 方式2续: 上一行是 server，这一行是 {
		if pendingServer && openBraceOnlyRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &SSLSite{
				ConfigFile: filePath,
			}
			continue
		}

		if pendingServer {
			pendingServer = false
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
	return s.scanHTTPConfigFile(s.mainConfigPath, 0)
}

// scanHTTPConfigFile 扫描配置文件中的 HTTP 站点（递归处理 include）
func (s *Scanner) scanHTTPConfigFile(configPath string, depth int) ([]*HTTPSite, error) {
	// 检查扫描深度限制
	if depth > maxScanDepth {
		s.logDebug("扫描深度超过限制 (%d)，跳过: %s", maxScanDepth, configPath)
		return nil, nil
	}

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
		incSites, err := s.scanHTTPConfigFile(inc, depth+1)
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
	defer func() { _ = file.Close() }()

	var sites []*HTTPSite
	var currentSite *HTTPSite
	inServerBlock := false
	braceCount := 0
	hasSSL := false
	inLocation := false       // 是否在 location 块内
	locationBraceCount := 0   // location 块的大括号计数
	pendingServer := false    // 是否有待处理的 server 关键字

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe := regexp.MustCompile(`^\s*server\s*$`)
	openBraceOnlyRe := regexp.MustCompile(`^\s*\{\s*$`)
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

		// 检测 server 块开始 - 方式1: server { 同一行
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			hasSSL = false
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &HTTPSite{
				ConfigFile: filePath,
			}
			continue
		}

		// 检测 server 块开始 - 方式2: server 单独一行
		if serverOnlyRe.MatchString(line) {
			pendingServer = true
			continue
		}

		// 检测 server 块开始 - 方式2续
		if pendingServer && openBraceOnlyRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			hasSSL = false
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &HTTPSite{
				ConfigFile: filePath,
			}
			continue
		}

		if pendingServer {
			pendingServer = false
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
	defer func() { _ = file.Close() }()

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

// ScanAll 扫描所有站点（包括 SSL 和非 SSL）
func (s *Scanner) ScanAll() ([]*Site, error) {
	// 优先尝试使用 nginx -T 获取合并配置（更可靠）
	sites, err := s.scanWithNginxT()
	if err == nil && len(sites) > 0 {
		s.logDebug("使用 nginx -T 扫描成功，发现 %d 个站点", len(sites))
		return sites, nil
	}
	if err != nil {
		s.logDebug("nginx -T 扫描失败: %v，回退到文件扫描", err)
	}

	// 回退到文件扫描方式
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
	return s.scanAllConfigFile(s.mainConfigPath, 0)
}

// findNginxBinary 查找 nginx 可执行文件路径
func findNginxBinary() string {
	// 方法1: 从运行中的进程获取准确路径（最可靠）
	if path := findNginxFromProcess(); path != "" {
		return path
	}

	// 方法2: 尝试 PATH 中的 nginx
	if path, err := exec.LookPath("nginx"); err == nil {
		return path
	}

	// 方法3: 尝试常见路径
	var paths []string
	if runtime.GOOS == "windows" {
		paths = []string{
			`C:\nginx\nginx.exe`,
			`C:\Program Files\nginx\nginx.exe`,
			`C:\Program Files (x86)\nginx\nginx.exe`,
		}
	} else {
		paths = []string{
			"/usr/sbin/nginx",
			"/usr/local/sbin/nginx",
			"/usr/local/nginx/sbin/nginx",
			"/opt/nginx/sbin/nginx",
			"/www/server/nginx/sbin/nginx", // 宝塔面板
		}
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// findNginxFromProcess 从运行中的进程查找 nginx 路径
func findNginxFromProcess() string {
	if runtime.GOOS == "windows" {
		return findNginxFromProcessWindows()
	}
	return findNginxFromProcessLinux()
}

// findNginxFromProcessLinux 从 Linux 进程查找 nginx 路径
func findNginxFromProcessLinux() string {
	// 方法1: 通过 ss 查看 80/443 端口的进程
	if path := findBinaryFromPort("nginx"); path != "" {
		return path
	}

	// 方法2: 通过 ps 查找 nginx 进程
	// ps -C nginx -o pid= 获取 nginx 进程的 PID
	output, err := executor.RunOutput("ps -C nginx -o pid=")
	if err != nil || len(output) == 0 {
		return ""
	}

	// 取第一个 PID（master 进程）
	pids := strings.Fields(string(output))
	if len(pids) == 0 {
		return ""
	}

	pid := pids[0]

	// 检查是否是容器进程（容器进程交给 Docker 扫描器处理）
	if isContainerProcess(pid) {
		return ""
	}

	// 通过 /proc/<pid>/exe 获取可执行文件路径
	exePath := fmt.Sprintf("/proc/%s/exe", pid)
	realPath, err := os.Readlink(exePath)
	if err != nil {
		return ""
	}

	// 验证路径在宿主机上存在（容器内路径可能不存在）
	if _, err := os.Stat(realPath); err != nil {
		return ""
	}

	return realPath
}

// findBinaryFromPort 通过端口查找进程的可执行文件路径
func findBinaryFromPort(processName string) string {
	// 尝试 ss 命令: ss -tlnp | grep :80
	output, err := executor.RunOutput("ss -tlnp")
	if err != nil {
		// 尝试 netstat
		output, err = executor.RunOutput("netstat -tlnp")
		if err != nil {
			return ""
		}
	}

	// 查找包含 :80 或 :443 且包含进程名的行
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, processName) {
			continue
		}
		if !strings.Contains(line, ":80") && !strings.Contains(line, ":443") {
			continue
		}

		// 提取 PID，格式如: users:(("nginx",pid=1234,fd=6))
		// 或 netstat 格式: 1234/nginx
		pidRe := regexp.MustCompile(`pid=(\d+)|(\d+)/` + processName)
		matches := pidRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			pid := matches[1]
			if pid == "" {
				pid = matches[2]
			}
			if pid != "" {
				// 检查是否是容器进程
				if isContainerProcess(pid) {
					continue
				}

				exePath := fmt.Sprintf("/proc/%s/exe", pid)
				if realPath, err := os.Readlink(exePath); err == nil {
					// 验证路径存在
					if _, statErr := os.Stat(realPath); statErr == nil {
						return realPath
					}
				}
			}
		}
	}

	return ""
}

// isContainerProcess 检查进程是否运行在容器内
func isContainerProcess(pid string) bool {
	// 检查 /proc/<pid>/cgroup，容器进程会包含 docker 或 containerd 等关键字
	cgroupPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false
	}

	content := string(data)
	// Docker 容器的 cgroup 路径包含 docker 或 containerd
	if strings.Contains(content, "/docker/") ||
		strings.Contains(content, "/containerd/") ||
		strings.Contains(content, "/lxc/") ||
		strings.Contains(content, "/kubepods/") {
		return true
	}

	return false
}

// findNginxFromProcessWindows 从 Windows 进程查找 nginx 路径
func findNginxFromProcessWindows() string {
	// wmic process where "name='nginx.exe'" get ExecutablePath
	cmd := exec.Command("wmic", "process", "where", "name='nginx.exe'", "get", "ExecutablePath")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "ExecutablePath" && strings.HasSuffix(strings.ToLower(line), "nginx.exe") {
			return line
		}
	}

	return ""
}

// scanWithNginxT 使用 nginx -T 获取合并配置并解析
func (s *Scanner) scanWithNginxT() ([]*Site, error) {
	nginxPath := findNginxBinary()
	if nginxPath == "" {
		return nil, fmt.Errorf("未找到 nginx 可执行文件")
	}

	output, err := executor.RunScan(nginxPath, "-T")
	if err != nil {
		// 检查是否有有效输出（可能只是警告）
		if !strings.Contains(string(output), "server") {
			return nil, fmt.Errorf("nginx -T 执行失败: %w", err)
		}
	}

	content := string(output)

	// 跟踪当前配置文件
	configFileRe := regexp.MustCompile(`# configuration file ([^:]+):`)
	currentFile := ""

	var sites []*Site
	var currentSite *Site
	inServerBlock := false
	braceCount := 0
	inLocation := false
	locationBraceCount := 0
	pendingServer := false

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe := regexp.MustCompile(`^\s*server\s*$`)
	openBraceOnlyRe := regexp.MustCompile(`^\s*\{\s*$`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+([^;]+);`)
	sslKeyRe := regexp.MustCompile(`^\s*ssl_certificate_key\s+([^;]+);`)
	rootRe := regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe := regexp.MustCompile(`^\s*location\s+`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		// 跟踪配置文件
		if matches := configFileRe.FindStringSubmatch(line); len(matches) > 1 {
			currentFile = matches[1]
			continue
		}

		// 跳过注释行和 nginx 输出的提示信息
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "nginx:") {
			continue
		}

		// 检测 server 块开始 - 方式1: server { 同一行
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &Site{
				ConfigFile: currentFile,
			}
			continue
		}

		// 检测 server 块开始 - 方式2: server 单独一行
		if serverOnlyRe.MatchString(line) {
			pendingServer = true
			continue
		}

		// 检测 server 块开始 - 方式2续
		if pendingServer && openBraceOnlyRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &Site{
				ConfigFile: currentFile,
			}
			continue
		}

		if pendingServer {
			pendingServer = false
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
			if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
				sites = append(sites, currentSite)
			}
			inServerBlock = false
			currentSite = nil
			continue
		}

		// 解析 server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name == "_" {
					continue
				}
				if currentSite.ServerName == "" && !strings.HasPrefix(name, "*") {
					currentSite.ServerName = name
				} else {
					currentSite.ServerAlias = append(currentSite.ServerAlias, name)
				}
			}
			if currentSite.ServerName == "" && len(names) > 0 {
				currentSite.ServerName = names[0]
			}
		}

		// 解析 listen
		if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
			port := strings.TrimSpace(matches[1])
			currentSite.ListenPorts = append(currentSite.ListenPorts, port)
			if strings.Contains(port, "ssl") {
				currentSite.HasSSL = true
			}
		}

		// 解析 ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			certPath = strings.Trim(certPath, `"'`)
			currentSite.CertificatePath = certPath
			currentSite.HasSSL = true
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			currentSite.PrivateKeyPath = keyPath
		}

		// 解析 root
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
	if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
		sites = append(sites, currentSite)
	}

	return sites, nil
}

// scanAllConfigFile 扫描配置文件中的所有站点（递归处理 include）
func (s *Scanner) scanAllConfigFile(configPath string, depth int) ([]*Site, error) {
	// 检查扫描深度限制
	if depth > maxScanDepth {
		s.logDebug("扫描深度超过限制 (%d)，跳过: %s", maxScanDepth, configPath)
		return nil, nil
	}

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
		s.logDebug("扫描文件不存在: %s", configPath)
		return nil, nil
	}

	s.logDebug("扫描文件: %s", configPath)

	var sites []*Site

	// 解析当前文件
	fileSites, err := s.parseAllConfigFile(configPath)
	if err == nil {
		s.logDebug("  发现 %d 个 server 块", len(fileSites))
		sites = append(sites, fileSites...)
	} else {
		s.logDebug("  解析失败: %v", err)
	}

	// 查找 include 指令
	includes, err := s.findIncludes(configPath)
	if err != nil {
		s.logDebug("  查找 include 失败: %v", err)
		return sites, nil
	}

	// 递归扫描 include 的文件
	for _, inc := range includes {
		incSites, err := s.scanAllConfigFile(inc, depth+1)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// parseAllConfigFile 解析单个配置文件中的所有站点
func (s *Scanner) parseAllConfigFile(filePath string) ([]*Site, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var sites []*Site
	var currentSite *Site
	inServerBlock := false
	braceCount := 0
	inLocation := false
	locationBraceCount := 0
	pendingServer := false // 是否有待处理的 server 关键字（用于 server\n{ 格式）

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)       // server { 同一行
	serverOnlyRe := regexp.MustCompile(`^\s*server\s*$`)         // server 单独一行
	openBraceOnlyRe := regexp.MustCompile(`^\s*\{\s*$`)          // { 单独一行
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

		// 检测 server 块开始 - 方式1: server { 同一行
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &Site{
				ConfigFile: filePath,
			}
			continue
		}

		// 检测 server 块开始 - 方式2: server 单独一行
		if serverOnlyRe.MatchString(line) {
			pendingServer = true
			continue
		}

		// 检测 server 块开始 - 方式2续: 上一行是 server，这一行是 {
		if pendingServer && openBraceOnlyRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingServer = false
			currentSite = &Site{
				ConfigFile: filePath,
			}
			continue
		}

		// 如果 pendingServer 但这一行不是 {，重置状态
		if pendingServer {
			pendingServer = false
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
			// 保存所有有效站点（有 server_name）
			if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
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
			// 检测 SSL
			if strings.Contains(port, "ssl") {
				currentSite.HasSSL = true
			}
		}

		// 解析 ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			certPath = strings.Trim(certPath, `"'`)
			currentSite.CertificatePath = certPath
			currentSite.HasSSL = true
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			currentSite.PrivateKeyPath = keyPath
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
	if currentSite != nil && currentSite.ServerName != "" && currentSite.ServerName != "_" {
		sites = append(sites, currentSite)
	}

	return sites, scanner.Err()
}

// FindAllByDomain 根据域名查找站点（包括非 SSL）
func (s *Scanner) FindAllByDomain(domain string) (*Site, error) {
	sites, err := s.ScanAll()
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
