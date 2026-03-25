// Package scanner 扫描 Nginx 配置文件提取 SSL 证书路径
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/internal/executor"
	"github.com/zhuxbo/sslctl/pkg/matcher"
	"github.com/zhuxbo/sslctl/pkg/util"
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

// maxScanFiles 最大扫描文件数，防止 glob 展开大量文件导致性能问题
const maxScanFiles = 1000

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
	// 优先使用动态路径（避免 PATH 里的 nginx 不可用）
	nginxPath := findNginxBinary()
	var output []byte
	if nginxPath != "" {
		args := buildNginxArgs(nginxPath, "-t")
		output, _ = executor.RunScan(nginxPath, args...)
	}
	if len(output) == 0 {
		output, _ = executor.RunOutput("nginx -t")
	}

	// nginx -t 输出: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
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
	// nginx -V 输出编译信息，不需要 -p（与运行时目录无关）
	nginxPath := findNginxBinary()
	var output []byte
	var err error
	if nginxPath != "" {
		output, err = executor.RunScan(nginxPath, "-V")
	}
	if len(output) == 0 {
		output, err = executor.RunOutput("nginx -V")
	}
	if err != nil && len(output) == 0 {
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
	// 优先使用动态路径（处理 Windows nginx 不在 PATH 或需要 -p 的情况）
	var output []byte
	var err error
	if nginxPath := findNginxBinary(); nginxPath != "" {
		args := buildNginxArgs(nginxPath, "-T")
		output, err = executor.RunScan(nginxPath, args...)
	}
	if len(output) == 0 {
		output, err = executor.RunOutput("nginx -T")
	}
	if err != nil {
		if len(output) == 0 {
			return "", nil, fmt.Errorf("nginx -T 执行失败: %w", err)
		}
	}

	content := string(output)

	// 解析配置文件位置映射
	// 格式: # configuration file /path/to/file:
	fileMap := make(map[int]string)
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
	s.scannedFiles = make(map[string]bool)
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
	// 检查文件总数限制
	if len(s.scannedFiles) >= maxScanFiles {
		s.logDebug("扫描文件数超过限制 (%d)，跳过: %s", maxScanFiles, configPath)
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

// parseOptions 配置解析选项，参数化各解析函数的差异
type parseOptions struct {
	skipNginxLines  bool // 跳过 "nginx:" 开头的行（用于 nginx -T 输出）
	trackConfigFile bool // 跟踪 "# configuration file ..." 行（用于 nginx -T 输出）
}

// rawBlock 通用 server 块解析结果
type rawBlock struct {
	configFile      string
	serverName      string
	serverAlias     []string
	listenPorts     []string
	webroot         string
	hasSSL          bool
	certificatePath string
	privateKeyPath  string
}

// 编译一次正则表达式，避免每次解析重复编译
var (
	serverBlockRe  = regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe   = regexp.MustCompile(`^\s*server\s*$`)
	openBraceOnlyRe = regexp.MustCompile(`^\s*\{\s*$`)
	serverNameRe   = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe       = regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe      = regexp.MustCompile(`^\s*ssl_certificate\s+([^;]+);`)
	sslKeyRe       = regexp.MustCompile(`^\s*ssl_certificate_key\s+([^;]+);`)
	rootRe         = regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe     = regexp.MustCompile(`^\s*location\s+`)
	configFileRe   = regexp.MustCompile(`# configuration file (.+):`)
)

// parseServerBlocks 统一的 server 块解析引擎
// 从文本行中提取所有 server 块信息
func parseServerBlocks(lines []string, defaultConfigFile string, opts parseOptions) []rawBlock {
	var blocks []rawBlock
	var current *rawBlock
	inServerBlock := false
	braceCount := 0
	inLocation := false
	locationBraceCount := 0
	pendingLocation := false
	pendingServer := false
	currentFile := defaultConfigFile

	for _, line := range lines {
		// 跟踪配置文件（nginx -T 模式）
		if opts.trackConfigFile {
			if matches := configFileRe.FindStringSubmatch(line); len(matches) > 1 {
				currentFile = matches[1]
				continue
			}
		}

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// nginx -T 模式下跳过 nginx: 开头的提示信息
		if opts.skipNginxLines && strings.HasPrefix(trimmed, "nginx:") {
			continue
		}

		// 检测 server 块开始 - 方式1: server { 同一行
		if serverBlockRe.MatchString(line) {
			inServerBlock = true
			braceCount = 1
			inLocation = false
			locationBraceCount = 0
			pendingLocation = false
			pendingServer = false
			current = &rawBlock{configFile: currentFile}
			continue
		}

		// 检测 server 块开始 - 方式2: server 单独一行
		if serverOnlyRe.MatchString(line) {
			pendingServer = true
			continue
		}

		// 检测 server 块开始 - 方式2续: server 之后等待 {（跳过空行）
		if pendingServer {
			if trimmed == "" {
				continue
			}
			if openBraceOnlyRe.MatchString(line) {
				inServerBlock = true
				braceCount = 1
				inLocation = false
				locationBraceCount = 0
				pendingServer = false
				current = &rawBlock{configFile: currentFile}
				continue
			}
			pendingServer = false
		}

		if !inServerBlock {
			continue
		}

		// 检测 location 块开始
		if locationRe.MatchString(line) {
			if strings.Contains(line, "{") {
				inLocation = true
				locationBraceCount = 1
			} else {
				pendingLocation = true
			}
		}
		if pendingLocation && !locationRe.MatchString(line) && strings.Contains(line, "{") {
			inLocation = true
			locationBraceCount = 0
			pendingLocation = false
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
			if current != nil {
				blocks = append(blocks, *current)
			}
			inServerBlock = false
			current = nil
			continue
		}

		// 解析 server_name（保存所有域名别名）
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name == "_" {
					continue
				}
				if current.serverName == "" && !strings.HasPrefix(name, "*") {
					current.serverName = name
				} else {
					current.serverAlias = append(current.serverAlias, name)
				}
			}
			if current.serverName == "" && len(names) > 0 {
				current.serverName = names[0]
			}
		}

		// 解析 listen
		if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
			port := strings.TrimSpace(matches[1])
			current.listenPorts = append(current.listenPorts, port)
			if strings.Contains(port, "ssl") {
				current.hasSSL = true
			}
		}

		// 解析 ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			certPath = strings.Trim(certPath, `"'`)
			current.certificatePath = certPath
			current.hasSSL = true
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			current.privateKeyPath = keyPath
		}

		// 解析 root（仅在 server 块级别，不在 location 块内）
		if !inLocation {
			if matches := rootRe.FindStringSubmatch(line); len(matches) > 1 {
				if current.webroot == "" {
					webroot := strings.TrimSpace(matches[1])
					webroot = strings.Trim(webroot, `"'`)
					current.webroot = webroot
				}
			}
		}
	}

	// 处理最后一个 server 块
	if current != nil {
		blocks = append(blocks, *current)
	}

	return blocks
}

// readFileLines 读取文件并返回行切片
func readFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var lines []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// parseConfigFile 解析单个配置文件，提取 SSL 站点
func (s *Scanner) parseConfigFile(filePath string) ([]*SSLSite, error) {
	lines, err := readFileLines(filePath)
	if err != nil {
		return nil, err
	}

	blocks := parseServerBlocks(lines, filePath, parseOptions{})

	var sites []*SSLSite
	for _, b := range blocks {
		if b.certificatePath != "" && b.privateKeyPath != "" {
			sites = append(sites, &SSLSite{
				ConfigFile:      b.configFile,
				ServerName:      b.serverName,
				ServerAlias:     b.serverAlias,
				CertificatePath: b.certificatePath,
				PrivateKeyPath:  b.privateKeyPath,
				ListenPorts:     b.listenPorts,
				Webroot:         b.webroot,
			})
		}
	}
	return sites, nil
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
		if matcher.MatchDomain(strings.ToLower(site.ServerName), strings.ToLower(domain)) {
			return site, nil
		}

		// 检查别名
		for _, alias := range site.ServerAlias {
			if matcher.MatchDomain(strings.ToLower(alias), strings.ToLower(domain)) {
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
	// 检查文件总数限制
	if len(s.scannedFiles) >= maxScanFiles {
		s.logDebug("扫描文件数超过限制 (%d)，跳过: %s", maxScanFiles, configPath)
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

// extractListenPort 从 listen 指令值中提取端口号（用于 HTTP 站点）
func extractListenPort(listenValue string) string {
	parts := strings.Fields(listenValue)
	if len(parts) == 0 {
		return ""
	}
	port := parts[0]
	// 处理 [::]:80 格式
	if strings.Contains(port, "]:") {
		port = strings.Split(port, "]:")[1]
	} else if strings.Contains(port, ":") {
		port = strings.Split(port, ":")[1]
	}
	return port
}

// parseHTTPConfigFile 解析单个配置文件中的 HTTP 站点
func (s *Scanner) parseHTTPConfigFile(filePath string) ([]*HTTPSite, error) {
	lines, err := readFileLines(filePath)
	if err != nil {
		return nil, err
	}

	blocks := parseServerBlocks(lines, filePath, parseOptions{})

	var sites []*HTTPSite
	for _, b := range blocks {
		if b.hasSSL || b.serverName == "" {
			continue
		}
		site := &HTTPSite{
			ConfigFile: b.configFile,
			ServerName: b.serverName,
			Webroot:    b.webroot,
		}
		// 取第一个非 SSL 端口
		for _, lp := range b.listenPorts {
			if !strings.Contains(lp, "ssl") {
				site.ListenPort = extractListenPort(lp)
				break
			}
		}
		sites = append(sites, site)
	}
	return sites, nil
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
	// 已指定配置文件路径时，直接使用文件扫描（不走 nginx -T）
	if s.mainConfigPath == "" {
		// 优先尝试使用 nginx -T 获取合并配置（更可靠）
		sites, err := s.scanWithNginxT()
		if err == nil && len(sites) > 0 {
			s.logDebug("使用 nginx -T 扫描成功，发现 %d 个站点", len(sites))
			return sites, nil
		}
		if err != nil {
			s.logDebug("nginx -T 扫描失败: %v，回退到文件扫描", err)
		}
	}

	// 文件扫描方式
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

// buildNginxArgs 构建 nginx 命令参数
// Windows 上 nginx 默认用当前工作目录作为 prefix，需要 -p 指定实际安装目录
// 仅当二进制路径是绝对路径且其目录下存在 conf/nginx.conf 时才加 -p
func buildNginxArgs(nginxPath string, args ...string) []string {
	if runtime.GOOS == "windows" && filepath.IsAbs(nginxPath) {
		dir := filepath.Dir(nginxPath)
		confPath := filepath.Join(dir, "conf", "nginx.conf")
		if _, err := os.Stat(confPath); err == nil {
			return append([]string{"-p", dir + string(filepath.Separator)}, args...)
		}
	}
	return args
}

// getNginxPrefix 从 nginx 二进制路径推导 prefix 目录
// 返回空字符串表示不需要特殊处理（Linux 或路径无效）
func getNginxPrefix(nginxPath string) string {
	if !filepath.IsAbs(nginxPath) {
		return ""
	}
	dir := filepath.Dir(nginxPath)
	if _, err := os.Stat(filepath.Join(dir, "conf", "nginx.conf")); err == nil {
		return dir
	}
	return ""
}

// resolveNginxPath 将 nginx 配置中的相对路径解析为绝对路径
func resolveNginxPath(prefix, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(prefix, path)
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
// 使用公共函数 util.FindBinaryFromPort
func findBinaryFromPort(processName string) string {
	return util.FindBinaryFromPort(processName)
}

// isContainerProcess 检查进程是否运行在容器内
// 使用公共函数 util.IsContainerProcess
func isContainerProcess(pid string) bool {
	return util.IsContainerProcess(pid)
}

// findNginxFromProcessWindows 从 Windows 进程查找 nginx 路径
// 优先使用 PowerShell (Windows 11+ wmic 已弃用)，回退到 wmic
func findNginxFromProcessWindows() string {
	// 优先尝试 PowerShell (Get-Process)
	if path := findNginxFromProcessPowerShell(); path != "" {
		return path
	}

	// 回退到 wmic (兼容旧版 Windows)
	return findNginxFromProcessWMIC()
}

// processTimeout Windows 进程查找命令的超时时间（防止控制台损坏导致卡死）
const processTimeout = 10 * time.Second

// findNginxFromProcessPowerShell 使用 PowerShell 查找 nginx 进程
func findNginxFromProcessPowerShell() string {
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-Process -Name nginx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	path := strings.TrimSpace(string(output))
	if path != "" && strings.HasSuffix(strings.ToLower(path), "nginx.exe") {
		return path
	}

	return ""
}

// findNginxFromProcessWMIC 使用 wmic 查找 nginx 进程（兼容旧版 Windows）
func findNginxFromProcessWMIC() string {
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wmic", "process", "where", "name='nginx.exe'", "get", "ExecutablePath")
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

// rawBlocksToSites 将 rawBlock 转换为 Site（过滤掉 _ 和空 server_name）
func rawBlocksToSites(blocks []rawBlock) []*Site {
	var sites []*Site
	for _, b := range blocks {
		if b.serverName == "" || b.serverName == "_" {
			continue
		}
		sites = append(sites, &Site{
			ConfigFile:      b.configFile,
			ServerName:      b.serverName,
			ServerAlias:     b.serverAlias,
			ListenPorts:     b.listenPorts,
			Webroot:         b.webroot,
			HasSSL:          b.hasSSL,
			CertificatePath: b.certificatePath,
			PrivateKeyPath:  b.privateKeyPath,
		})
	}
	return sites
}

// scanWithNginxT 使用 nginx -T 获取合并配置并解析
func (s *Scanner) scanWithNginxT() ([]*Site, error) {
	nginxPath := findNginxBinary()
	if nginxPath == "" {
		return nil, fmt.Errorf("未找到 nginx 可执行文件")
	}

	// Windows 上 nginx 默认用当前工作目录作为 prefix，需要显式指定 -p
	args := buildNginxArgs(nginxPath, "-T")
	output, err := executor.RunScan(nginxPath, args...)
	if err != nil {
		if !strings.Contains(string(output), "server") {
			return nil, fmt.Errorf("nginx -T 执行失败: %w", err)
		}
	}

	lines := strings.Split(string(output), "\n")
	blocks := parseServerBlocks(lines, "", parseOptions{
		skipNginxLines:  true,
		trackConfigFile: true,
	})

	sites := rawBlocksToSites(blocks)

	// 解析相对路径：Windows 上 nginx 配置常用相对路径，需基于 prefix 目录转为绝对路径
	if prefix := getNginxPrefix(nginxPath); prefix != "" {
		for _, site := range sites {
			site.CertificatePath = resolveNginxPath(prefix, site.CertificatePath)
			site.PrivateKeyPath = resolveNginxPath(prefix, site.PrivateKeyPath)
			site.Webroot = resolveNginxPath(prefix, site.Webroot)
		}
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
	// 检查文件总数限制
	if len(s.scannedFiles) >= maxScanFiles {
		s.logDebug("扫描文件数超过限制 (%d)，跳过: %s", maxScanFiles, configPath)
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
	lines, err := readFileLines(filePath)
	if err != nil {
		return nil, err
	}

	blocks := parseServerBlocks(lines, filePath, parseOptions{})
	return rawBlocksToSites(blocks), nil
}

// FindAllByDomain 根据域名查找站点（包括非 SSL）
func (s *Scanner) FindAllByDomain(domain string) (*Site, error) {
	sites, err := s.ScanAll()
	if err != nil {
		return nil, err
	}

	for _, site := range sites {
		// 检查主域名
		if matcher.MatchDomain(strings.ToLower(site.ServerName), strings.ToLower(domain)) {
			return site, nil
		}

		// 检查别名
		for _, alias := range site.ServerAlias {
			if matcher.MatchDomain(strings.ToLower(alias), strings.ToLower(domain)) {
				return site, nil
			}
		}
	}

	return nil, nil
}
