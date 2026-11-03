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
	"sync"
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
	ConfigFile string // 配置文件路径
	ServerName string // 服务器名称（域名）
	ListenPort string // 监听端口
	Webroot    string // Web 根目录 (root)
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

// 系统探测入口集中于此，便于在其他平台验证 Windows 实例隔离分支。
var scanSystem = struct {
	goos          string
	findBinary    func() string
	runScan       func(string, ...string) ([]byte, error)
	runOutput     func(string) ([]byte, error)
	stat          func(string) (os.FileInfo, error)
	commandOutput func(*exec.Cmd) ([]byte, error)
}{runtime.GOOS, findNginxBinary, executor.RunScan, executor.RunOutput, os.Stat, (*exec.Cmd).Output}

// Scanner Nginx 配置扫描器
type Scanner struct {
	mainConfigPath string                       // 主配置文件路径
	configRoot     string                       // 配置根目录
	executablePath string                       // 本次自动扫描固定使用的 nginx 可执行文件
	scannedFiles   map[string]bool              // 已扫描的文件（避免循环）
	debug          bool                         // 调试模式
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
		configRoot:     mainConfigRoot(configPath),
		scannedFiles:   make(map[string]bool),
	}
}

// ExecutablePath 返回本次自动扫描固定使用的 nginx 可执行文件。
// 显式配置文件扫描没有可靠的实例关联，返回空字符串。
func (s *Scanner) ExecutablePath() string {
	return s.executablePath
}

func (s *Scanner) ensureExecutablePath() string {
	if s.executablePath == "" {
		s.executablePath = scanSystem.findBinary()
	}
	return s.executablePath
}

func mainConfigRoot(configPath string) string {
	if absolute, err := filepath.Abs(configPath); err == nil {
		return filepath.Dir(absolute)
	}
	return filepath.Dir(configPath)
}

// DetectNginx 检测 Nginx 是否安装并获取配置路径
func DetectNginx() (configPath string, err error) {
	return detectNginxFor(findNginxBinary())
}

func detectNginxFor(nginxPath string) (configPath string, err error) {
	// 方法1: 通过 nginx -t 获取配置路径
	configPath, err = getNginxConfigFromTestFor(nginxPath)
	if err == nil && configPath != "" {
		return configPath, nil
	}

	// 方法2: 通过 nginx -V 获取编译时的默认路径
	configPath, err = getNginxConfigFromVersionFor(nginxPath)
	if err == nil && configPath != "" {
		return configPath, nil
	}

	// Windows 多实例场景只能回退到同一可执行文件目录下的配置；
	// 继续检查 C:\nginx 等全局常见路径会把 G 盘实例与另一套配置串线。
	if scanSystem.goos == "windows" {
		if exactPath := windowsConfigPathForExecutable(nginxPath); exactPath != "" {
			if _, statErr := scanSystem.stat(exactPath); statErr == nil {
				return exactPath, nil
			}
			return "", fmt.Errorf("无法检测目标 Nginx 实例的配置文件: %s", exactPath)
		}
	}

	// 方法3: 尝试常见路径
	commonPaths := getCommonNginxPaths()
	for _, p := range commonPaths {
		if _, err := scanSystem.stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("无法检测 Nginx 配置文件路径")
}

func windowsConfigPathForExecutable(executable string) string {
	path := strings.ReplaceAll(strings.TrimSpace(executable), "/", `\`)
	idx := strings.LastIndex(path, `\`)
	if idx <= 2 {
		return ""
	}
	if !strings.EqualFold(path[idx+1:], "nginx.exe") {
		return ""
	}
	return path[:idx] + `\conf\nginx.conf`
}

// getNginxConfigFromTestFor 通过指定 nginx 的 -t 输出获取配置路径。
func getNginxConfigFromTestFor(nginxPath string) (string, error) {
	// 优先使用传入的动态路径（避免 PATH 里的另一套 nginx 串线）
	var output []byte
	if nginxPath != "" {
		args := buildNginxArgs(nginxPath, "-t")
		output, _ = scanSystem.runScan(nginxPath, args...)
	}
	if len(output) == 0 {
		output, _ = scanSystem.runOutput("nginx -t")
	}

	// nginx -t 输出: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
	if configPath := parseMainConfigPath(output); configPath != "" {
		if _, err := scanSystem.stat(configPath); err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("无法从 nginx -t 获取配置路径")
}

// parseMainConfigPath 从 nginx -t/-T 输出中提取实际使用的主配置文件。
// ssl_certificate、ssl_certificate_key 和 include 的相对路径均以该文件所在目录为基准。
func parseMainConfigPath(output []byte) string {
	re := regexp.MustCompile(`(?m)configuration file (.+?) (?:syntax is ok|test is successful|test failed)`)
	if matches := re.FindSubmatch(output); len(matches) > 1 {
		return strings.TrimSpace(string(matches[1]))
	}

	// nginx -T 还会用此格式标记每个配置文件；首个标记是主配置文件。
	re = regexp.MustCompile(`(?m)^# configuration file (.+):\r?$`)
	if matches := re.FindSubmatch(output); len(matches) > 1 {
		return strings.TrimSpace(string(matches[1]))
	}

	return ""
}

// getNginxConfigFromVersionFor 通过指定 nginx 的 -V 输出获取配置路径。
func getNginxConfigFromVersionFor(nginxPath string) (string, error) {
	// nginx -V 输出编译信息，不需要 -p（与运行时目录无关）
	var output []byte
	var err error
	if nginxPath != "" {
		output, err = scanSystem.runScan(nginxPath, "-V")
	}
	if len(output) == 0 {
		output, err = scanSystem.runOutput("nginx -V")
	}
	if err != nil && len(output) == 0 {
		return "", err
	}

	// 匹配 --conf-path
	re := regexp.MustCompile(`--conf-path=([^\s]+)`)
	matches := re.FindSubmatch(output)
	if len(matches) > 1 {
		configPath := string(matches[1])
		if _, err := scanSystem.stat(configPath); err == nil {
			return configPath, nil
		}
	}

	// 匹配 --prefix 然后拼接 conf/nginx.conf
	re = regexp.MustCompile(`--prefix=([^\s]+)`)
	matches = re.FindSubmatch(output)
	if len(matches) > 1 {
		prefix := string(matches[1])
		configPath := filepath.Join(prefix, "conf", "nginx.conf")
		if _, err := scanSystem.stat(configPath); err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("无法从 nginx -V 获取配置路径")
}

// getCommonNginxPaths 获取常见的 Nginx 配置路径
func getCommonNginxPaths() []string {
	if runtime.GOOS == "windows" {
		paths := []string{
			`C:\nginx\conf\nginx.conf`,
			`C:\Program Files\nginx\conf\nginx.conf`,
		}
		// Windows 集成面板
		if matches, _ := filepath.Glob(`C:\phpstudy_pro\Extensions\Nginx*\conf\nginx.conf`); len(matches) > 0 {
			paths = append(paths, matches...)
		}
		return paths
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
		configPath, err := detectNginxFor(s.ensureExecutablePath())
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.configRoot = mainConfigRoot(configPath)
	}

	// 从主配置文件开始递归扫描
	s.scannedFiles = make(map[string]bool)
	sites, err := s.scanConfigFile(s.mainConfigPath, 0)
	if err != nil {
		return nil, err
	}
	configRoot := s.configRoot
	if configRoot == "" {
		configRoot = mainConfigRoot(s.mainConfigPath)
	}
	for _, site := range sites {
		site.CertificatePath = resolveNginxPath(configRoot, site.CertificatePath)
		site.PrivateKeyPath = resolveNginxPath(configRoot, site.PrivateKeyPath)
	}
	for _, site := range sites {
		if site.Webroot != "" && !filepath.IsAbs(site.Webroot) {
			nginxPath := s.executablePath
			if nginxPath == "" {
				nginxPath = scanSystem.findBinary()
			}
			prefix, _, ok := getNginxPrefix(nginxPath)
			if ok && prefix != "" {
				for _, target := range sites {
					target.Webroot = resolveNginxPath(prefix, target.Webroot)
				}
			}
			break
		}
	}
	return sites, nil
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

	configRoot := s.configRoot
	if configRoot == "" {
		configRoot = mainConfigRoot(configPath)
	}
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

			// Nginx 的 include 相对路径以主 nginx.conf 所在目录为基准，
			// 而不是当前被 include 文件所在目录。
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(configRoot, pattern)
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
	serverBlockRe   = regexp.MustCompile(`^\s*server\s*\{`)
	serverOnlyRe    = regexp.MustCompile(`^\s*server\s*$`)
	openBraceOnlyRe = regexp.MustCompile(`^\s*\{\s*$`)
	serverNameRe    = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe        = regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe       = regexp.MustCompile(`^\s*ssl_certificate\s+([^;]+);`)
	sslKeyRe        = regexp.MustCompile(`^\s*ssl_certificate_key\s+([^;]+);`)
	rootRe          = regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe      = regexp.MustCompile(`^\s*location\s+`)
	configFileRe    = regexp.MustCompile(`# configuration file (.+):`)
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
			certPath = strings.ReplaceAll(certPath, `\\`, `\`)
			current.certificatePath = certPath
			current.hasSSL = true
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			keyPath = strings.ReplaceAll(keyPath, `\\`, `\`)
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
		configPath, err := detectNginxFor(s.ensureExecutablePath())
		if err != nil {
			return nil, err
		}
		s.mainConfigPath = configPath
		s.configRoot = mainConfigRoot(configPath)
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
		s.configRoot = mainConfigRoot(configPath)
	}

	// 重置已扫描文件记录
	s.scannedFiles = make(map[string]bool)

	// 从主配置文件开始递归扫描
	allSites, err := s.scanAllConfigFile(s.mainConfigPath, 0)
	if err != nil {
		return nil, err
	}
	return s.resolveSitePaths(allSites)
}

// resolveSitePaths 按 Nginx 的两类路径基准解析站点路径：
// 证书和私钥相对于主 nginx.conf 所在目录，root 相对于 nginx prefix。
func (s *Scanner) resolveSitePaths(sites []*Site) ([]*Site, error) {
	configRoot := s.configRoot
	if configRoot == "" && s.mainConfigPath != "" {
		configRoot = mainConfigRoot(s.mainConfigPath)
	}
	for _, site := range sites {
		if hasRelativeCertPath(site) && configRoot == "" {
			return nil, fmt.Errorf("无法确定 nginx 主配置文件目录，不能解析站点 %s 的相对证书路径", site.ServerName)
		}
		site.CertificatePath = resolveNginxPath(configRoot, site.CertificatePath)
		site.PrivateKeyPath = resolveNginxPath(configRoot, site.PrivateKeyPath)
	}

	// root 属于普通路径，仍使用 nginx prefix；探测失败时保持原值，
	// 不影响已经能够准确解析的证书和私钥路径。
	for _, site := range sites {
		if site.Webroot != "" && !filepath.IsAbs(site.Webroot) {
			nginxPath := s.executablePath
			if nginxPath == "" {
				nginxPath = scanSystem.findBinary()
			}
			prefix, _, ok := getNginxPrefix(nginxPath)
			if ok && prefix != "" {
				for _, target := range sites {
					target.Webroot = resolveNginxPath(prefix, target.Webroot)
				}
			}
			break
		}
	}
	return sites, nil
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
		// Windows 集成面板
		if matches, _ := filepath.Glob(`C:\phpstudy_pro\Extensions\Nginx*\nginx.exe`); len(matches) > 0 {
			paths = append(paths, matches...)
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

// prefixOverride 由 CLI 层通过 SetPrefixOverride 设置，对应 --nginx-prefix
// 仅在当前进程内生效，不写入配置文件
var (
	prefixOverride   string
	prefixOverrideMu sync.RWMutex
)

// SetPrefixOverride 设置 nginx prefix 显式覆盖值
// 由 CLI 层在解析 --nginx-prefix 后调用。传入空字符串等价于清除。
func SetPrefixOverride(prefix string) {
	prefixOverrideMu.Lock()
	defer prefixOverrideMu.Unlock()
	prefixOverride = prefix
}

func getPrefixOverride() string {
	prefixOverrideMu.RLock()
	defer prefixOverrideMu.RUnlock()
	return prefixOverride
}

// prefixCandidates 返回 Windows 下常见的 prefix 候选路径
// 按使用频率排序：nginx.exe 所在目录（手动启动）、conf 子目录（面板场景）
func prefixCandidates(nginxPath string) []string {
	if !filepath.IsAbs(nginxPath) {
		return nil
	}
	dir := filepath.Dir(nginxPath)
	return []string{
		dir + string(filepath.Separator),
		filepath.Join(dir, "conf") + string(filepath.Separator),
	}
}

// getNginxPrefix 以多策略探测 nginx 相对路径的解析基准（prefix）
// 返回：
//   - prefix: 推测的 prefix 目录（空表示未知）
//   - candidates: 常见候选路径（仅 Windows 有意义，供失败时提示）
//   - ok: 是否可信地确定了 prefix
//
// 策略优先级：显式 override > nginx -V --prefix= > 运行进程 -p 参数 > error.log 启发式
func getNginxPrefix(nginxPath string) (prefix string, candidates []string, ok bool) {
	// 1. 显式 override（--nginx-prefix）
	if p := getPrefixOverride(); p != "" {
		return p, nil, true
	}

	// 2. nginx -V --prefix=（编译时 prefix，跨平台最可靠）
	if p := getPrefixFromVersion(nginxPath); p != "" {
		return p, nil, true
	}

	// 3. Windows 运行进程命令行的 -p 参数
	if scanSystem.goos == "windows" {
		if p := getPrefixFromProcessCmdline(nginxPath); p != "" {
			return p, nil, true
		}
	}

	// Linux 通常走不到这里（编译时 --prefix 非空），返回空让 resolveNginxPath 原样透传
	if scanSystem.goos != "windows" {
		return "", nil, false
	}

	candidates = prefixCandidates(nginxPath)
	if len(candidates) == 0 {
		return "", nil, false
	}

	// 4. error.log 启发式探测
	//    nginx 启动即创建 logs/error.log，其路径同样受 prefix 解析影响
	dir := filepath.Dir(nginxPath)
	if _, err := os.Stat(filepath.Join(dir, "logs", "error.log")); err == nil {
		return dir + string(filepath.Separator), candidates, true
	}
	if _, err := os.Stat(filepath.Join(dir, "conf", "logs", "error.log")); err == nil {
		return filepath.Join(dir, "conf") + string(filepath.Separator), candidates, true
	}

	// 全部策略失败
	return "", candidates, false
}

// getPrefixFromVersion 通过 nginx -V 输出解析编译时 --prefix=
func getPrefixFromVersion(nginxPath string) string {
	var output []byte
	if nginxPath != "" {
		output, _ = scanSystem.runScan(nginxPath, "-V")
	}
	if len(output) == 0 {
		output, _ = scanSystem.runOutput("nginx -V")
	}
	if len(output) == 0 {
		return ""
	}
	re := regexp.MustCompile(`--prefix=([^\s]+)`)
	matches := re.FindSubmatch(output)
	if len(matches) <= 1 {
		return ""
	}
	p := strings.TrimSpace(string(matches[1]))
	if p == "" || !filepath.IsAbs(p) {
		return ""
	}
	return p
}

// getPrefixFromProcessCmdline 从运行中的 nginx 进程命令行解析 -p 参数
// Windows 专用，使用 PowerShell Get-CimInstance 读取 Win32_Process.CommandLine
// 失败时（权限不足 / PowerShell 不可用）返回空字符串
func getPrefixFromProcessCmdline(nginxPath string) string {
	if scanSystem.goos != "windows" {
		return ""
	}
	if nginxPath == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process -Filter \"Name='nginx.exe'\" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.Equals($args[0], [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -ExpandProperty CommandLine -First 1",
		nginxPath)
	output, err := scanSystem.commandOutput(cmd)
	if err != nil {
		return ""
	}
	return parsePrefixFromCmdline(string(output))
}

// parsePrefixFromCmdline 从完整命令行解析 -p 参数值
// 支持 -p value、-p"value"、-p "value" 三种形式
func parsePrefixFromCmdline(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	// 逐 token 扫描，处理带引号的路径
	tokens := tokenizeCmdline(cmdline)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "-p" && i+1 < len(tokens) {
			return strings.Trim(tokens[i+1], `"'`)
		}
		if strings.HasPrefix(tok, "-p") && len(tok) > 2 {
			return strings.Trim(tok[2:], `"'`)
		}
	}
	return ""
}

// tokenizeCmdline 按空白切分命令行，尊重双引号
func tokenizeCmdline(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
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

	// 宿主机上跳过容器进程（交给 Docker 扫描器），容器内不跳过
	if util.ShouldSkipContainerProcess(pid) {
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
	nginxPath := s.ensureExecutablePath()
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
	if configPath := parseMainConfigPath(output); configPath != "" {
		s.mainConfigPath = configPath
		s.configRoot = mainConfigRoot(configPath)
	}

	lines := strings.Split(string(output), "\n")
	blocks := parseServerBlocks(lines, "", parseOptions{
		skipNginxLines:  true,
		trackConfigFile: true,
	})

	sites := rawBlocksToSites(blocks)

	return s.resolveSitePaths(sites)
}

// hasRelativeCertPath 判断站点的证书/私钥路径是否有相对路径
func hasRelativeCertPath(site *Site) bool {
	if site.CertificatePath != "" && !filepath.IsAbs(site.CertificatePath) {
		return true
	}
	if site.PrivateKeyPath != "" && !filepath.IsAbs(site.PrivateKeyPath) {
		return true
	}
	return false
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
