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

	"github.com/zhuxbo/sslctl/pkg/util"
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

// Site 通用站点信息（合并 SSL 和非 SSL）
type Site struct {
	ConfigFile      string   `json:"config_file"`                // 配置文件路径
	ServerName      string   `json:"server_name"`                // 服务器名称（主域名）
	ServerAlias     []string `json:"server_alias,omitempty"`     // 域名别名列表
	ListenPorts     []string `json:"listen_ports"`               // 监听端口
	Webroot         string   `json:"webroot,omitempty"`          // Web 根目录 (DocumentRoot)
	HasSSL          bool     `json:"has_ssl"`                    // 是否配置了 SSL
	CertificatePath string   `json:"certificate_path,omitempty"` // 证书路径 (SSLCertificateFile)
	PrivateKeyPath  string   `json:"private_key_path,omitempty"` // 私钥路径 (SSLCertificateKeyFile)
	ChainPath       string   `json:"chain_path,omitempty"`       // 证书链路径 (SSLCertificateChainFile)
}

// Scanner Apache 配置扫描器
type Scanner struct {
	mainConfigPath string            // 主配置文件路径
	serverRoot     string            // ServerRoot 路径
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
	defer func() { _ = file.Close() }()

	configDir := filepath.Dir(configPath)
	var includes []string

	// 匹配 Include 和 IncludeOptional 指令
	includeRe := regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+(.+)$`)

	lineScanner := bufio.NewScanner(file)
	for lineScanner.Scan() {
		line := lineScanner.Text()

		// 跳过注释
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			pattern := strings.TrimSpace(matches[1])
			// 去除引号
			pattern = strings.Trim(pattern, `"'`)

			originalPattern := pattern

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
				s.logDebug("Include %s => %d files", originalPattern, len(files))
				includes = append(includes, files...)
			} else if err == nil {
				// 可能是精确路径
				if _, err := os.Stat(pattern); err == nil {
					s.logDebug("Include %s => 1 file (exact)", originalPattern)
					includes = append(includes, pattern)
				} else {
					s.logDebug("Include %s => no match (pattern: %s)", originalPattern, pattern)
				}
			} else {
				s.logDebug("Include %s => glob error: %v", originalPattern, err)
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
	defer func() { _ = file.Close() }()

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
	defer func() { _ = file.Close() }()

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

// ScanAll 扫描所有站点（包括 SSL 和非 SSL）
func (s *Scanner) ScanAll() ([]*Site, error) {
	// 优先尝试使用 apachectl -S 获取虚拟主机列表（更可靠）
	sites, err := s.scanWithApacheCtl()
	if err == nil && len(sites) > 0 {
		s.logDebug("使用 apachectl -S 扫描成功，发现 %d 个站点", len(sites))
		return sites, nil
	}
	if err != nil {
		s.logDebug("apachectl -S 扫描失败: %v，回退到文件扫描", err)
	}

	// 回退到文件扫描方式
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
	return s.scanAllConfigFile(s.mainConfigPath)
}

// findApacheBinary 查找 Apache 可执行文件路径
func findApacheBinary() string {
	// 方法1: 从运行中的进程获取准确路径（最可靠）
	if path := findApacheFromProcess(); path != "" {
		return path
	}

	// 方法2: 尝试 PATH 中的命令
	commands := []string{"apache2ctl", "apachectl", "httpd"}
	for _, cmd := range commands {
		if path, err := exec.LookPath(cmd); err == nil {
			return path
		}
	}

	// 方法3: 尝试常见路径
	var paths []string
	if runtime.GOOS == "windows" {
		paths = []string{
			`C:\Apache24\bin\httpd.exe`,
			`C:\Apache\bin\httpd.exe`,
			`C:\Program Files\Apache24\bin\httpd.exe`,
			`C:\Program Files (x86)\Apache24\bin\httpd.exe`,
			`C:\xampp\apache\bin\httpd.exe`,
		}
	} else {
		paths = []string{
			"/usr/sbin/apache2ctl",
			"/usr/sbin/apachectl",
			"/usr/sbin/httpd",
			"/usr/local/sbin/httpd",
			"/usr/local/apache2/bin/httpd",
			"/usr/local/apache2/bin/apachectl",
			"/opt/apache/bin/httpd",
			"/www/server/apache/bin/httpd",       // 宝塔面板
			"/www/server/apache/bin/apachectl",   // 宝塔面板
		}
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// findApacheFromProcess 从运行中的进程查找 Apache 路径
func findApacheFromProcess() string {
	if runtime.GOOS == "windows" {
		return findApacheFromProcessWindows()
	}
	return findApacheFromProcessLinux()
}

// findApacheFromProcessLinux 从 Linux 进程查找 Apache 路径
func findApacheFromProcessLinux() string {
	// Apache 进程名可能是 apache2, httpd, 或其他
	processNames := []string{"apache2", "httpd"}

	for _, name := range processNames {
		// 方法1: 通过 ss 查看 80/443 端口的进程
		if path := findBinaryFromPort(name); path != "" {
			return path
		}

		// 方法2: 通过 ps 查找进程
		cmd := exec.Command("ps", "-C", name, "-o", "pid=")
		output, err := cmd.Output()
		if err != nil || len(output) == 0 {
			continue
		}

		// 取第一个 PID（可能是 master 进程）
		pids := strings.Fields(string(output))
		if len(pids) == 0 {
			continue
		}

		pid := pids[0]

		// 检查是否是容器进程（容器进程交给 Docker 扫描器处理）
		if isContainerProcess(pid) {
			continue
		}

		// 通过 /proc/<pid>/exe 获取可执行文件路径
		exePath := fmt.Sprintf("/proc/%s/exe", pid)
		realPath, err := os.Readlink(exePath)
		if err != nil {
			continue
		}

		// 验证路径在宿主机上存在
		if _, err := os.Stat(realPath); err != nil {
			continue
		}

		return realPath
	}

	return ""
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

// findApacheFromProcessWindows 从 Windows 进程查找 Apache 路径
func findApacheFromProcessWindows() string {
	// wmic process where "name='httpd.exe'" get ExecutablePath
	cmd := exec.Command("wmic", "process", "where", "name='httpd.exe'", "get", "ExecutablePath")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "ExecutablePath" && strings.HasSuffix(strings.ToLower(line), "httpd.exe") {
			return line
		}
	}

	return ""
}

// scanWithApacheCtl 使用 apachectl -S 获取虚拟主机列表
func (s *Scanner) scanWithApacheCtl() ([]*Site, error) {
	// 查找 Apache 可执行文件
	apachePath := findApacheBinary()
	if apachePath == "" {
		return nil, fmt.Errorf("未找到 Apache 可执行文件")
	}

	var output []byte
	var err error

	// 执行 -S 参数
	output, err = exec.Command(apachePath, "-S").CombinedOutput()
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("执行 %s -S 失败: %w", apachePath, err)
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("无法执行 apachectl -S")
	}

	content := string(output)
	s.logDebug("apachectl -S 输出:\n%s", content)

	// 解析输出
	// 格式示例:
	// *:80                   is a NameVirtualHost
	//          default server example.com (/etc/apache2/sites-enabled/example.conf:1)
	//          port 80 namevhost example.com (/etc/apache2/sites-enabled/example.conf:1)
	// *:443                  is a NameVirtualHost
	//          default server example.com (/etc/apache2/sites-enabled/example-ssl.conf:2)
	//          port 443 namevhost example.com (/etc/apache2/sites-enabled/example-ssl.conf:2)

	var sites []*Site
	siteMap := make(map[string]*Site) // 用于合并同一站点的 HTTP 和 HTTPS

	// 匹配虚拟主机行
	// port 80 namevhost example.com (/path/to/config:line)
	// port 443 namevhost example.com (/path/to/config:line)
	vhostRe := regexp.MustCompile(`port\s+(\d+)\s+namevhost\s+(\S+)\s+\(([^:]+):(\d+)\)`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if matches := vhostRe.FindStringSubmatch(line); len(matches) > 4 {
			port := matches[1]
			serverName := matches[2]
			configFile := matches[3]

			// 检查是否已有此站点
			key := serverName + ":" + configFile
			site, exists := siteMap[key]
			if !exists {
				site = &Site{
					ServerName: serverName,
					ConfigFile: configFile,
				}
				siteMap[key] = site
			}

			// 添加端口
			portStr := port
			if port == "443" {
				portStr = "443 ssl"
				site.HasSSL = true
			}
			site.ListenPorts = append(site.ListenPorts, portStr)
		}
	}

	// 转换为列表
	for _, site := range siteMap {
		sites = append(sites, site)
	}

	// 如果 apachectl -S 输出了站点，尝试从配置文件补充详细信息
	for _, site := range sites {
		s.enrichSiteFromConfig(site)
	}

	return sites, nil
}

// enrichSiteFromConfig 从配置文件补充站点详细信息
// enrichSiteFromConfig 从配置文件补充站点详细信息（仅解析匹配的 VirtualHost 块）
func (s *Scanner) enrichSiteFromConfig(site *Site) {
	if site.ConfigFile == "" || site.ServerName == "" {
		return
	}

	file, err := os.Open(site.ConfigFile)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	// 正则表达式
	vhostStartRe := regexp.MustCompile(`(?i)^\s*<VirtualHost\s+([^>]+)>`)
	vhostEndRe := regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	serverNameRe := regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	serverAliasRe := regexp.MustCompile(`(?i)^\s*ServerAlias\s+(.+)$`)
	sslCertRe := regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(.+)$`)
	sslKeyRe := regexp.MustCompile(`(?i)^\s*SSLCertificateKeyFile\s+(.+)$`)
	sslChainRe := regexp.MustCompile(`(?i)^\s*SSLCertificateChainFile\s+(.+)$`)
	docRootRe := regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)

	inVirtualHost := false
	inTargetVHost := false // 是否在目标站点的 VirtualHost 块内
	var currentServerName string
	var currentAliases []string
	var currentCertPath, currentKeyPath, currentChainPath, currentWebroot string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 跳过注释行
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// VirtualHost 开始
		if vhostStartRe.MatchString(line) {
			inVirtualHost = true
			inTargetVHost = false
			_ = currentServerName // 重置但后续会重新赋值
			currentServerName = ""
			currentAliases = nil
			currentCertPath = ""
			currentKeyPath = ""
			currentChainPath = ""
			currentWebroot = ""
			continue
		}

		// VirtualHost 结束
		if vhostEndRe.MatchString(line) {
			// 如果是目标站点，更新信息
			if inTargetVHost {
				if len(currentAliases) > 0 {
					site.ServerAlias = currentAliases
				}
				if currentCertPath != "" {
					site.CertificatePath = currentCertPath
				}
				if currentKeyPath != "" {
					site.PrivateKeyPath = currentKeyPath
				}
				if currentChainPath != "" {
					site.ChainPath = currentChainPath
				}
				if currentWebroot != "" && site.Webroot == "" {
					site.Webroot = currentWebroot
				}
				return // 找到目标站点，提前返回
			}
			inVirtualHost = false
			continue
		}

		if !inVirtualHost {
			continue
		}

		// 解析 ServerName
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			currentServerName = strings.TrimSpace(matches[1])
			currentServerName = strings.Trim(currentServerName, `"'`)
			// 检查是否是目标站点
			if currentServerName == site.ServerName {
				inTargetVHost = true
			}
		}

		// 只解析目标 VirtualHost 块的内容
		if !inTargetVHost {
			continue
		}

		// 解析 ServerAlias
		if matches := serverAliasRe.FindStringSubmatch(line); len(matches) > 1 {
			aliases := strings.Fields(matches[1])
			for _, alias := range aliases {
				alias = strings.Trim(alias, `"'`)
				currentAliases = append(currentAliases, alias)
			}
		}

		// 解析 SSLCertificateFile
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			currentCertPath = strings.TrimSpace(matches[1])
			currentCertPath = strings.Trim(currentCertPath, `"'`)
		}

		// 解析 SSLCertificateKeyFile
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			currentKeyPath = strings.TrimSpace(matches[1])
			currentKeyPath = strings.Trim(currentKeyPath, `"'`)
		}

		// 解析 SSLCertificateChainFile
		if matches := sslChainRe.FindStringSubmatch(line); len(matches) > 1 {
			currentChainPath = strings.TrimSpace(matches[1])
			currentChainPath = strings.Trim(currentChainPath, `"'`)
		}

		// 解析 DocumentRoot
		if matches := docRootRe.FindStringSubmatch(line); len(matches) > 1 {
			currentWebroot = strings.TrimSpace(matches[1])
			currentWebroot = strings.Trim(currentWebroot, `"'`)
		}
	}
}

// scanAllConfigFile 扫描配置文件中的所有站点（递归处理 Include）
func (s *Scanner) scanAllConfigFile(configPath string) ([]*Site, error) {
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
		s.logDebug("  发现 %d 个 VirtualHost 块", len(fileSites))
		sites = append(sites, fileSites...)
	} else {
		s.logDebug("  解析失败: %v", err)
	}

	// 查找 Include/IncludeOptional 指令
	includes, err := s.findIncludes(configPath)
	if err != nil {
		s.logDebug("  查找 Include 失败: %v", err)
		return sites, nil
	}

	// 递归扫描 include 的文件
	for _, inc := range includes {
		incSites, err := s.scanAllConfigFile(inc)
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
	sslEngineRe := regexp.MustCompile(`(?i)^\s*SSLEngine\s+on`)
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
			listenPort := strings.TrimSpace(matches[1])
			currentSite = &Site{
				ConfigFile:  filePath,
				ListenPorts: []string{listenPort},
			}
			// 检测端口是否为 443（通常是 SSL）
			if strings.Contains(listenPort, ":443") {
				currentSite.HasSSL = true
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
			// 保存所有有效站点（有 ServerName）
			if currentSite != nil && currentSite.ServerName != "" {
				sites = append(sites, currentSite)
			}
			inVirtualHost = false
			currentSite = nil
			continue
		}

		// 检测 SSL 配置
		if sslEngineRe.MatchString(line) {
			currentSite.HasSSL = true
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
			currentSite.HasSSL = true
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
	if currentSite != nil && currentSite.ServerName != "" {
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
