// Package docker 提供 Docker 容器操作支持
package docker

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/zhuxbo/cert-deploy/pkg/util"
)

// SSLSite Docker 容器内的 SSL 站点
type SSLSite struct {
	// 容器信息
	ContainerID   string
	ContainerName string

	// 配置信息
	ConfigFile      string   // 容器内配置文件路径
	ServerName      string   // 主域名
	ServerAlias     []string // 域名别名
	CertificatePath string   // 容器内证书路径
	PrivateKeyPath  string   // 容器内私钥路径
	ListenPorts     []string // 监听端口
	Webroot         string   // 容器内 Web 根目录

	// 宿主机路径（通过挂载卷计算）
	HostCertPath string
	HostKeyPath  string
	HostWebroot  string
	VolumeMode   bool // 是否挂载卷模式
}

// Scanner Docker Nginx 扫描器
type Scanner struct {
	client       *Client
	scannedFiles map[string]bool // 已扫描的文件（避免循环）
	mounts       []MountInfo     // 容器挂载信息
}

// NewScanner 创建 Docker 扫描器
func NewScanner(client *Client) *Scanner {
	return &Scanner{
		client:       client,
		scannedFiles: make(map[string]bool),
	}
}

// Scan 扫描容器内的 SSL 站点
func (s *Scanner) Scan(ctx context.Context) ([]*SSLSite, error) {
	// 1. 检测 Nginx 配置路径
	configPath, err := s.DetectNginxConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("detect nginx config failed: %w", err)
	}

	// 2. 获取容器挂载信息
	info, err := s.client.GetContainerInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("get container info failed: %w", err)
	}
	s.mounts = info.Mounts

	// 3. 从主配置文件开始递归扫描
	s.scannedFiles = make(map[string]bool)
	sites, err := s.scanConfigFile(ctx, configPath, info)
	if err != nil {
		return nil, err
	}

	return sites, nil
}

// DetectNginxConfig 检测容器内 Nginx 配置路径
func (s *Scanner) DetectNginxConfig(ctx context.Context) (string, error) {
	// 方法1: nginx -t
	output, err := s.client.Exec(ctx, "nginx -t 2>&1")
	if err == nil {
		re := regexp.MustCompile(`configuration file (.+?) `)
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return matches[1], nil
		}
	}

	// 方法2: 常见路径
	commonPaths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf",
	}

	for _, p := range commonPaths {
		_, err := s.client.Exec(ctx, fmt.Sprintf("test -f %s && echo ok", p))
		if err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("无法检测容器内 Nginx 配置路径")
}

// scanConfigFile 扫描配置文件（递归处理 include）
func (s *Scanner) scanConfigFile(ctx context.Context, configPath string, info *ContainerInfo) ([]*SSLSite, error) {
	// 避免重复扫描
	if s.scannedFiles[configPath] {
		return nil, nil
	}
	s.scannedFiles[configPath] = true

	var sites []*SSLSite

	// 读取配置文件内容
	content, err := s.readContainerFile(ctx, configPath)
	if err != nil {
		return nil, nil // 文件不存在，跳过
	}

	// 解析当前文件
	fileSites := s.parseConfig(content, configPath, info)
	sites = append(sites, fileSites...)

	// 查找 include 指令
	includes := s.findIncludes(ctx, content, configPath)

	// 递归扫描 include 的文件
	for _, inc := range includes {
		incSites, err := s.scanConfigFile(ctx, inc, info)
		if err == nil {
			sites = append(sites, incSites...)
		}
	}

	return sites, nil
}

// readContainerFile 读取容器内文件
func (s *Scanner) readContainerFile(ctx context.Context, filePath string) (string, error) {
	output, err := s.client.Exec(ctx, fmt.Sprintf("cat %s", util.ShellQuote(filePath)))
	if err != nil {
		return "", err
	}
	return output, nil
}

// findIncludes 查找配置文件中的 include 指令
func (s *Scanner) findIncludes(ctx context.Context, content, configPath string) []string {
	configDir := getDir(configPath)
	var includes []string

	includeRe := regexp.MustCompile(`(?m)^\s*include\s+([^;]+);`)
	matches := includeRe.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		pattern := strings.TrimSpace(match[1])
		pattern = strings.Trim(pattern, `"'`)

		// 处理相对路径
		if !strings.HasPrefix(pattern, "/") {
			pattern = configDir + "/" + pattern
		}

		// 处理 glob 模式
		if strings.Contains(pattern, "*") {
			if strings.HasSuffix(pattern, "/*.conf") {
				dir := strings.TrimSuffix(pattern, "/*.conf")
				// 使用 ls 命令列出目录中的 .conf 文件
				output, err := s.client.Exec(ctx, fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null", util.ShellQuote(dir)))
				if err == nil && output != "" {
					for _, f := range strings.Split(output, "\n") {
						f = strings.TrimSpace(f)
						if f != "" {
							includes = append(includes, f)
						}
					}
				}
			}
		} else {
			includes = append(includes, pattern)
		}
	}

	return includes
}

// parseConfig 解析配置内容
func (s *Scanner) parseConfig(content, configPath string, info *ContainerInfo) []*SSLSite {
	var sites []*SSLSite
	var currentSite *SSLSite
	inServerBlock := false
	braceCount := 0
	inLocation := false
	locationBraceCount := 0

	// 正则表达式
	serverBlockRe := regexp.MustCompile(`^\s*server\s*\{`)
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRe := regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+([^;]+);`)
	sslKeyRe := regexp.MustCompile(`^\s*ssl_certificate_key\s+([^;]+);`)
	rootRe := regexp.MustCompile(`^\s*root\s+([^;]+);`)
	locationRe := regexp.MustCompile(`^\s*location\s+`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
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
				ContainerID:   info.ID,
				ContainerName: info.Name,
				ConfigFile:    configPath,
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
			if currentSite != nil && currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
				// 计算宿主机路径
				s.resolveHostPaths(currentSite)
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
		}

		// 解析 ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			certPath := strings.TrimSpace(matches[1])
			certPath = strings.Trim(certPath, `"'`)
			currentSite.CertificatePath = certPath
		}

		// 解析 ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			keyPath := strings.TrimSpace(matches[1])
			keyPath = strings.Trim(keyPath, `"'`)
			currentSite.PrivateKeyPath = keyPath
		}

		// 解析 root（仅在 server 块级别）
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
	if currentSite != nil && currentSite.CertificatePath != "" && currentSite.PrivateKeyPath != "" {
		s.resolveHostPaths(currentSite)
		sites = append(sites, currentSite)
	}

	return sites
}

// resolveHostPaths 解析宿主机路径
func (s *Scanner) resolveHostPaths(site *SSLSite) {
	// 查找证书路径对应的挂载
	certMount := s.client.FindMountForPath(s.mounts, site.CertificatePath)
	if certMount != nil {
		site.HostCertPath = s.client.ResolveHostPath(site.CertificatePath, certMount)
		site.VolumeMode = true
	}

	// 查找私钥路径对应的挂载
	keyMount := s.client.FindMountForPath(s.mounts, site.PrivateKeyPath)
	if keyMount != nil {
		site.HostKeyPath = s.client.ResolveHostPath(site.PrivateKeyPath, keyMount)
	}

	// 查找 webroot 对应的挂载
	if site.Webroot != "" {
		webrootMount := s.client.FindMountForPath(s.mounts, site.Webroot)
		if webrootMount != nil {
			site.HostWebroot = s.client.ResolveHostPath(site.Webroot, webrootMount)
		}
	}
}

// FindByDomain 根据域名查找站点
func (s *Scanner) FindByDomain(ctx context.Context, domain string) (*SSLSite, error) {
	sites, err := s.Scan(ctx)
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
				suffix := alias[1:]
				if strings.HasSuffix(domain, suffix) {
					return site, nil
				}
			}
		}

		// 主域名通配符匹配
		if strings.HasPrefix(site.ServerName, "*.") {
			suffix := site.ServerName[1:]
			if strings.HasSuffix(domain, suffix) {
				return site, nil
			}
		}
	}

	return nil, nil
}

// getDir 获取路径的目录部分
func getDir(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx == -1 {
		return "."
	}
	return path[:idx]
}
