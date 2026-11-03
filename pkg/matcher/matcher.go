// Package matcher 提供域名匹配逻辑
package matcher

import (
	"net"
	"strings"

	"github.com/zhuxbo/sslctl/pkg/config"
	"golang.org/x/net/idna"
)

// Matcher 域名匹配器
type Matcher struct {
	certDomains []string // 证书域名列表
}

// New 创建匹配器
func New(certDomains []string) *Matcher {
	lower := make([]string, len(certDomains))
	for i, d := range certDomains {
		lower[i] = toASCIILower(d)
	}
	return &Matcher{certDomains: lower}
}

// toASCIILower 将域名转为小写 ASCII（Punycode），转换失败时保留原始字符串
// IP 地址直接返回原字符串（无需 IDNA 转换）
func toASCIILower(domain string) string {
	// IP 地址不需要 IDNA 转换
	if net.ParseIP(domain) != nil {
		return domain
	}
	lower := strings.ToLower(domain)
	// 通配符域名：对 baseDomain 部分做 IDN 转换
	if strings.HasPrefix(lower, "*.") {
		base := lower[2:]
		if ascii, err := idna.Lookup.ToASCII(base); err == nil {
			return "*." + ascii
		}
		return lower
	}
	if ascii, err := idna.Lookup.ToASCII(lower); err == nil {
		return ascii
	}
	return lower
}

// Match 匹配站点域名
// siteDomains: 站点的所有域名（ServerName + ServerAlias）
// 返回匹配结果
func (m *Matcher) Match(siteDomains []string) *config.MatchResult {
	if len(siteDomains) == 0 {
		return &config.MatchResult{
			Type:           config.MatchTypeNone,
			MatchedDomains: nil,
			MissedDomains:  nil,
		}
	}

	var matched, missed []string
	for _, siteDomain := range siteDomains {
		if m.matchesDomain(siteDomain) {
			matched = append(matched, siteDomain)
		} else {
			missed = append(missed, siteDomain)
		}
	}

	// 判断匹配类型
	if len(matched) == 0 {
		return &config.MatchResult{
			Type:           config.MatchTypeNone,
			MatchedDomains: nil,
			MissedDomains:  siteDomains,
		}
	}

	if len(missed) == 0 {
		return &config.MatchResult{
			Type:           config.MatchTypeFull,
			MatchedDomains: matched,
			MissedDomains:  nil,
		}
	}

	return &config.MatchResult{
		Type:           config.MatchTypePartial,
		MatchedDomains: matched,
		MissedDomains:  missed,
	}
}

// matchesDomain 检查证书是否覆盖指定域名
func (m *Matcher) matchesDomain(domain string) bool {
	domain = toASCIILower(domain)
	for _, certDomain := range m.certDomains {
		if MatchDomain(certDomain, domain) {
			return true
		}
	}
	return false
}

// MatchDomain 匹配单个域名
// certDomain: 证书域名（或站点域名），可能是通配符（如 *.example.com）
// targetDomain: 目标域名（如 www.example.com）
func MatchDomain(certDomain, targetDomain string) bool {
	// IP 精确匹配（IP 不支持通配符）
	certIP := net.ParseIP(certDomain)
	targetIP := net.ParseIP(targetDomain)
	if certIP != nil || targetIP != nil {
		return certIP != nil && targetIP != nil && certIP.Equal(targetIP)
	}

	// 精确匹配
	if certDomain == targetDomain {
		return true
	}

	// 通配符匹配：*.example.com 匹配 www.example.com
	if strings.HasPrefix(certDomain, "*.") {
		// 获取通配符的基础域名部分
		baseDomain := certDomain[2:] // 去掉 "*."

		// 边界检查：baseDomain 非空且至少包含一个 "."
		if baseDomain == "" || !strings.Contains(baseDomain, ".") {
			return false
		}

		// 目标域名必须以基础域名结尾
		if !strings.HasSuffix(targetDomain, baseDomain) {
			return false
		}

		// 目标域名必须是 xxx.baseDomain 格式
		prefix := strings.TrimSuffix(targetDomain, baseDomain)
		if prefix == "" {
			// 通配符证书不匹配根域名本身（*.example.com 不匹配 example.com）
			return false
		}

		// 前缀必须以 . 结尾，且前缀不能再包含 .（只匹配一级）
		if !strings.HasSuffix(prefix, ".") {
			return false
		}
		prefix = strings.TrimSuffix(prefix, ".")
		if strings.Contains(prefix, ".") {
			// *.example.com 不匹配 a.b.example.com
			return false
		}

		return true
	}

	return false
}

// SiteMatchResult 批量匹配站点的结果
type SiteMatchResult struct {
	Site   *ScannedSiteInfo    // 站点信息
	Result *config.MatchResult // 匹配结果
}

// ScannedSiteInfo 扫描到的站点信息
type ScannedSiteInfo struct {
	ServerName     string   // 主域名
	ServerAlias    []string // 别名
	ConfigFile     string   // 配置文件路径
	HasSSL         bool     // 是否已启用 SSL
	CertPath       string   // 证书路径
	KeyPath        string   // 私钥路径
	ChainPath      string   // 证书链路径（Apache SSLCertificateChainFile）
	Webroot        string   // Web 根目录
	ServerType     string   // 服务器类型
	ExecutablePath string   // 扫描该本地站点时实际使用的 Web 服务器可执行文件

	// Docker 特有
	ContainerID   string // 容器 ID（非空表示 Docker 站点）
	ContainerName string // 容器名（用于构建 docker exec 重载命令）
	HostCertPath  string // 宿主机证书路径（挂载卷映射后的路径）
	HostKeyPath   string // 宿主机私钥路径
	HostChainPath string // 宿主机证书链路径（Apache SSLCertificateChainFile 的挂载映射）
	VolumeMode    bool   // 证书路径是否挂载为卷
}

// MatchSites 批量匹配站点
func (m *Matcher) MatchSites(sites []*ScannedSiteInfo) (full, partial, none []*SiteMatchResult) {
	for _, site := range sites {
		domains := append([]string{site.ServerName}, site.ServerAlias...)
		result := m.Match(domains)

		smr := &SiteMatchResult{
			Site:   site,
			Result: result,
		}

		switch result.Type {
		case config.MatchTypeFull:
			full = append(full, smr)
		case config.MatchTypePartial:
			partial = append(partial, smr)
		case config.MatchTypeNone:
			none = append(none, smr)
		}
	}
	return
}

// FindBestMatch 在站点列表中找到最佳匹配
// 优先级：完全匹配 > 部分匹配
// 在同类型中，优先选择已启用 SSL 的站点
func (m *Matcher) FindBestMatch(sites []*ScannedSiteInfo) *SiteMatchResult {
	full, partial, _ := m.MatchSites(sites)

	// 优先完全匹配
	if len(full) > 0 {
		// 优先选择已启用 SSL 的
		for _, smr := range full {
			if smr.Site.HasSSL {
				return smr
			}
		}
		return full[0]
	}

	// 其次部分匹配
	if len(partial) > 0 {
		for _, smr := range partial {
			if smr.Site.HasSSL {
				return smr
			}
		}
		return partial[0]
	}

	return nil
}

// ContainsDomain 检查域名列表是否包含指定域名
func ContainsDomain(domains []string, target string) bool {
	target = strings.ToLower(target)
	for _, d := range domains {
		if strings.ToLower(d) == target {
			return true
		}
	}
	return false
}

// MatchesDomain 检查 serverName 是否匹配目标域名（支持通配符）
// 这是一个便捷函数，用于单次匹配
func MatchesDomain(serverName, domain string) bool {
	return MatchDomain(strings.ToLower(serverName), strings.ToLower(domain))
}

// StripPort 剥离主机名中可选的 scheme 前缀（如 https://）和端口后缀（如 :443），
// 返回纯主机名/域名。用于规范化 Apache ServerName/ServerAlias——其语法为
// [scheme://]fqdn[:port]，httpd-ssl.conf 默认模板会写成 "ServerName www.example.com:443"，
// 端口若不剥离会导致域名匹配失败，并污染以 ServerName 命名的证书目录（Windows 上 ":" 为非法路径字符）。
//
//	"www.example.com:443"         -> "www.example.com"
//	"https://www.example.com:443" -> "www.example.com"
//	"www.example.com"             -> "www.example.com"
//	"[2001:db8::1]:443"           -> "2001:db8::1"
//	"2001:db8::1"                 -> "2001:db8::1"（裸 IPv6 原样保留）
//	"_default_"                   -> "_default_"
func StripPort(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	// 剥离 scheme 前缀
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// 剥离端口：net.SplitHostPort 能正确处理 [ipv6]:port；
	// 对无端口或裸 IPv6（多冒号）返回 error，此时保留原值
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
