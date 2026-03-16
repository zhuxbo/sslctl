// Package matcher 提供域名匹配逻辑
package matcher

import (
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
func toASCIILower(domain string) string {
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
	Site      *ScannedSiteInfo     // 站点信息
	Result    *config.MatchResult  // 匹配结果
}

// ScannedSiteInfo 扫描到的站点信息
type ScannedSiteInfo struct {
	ServerName  string   // 主域名
	ServerAlias []string // 别名
	ConfigFile  string   // 配置文件路径
	HasSSL      bool     // 是否已启用 SSL
	CertPath    string   // 证书路径
	KeyPath     string   // 私钥路径
	ChainPath   string   // 证书链路径（Apache SSLCertificateChainFile）
	Webroot     string   // Web 根目录
	ServerType  string   // 服务器类型
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
