// Package matcher 域名匹配测试
package matcher

import (
	"testing"

	"github.com/zhuxbo/cert-deploy/pkg/config"
)

// TestMatchDomain 测试单域名匹配
func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name       string
		certDomain string
		target     string
		want       bool
	}{
		// 精确匹配（matchDomain 内部不做大小写转换，由调用者处理）
		{"精确匹配", "example.com", "example.com", true},
		{"精确匹配大小写相同", "example.com", "example.com", true},
		{"精确匹配不同域名", "example.com", "other.com", false},

		// 通配符匹配
		{"通配符匹配子域名", "*.example.com", "www.example.com", true},
		{"通配符匹配 api 子域名", "*.example.com", "api.example.com", true},
		{"通配符不匹配根域名", "*.example.com", "example.com", false},
		{"通配符不匹配多级子域名", "*.example.com", "a.b.example.com", false},
		{"通配符小写匹配", "*.example.com", "www.example.com", true},

		// 边界情况
		{"空域名", "", "", true},
		{"空证书域名", "", "example.com", false},
		{"空目标域名", "example.com", "", false},

		// 非通配符不匹配子域名
		{"非通配符不匹配子域名", "example.com", "www.example.com", false},
		{"子域名不匹配父域名", "www.example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchDomain(tt.certDomain, tt.target)
			if got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.certDomain, tt.target, got, tt.want)
			}
		})
	}
}

// TestMatchesDomain 测试便捷函数
func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		domain     string
		want       bool
	}{
		{"精确匹配", "example.com", "example.com", true},
		{"通配符匹配", "*.example.com", "www.example.com", true},
		{"不匹配", "example.com", "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesDomain(tt.serverName, tt.domain); got != tt.want {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.serverName, tt.domain, got, tt.want)
			}
		})
	}
}

// TestContainsDomain 测试域名列表包含检查
func TestContainsDomain(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		target  string
		want    bool
	}{
		{"包含目标域名", []string{"example.com", "other.com"}, "example.com", true},
		{"大小写不敏感", []string{"Example.COM"}, "example.com", true},
		{"不包含目标域名", []string{"example.com"}, "other.com", false},
		{"空列表", []string{}, "example.com", false},
		{"nil 列表", nil, "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsDomain(tt.domains, tt.target); got != tt.want {
				t.Errorf("ContainsDomain(%v, %q) = %v, want %v", tt.domains, tt.target, got, tt.want)
			}
		})
	}
}

// TestMatcherMatch 测试 Matcher.Match 方法
func TestMatcherMatch(t *testing.T) {
	tests := []struct {
		name        string
		certDomains []string
		siteDomains []string
		wantType    config.MatchType
		wantMatched []string
		wantMissed  []string
	}{
		{
			name:        "完全匹配单域名",
			certDomains: []string{"example.com"},
			siteDomains: []string{"example.com"},
			wantType:    config.MatchTypeFull,
			wantMatched: []string{"example.com"},
			wantMissed:  nil,
		},
		{
			name:        "完全匹配多域名",
			certDomains: []string{"*.example.com", "example.com"},
			siteDomains: []string{"www.example.com", "example.com"},
			wantType:    config.MatchTypeFull,
			wantMatched: []string{"www.example.com", "example.com"},
			wantMissed:  nil,
		},
		{
			name:        "部分匹配",
			certDomains: []string{"example.com"},
			siteDomains: []string{"example.com", "other.com"},
			wantType:    config.MatchTypePartial,
			wantMatched: []string{"example.com"},
			wantMissed:  []string{"other.com"},
		},
		{
			name:        "不匹配",
			certDomains: []string{"example.com"},
			siteDomains: []string{"other.com"},
			wantType:    config.MatchTypeNone,
			wantMatched: nil,
			wantMissed:  []string{"other.com"},
		},
		{
			name:        "站点域名为空",
			certDomains: []string{"example.com"},
			siteDomains: []string{},
			wantType:    config.MatchTypeNone,
			wantMatched: nil,
			wantMissed:  nil,
		},
		{
			name:        "站点域名为 nil",
			certDomains: []string{"example.com"},
			siteDomains: nil,
			wantType:    config.MatchTypeNone,
			wantMatched: nil,
			wantMissed:  nil,
		},
		{
			name:        "通配符完全匹配多子域名",
			certDomains: []string{"*.example.com"},
			siteDomains: []string{"www.example.com", "api.example.com", "mail.example.com"},
			wantType:    config.MatchTypeFull,
			wantMatched: []string{"www.example.com", "api.example.com", "mail.example.com"},
			wantMissed:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.certDomains)
			result := m.Match(tt.siteDomains)

			if result.Type != tt.wantType {
				t.Errorf("Match().Type = %v, want %v", result.Type, tt.wantType)
			}

			if !stringSliceEqual(result.MatchedDomains, tt.wantMatched) {
				t.Errorf("Match().MatchedDomains = %v, want %v", result.MatchedDomains, tt.wantMatched)
			}

			if !stringSliceEqual(result.MissedDomains, tt.wantMissed) {
				t.Errorf("Match().MissedDomains = %v, want %v", result.MissedDomains, tt.wantMissed)
			}
		})
	}
}

// TestMatcherMatchSites 测试批量站点匹配
func TestMatcherMatchSites(t *testing.T) {
	m := New([]string{"*.example.com", "example.com"})

	sites := []*ScannedSiteInfo{
		{
			ServerName:  "www.example.com",
			ServerAlias: []string{"example.com"},
			HasSSL:      true,
		},
		{
			ServerName:  "api.example.com",
			ServerAlias: nil,
			HasSSL:      false,
		},
		{
			ServerName: "other.com",
			HasSSL:     true,
		},
		{
			ServerName:  "mixed.example.com",
			ServerAlias: []string{"mixed.other.com"},
			HasSSL:      false,
		},
	}

	full, partial, none := m.MatchSites(sites)

	// 验证完全匹配
	if len(full) != 2 {
		t.Errorf("full matches count = %d, want 2", len(full))
	}

	// 验证部分匹配
	if len(partial) != 1 {
		t.Errorf("partial matches count = %d, want 1", len(partial))
	}
	if len(partial) > 0 && partial[0].Site.ServerName != "mixed.example.com" {
		t.Errorf("partial[0].Site.ServerName = %s, want mixed.example.com", partial[0].Site.ServerName)
	}

	// 验证不匹配
	if len(none) != 1 {
		t.Errorf("none matches count = %d, want 1", len(none))
	}
	if len(none) > 0 && none[0].Site.ServerName != "other.com" {
		t.Errorf("none[0].Site.ServerName = %s, want other.com", none[0].Site.ServerName)
	}
}

// TestMatcherFindBestMatch 测试最佳匹配查找
func TestMatcherFindBestMatch(t *testing.T) {
	tests := []struct {
		name     string
		sites    []*ScannedSiteInfo
		wantSite string
	}{
		{
			name: "优先完全匹配且已启用 SSL",
			sites: []*ScannedSiteInfo{
				{ServerName: "www.example.com", HasSSL: false},
				{ServerName: "api.example.com", HasSSL: true},
			},
			wantSite: "api.example.com",
		},
		{
			name: "完全匹配无 SSL 优先于部分匹配",
			sites: []*ScannedSiteInfo{
				{ServerName: "www.example.com", HasSSL: false},
				{ServerName: "mixed.example.com", ServerAlias: []string{"other.com"}, HasSSL: true},
			},
			wantSite: "www.example.com",
		},
		{
			name: "部分匹配优先 SSL 已启用",
			sites: []*ScannedSiteInfo{
				{ServerName: "mixed.example.com", ServerAlias: []string{"other.com"}, HasSSL: false},
				{ServerName: "mixed2.example.com", ServerAlias: []string{"other2.com"}, HasSSL: true},
			},
			wantSite: "mixed2.example.com",
		},
		{
			name: "无匹配返回 nil",
			sites: []*ScannedSiteInfo{
				{ServerName: "other.com"},
			},
			wantSite: "",
		},
		{
			name:     "空站点列表返回 nil",
			sites:    []*ScannedSiteInfo{},
			wantSite: "",
		},
	}

	m := New([]string{"*.example.com"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.FindBestMatch(tt.sites)

			if tt.wantSite == "" {
				if result != nil {
					t.Errorf("FindBestMatch() = %v, want nil", result.Site.ServerName)
				}
				return
			}

			if result == nil {
				t.Errorf("FindBestMatch() = nil, want %s", tt.wantSite)
				return
			}

			if result.Site.ServerName != tt.wantSite {
				t.Errorf("FindBestMatch().Site.ServerName = %s, want %s", result.Site.ServerName, tt.wantSite)
			}
		})
	}
}

// TestNew 测试创建匹配器
func TestNew(t *testing.T) {
	domains := []string{"example.com", "*.example.com"}
	m := New(domains)

	if m == nil {
		t.Fatal("New() returned nil")
	}

	if len(m.certDomains) != 2 {
		t.Errorf("New() certDomains length = %d, want 2", len(m.certDomains))
	}
}

// stringSliceEqual 比较两个字符串切片是否相等
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
