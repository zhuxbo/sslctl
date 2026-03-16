package setup

import (
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
)

func TestBetterCandidate(t *testing.T) {
	tests := []struct {
		name string
		a, b siteCandidate
		want bool
	}{
		{
			name: "完全匹配优先于部分匹配",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 1},
			b:    siteCandidate{matchType: config.MatchTypePartial, matchedCount: 3, orderID: 100},
			want: true,
		},
		{
			name: "部分匹配不优于完全匹配",
			a:    siteCandidate{matchType: config.MatchTypePartial, matchedCount: 5, orderID: 100},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 1},
			want: false,
		},
		{
			name: "同级别匹配域名数多的优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 3, orderID: 1},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 1, orderID: 100},
			want: true,
		},
		{
			name: "同级别同数量OrderID大的优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 200},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: true,
		},
		{
			name: "同级别同数量OrderID小的不优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 50},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: false,
		},
		{
			name: "完全相同不优先",
			a:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			b:    siteCandidate{matchType: config.MatchTypeFull, matchedCount: 2, orderID: 100},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := betterCandidate(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("betterCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}
