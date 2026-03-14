package matcher

import (
	"testing"
)

// FuzzMatchDomain 对域名匹配进行模糊测试（含 IDN/Punycode 支持）
func FuzzMatchDomain(f *testing.F) {
	// 种子语料
	f.Add("example.com", "example.com")
	f.Add("*.example.com", "sub.example.com")
	f.Add("*.example.com", "example.com")
	f.Add("sub.sub.example.com", "*.example.com")
	f.Add("", "")
	f.Add("a", "b")
	f.Add("*.com", "test.com")
	f.Add("example.com", "EXAMPLE.COM")                           // 大小写
	f.Add("xn--nxasmq6b.example.com", "xn--nxasmq6b.example.com") // Punycode
	f.Add("*.xn--nxasmq6b.com", "test.xn--nxasmq6b.com")
	f.Add(string(make([]byte, 255)), "example.com") // 超长域名

	f.Fuzz(func(t *testing.T, certDomain, targetDomain string) {
		// 不检查返回值，只确保不 panic
		_ = MatchDomain(certDomain, targetDomain)
	})
}
