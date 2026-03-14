package validator

import (
	"testing"
)

// FuzzValidateCert 对证书 PEM 解析进行模糊测试
func FuzzValidateCert(f *testing.F) {
	// 种子语料：各种 PEM 格式
	f.Add("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh\n-----END CERTIFICATE-----\n")
	f.Add("-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n")
	f.Add("not a PEM at all")
	f.Add("")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----\n")
	f.Add("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
	f.Add("-----BEGIN CERTIFICATE-----\n\n\n\n-----END CERTIFICATE-----\n")
	f.Add(string(make([]byte, 10000))) // 大量空字节

	f.Fuzz(func(t *testing.T, certPEM string) {
		v := New("")
		// 不检查返回值，只确保不 panic
		_, _ = v.ValidateCert(certPEM)
	})
}

// FuzzValidateKey 对私钥 PEM 解析进行模糊测试
func FuzzValidateKey(f *testing.F) {
	// 种子语料
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----\n")
	f.Add("-----BEGIN EC PRIVATE KEY-----\nfoo\n-----END EC PRIVATE KEY-----\n")
	f.Add("-----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----\n")
	f.Add("not a PEM")
	f.Add("")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n")
	f.Add("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n")

	f.Fuzz(func(t *testing.T, keyPEM string) {
		v := New("")
		// 不检查返回值，只确保不 panic
		_ = v.ValidateKey(keyPEM)
	})
}

// FuzzMatchDomain 对域名匹配进行模糊测试
func FuzzMatchDomain(f *testing.F) {
	// 种子语料：各种域名格式
	f.Add("example.com", "example.com")
	f.Add("*.example.com", "sub.example.com")
	f.Add("*.example.com", "example.com")
	f.Add("example.com", "*.example.com")
	f.Add("", "")
	f.Add("a", "a")
	f.Add("*.com", "test.com")
	f.Add("xn--nxasmq6b.example.com", "xn--nxasmq6b.example.com") // Punycode
	f.Add("*.xn--nxasmq6b.com", "test.xn--nxasmq6b.com")
	f.Add("sub.sub.example.com", "*.example.com")
	f.Add(string(make([]byte, 255)), string(make([]byte, 255))) // 最大域名长度

	f.Fuzz(func(t *testing.T, siteDomain, certDomain string) {
		// 不检查返回值，只确保不 panic
		_ = MatchDomain(siteDomain, certDomain)
	})
}
