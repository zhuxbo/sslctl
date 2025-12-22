package validator

import (
	"testing"

	"github.com/cnssl/cert-deploy/testdata/certs"
)

func TestMatchDomain_ExactMatch(t *testing.T) {
	tests := []struct {
		siteDomain string
		certDomain string
		expected   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true}, // 大小写不敏感
		{"www.example.com", "www.example.com", true},
		{"example.com", "other.com", false},
	}

	for _, tt := range tests {
		result := MatchDomain(tt.siteDomain, tt.certDomain)
		if result != tt.expected {
			t.Errorf("MatchDomain(%q, %q) = %v, 期望 %v", tt.siteDomain, tt.certDomain, result, tt.expected)
		}
	}
}

func TestMatchDomain_Wildcard(t *testing.T) {
	tests := []struct {
		siteDomain string
		certDomain string
		expected   bool
	}{
		// 通配符匹配单层子域名
		{"www.example.com", "*.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"test.example.com", "*.example.com", true},

		// 通配符不匹配根域名
		{"example.com", "*.example.com", false},

		// 通配符不匹配多层子域名
		{"a.b.example.com", "*.example.com", false},
		{"www.api.example.com", "*.example.com", false},

		// 大小写不敏感
		{"WWW.Example.COM", "*.example.com", true},

		// 不同域名
		{"www.other.com", "*.example.com", false},
	}

	for _, tt := range tests {
		result := MatchDomain(tt.siteDomain, tt.certDomain)
		if result != tt.expected {
			t.Errorf("MatchDomain(%q, %q) = %v, 期望 %v", tt.siteDomain, tt.certDomain, result, tt.expected)
		}
	}
}

func TestDomainValidator_ValidateDomainCoverage(t *testing.T) {
	// 生成测试证书
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	tests := []struct {
		name        string
		domains     []string
		ignoreMis   bool
		expectError bool
	}{
		{
			name:        "所有域名被覆盖",
			domains:     []string{"example.com", "www.example.com"},
			ignoreMis:   false,
			expectError: false,
		},
		{
			name:        "部分域名被覆盖",
			domains:     []string{"example.com"},
			ignoreMis:   false,
			expectError: false,
		},
		{
			name:        "域名未被覆盖",
			domains:     []string{"other.com"},
			ignoreMis:   false,
			expectError: true,
		},
		{
			name:        "域名未被覆盖但忽略",
			domains:     []string{"other.com"},
			ignoreMis:   true,
			expectError: false,
		},
		{
			name:        "混合域名 - 部分未覆盖",
			domains:     []string{"example.com", "other.com"},
			ignoreMis:   false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := NewDomainValidator(tt.domains, tt.ignoreMis)
			err := dv.ValidateDomainCoverage(testCert.Cert)

			if tt.expectError && err == nil {
				t.Error("期望返回错误，但实际通过")
			}
			if !tt.expectError && err != nil {
				t.Errorf("期望通过，但返回错误: %v", err)
			}
		})
	}
}

func TestDomainValidator_WildcardCert(t *testing.T) {
	// 生成通配符证书
	testCert, err := certs.GenerateWildcardCert("example.com")
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	tests := []struct {
		name        string
		domains     []string
		expectError bool
	}{
		{
			name:        "通配符匹配子域名",
			domains:     []string{"www.example.com", "api.example.com"},
			expectError: false,
		},
		{
			name:        "通配符不匹配多层子域名",
			domains:     []string{"a.b.example.com"},
			expectError: true,
		},
		{
			name:        "根域名在 SAN 中",
			domains:     []string{"example.com"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dv := NewDomainValidator(tt.domains, false)
			err := dv.ValidateDomainCoverage(testCert.Cert)

			if tt.expectError && err == nil {
				t.Error("期望返回错误，但实际通过")
			}
			if !tt.expectError && err != nil {
				t.Errorf("期望通过，但返回错误: %v", err)
			}
		})
	}
}

func TestExtractCertDomains(t *testing.T) {
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com", "www.example.com", "api.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	domains := ExtractCertDomains(testCert.Cert)

	// 检查域名数量（CN + SAN，去重后）
	if len(domains) < 3 {
		t.Errorf("期望至少 3 个域名，实际 %d", len(domains))
	}

	// 检查是否包含期望的域名
	domainSet := make(map[string]bool)
	for _, d := range domains {
		domainSet[d] = true
	}

	expected := []string{"example.com", "www.example.com", "api.example.com"}
	for _, e := range expected {
		if !domainSet[e] {
			t.Errorf("期望包含域名 %s，但未找到", e)
		}
	}
}
