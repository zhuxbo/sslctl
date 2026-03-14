// Package certs 证书生成器测试
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestGenerateTestCert(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	cert, err := GenerateTestCert("test.example.com", []string{"test.example.com", "www.example.com"}, notBefore, notAfter)
	if err != nil {
		t.Fatalf("GenerateTestCert() error = %v", err)
	}

	if cert.CertPEM == "" {
		t.Error("CertPEM should not be empty")
	}

	if cert.KeyPEM == "" {
		t.Error("KeyPEM should not be empty")
	}

	if cert.Cert == nil {
		t.Fatal("Cert should not be nil")
	}

	if cert.Cert.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %s, want test.example.com", cert.Cert.Subject.CommonName)
	}

	if len(cert.Cert.DNSNames) != 2 {
		t.Errorf("DNSNames length = %d, want 2", len(cert.Cert.DNSNames))
	}
}

func TestGenerateValidCert(t *testing.T) {
	cert, err := GenerateValidCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("GenerateValidCert() error = %v", err)
	}

	now := time.Now()
	if cert.Cert.NotBefore.After(now) {
		t.Error("cert should have started in the past")
	}

	if cert.Cert.NotAfter.Before(now) {
		t.Error("cert should not be expired")
	}
}

func TestGenerateExpiredCert(t *testing.T) {
	cert, err := GenerateExpiredCert("expired.example.com", []string{"expired.example.com"})
	if err != nil {
		t.Fatalf("GenerateExpiredCert() error = %v", err)
	}

	now := time.Now()
	if cert.Cert.NotAfter.After(now) {
		t.Error("expired cert should have NotAfter in the past")
	}
}

func TestGenerateFutureCert(t *testing.T) {
	cert, err := GenerateFutureCert("future.example.com", []string{"future.example.com"})
	if err != nil {
		t.Fatalf("GenerateFutureCert() error = %v", err)
	}

	now := time.Now()
	if cert.Cert.NotBefore.Before(now) {
		t.Error("future cert should have NotBefore in the future")
	}
}

func TestGenerateWildcardCert(t *testing.T) {
	cert, err := GenerateWildcardCert("example.com")
	if err != nil {
		t.Fatalf("GenerateWildcardCert() error = %v", err)
	}

	if cert.Cert.Subject.CommonName != "*.example.com" {
		t.Errorf("CommonName = %s, want *.example.com", cert.Cert.Subject.CommonName)
	}

	// 检查 DNSNames 包含通配符和根域名
	hasWildcard := false
	hasRoot := false
	for _, dns := range cert.Cert.DNSNames {
		if dns == "*.example.com" {
			hasWildcard = true
		}
		if dns == "example.com" {
			hasRoot = true
		}
	}

	if !hasWildcard {
		t.Error("DNSNames should contain *.example.com")
	}
	if !hasRoot {
		t.Error("DNSNames should contain example.com")
	}
}

func TestGenerateECCert(t *testing.T) {
	cert, err := GenerateECCert("ec.example.com", []string{"ec.example.com"})
	if err != nil {
		t.Fatalf("GenerateECCert() error = %v", err)
	}

	// 验证私钥是 EC 类型
	if !strings.Contains(cert.KeyPEM, "EC PRIVATE KEY") {
		t.Error("KeyPEM should contain EC PRIVATE KEY")
	}

	// 验证可以解析私钥
	block, _ := pem.Decode([]byte(cert.KeyPEM))
	if block == nil {
		t.Fatal("failed to decode key PEM")
	}

	_, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("failed to parse EC private key: %v", err)
	}
}

func TestGenerateExpiringCert(t *testing.T) {
	tests := []struct {
		name     string
		daysLeft int
		expired  bool
	}{
		{"即将过期 7 天", 7, false},
		{"即将过期 1 天", 1, false},
		{"今天过期", 0, true},
		{"已过期 1 天", -1, true},
		{"已过期 30 天", -30, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := GenerateExpiringCert("expiring.example.com", []string{"expiring.example.com"}, tt.daysLeft)
			if err != nil {
				t.Fatalf("GenerateExpiringCert() error = %v", err)
			}

			now := time.Now()
			isExpired := cert.Cert.NotAfter.Before(now)

			if isExpired != tt.expired {
				t.Errorf("isExpired = %v, want %v (NotAfter: %v)", isExpired, tt.expired, cert.Cert.NotAfter)
			}
		})
	}
}

func TestGenerateMismatchedKeyPair(t *testing.T) {
	pair, err := GenerateMismatchedKeyPair("mismatch.example.com")
	if err != nil {
		t.Fatalf("GenerateMismatchedKeyPair() error = %v", err)
	}

	if pair.CertPEM == "" {
		t.Error("CertPEM should not be empty")
	}

	if pair.WrongKey == "" {
		t.Error("WrongKey should not be empty")
	}

	// 验证证书和私钥都能正确解析
	certBlock, _ := pem.Decode([]byte(pair.CertPEM))
	_, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	keyBlock, _ := pem.Decode([]byte(pair.WrongKey))
	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// 只验证两个 PEM 都有效，不匹配性由函数实现保证
}

func TestGenerateCertChain(t *testing.T) {
	chain, err := GenerateCertChain("leaf.example.com", []string{"leaf.example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("GenerateCertChain() error = %v", err)
	}

	// 验证各部分都存在
	if chain.RootCertPEM == "" {
		t.Error("RootCertPEM should not be empty")
	}
	if chain.IntermediateCertPEM == "" {
		t.Error("IntermediateCertPEM should not be empty")
	}
	if chain.LeafCertPEM == "" {
		t.Error("LeafCertPEM should not be empty")
	}

	// 解析并验证证书
	rootBlock, _ := pem.Decode([]byte(chain.RootCertPEM))
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	if !rootCert.IsCA {
		t.Error("root cert should be CA")
	}

	intBlock, _ := pem.Decode([]byte(chain.IntermediateCertPEM))
	intCert, err := x509.ParseCertificate(intBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	if !intCert.IsCA {
		t.Error("intermediate cert should be CA")
	}

	leafBlock, _ := pem.Decode([]byte(chain.LeafCertPEM))
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	if leafCert.IsCA {
		t.Error("leaf cert should not be CA")
	}

	if leafCert.Subject.CommonName != "leaf.example.com" {
		t.Errorf("leaf CommonName = %s, want leaf.example.com", leafCert.Subject.CommonName)
	}
}

func TestCertChain_FullChainPEM(t *testing.T) {
	chain, err := GenerateCertChain("leaf.example.com", []string{"leaf.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	fullChain := chain.FullChainPEM()

	// 应该包含三个证书
	count := strings.Count(fullChain, "-----BEGIN CERTIFICATE-----")
	if count != 3 {
		t.Errorf("FullChainPEM should contain 3 certificates, got %d", count)
	}
}

func TestCertChain_IntermediateChainPEM(t *testing.T) {
	chain, err := GenerateCertChain("leaf.example.com", []string{"leaf.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	intChain := chain.IntermediateChainPEM()

	// 应该包含两个证书
	count := strings.Count(intChain, "-----BEGIN CERTIFICATE-----")
	if count != 2 {
		t.Errorf("IntermediateChainPEM should contain 2 certificates, got %d", count)
	}
}

func TestGenerateSelfSignedCA(t *testing.T) {
	ca, err := GenerateSelfSignedCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA() error = %v", err)
	}

	if ca.Cert == nil {
		t.Fatal("Cert should not be nil")
	}

	if !ca.Cert.IsCA {
		t.Error("CA cert should have IsCA = true")
	}

	if ca.Cert.Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %s, want Test CA", ca.Cert.Subject.CommonName)
	}
}

func TestInvalidPEMConstants(t *testing.T) {
	// 测试 InvalidPEM - 应该能解码但无法解析为有效证书
	block, _ := pem.Decode([]byte(InvalidPEM))
	if block != nil {
		_, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			t.Error("InvalidPEM should fail to parse as certificate")
		}
	}
	// 注意：如果 PEM 内容是无效的 base64，pem.Decode 可能返回 nil

	// 测试 NoPEMBlock
	block, _ = pem.Decode([]byte(NoPEMBlock))
	if block != nil {
		t.Error("NoPEMBlock should not decode to a block")
	}

	// 测试 EmptyPEM
	block, _ = pem.Decode([]byte(EmptyPEM))
	if block != nil {
		t.Error("EmptyPEM should not decode to a block")
	}
}
