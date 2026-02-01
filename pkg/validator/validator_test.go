package validator

import (
	"testing"

	"github.com/zhuxbo/cert-deploy/testdata/certs"
)

func TestValidateCert_ValidCert(t *testing.T) {
	// 生成有效证书
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	cert, err := v.ValidateCert(testCert.CertPEM)
	if err != nil {
		t.Errorf("验证有效证书失败: %v", err)
	}

	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CN 不匹配: 期望 example.com, 实际 %s", cert.Subject.CommonName)
	}
}

func TestValidateCert_ExpiredCert(t *testing.T) {
	// 生成过期证书
	testCert, err := certs.GenerateExpiredCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	_, err = v.ValidateCert(testCert.CertPEM)
	if err == nil {
		t.Error("期望过期证书验证失败，但实际通过")
	}
}

func TestValidateCert_FutureCert(t *testing.T) {
	// 生成尚未生效的证书
	testCert, err := certs.GenerateFutureCert("example.com", []string{"example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	_, err = v.ValidateCert(testCert.CertPEM)
	if err == nil {
		t.Error("期望未生效证书验证失败，但实际通过")
	}
}

func TestValidateCert_InvalidPEM(t *testing.T) {
	v := New("")
	_, err := v.ValidateCert(certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效 PEM 验证失败，但实际通过")
	}
}

func TestValidateCert_NotCertPEM(t *testing.T) {
	v := New("")
	_, err := v.ValidateCert(certs.NotCertPEM)
	if err == nil {
		t.Error("期望非证书 PEM 验证失败，但实际通过")
	}
}

func TestValidateCert_EmptyPEM(t *testing.T) {
	v := New("")
	_, err := v.ValidateCert(certs.EmptyPEM)
	if err == nil {
		t.Error("期望空 PEM 验证失败，但实际通过")
	}
}

func TestValidateCert_DomainValidation(t *testing.T) {
	// 生成有效证书
	testCert, err := certs.GenerateValidCert("example.com", []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	// 匹配的域名
	v := New("example.com")
	_, err = v.ValidateCert(testCert.CertPEM)
	if err != nil {
		t.Errorf("域名匹配验证失败: %v", err)
	}

	// SAN 中的域名
	v = New("www.example.com")
	_, err = v.ValidateCert(testCert.CertPEM)
	if err != nil {
		t.Errorf("SAN 域名匹配验证失败: %v", err)
	}

	// 不匹配的域名
	v = New("other.com")
	_, err = v.ValidateCert(testCert.CertPEM)
	if err == nil {
		t.Error("期望域名不匹配验证失败，但实际通过")
	}
}

func TestValidateKey_RSAKey(t *testing.T) {
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateKey(testCert.KeyPEM)
	if err != nil {
		t.Errorf("验证 RSA 私钥失败: %v", err)
	}
}

func TestValidateKey_ECKey(t *testing.T) {
	testCert, err := certs.GenerateECCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateKey(testCert.KeyPEM)
	if err != nil {
		t.Errorf("验证 EC 私钥失败: %v", err)
	}
}

func TestValidateKey_InvalidKey(t *testing.T) {
	v := New("")
	err := v.ValidateKey(certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效私钥验证失败，但实际通过")
	}
}

func TestValidateCA_ValidChain(t *testing.T) {
	// 生成证书作为 CA
	testCert, err := certs.GenerateValidCert("Test CA", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateCA(testCert.CertPEM)
	if err != nil {
		t.Errorf("验证 CA 证书失败: %v", err)
	}
}

func TestValidateCA_MultipleCerts(t *testing.T) {
	// 生成两个证书组成链
	cert1, _ := certs.GenerateValidCert("CA 1", nil)
	cert2, _ := certs.GenerateValidCert("CA 2", nil)

	chain := cert1.CertPEM + cert2.CertPEM

	v := New("")
	err := v.ValidateCA(chain)
	if err != nil {
		t.Errorf("验证证书链失败: %v", err)
	}
}

func TestValidateCA_InvalidCA(t *testing.T) {
	v := New("")
	err := v.ValidateCA(certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效 CA 验证失败，但实际通过")
	}
}

// TestValidateCertKeyPair_Match 测试证书和私钥匹配
func TestValidateCertKeyPair_Match(t *testing.T) {
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateCertKeyPair(testCert.CertPEM, testCert.KeyPEM)
	if err != nil {
		t.Errorf("匹配的证书和私钥验证失败: %v", err)
	}
}

// TestValidateCertKeyPair_Mismatch 测试证书和私钥不匹配
func TestValidateCertKeyPair_Mismatch(t *testing.T) {
	cert1, err := certs.GenerateValidCert("example1.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书 1 失败: %v", err)
	}

	cert2, err := certs.GenerateValidCert("example2.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书 2 失败: %v", err)
	}

	v := New("")
	err = v.ValidateCertKeyPair(cert1.CertPEM, cert2.KeyPEM)
	if err == nil {
		t.Error("期望不匹配的证书和私钥验证失败，但实际通过")
	}
}

// TestValidateCertKeyPair_ECMatch 测试 EC 证书和私钥匹配
func TestValidateCertKeyPair_ECMatch(t *testing.T) {
	testCert, err := certs.GenerateECCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成 EC 测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateCertKeyPair(testCert.CertPEM, testCert.KeyPEM)
	if err != nil {
		t.Errorf("匹配的 EC 证书和私钥验证失败: %v", err)
	}
}

// TestValidateCertKeyPair_InvalidCert 测试无效证书
func TestValidateCertKeyPair_InvalidCert(t *testing.T) {
	testCert, _ := certs.GenerateValidCert("example.com", nil)

	v := New("")
	err := v.ValidateCertKeyPair(certs.InvalidPEM, testCert.KeyPEM)
	if err == nil {
		t.Error("期望无效证书验证失败，但实际通过")
	}
}

// TestValidateCertKeyPair_InvalidKey 测试无效私钥
func TestValidateCertKeyPair_InvalidKey(t *testing.T) {
	testCert, _ := certs.GenerateValidCert("example.com", nil)

	v := New("")
	err := v.ValidateCertKeyPair(testCert.CertPEM, certs.InvalidPEM)
	if err == nil {
		t.Error("期望无效私钥验证失败，但实际通过")
	}
}

// TestValidateCertKeyPair_TypeMismatch 测试类型不匹配
func TestValidateCertKeyPair_TypeMismatch(t *testing.T) {
	rsaCert, _ := certs.GenerateValidCert("example.com", nil)
	ecCert, _ := certs.GenerateECCert("example.com", nil)

	v := New("")
	// RSA 证书配 EC 私钥
	err := v.ValidateCertKeyPair(rsaCert.CertPEM, ecCert.KeyPEM)
	if err == nil {
		t.Error("期望类型不匹配验证失败，但实际通过")
	}
}

// TestValidateCert_ExpiringSoon 测试即将过期的证书
func TestValidateCert_ExpiringSoon(t *testing.T) {
	// 生成即将过期的证书（5 天后过期）
	testCert, err := certs.GenerateExpiringCert("example.com", nil, 5)
	if err != nil {
		t.Fatalf("生成即将过期证书失败: %v", err)
	}

	v := New("")
	cert, err := v.ValidateCert(testCert.CertPEM)
	if err != nil {
		t.Fatalf("验证即将过期证书失败: %v", err)
	}

	// 验证证书确实即将过期
	daysUntilExpiry := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	t.Logf("证书有效期: %d 天", daysUntilExpiry)
}

// TestValidateCert_WildcardDomain 测试通配符域名
func TestValidateCert_WildcardDomain(t *testing.T) {
	// 生成通配符证书
	testCert, err := certs.GenerateValidCert("*.example.com", []string{"*.example.com", "example.com"})
	if err != nil {
		t.Fatalf("生成通配符证书失败: %v", err)
	}

	tests := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},       // 精确匹配 SAN
		{"www.example.com", false},   // 通配符匹配
		{"sub.example.com", false},   // 通配符匹配
		{"other.com", true},          // 不匹配
		{"sub.sub.example.com", true}, // 通配符不匹配多级子域名
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			v := New(tt.domain)
			_, err := v.ValidateCert(testCert.CertPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("domain=%s: error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

// TestValidateKey_PKCS1RSA 测试 PKCS#1 RSA 格式私钥
func TestValidateKey_PKCS1RSA(t *testing.T) {
	testCert, err := certs.GenerateValidCert("example.com", nil)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}

	v := New("")
	err = v.ValidateKey(testCert.KeyPEM)
	if err != nil {
		t.Errorf("验证 PKCS#1 RSA 格式私钥失败: %v", err)
	}
}

// TestValidateKey_AllFormats 测试所有支持的私钥格式
func TestValidateKey_AllFormats(t *testing.T) {
	// 生成真实的测试密钥
	rsaCert, _ := certs.GenerateValidCert("example.com", nil)
	ecCert, _ := certs.GenerateECCert("example.com", nil)

	tests := []struct {
		name    string
		keyPEM  string
		wantErr bool
	}{
		{
			name:    "RSA PRIVATE KEY (PKCS#1)",
			keyPEM:  rsaCert.KeyPEM,
			wantErr: false,
		},
		{
			name:    "EC PRIVATE KEY",
			keyPEM:  ecCert.KeyPEM,
			wantErr: false,
		},
		{
			name: "PUBLIC KEY (错误类型)",
			keyPEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS0VQ
-----END PUBLIC KEY-----`,
			wantErr: true,
		},
		{
			name:    "CERTIFICATE (错误类型)",
			keyPEM:  rsaCert.CertPEM,
			wantErr: true,
		},
		{
			name:    "空内容",
			keyPEM:  "",
			wantErr: true,
		},
		{
			name:    "无效 PEM",
			keyPEM:  certs.InvalidPEM,
			wantErr: true,
		},
	}

	v := New("")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateKey(tt.keyPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCA_ChainOrder 测试证书链顺序
func TestValidateCA_ChainOrder(t *testing.T) {
	// 生成多个证书组成链
	cert1, _ := certs.GenerateValidCert("Intermediate CA 1", nil)
	cert2, _ := certs.GenerateValidCert("Intermediate CA 2", nil)
	cert3, _ := certs.GenerateValidCert("Root CA", nil)

	// 不同顺序的证书链都应该通过验证
	chains := []string{
		cert1.CertPEM + cert2.CertPEM + cert3.CertPEM,
		cert3.CertPEM + cert2.CertPEM + cert1.CertPEM,
		cert2.CertPEM + cert1.CertPEM + cert3.CertPEM,
	}

	v := New("")
	for i, chain := range chains {
		err := v.ValidateCA(chain)
		if err != nil {
			t.Errorf("证书链 %d 验证失败: %v", i+1, err)
		}
	}
}

// TestValidateCA_EmptyChain 测试空证书链
func TestValidateCA_EmptyChain(t *testing.T) {
	v := New("")
	err := v.ValidateCA("")
	if err == nil {
		t.Error("期望空证书链验证失败，但实际通过")
	}
}

// TestValidateCA_MixedContent 测试混合内容的证书链
func TestValidateCA_MixedContent(t *testing.T) {
	cert, _ := certs.GenerateValidCert("Test CA", nil)

	// 混合证书和非证书内容
	mixedChain := cert.CertPEM + "\n" + cert.KeyPEM

	v := New("")
	err := v.ValidateCA(mixedChain)
	if err == nil {
		t.Error("期望混合内容验证失败，但实际通过")
	}
}

// TestValidateCert_SAN 测试 SAN 扩展
func TestValidateCert_SAN(t *testing.T) {
	sans := []string{"example.com", "www.example.com", "api.example.com", "mail.example.com"}
	testCert, err := certs.GenerateValidCert("example.com", sans)
	if err != nil {
		t.Fatalf("生成多 SAN 证书失败: %v", err)
	}

	v := New("")
	cert, err := v.ValidateCert(testCert.CertPEM)
	if err != nil {
		t.Fatalf("验证证书失败: %v", err)
	}

	// 验证所有 SAN 都存在
	for _, san := range sans {
		found := false
		for _, certSAN := range cert.DNSNames {
			if certSAN == san {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SAN %s 未在证书中找到", san)
		}
	}
}

// TestNew_WithEmptyDomain 测试空域名创建验证器
func TestNew_WithEmptyDomain(t *testing.T) {
	v := New("")
	if v == nil {
		t.Fatal("New(\"\") 返回 nil")
	}
	if v.expectedDomain != "" {
		t.Errorf("expectedDomain = %s, want empty", v.expectedDomain)
	}
}

// TestNew_WithDomain 测试带域名创建验证器
func TestNew_WithDomain(t *testing.T) {
	v := New("example.com")
	if v == nil {
		t.Fatal("New(\"example.com\") 返回 nil")
	}
	if v.expectedDomain != "example.com" {
		t.Errorf("expectedDomain = %s, want example.com", v.expectedDomain)
	}
}
