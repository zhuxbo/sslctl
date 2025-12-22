package validator

import (
	"testing"

	"github.com/cnssl/cert-deploy/testdata/certs"
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
