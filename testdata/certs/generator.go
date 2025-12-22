// Package certs 测试用证书生成器
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// TestCert 测试证书
type TestCert struct {
	CertPEM string
	KeyPEM  string
	Cert    *x509.Certificate
}

// GenerateTestCert 生成测试用自签名证书
func GenerateTestCert(cn string, dnsNames []string, notBefore, notAfter time.Time) (*TestCert, error) {
	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// 证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// 自签名
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// PEM 编码证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM 编码私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 解析证书用于返回
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &TestCert{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		Cert:    cert,
	}, nil
}

// GenerateValidCert 生成有效期内的证书
func GenerateValidCert(cn string, dnsNames []string) (*TestCert, error) {
	now := time.Now()
	return GenerateTestCert(cn, dnsNames, now.Add(-time.Hour), now.Add(365*24*time.Hour))
}

// GenerateExpiredCert 生成已过期的证书
func GenerateExpiredCert(cn string, dnsNames []string) (*TestCert, error) {
	now := time.Now()
	return GenerateTestCert(cn, dnsNames, now.Add(-2*365*24*time.Hour), now.Add(-365*24*time.Hour))
}

// GenerateFutureCert 生成尚未生效的证书
func GenerateFutureCert(cn string, dnsNames []string) (*TestCert, error) {
	now := time.Now()
	return GenerateTestCert(cn, dnsNames, now.Add(24*time.Hour), now.Add(365*24*time.Hour))
}

// GenerateWildcardCert 生成通配符证书
func GenerateWildcardCert(domain string) (*TestCert, error) {
	cn := "*." + domain
	dnsNames := []string{cn, domain}
	return GenerateValidCert(cn, dnsNames)
}

// GenerateECCert 生成 EC 证书
func GenerateECCert(cn string, dnsNames []string) (*TestCert, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	pub := privateKey.Public()
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	cert, _ := x509.ParseCertificate(certDER)

	return &TestCert{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		Cert:    cert,
	}, nil
}

// InvalidPEM 无效的 PEM 数据
const InvalidPEM = `-----BEGIN CERTIFICATE-----
this is not valid base64 data!!!
-----END CERTIFICATE-----`

// NotCertPEM 非证书 PEM（私钥类型）
const NotCertPEM = `-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0Z3VS
-----END PRIVATE KEY-----`

// EmptyPEM 空 PEM
const EmptyPEM = ``

// NoPEMBlock 没有 PEM 块
const NoPEMBlock = `just some random text without PEM blocks`
