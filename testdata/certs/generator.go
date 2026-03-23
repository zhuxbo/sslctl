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
	"fmt"
	"math/big"
	"net"
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

// GenerateExpiringCert 生成即将过期的证书
// daysLeft: 距离过期的天数（可为负数表示已过期）
func GenerateExpiringCert(cn string, dnsNames []string, daysLeft int) (*TestCert, error) {
	now := time.Now()
	notBefore := now.Add(-365 * 24 * time.Hour) // 一年前生效
	notAfter := now.Add(time.Duration(daysLeft) * 24 * time.Hour)
	return GenerateTestCert(cn, dnsNames, notBefore, notAfter)
}

// MismatchedKeyPair 生成证书和不匹配的私钥
type MismatchedKeyPair struct {
	CertPEM  string // 证书 PEM
	WrongKey string // 不匹配的私钥 PEM
}

// GenerateMismatchedKeyPair 生成证书和不匹配的私钥对
func GenerateMismatchedKeyPair(cn string) (*MismatchedKeyPair, error) {
	// 生成证书
	cert, err := GenerateValidCert(cn, []string{cn})
	if err != nil {
		return nil, err
	}

	// 生成另一个私钥
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(wrongKey),
	})

	return &MismatchedKeyPair{
		CertPEM:  cert.CertPEM,
		WrongKey: string(wrongKeyPEM),
	}, nil
}

// CertChain 证书链
type CertChain struct {
	RootCertPEM         string
	RootKeyPEM          string
	IntermediateCertPEM string
	IntermediateKeyPEM  string
	LeafCertPEM         string
	LeafKeyPEM          string
}

// GenerateCertChain 生成证书链（Root -> Intermediate -> Leaf）
func GenerateCertChain(leafCN string, leafDNS []string) (*CertChain, error) {
	now := time.Now()

	// 1. 生成 Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// 2. 生成 Intermediate CA
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	intTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, &intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	intCert, _ := x509.ParseCertificate(intDER)

	// 3. 生成 Leaf 证书
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: leafCN,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              leafDNS,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		return nil, err
	}

	return &CertChain{
		RootCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		RootKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
		})),
		IntermediateCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})),
		IntermediateKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(intKey),
		})),
		LeafCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		LeafKeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(leafKey),
		})),
	}, nil
}

// FullChainPEM 返回完整证书链 PEM（Leaf + Intermediate + Root）
func (c *CertChain) FullChainPEM() string {
	return c.LeafCertPEM + c.IntermediateCertPEM + c.RootCertPEM
}

// IntermediateChainPEM 返回中间证书链 PEM（Leaf + Intermediate）
func (c *CertChain) IntermediateChainPEM() string {
	return c.LeafCertPEM + c.IntermediateCertPEM
}

// GenerateIPCert 生成 IP 证书（CN 为 IP，SAN 包含 IP）
func GenerateIPCert(ipStr string, notBefore, notAfter time.Time) (*TestCert, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: ipStr,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

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

// GenerateValidIPCert 生成有效期内的 IP 证书
func GenerateValidIPCert(ipStr string) (*TestCert, error) {
	now := time.Now()
	return GenerateIPCert(ipStr, now.Add(-time.Hour), now.Add(365*24*time.Hour))
}

// GenerateSelfSignedCA 生成自签名 CA 证书
func GenerateSelfSignedCA(cn string) (*TestCert, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	cert, _ := x509.ParseCertificate(certDER)

	return &TestCert{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		Cert:    cert,
	}, nil
}
