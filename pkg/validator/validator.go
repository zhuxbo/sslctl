// Package validator 负责证书校验
package validator

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/cnssl/cert-deploy/pkg/errors"
)

// Validator 证书校验器
type Validator struct {
	expectedDomain string // 期望的域名，为空则跳过域名校验
}

// New 创建新的 Validator
func New(expectedDomain string) *Validator {
	return &Validator{
		expectedDomain: expectedDomain,
	}
}

// ValidateCert 校验证书内容
func (v *Validator) ValidateCert(certPEM string) (*x509.Certificate, error) {
	// 解析 PEM 编码的证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.NewValidateError("failed to decode PEM block", nil)
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.NewValidateError(fmt.Sprintf("invalid PEM type: %s (expected CERTIFICATE)", block.Type), nil)
	}

	// 解析 X.509 证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.NewValidateError("failed to parse X.509 certificate", err)
	}

	// 检查证书有效期
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, errors.NewValidateError(
			fmt.Sprintf("certificate not yet valid (NotBefore: %s)", cert.NotBefore.Format(time.RFC3339)),
			nil,
		)
	}

	if now.After(cert.NotAfter) {
		return nil, errors.NewValidateError(
			fmt.Sprintf("certificate expired (NotAfter: %s)", cert.NotAfter.Format(time.RFC3339)),
			nil,
		)
	}

	// 域名校验（可选）
	if v.expectedDomain != "" {
		if err := v.validateDomain(cert); err != nil {
			return nil, err
		}
	}

	return cert, nil
}

// validateDomain 校验证书域名
func (v *Validator) validateDomain(cert *x509.Certificate) error {
	// 检查 CN
	if cert.Subject.CommonName == v.expectedDomain {
		return nil
	}

	// 检查 SAN (Subject Alternative Name)
	for _, san := range cert.DNSNames {
		// 支持通配符证书
		if MatchDomain(v.expectedDomain, san) {
			return nil
		}
	}

	return errors.NewValidateError(
		fmt.Sprintf("domain mismatch: expected %s, got CN=%s, SAN=%v",
			v.expectedDomain, cert.Subject.CommonName, cert.DNSNames),
		nil,
	)
}

// ValidateKey 校验私钥格式
func (v *Validator) ValidateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return errors.NewValidateError("failed to decode private key PEM block", nil)
	}

	// 支持多种私钥类型
	validTypes := []string{
		"PRIVATE KEY",     // PKCS#8
		"RSA PRIVATE KEY", // PKCS#1 RSA
		"EC PRIVATE KEY",  // PKCS#1 EC
		"ENCRYPTED PRIVATE KEY",
	}

	for _, t := range validTypes {
		if block.Type == t {
			return nil
		}
	}

	return errors.NewValidateError(
		fmt.Sprintf("invalid private key type: %s (expected one of: %v)", block.Type, validTypes),
		nil,
	)
}

// ValidateCA 校验 CA 证书格式
func (v *Validator) ValidateCA(caPEM string) error {
	// CA 证书可以是证书链（多个证书）
	rest := []byte(caPEM)
	count := 0

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return errors.NewValidateError(fmt.Sprintf("invalid CA PEM type: %s", block.Type), nil)
		}

		// 尝试解析证书
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.NewValidateError("failed to parse CA certificate", err)
		}

		count++
		rest = remaining
	}

	if count == 0 {
		return errors.NewValidateError("no valid CA certificates found", nil)
	}

	return nil
}
