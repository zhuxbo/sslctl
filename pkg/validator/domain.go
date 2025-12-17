// Package validator 证书验证器
package validator

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/cnssl/cert-deploy/pkg/errors"
)

// DomainValidator 域名验证器
type DomainValidator struct {
	domains              []string
	ignoreDomainMismatch bool
}

// NewDomainValidator 创建域名验证器
func NewDomainValidator(domains []string, ignoreMismatch bool) *DomainValidator {
	return &DomainValidator{
		domains:              domains,
		ignoreDomainMismatch: ignoreMismatch,
	}
}

// ValidateDomainCoverage 验证证书是否覆盖站点的所有域名
func (v *DomainValidator) ValidateDomainCoverage(cert *x509.Certificate) error {
	// 提取证书支持的所有域名
	certDomains := make(map[string]bool)

	// CommonName
	if cert.Subject.CommonName != "" {
		certDomains[strings.ToLower(cert.Subject.CommonName)] = true
	}

	// SANs (Subject Alternative Names)
	for _, san := range cert.DNSNames {
		certDomains[strings.ToLower(san)] = true
	}

	// 检查站点的每个域名是否被证书覆盖
	var uncovered []string
	for _, siteDomain := range v.domains {
		covered := false

		for certDomain := range certDomains {
			if MatchDomain(siteDomain, certDomain) {
				covered = true
				break
			}
		}

		if !covered {
			uncovered = append(uncovered, siteDomain)
		}
	}

	if len(uncovered) > 0 {
		err := errors.NewValidateError(
			fmt.Sprintf("certificate does not cover these domains: %v", uncovered),
			nil,
		)

		// 如果配置为忽略域名不匹配,返回警告而不是错误
		if v.ignoreDomainMismatch {
			// 在实际使用中,这里应该记录警告日志
			return nil
		}

		return err
	}

	return nil
}

// MatchDomain 检查域名是否匹配(支持通配符)
func MatchDomain(siteDomain, certDomain string) bool {
	siteDomain = strings.ToLower(siteDomain)
	certDomain = strings.ToLower(certDomain)

	// 精确匹配
	if siteDomain == certDomain {
		return true
	}

	// 通配符匹配 (*.example.com 仅匹配一层子域名，不匹配根域名)
	if strings.HasPrefix(certDomain, "*.") {
		base := certDomain[2:] // 去掉 "*."

		// 检查是否是直接子域名
		if strings.HasSuffix(siteDomain, "."+base) {
			// 确保没有更多的子域名层级
			// 例如: *.example.com 匹配 www.example.com 但不匹配 a.www.example.com
			prefix := strings.TrimSuffix(siteDomain, "."+base)
			if !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}

// ExtractCertDomains 提取证书支持的所有域名
func ExtractCertDomains(cert *x509.Certificate) []string {
	domains := make(map[string]bool)

	// CommonName
	if cert.Subject.CommonName != "" {
		domains[cert.Subject.CommonName] = true
	}

	// SANs
	for _, san := range cert.DNSNames {
		domains[san] = true
	}

	// 转换为切片
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}
