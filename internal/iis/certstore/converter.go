// Package certstore Windows 证书存储管理
package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// Converter 证书格式转换器
type Converter struct {
	tempDir string // 临时文件目录
}

// NewConverter 创建转换器
func NewConverter(tempDir string) *Converter {
	return &Converter{
		tempDir: tempDir,
	}
}

// ConvertToPFX 将 PEM 格式转换为 PFX 格式
// cert: 服务器证书 PEM
// key: 私钥 PEM
// intermediate: 中间证书 PEM (可选，支持多个证书块)
// password: PFX 密码
// 返回: PFX 文件路径
func (c *Converter) ConvertToPFX(cert, key, intermediate, password string) (string, error) {
	// 0. 确保临时目录存在
	if err := os.MkdirAll(c.tempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// 1. 解析证书
	certParsed, err := parseCertificate(cert)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 2. 解析私钥
	keyParsed, err := parsePrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// 3. 解析中间证书(可选，支持多个证书块)
	var caCerts []*x509.Certificate
	if intermediate != "" {
		rest := []byte(intermediate)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return "", fmt.Errorf("failed to parse intermediate certificate: %w", err)
				}
				caCerts = append(caCerts, caCert)
			}
			rest = remaining
		}
	}

	// 4. 转换为 PFX (使用 Legacy 编码器以获得更好的兼容性)
	pfxData, err := pkcs12.Legacy.Encode(keyParsed, certParsed, caCerts, password)
	if err != nil {
		return "", fmt.Errorf("failed to encode PFX: %w", err)
	}

	// 5. 写入临时文件（使用唯一文件名避免并发冲突）
	pfxFile, err := os.CreateTemp(c.tempDir, "cert_*.pfx")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	pfxPath := pfxFile.Name()

	if _, err := pfxFile.Write(pfxData); err != nil {
		pfxFile.Close()
		os.Remove(pfxPath)
		return "", fmt.Errorf("failed to write PFX file: %w", err)
	}

	if err := pfxFile.Chmod(0600); err != nil {
		pfxFile.Close()
		os.Remove(pfxPath)
		return "", fmt.Errorf("failed to set PFX file permissions: %w", err)
	}

	if err := pfxFile.Close(); err != nil {
		os.Remove(pfxPath)
		return "", fmt.Errorf("failed to close PFX file: %w", err)
	}

	return pfxPath, nil
}

// CleanupPFX 清理临时 PFX 文件
func (c *Converter) CleanupPFX(pfxPath string) error {
	if pfxPath == "" {
		return nil
	}
	if err := os.Remove(pfxPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// parseCertificate 解析 PEM 格式证书
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return cert, nil
}

// parsePrivateKey 解析 PEM 格式私钥
func parsePrivateKey(keyPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return key, nil

	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key: %w", err)
		}
		return key, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// GeneratePassword 生成随机 PFX 密码
func GeneratePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	password := make([]byte, length)

	for i := range password {
		randomIndex := make([]byte, 1)
		if _, err := rand.Read(randomIndex); err != nil {
			return "", err
		}
		password[i] = charset[int(randomIndex[0])%len(charset)]
	}

	return string(password), nil
}

// ValidatePrivateKey 验证私钥是否与证书匹配
func ValidatePrivateKey(cert *x509.Certificate, key interface{}) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate public key type mismatch: expected RSA")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fmt.Errorf("private key does not match certificate")
		}

	default:
		return nil
	}

	return nil
}
