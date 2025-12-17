// Package csr 提供本地私钥与 CSR 生成
package csr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
)

// KeyOptions 私钥生成参数
type KeyOptions struct {
	Type  string // rsa|ecdsa
	Size  int    // 2048|4096
	Curve string // prime256v1|secp384r1|secp521r1
}

// CSROptions CSR 生成参数（支持 OV 字段）
type CSROptions struct {
	CommonName   string
	Organization string
	Country      string
	State        string
	Locality     string
	Email        string
}

// GenerateKeyAndCSR 生成私钥与 CSR（支持 RSA/ECDSA）
// 返回：keyPEM, csrPEM, csrHash(hex)
func GenerateKeyAndCSR(keyOpt KeyOptions, csrOpt CSROptions) (string, string, string, error) {
	// 默认 RSA 2048
	if keyOpt.Type == "" {
		keyOpt.Type = "rsa"
	}
	if keyOpt.Type == "rsa" && keyOpt.Size == 0 {
		keyOpt.Size = 2048
	}
	if keyOpt.Type == "ecdsa" && keyOpt.Curve == "" {
		keyOpt.Curve = "prime256v1"
	}

	var priv interface{}
	var err error
	switch keyOpt.Type {
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, keyOpt.Size)
	case "ecdsa":
		var curve elliptic.Curve
		switch keyOpt.Curve {
		case "prime256v1":
			curve = elliptic.P256()
		case "secp384r1":
			curve = elliptic.P384()
		case "secp521r1":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return "", "", "", err
	}

	subj := pkix.Name{CommonName: csrOpt.CommonName}
	if csrOpt.Organization != "" {
		subj.Organization = []string{csrOpt.Organization}
	}
	if csrOpt.Country != "" {
		subj.Country = []string{csrOpt.Country}
	}
	if csrOpt.State != "" {
		subj.Province = []string{csrOpt.State}
	}
	if csrOpt.Locality != "" {
		subj.Locality = []string{csrOpt.Locality}
	}

	var emailAddresses []string
	if csrOpt.Email != "" {
		emailAddresses = []string{csrOpt.Email}
	}

	tpl := x509.CertificateRequest{
		Subject:        subj,
		EmailAddresses: emailAddresses,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		return "", "", "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	var keyPEM []byte
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		b, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return "", "", "", e
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}

	sum := sha256.Sum256(csrPEM)
	return string(keyPEM), string(csrPEM), hex.EncodeToString(sum[:]), nil
}
