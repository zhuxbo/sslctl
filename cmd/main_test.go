package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
)

func TestResolveReleaseURL_FromConfig_TrimsAndSaves(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir error: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	cfg.ReleaseURL = "https://localhost/"
	releaseURL, err := resolveReleaseURL(cm, cfg)
	if err != nil {
		t.Fatalf("resolveReleaseURL error: %v", err)
	}
	if releaseURL != "https://localhost" {
		t.Fatalf("releaseURL = %q, want %q", releaseURL, "https://localhost")
	}

	// 确认已保存为去尾斜杠的值
	cfg2, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}
	if cfg2.ReleaseURL != "https://localhost" {
		t.Fatalf("saved releaseURL = %q, want %q", cfg2.ReleaseURL, "https://localhost")
	}
}

func TestResolveReleaseURL_NonTerminalError(t *testing.T) {
	cm, err := config.NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir error: %v", err)
	}

	cfg, err := cm.Load()
	if err != nil {
		t.Fatalf("Load config error: %v", err)
	}

	// 强制进入需要交互输入的分支
	cfg.ReleaseURL = ""

	// 使用管道替换 stdin，确保非交互终端
	oldStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = reader.Close()
		_ = writer.Close()
	})

	_, err = resolveReleaseURL(cm, cfg)
	if err == nil {
		t.Fatal("expected error for non-terminal stdin")
	}
	if !strings.Contains(err.Error(), "交互终端") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// generateTestCert 生成测试证书 PEM 文件
func generateTestCert(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseRollbackCert(t *testing.T) {
	tmpDir := t.TempDir()

	// 正常证书
	certPEM := generateTestCert(t, "example.com", time.Now().Add(365*24*time.Hour))
	certPath := filepath.Join(tmpDir, "cert.pem")
	_ = os.WriteFile(certPath, certPEM, 0644)

	cert, err := parseRollbackCert(certPath)
	if err != nil {
		t.Fatalf("解析有效证书失败: %v", err)
	}
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CN = %s, want example.com", cert.Subject.CommonName)
	}

	// 无效 PEM
	invalidPath := filepath.Join(tmpDir, "invalid.pem")
	_ = os.WriteFile(invalidPath, []byte("not a cert"), 0644)
	_, err = parseRollbackCert(invalidPath)
	if err == nil {
		t.Error("解析无效 PEM 应返回错误")
	}

	// 文件不存在
	_, err = parseRollbackCert(filepath.Join(tmpDir, "nonexistent.pem"))
	if err == nil {
		t.Error("文件不存在应返回错误")
	}
}

func TestCertHasSite(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{ServerName: "a.com"},
			{ServerName: "b.com"},
		},
	}

	if !certHasSite(cert, "a.com") {
		t.Error("应匹配 a.com")
	}
	if !certHasSite(cert, "b.com") {
		t.Error("应匹配 b.com")
	}
	if certHasSite(cert, "c.com") {
		t.Error("不应匹配 c.com")
	}
}
