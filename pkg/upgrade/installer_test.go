package upgrade

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyChecksum_Valid(t *testing.T) {
	data := []byte("test data")
	hash := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(hash[:])

	if err := VerifyChecksum(data, expected); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	data := []byte("test data")
	if err := VerifyChecksum(data, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("expected error for checksum mismatch")
	}
}

func TestVerifyChecksum_Empty(t *testing.T) {
	if err := VerifyChecksum([]byte("data"), ""); err != nil {
		t.Errorf("expected nil for empty checksum, got: %v", err)
	}
}

func TestGetBinaryPath(t *testing.T) {
	path := GetBinaryPath()
	if runtime.GOOS == "windows" {
		if filepath.Ext(path) != ".exe" && path != "/usr/local/bin/sslctl" {
			t.Logf("Windows path: %s", path)
		}
	} else {
		if path != "/usr/local/bin/sslctl" {
			t.Errorf("path = %q, want /usr/local/bin/sslctl", path)
		}
	}
}

func TestGetDownloadFilename(t *testing.T) {
	filename := GetDownloadFilename()
	expectedPrefix := fmt.Sprintf("sslctl-%s-%s", runtime.GOOS, runtime.GOARCH)

	if runtime.GOOS == "windows" {
		expected := expectedPrefix + ".exe.gz"
		if filename != expected {
			t.Errorf("filename = %q, want %q", filename, expected)
		}
	} else {
		expected := expectedPrefix + ".gz"
		if filename != expected {
			t.Errorf("filename = %q, want %q", filename, expected)
		}
	}
}

func TestGetDownloadURL(t *testing.T) {
	url := GetDownloadURL("stable", "v1.0.0")
	filename := GetDownloadFilename()
	expected := ReleaseURL + "/stable/v1.0.0/" + filename
	if url != expected {
		t.Errorf("url = %q, want %q", url, expected)
	}
}

// makeGzipData 创建 gzip 压缩的测试数据
func makeGzipData(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(content); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestInstallTo_Success(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sslctl-test")
	content := []byte("#!/bin/sh\necho hello")
	gzData := makeGzipData(t, content)

	result, err := installTo(gzData, binPath)
	if err != nil {
		t.Fatalf("installTo: %v", err)
	}
	if result != binPath {
		t.Errorf("result = %q, want %q", result, binPath)
	}

	// 验证文件内容
	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read installed file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}

	// 验证权限
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("file is not executable")
	}
}

func TestInstallTo_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "subdir", "sslctl-test")
	content := []byte("binary")
	gzData := makeGzipData(t, content)

	result, err := installTo(gzData, binPath)
	if err != nil {
		t.Fatalf("installTo: %v", err)
	}
	if result != binPath {
		t.Errorf("result = %q, want %q", result, binPath)
	}

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch")
	}
}

func TestInstallTo_InvalidGzip(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sslctl-test")

	_, err := installTo([]byte("not gzip data"), binPath)
	if err == nil {
		t.Error("expected error for invalid gzip")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "src")
	dstPath := filepath.Join(tmpDir, "dst")

	content := []byte("test content")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch")
	}

	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("file is not executable after copy")
	}
}

func TestCopyFile_SrcNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	err := copyFile(filepath.Join(tmpDir, "nonexistent"), filepath.Join(tmpDir, "dst"))
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

func TestDownloadBinaryWithClient_Success(t *testing.T) {
	gzData := makeGzipData(t, []byte("binary data"))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzData)
	}))
	defer server.Close()

	data, err := downloadBinaryWithClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(data, gzData) {
		t.Error("data mismatch")
	}
}

func TestDownloadBinaryWithClient_HTTPSOnly(t *testing.T) {
	_, err := downloadBinaryWithClient("http://example.com/file.gz", http.DefaultClient)
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "仅允许 HTTPS") {
		t.Errorf("error message should mention HTTPS: %v", err)
	}
}

func TestDownloadBinaryWithClient_HTTPError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := downloadBinaryWithClient(server.URL, server.Client())
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error message should contain status code: %v", err)
	}
}

func TestDownloadBinaryWithClient_SizeLimit(t *testing.T) {
	// 创建一个返回超大数据的服务器
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 写入 maxDownloadSize + 1 字节的零数据
		data := make([]byte, maxDownloadSize+1)
		w.Write(data)
	}))
	defer server.Close()

	_, err := downloadBinaryWithClient(server.URL, server.Client())
	if err == nil {
		t.Error("expected error for oversized download")
	}
}

func TestDownloadBinaryWithClient_404(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := downloadBinaryWithClient(server.URL, server.Client())
	if err == nil {
		t.Error("expected error for HTTP 404")
	}
}

func TestDownloadBinary_HTTPSOnly(t *testing.T) {
	_, err := DownloadBinary("http://example.com/file.gz")
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
}

func TestSecureHTTPClient(t *testing.T) {
	client := secureHTTPClient()

	if client.Timeout != downloadTimeout {
		t.Errorf("timeout = %v, want %v", client.Timeout, downloadTimeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}

	// TLS 1.2 = 0x0303
	if transport.TLSClientConfig.MinVersion < 0x0303 {
		t.Errorf("MinVersion = %x, want >= 0x0303 (TLS 1.2)", transport.TLSClientConfig.MinVersion)
	}
}

func TestMaxDownloadSizeConstant(t *testing.T) {
	// 验证大小限制常量值为 100MB
	expected := int64(100 * 1024 * 1024)
	if maxDownloadSize != expected {
		t.Errorf("maxDownloadSize = %d, want %d", maxDownloadSize, expected)
	}
}

func TestDownloadBinaryWithClient_EmptyBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// 空 body
	}))
	defer server.Close()

	data, err := downloadBinaryWithClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestDownloadBinaryWithClient_ExactLimitSize(t *testing.T) {
	// LimitReader 最多返回 maxDownloadSize 字节
	// 如果恰好等于 maxDownloadSize，应该报错
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 写入恰好 maxDownloadSize 的数据
		// 使用 io.CopyN 避免内存分配
		w.Header().Set("Content-Length", fmt.Sprintf("%d", maxDownloadSize))
		_, _ = io.CopyN(w, &zeroReader{}, maxDownloadSize)
	}))
	defer server.Close()

	_, err := downloadBinaryWithClient(server.URL, server.Client())
	if err == nil {
		t.Error("expected error for data at exact size limit")
	}
}

// zeroReader 返回零字节的读取器
type zeroReader struct{}

func (z *zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// generateTestKeyPair 生成用于测试的 Ed25519 密钥对
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// saveAndRestoreKeys 保存并在测试结束时恢复密钥环
func saveAndRestoreKeys(t *testing.T) {
	t.Helper()
	oldKeys := releasePublicKeys
	t.Cleanup(func() { releasePublicKeys = oldKeys })
}

// --- 旧格式兼容测试（ed25519:<base64>）---

func TestVerifySignature_LegacyFormat_Valid(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv, data)
	sigStr := "ed25519:" + base64.StdEncoding.EncodeToString(sig)

	if err := VerifySignature(data, sigStr); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifySignature_LegacyFormat_Invalid(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv, data)
	sigStr := "ed25519:" + base64.StdEncoding.EncodeToString(sig)

	// 篡改数据
	tamperedData := []byte("tampered binary data")
	if err := VerifySignature(tamperedData, sigStr); err == nil {
		t.Error("expected error for tampered data")
	}
}

func TestVerifySignature_LegacyFormat_WrongKey(t *testing.T) {
	pub1, _ := generateTestKeyPair(t)
	_, priv2 := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv2, data) // 用错误的私钥签名
	sigStr := "ed25519:" + base64.StdEncoding.EncodeToString(sig)

	if err := VerifySignature(data, sigStr); err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestVerifySignature_LegacyFormat_MultipleKeys(t *testing.T) {
	pub1, _ := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{
		"key-1": pub1,
		"key-2": pub2,
	})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv2, data) // 用 key-2 的私钥签名
	sigStr := "ed25519:" + base64.StdEncoding.EncodeToString(sig)

	// 旧格式遍历所有公钥，key-2 应该匹配
	if err := VerifySignature(data, sigStr); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- 新格式测试（ed25519:<key_id>:<base64>）---

func TestVerifySignature_NewFormat_Valid(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv, data)
	sigStr := "ed25519:key-1:" + base64.StdEncoding.EncodeToString(sig)

	if err := VerifySignature(data, sigStr); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifySignature_NewFormat_KeyNotFound(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	_, priv2 := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv2, data)
	sigStr := "ed25519:key-2:" + base64.StdEncoding.EncodeToString(sig)

	err := VerifySignature(data, sigStr)
	if err == nil {
		t.Fatal("expected error for unknown key ID")
	}

	var keyNotFound *ErrKeyNotFound
	if !errors.As(err, &keyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got: %T: %v", err, err)
	}
	if keyNotFound.KeyID != "key-2" {
		t.Errorf("KeyID = %q, want %q", keyNotFound.KeyID, "key-2")
	}
}

func TestVerifySignature_NewFormat_TamperedData(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	data := []byte("test binary data")
	sig := ed25519.Sign(priv, data)
	sigStr := "ed25519:key-1:" + base64.StdEncoding.EncodeToString(sig)

	// 验证篡改数据时返回"文件可能被篡改"而不是 ErrKeyNotFound
	tamperedData := []byte("tampered binary data")
	err := VerifySignature(tamperedData, sigStr)
	if err == nil {
		t.Fatal("expected error for tampered data")
	}
	if strings.Contains(err.Error(), "密钥环") {
		t.Errorf("should not be ErrKeyNotFound for tampered data: %v", err)
	}
	if !strings.Contains(err.Error(), "篡改") {
		t.Errorf("error should mention tamper: %v", err)
	}
}

func TestVerifySignature_NewFormat_MultipleKeys(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{
		"key-1": pub1,
		"key-2": pub2,
	})

	data := []byte("test binary data")

	// key-1 签名
	sig1 := ed25519.Sign(priv1, data)
	sigStr1 := "ed25519:key-1:" + base64.StdEncoding.EncodeToString(sig1)
	if err := VerifySignature(data, sigStr1); err != nil {
		t.Errorf("key-1 verification failed: %v", err)
	}

	// key-2 签名
	sig2 := ed25519.Sign(priv2, data)
	sigStr2 := "ed25519:key-2:" + base64.StdEncoding.EncodeToString(sig2)
	if err := VerifySignature(data, sigStr2); err != nil {
		t.Errorf("key-2 verification failed: %v", err)
	}
}

// --- 通用测试 ---

func TestVerifySignature_EmptySignature_NoKeys(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	// 空密钥环 + 空签名 → 兼容旧版本，跳过验证
	if err := VerifySignature([]byte("data"), ""); err != nil {
		t.Errorf("expected nil for empty signature with empty keyring, got: %v", err)
	}
}

func TestVerifySignature_EmptySignature_WithKeys(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	// 已配置公钥 + 空签名 → 拒绝（防止降级攻击）
	err := VerifySignature([]byte("data"), "")
	if err == nil {
		t.Error("expected error for empty signature with configured keys")
	}
	if !strings.Contains(err.Error(), "未提供数字签名") {
		t.Errorf("error should mention missing signature, got: %v", err)
	}
}

func TestVerifySignature_NoPublicKeys_EmptySignature(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	// 空密钥环 + 空签名 → 应通过（兼容旧版本）
	if err := VerifySignature([]byte("data"), ""); err != nil {
		t.Errorf("expected nil for empty signature with empty keyring, got: %v", err)
	}
}

func TestVerifySignature_HasPublicKeys_EmptySignature(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	// 已配置公钥 + 空签名 → 拒绝安装（防止降级攻击）
	err := VerifySignature([]byte("data"), "")
	if err == nil {
		t.Fatal("expected error for empty signature when keys are configured")
	}
	if !strings.Contains(err.Error(), "未提供数字签名") {
		t.Errorf("error should mention missing signature, got: %v", err)
	}
}

func TestVerifySignature_NoPublicKeys(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	// 密钥环为空但签名非空时应返回错误
	err := VerifySignature([]byte("data"), "ed25519:AAAA")
	if err == nil {
		t.Error("expected error when no public keys but signature provided")
	}
	var noKeys *ErrNoPublicKeys
	if !errors.As(err, &noKeys) {
		t.Errorf("expected ErrNoPublicKeys, got: %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "公钥") {
		t.Errorf("error should mention public keys, got: %v", err)
	}
}

func TestVerifySignature_InvalidFormat(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	if err := VerifySignature([]byte("data"), "rsa:AAAA"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestVerifySignature_InvalidBase64(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	if err := VerifySignature([]byte("data"), "ed25519:not-valid-base64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestVerifySignature_WrongSignatureLength(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	// 签名长度不正确（旧格式）
	shortSig := base64.StdEncoding.EncodeToString([]byte("too short"))
	if err := VerifySignature([]byte("data"), "ed25519:"+shortSig); err == nil {
		t.Error("expected error for wrong signature length")
	}
}

func TestVerifySignature_NewFormat_InvalidBase64(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	if err := VerifySignature([]byte("data"), "ed25519:key-1:not-valid!!!"); err == nil {
		t.Error("expected error for invalid base64 in new format")
	}
}

func TestVerifySignature_NewFormat_WrongSignatureLength(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	saveAndRestoreKeys(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub})

	shortSig := base64.StdEncoding.EncodeToString([]byte("short"))
	if err := VerifySignature([]byte("data"), "ed25519:key-1:"+shortSig); err == nil {
		t.Error("expected error for wrong signature length in new format")
	}
}

// --- ErrKeyNotFound 测试 ---

func TestErrKeyNotFound_Error(t *testing.T) {
	err := &ErrKeyNotFound{KeyID: "key-99"}
	msg := err.Error()
	if !strings.Contains(msg, "key-99") {
		t.Errorf("error message should contain key ID: %s", msg)
	}
	if !strings.Contains(msg, "密钥环") {
		t.Errorf("error message should mention keyring: %s", msg)
	}
}

func TestErrKeyNotFound_ErrorsAs(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &ErrKeyNotFound{KeyID: "key-1"})
	var keyNotFound *ErrKeyNotFound
	if !errors.As(err, &keyNotFound) {
		t.Error("errors.As should match ErrKeyNotFound")
	}
}

// --- AddReleasePublicKey 测试 ---

func TestAddReleasePublicKey(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	pub, _ := generateTestKeyPair(t)
	AddReleasePublicKey("test-key", pub)

	if _, ok := releasePublicKeys["test-key"]; !ok {
		t.Error("key not added to keyring")
	}
}
