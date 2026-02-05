package upgrade

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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
