// Package testutil 测试辅助工具
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TempDir 创建临时目录辅助结构
type TempDir struct {
	t   *testing.T
	dir string
}

// NewTempDir 创建临时目录
func NewTempDir(t *testing.T) *TempDir {
	t.Helper()
	return &TempDir{
		t:   t,
		dir: t.TempDir(),
	}
}

// Path 返回临时目录路径
func (td *TempDir) Path() string {
	return td.dir
}

// Join 拼接路径
func (td *TempDir) Join(elem ...string) string {
	return filepath.Join(append([]string{td.dir}, elem...)...)
}

// MkdirAll 创建子目录
func (td *TempDir) MkdirAll(path string, perm os.FileMode) string {
	td.t.Helper()
	fullPath := td.Join(path)
	if err := os.MkdirAll(fullPath, perm); err != nil {
		td.t.Fatalf("failed to create directory %s: %v", fullPath, err)
	}
	return fullPath
}

// WriteFile 写入文件
func (td *TempDir) WriteFile(path string, content []byte, perm os.FileMode) string {
	td.t.Helper()
	fullPath := td.Join(path)

	// 确保父目录存在
	parent := filepath.Dir(fullPath)
	if err := os.MkdirAll(parent, 0755); err != nil {
		td.t.Fatalf("failed to create parent directory: %v", err)
	}

	if err := os.WriteFile(fullPath, content, perm); err != nil {
		td.t.Fatalf("failed to write file %s: %v", fullPath, err)
	}
	return fullPath
}

// WriteString 写入字符串到文件
func (td *TempDir) WriteString(path, content string, perm os.FileMode) string {
	return td.WriteFile(path, []byte(content), perm)
}

// ReadFile 读取文件内容
func (td *TempDir) ReadFile(path string) []byte {
	td.t.Helper()
	fullPath := td.Join(path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		td.t.Fatalf("failed to read file %s: %v", fullPath, err)
	}
	return data
}

// Exists 检查文件或目录是否存在
func (td *TempDir) Exists(path string) bool {
	fullPath := td.Join(path)
	_, err := os.Stat(fullPath)
	return err == nil
}

// IsDir 检查是否为目录
func (td *TempDir) IsDir(path string) bool {
	fullPath := td.Join(path)
	info, err := os.Stat(fullPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Remove 删除文件或目录
func (td *TempDir) Remove(path string) {
	td.t.Helper()
	fullPath := td.Join(path)
	if err := os.RemoveAll(fullPath); err != nil {
		td.t.Fatalf("failed to remove %s: %v", fullPath, err)
	}
}

// SetupCertFiles 创建测试用证书和私钥文件
func (td *TempDir) SetupCertFiles(subdir string) (certPath, keyPath string) {
	td.t.Helper()
	certContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpAtest123
-----END CERTIFICATE-----`
	keyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKtest123
-----END RSA PRIVATE KEY-----`

	certPath = td.WriteString(filepath.Join(subdir, "cert.pem"), certContent, 0644)
	keyPath = td.WriteString(filepath.Join(subdir, "key.pem"), keyContent, 0600)
	return
}

// SetupCertFilesWithChain 创建包含证书链的测试文件
func (td *TempDir) SetupCertFilesWithChain(subdir string) (certPath, keyPath, chainPath string) {
	td.t.Helper()
	certPath, keyPath = td.SetupCertFiles(subdir)
	chainContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpAchain123
-----END CERTIFICATE-----`
	chainPath = td.WriteString(filepath.Join(subdir, "chain.pem"), chainContent, 0644)
	return
}

// SetupNginxConfig 创建测试用 Nginx 配置文件
func (td *TempDir) SetupNginxConfig(subdir, content string) string {
	td.t.Helper()
	return td.WriteString(filepath.Join(subdir, "nginx.conf"), content, 0644)
}

// SetupApacheConfig 创建测试用 Apache 配置文件
func (td *TempDir) SetupApacheConfig(subdir, content string) string {
	td.t.Helper()
	return td.WriteString(filepath.Join(subdir, "apache.conf"), content, 0644)
}
