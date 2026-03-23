package certops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

func TestPlaceValidationFiles(t *testing.T) {
	log := logger.NewNopLogger()
	webroot := t.TempDir()

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{
				Enabled: true,
				Paths:   config.BindingPaths{Webroot: webroot},
			},
		},
	}

	file := &fetcher.FileChallenge{
		Path:    "/.well-known/pki-validation/fileauth.txt",
		Content: "test-validation-content-12345",
	}

	placed := placeValidationFiles(cert, file, log)
	if len(placed) != 1 {
		t.Fatalf("期望写入 1 个文件，实际 %d", len(placed))
	}

	// 验证文件内容
	content, err := os.ReadFile(placed[0])
	if err != nil {
		t.Fatalf("读取验证文件失败: %v", err)
	}
	if string(content) != file.Content {
		t.Errorf("文件内容 = %q, 期望 %q", string(content), file.Content)
	}

	// 验证路径在 webroot 下
	expected := filepath.Join(webroot, ".well-known", "pki-validation", "fileauth.txt")
	if placed[0] != expected {
		t.Errorf("路径 = %s, 期望 %s", placed[0], expected)
	}
}

func TestPlaceValidationFiles_NoWebroot(t *testing.T) {
	log := logger.NewNopLogger()

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{}}, // 无 webroot
		},
	}

	file := &fetcher.FileChallenge{
		Path:    "/.well-known/pki-validation/test.txt",
		Content: "content",
	}

	placed := placeValidationFiles(cert, file, log)
	if len(placed) != 0 {
		t.Errorf("无 webroot 时不应写入文件，实际写入 %d 个", len(placed))
	}
}

func TestPlaceValidationFiles_Dedup(t *testing.T) {
	log := logger.NewNopLogger()
	webroot := t.TempDir()

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{Webroot: webroot}},
			{Enabled: true, Paths: config.BindingPaths{Webroot: webroot}}, // 重复
		},
	}

	file := &fetcher.FileChallenge{
		Path:    "/.well-known/pki-validation/test.txt",
		Content: "content",
	}

	placed := placeValidationFiles(cert, file, log)
	if len(placed) != 1 {
		t.Errorf("重复 webroot 应只写入 1 次，实际 %d", len(placed))
	}
}

func TestPlaceValidationFiles_PathTraversal(t *testing.T) {
	log := logger.NewNopLogger()
	webroot := t.TempDir()

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{Webroot: webroot}},
		},
	}

	file := &fetcher.FileChallenge{
		Path:    "/../../etc/passwd",
		Content: "malicious",
	}

	placed := placeValidationFiles(cert, file, log)
	if len(placed) != 0 {
		t.Errorf("路径穿越攻击应被阻止，实际写入 %d 个文件", len(placed))
	}
}

func TestPlaceValidationFiles_NilFile(t *testing.T) {
	log := logger.NewNopLogger()

	cert := &config.CertConfig{CertName: "test"}
	placed := placeValidationFiles(cert, nil, log)
	if placed != nil {
		t.Errorf("nil file 应返回 nil")
	}
}

func TestPlaceValidationFiles_EmptyContent(t *testing.T) {
	log := logger.NewNopLogger()

	cert := &config.CertConfig{CertName: "test"}
	file := &fetcher.FileChallenge{Path: "/test.txt", Content: ""}
	placed := placeValidationFiles(cert, file, log)
	if placed != nil {
		t.Errorf("空 content 应返回 nil")
	}
}

func TestCleanupValidationFiles(t *testing.T) {
	log := logger.NewNopLogger()
	webroot := t.TempDir()

	// 创建验证文件
	validationDir := filepath.Join(webroot, ".well-known", "pki-validation")
	if err := os.MkdirAll(validationDir, 0755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(validationDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	cleanupValidationFiles([]string{filePath}, log)

	// 验证文件已删除
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("验证文件应已被删除")
	}

	// 验证空目录已删除
	if _, err := os.Stat(validationDir); !os.IsNotExist(err) {
		t.Error("空的 pki-validation 目录应已被删除")
	}
}

func TestCleanupValidationFiles_NonExistent(t *testing.T) {
	log := logger.NewNopLogger()
	// 不应 panic
	cleanupValidationFiles([]string{"/nonexistent/path/file.txt"}, log)
}

func TestPlaceValidationFiles_DisabledBinding(t *testing.T) {
	log := logger.NewNopLogger()
	webroot := t.TempDir()

	cert := &config.CertConfig{
		CertName: "test-cert",
		Bindings: []config.SiteBinding{
			{Enabled: false, Paths: config.BindingPaths{Webroot: webroot}}, // 禁用
		},
	}

	file := &fetcher.FileChallenge{
		Path:    "/.well-known/pki-validation/test.txt",
		Content: "content",
	}

	placed := placeValidationFiles(cert, file, log)
	if len(placed) != 0 {
		t.Errorf("禁用的绑定不应写入文件，实际写入 %d 个", len(placed))
	}
}

func TestCollectWebroots(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{Webroot: "/var/www/a"}},
			{Enabled: true, Paths: config.BindingPaths{Webroot: "/var/www/b"}},
			{Enabled: true, Paths: config.BindingPaths{Webroot: "/var/www/a"}}, // 重复
			{Enabled: false, Paths: config.BindingPaths{Webroot: "/var/www/c"}}, // 禁用
			{Enabled: true, Paths: config.BindingPaths{}},                       // 空 webroot
		},
	}

	webroots := collectWebroots(cert)
	if len(webroots) != 2 {
		t.Errorf("期望 2 个 webroot，实际 %d: %v", len(webroots), webroots)
	}
}
