package certops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/logger"
)

func TestGetPrivateKey_APIProvided(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/key.pem"}},
		},
	}

	key, err := GetPrivateKey(t.Context(), cert, "api-private-key", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "api-private-key" {
		t.Errorf("key = %q, want api-private-key", key)
	}
}

func TestGetPrivateKey_LocalFallback(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	keyContent := "-----BEGIN PRIVATE KEY-----\nlocal-key\n-----END PRIVATE KEY-----"

	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{PrivateKey: keyPath}},
		},
	}

	log := logger.NewNopLogger()
	key, err := GetPrivateKey(t.Context(), cert, "", log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != keyContent {
		t.Errorf("key content mismatch")
	}
}

func TestGetPrivateKey_NoKeyPath(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{},
	}

	_, err := GetPrivateKey(t.Context(), cert, "", nil)
	if err == nil {
		t.Error("expected error for no key path")
	}
}

func TestGetPrivateKey_FileNotExist(t *testing.T) {
	cert := &config.CertConfig{
		Bindings: []config.SiteBinding{
			{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/nonexistent/key.pem"}},
		},
	}

	_, err := GetPrivateKey(t.Context(), cert, "", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// GetPrivateKeyFromBindings/pickKeyPathFromBindings 已被 GetPrivateKeyForCert 取代
// （pending 感知，配对校验），对应测试见 renew_pending_rescue_test.go
