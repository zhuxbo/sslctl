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

	key, err := GetPrivateKey(cert, "api-private-key", nil)
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
	key, err := GetPrivateKey(cert, "", log)
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

	_, err := GetPrivateKey(cert, "", nil)
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

	_, err := GetPrivateKey(cert, "", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestGetPrivateKeyFromBindings_APIProvided(t *testing.T) {
	bindings := []config.SiteBinding{
		{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/path/to/key.pem"}},
	}

	key, err := GetPrivateKeyFromBindings(bindings, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "api-key" {
		t.Errorf("key = %q, want api-key", key)
	}
}

func TestGetPrivateKeyFromBindings_LocalFallback(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	keyContent := "-----BEGIN PRIVATE KEY-----\nlocal\n-----END PRIVATE KEY-----"

	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	bindings := []config.SiteBinding{
		{Enabled: true, Paths: config.BindingPaths{PrivateKey: keyPath}},
	}

	key, err := GetPrivateKeyFromBindings(bindings, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != keyContent {
		t.Errorf("key content mismatch")
	}
}

func TestGetPrivateKeyFromBindings_NoBindings(t *testing.T) {
	_, err := GetPrivateKeyFromBindings(nil, "")
	if err == nil {
		t.Error("expected error for nil bindings")
	}
}

func TestPickKeyPathFromBindings(t *testing.T) {
	tests := []struct {
		name     string
		bindings []config.SiteBinding
		want     string
	}{
		{
			name:     "空绑定",
			bindings: nil,
			want:     "",
		},
		{
			name: "优先启用的",
			bindings: []config.SiteBinding{
				{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/disabled.pem"}},
				{Enabled: true, Paths: config.BindingPaths{PrivateKey: "/enabled.pem"}},
			},
			want: "/enabled.pem",
		},
		{
			name: "全部禁用回退第一个",
			bindings: []config.SiteBinding{
				{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/first.pem"}},
				{Enabled: false, Paths: config.BindingPaths{PrivateKey: "/second.pem"}},
			},
			want: "/first.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickKeyPathFromBindings(tt.bindings)
			if got != tt.want {
				t.Errorf("pickKeyPathFromBindings() = %q, want %q", got, tt.want)
			}
		})
	}
}
