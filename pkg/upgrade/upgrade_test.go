package upgrade

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecute_AlreadyLatest(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false for same version")
	}
}

func TestExecute_CheckOnly(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
		"dev": &ChannelInfo{
			Latest: "2.1.0-beta",
			Versions: []VersionInfo{
				{Version: "2.1.0-beta", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:def"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
	if result.ToVersion != "v2.0.0" {
		t.Errorf("ToVersion = %q, want v2.0.0", result.ToVersion)
	}
}

func TestExecute_Force(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
		CheckOnly:      true,
		Force:          true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true with Force=true")
	}
}

func TestExecute_NoDowngrade(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "0.1.0",
			Versions: []VersionInfo{
				{Version: "0.1.0"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v0.1.1-beta",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false: should not downgrade from v0.1.1-beta to v0.1.0")
	}
}

func TestExecute_PreReleaseUpgrade(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "0.1.1",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v0.1.1-beta",
		Channel:        "main",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true: v0.1.1-beta should upgrade to v0.1.1")
	}
}

func TestExecute_FetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Error("expected error for server error")
	}
}

// signAndChecksum 为 gzData 生成签名和校验和
func signAndChecksum(t *testing.T, priv ed25519.PrivateKey, keyID string, gzData []byte) (string, string) {
	t.Helper()
	sig := ed25519.Sign(priv, gzData)
	sigStr := fmt.Sprintf("ed25519:%s:%s", keyID, base64.StdEncoding.EncodeToString(sig))
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])
	return sigStr, checksum
}

func TestExecute_SignatureKeyNotFound_ReinstallHint(t *testing.T) {
	saveAndRestoreKeys(t)
	pub1, _ := generateTestKeyPair(t)
	_, priv2 := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	gzData := makeGzipData(t, []byte("new binary"))
	// 用 key-2 签名（不在密钥环中）
	sig := ed25519.Sign(priv2, gzData)
	sigStr := "ed25519:key-2:" + base64.StdEncoding.EncodeToString(sig)
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{filename: checksum}, Signature: sigStr},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "签名密钥已更新") {
		t.Errorf("error should mention key rotation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}

func TestDownloadVerifyInstall_ErrNoPublicKeys_ReinstallHint(t *testing.T) {
	saveAndRestoreKeys(t)
	releasePublicKeys = map[string]ed25519.PublicKey{}

	_, priv := generateTestKeyPair(t)
	gzData := makeGzipData(t, []byte("new binary"))
	sigStr, checksum := signAndChecksum(t, priv, "key-1", gzData)

	filename := GetDownloadFilename()
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "2.0.0",
			Versions: []VersionInfo{
				{Version: "2.0.0", Checksums: map[string]string{filename: checksum}, Signature: sigStr},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(index)
			return
		}
		_, _ = w.Write(gzData)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "main",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for no public keys")
	}
	if !strings.Contains(err.Error(), "签名密钥已更新") {
		t.Errorf("error should mention key update, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}
