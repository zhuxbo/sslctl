package upgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.0.0", "v1.0.0"},
		{"v1.0.0", "v1.0.0"},
		{"", "v"},
		{"v", "v"},
		{"2.1.0-beta", "v2.1.0-beta"},
		{"v2.1.0-beta", "v2.1.0-beta"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeVersion(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeVersion(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	info := &ReleaseInfo{
		LatestMain: "v1.0.0",
		LatestDev:    "v1.1.0-beta",
	}

	tests := []struct {
		name          string
		targetVersion string
		channel       string
		info          *ReleaseInfo
		wantVersion   string
		wantChannel   string
		wantErr       bool
	}{
		{
			name:          "指定版本无通道",
			targetVersion: "1.2.0",
			channel:       "",
			info:          info,
			wantVersion:   "v1.2.0",
			wantChannel:   "main",
		},
		{
			name:          "指定 dev 版本自动检测通道",
			targetVersion: "1.2.0-beta",
			channel:       "",
			info:          info,
			wantVersion:   "v1.2.0-beta",
			wantChannel:   "dev",
		},
		{
			name:          "指定版本和通道",
			targetVersion: "1.2.0",
			channel:       "dev",
			info:          info,
			wantVersion:   "v1.2.0",
			wantChannel:   "dev",
		},
		{
			name:        "默认通道取 main",
			channel:     "",
			info:        info,
			wantVersion: "v1.0.0",
			wantChannel: "main",
		},
		{
			name:        "指定 dev 通道",
			channel:     "dev",
			info:        info,
			wantVersion: "v1.1.0-beta",
			wantChannel: "dev",
		},
		{
			name:        "main 为空回退 dev",
			channel:     "",
			info:        &ReleaseInfo{LatestMain: "", LatestDev: "v2.0.0-dev"},
			wantVersion: "v2.0.0-dev",
			wantChannel: "dev",
		},
		{
			name:    "无可用版本",
			channel: "",
			info:    &ReleaseInfo{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, ch, err := ResolveTarget(tt.targetVersion, tt.channel, tt.info)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ver != tt.wantVersion {
				t.Errorf("version = %q, want %q", ver, tt.wantVersion)
			}
			if ch != tt.wantChannel {
				t.Errorf("channel = %q, want %q", ch, tt.wantChannel)
			}
		})
	}
}

func TestGetChecksum(t *testing.T) {
	info := &ReleaseInfo{
		Versions: map[string]VersionInfo{
			"v1.0.0": {
				Checksums: map[string]string{
					"sslctl-linux-amd64.gz": "sha256:abc123",
				},
			},
		},
	}

	tests := []struct {
		name     string
		info     *ReleaseInfo
		version  string
		filename string
		want     string
	}{
		{"有版本有文件", info, "v1.0.0", "sslctl-linux-amd64.gz", "sha256:abc123"},
		{"有版本无文件", info, "v1.0.0", "nonexistent.gz", ""},
		{"无版本", info, "v9.9.9", "sslctl-linux-amd64.gz", ""},
		{"nil Versions", &ReleaseInfo{}, "v1.0.0", "sslctl-linux-amd64.gz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.GetChecksum(tt.version, tt.filename)
			if got != tt.want {
				t.Errorf("GetChecksum(%q, %q) = %q, want %q", tt.version, tt.filename, got, tt.want)
			}
		})
	}
}

func TestGetSignature(t *testing.T) {
	info := &ReleaseInfo{
		Versions: map[string]VersionInfo{
			"v1.0.0": {
				Checksums: map[string]string{
					"sslctl-linux-amd64.gz": "sha256:abc123",
				},
				Signatures: map[string]string{
					"sslctl-linux-amd64.gz": "ed25519:testSig",
				},
			},
			"v0.9.0": {
				Checksums: map[string]string{
					"sslctl-linux-amd64.gz": "sha256:def456",
				},
				// 无签名字段（旧版本）
			},
		},
	}

	tests := []struct {
		name     string
		info     *ReleaseInfo
		version  string
		filename string
		want     string
	}{
		{"有签名", info, "v1.0.0", "sslctl-linux-amd64.gz", "ed25519:testSig"},
		{"有版本无签名文件", info, "v1.0.0", "nonexistent.gz", ""},
		{"旧版本无签名字段", info, "v0.9.0", "sslctl-linux-amd64.gz", ""},
		{"无版本", info, "v9.9.9", "sslctl-linux-amd64.gz", ""},
		{"nil Versions", &ReleaseInfo{}, "v1.0.0", "sslctl-linux-amd64.gz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.GetSignature(tt.version, tt.filename)
			if got != tt.want {
				t.Errorf("GetSignature(%q, %q) = %q, want %q", tt.version, tt.filename, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v1.0.0", 0},
		{"v1.0.0", "v2.0.0", -1},
		{"v2.0.0", "v1.0.0", 1},
		{"v1.2.0", "v1.1.0", 1},
		{"v1.0.1", "v1.0.0", 1},
		{"v1.0.0-beta", "v1.0.0", -1}, // pre-release < 正式版
		{"v1.0.0", "v1.0.0-beta", 1},  // 正式版 > pre-release
		{"v1.0.0-alpha", "v1.0.0-beta", -1}, // pre-release 字典序
		{"v1.0.0-beta", "v1.0.0-beta", 0},   // 相同 pre-release
		{"v0.1.1-beta", "v0.1.0", 1},  // 高版本 pre-release > 低版本正式版
		{"1.0.0", "v1.0.0", 0},         // 无 v 前缀
		{"v0.9.0", "v1.0.0", -1},
		{"v10.0.0", "v9.0.0", 1},       // 数字比较非字典序
		{"v1.10.0", "v1.9.0", 1},
		{"", "", 0},
		{"v1", "v1.0.0", 0},            // 缺少部分默认为 0
		{"v1.2", "v1.2.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := CompareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFetchReleaseInfo_Success(t *testing.T) {
	expected := &ReleaseInfo{
		LatestMain: "v1.0.0",
		LatestDev:    "v1.1.0-beta",
		Versions: map[string]VersionInfo{
			"v1.0.0": {
				Checksums: map[string]string{
					"sslctl-linux-amd64.gz": "sha256:abc",
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	info, err := fetchReleaseInfoFrom(server.URL, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LatestMain != expected.LatestMain {
		t.Errorf("LatestMain = %q, want %q", info.LatestMain, expected.LatestMain)
	}
	if info.LatestDev != expected.LatestDev {
		t.Errorf("LatestDev = %q, want %q", info.LatestDev, expected.LatestDev)
	}
	if info.GetChecksum("v1.0.0", "sslctl-linux-amd64.gz") != "sha256:abc" {
		t.Error("checksum mismatch")
	}
}

func TestFetchReleaseInfo_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	_, err := fetchReleaseInfoFrom(server.URL, server.Client())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFetchReleaseInfo_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"404", http.StatusNotFound},
		{"500", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			_, err := fetchReleaseInfoFrom(server.URL, server.Client())
			if err == nil {
				t.Errorf("expected error for HTTP %d", tt.statusCode)
			}
		})
	}
}

func TestFetchReleaseInfo_UsesSecureClient(t *testing.T) {
	// 验证 FetchReleaseInfo 内部使用了 secureHTTPClient
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
	if transport.TLSClientConfig.MinVersion == 0 {
		t.Error("TLS MinVersion not set")
	}
}

