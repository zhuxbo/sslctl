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
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
		"dev": &ChannelInfo{
			Latest: "1.1.0-beta",
			Versions: []VersionInfo{
				{Version: "1.1.0-beta", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:def"}},
			},
		},
	}

	tests := []struct {
		name          string
		targetVersion string
		channel       string
		index         ReleaseIndex
		wantVersion   string
		wantChannel   string
		wantErr       bool
	}{
		{
			name:          "指定版本无通道",
			targetVersion: "1.2.0",
			channel:       "",
			index:         index,
			wantVersion:   "v1.2.0",
			wantChannel:   "main",
		},
		{
			name:          "指定 dev 版本自动检测通道",
			targetVersion: "1.2.0-beta",
			channel:       "",
			index:         index,
			wantVersion:   "v1.2.0-beta",
			wantChannel:   "dev",
		},
		{
			name:          "指定版本和通道",
			targetVersion: "1.2.0",
			channel:       "dev",
			index:         index,
			wantVersion:   "v1.2.0",
			wantChannel:   "dev",
		},
		{
			name:        "默认通道取 main Latest",
			channel:     "",
			index:       index,
			wantVersion: "v1.0.0",
			wantChannel: "main",
		},
		{
			name:        "dev 通道取 Latest",
			channel:     "dev",
			index:       index,
			wantVersion: "v1.1.0-beta",
			wantChannel: "dev",
		},
		{
			name:    "main 为空回退列表第一个",
			channel: "",
			index: ReleaseIndex{
				"main": &ChannelInfo{Latest: "", Versions: []VersionInfo{{Version: "2.0.0"}}},
			},
			wantVersion: "v2.0.0",
			wantChannel: "main",
		},
		{
			name:    "通道不存在",
			channel: "main",
			index:   ReleaseIndex{},
			wantErr: true,
		},
		{
			name:    "通道存在但无版本",
			channel: "main",
			index:   ReleaseIndex{"main": &ChannelInfo{}},
			wantErr: true,
		},
		{
			name:    "无效通道被拒绝",
			channel: "staging",
			index:   ReleaseIndex{"staging": &ChannelInfo{Latest: "1.0.0"}},
			wantErr: true,
		},
		{
			name:          "指定版本时无效通道被拒绝",
			targetVersion: "1.0.0",
			channel:       "beta",
			index:         index,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, ch, err := ResolveTarget(tt.targetVersion, tt.channel, tt.index)
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

func TestFindVersion(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc123"}},
				{Version: "0.9.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:def456"}},
			},
		},
	}

	// 找到
	v := index.FindVersion("main", "v1.0.0")
	if v == nil {
		t.Fatal("应找到 v1.0.0")
	}
	if v.Checksums["sslctl-linux-amd64.gz"] != "sha256:abc123" {
		t.Errorf("Checksum = %q, want sha256:abc123", v.Checksums["sslctl-linux-amd64.gz"])
	}

	// 无 v 前缀也能找到
	v = index.FindVersion("main", "1.0.0")
	if v == nil {
		t.Fatal("无 v 前缀应也能找到")
	}

	// 找不到
	v = index.FindVersion("main", "v9.9.9")
	if v != nil {
		t.Error("不应找到 v9.9.9")
	}

	// 通道不存在
	v = index.FindVersion("dev", "v1.0.0")
	if v != nil {
		t.Error("dev 通道不存在，不应找到")
	}
}

func TestGetChecksum(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{
					"sslctl-linux-amd64.gz": "sha256:abc123",
					"sslctl-linux-arm64.gz": "sha256:def456",
				}},
			},
		},
	}

	if got := index.GetChecksum("main", "v1.0.0", "sslctl-linux-amd64.gz"); got != "sha256:abc123" {
		t.Errorf("GetChecksum(amd64) = %q, want sha256:abc123", got)
	}
	if got := index.GetChecksum("main", "v1.0.0", "sslctl-linux-arm64.gz"); got != "sha256:def456" {
		t.Errorf("GetChecksum(arm64) = %q, want sha256:def456", got)
	}
	if got := index.GetChecksum("main", "v1.0.0", "sslctl-windows-amd64.exe.gz"); got != "" {
		t.Errorf("GetChecksum(windows) = %q, want empty", got)
	}
	if got := index.GetChecksum("main", "v9.9.9", "sslctl-linux-amd64.gz"); got != "" {
		t.Errorf("GetChecksum(v9.9.9) = %q, want empty", got)
	}
	if got := index.GetChecksum("dev", "v1.0.0", "sslctl-linux-amd64.gz"); got != "" {
		t.Errorf("GetChecksum(dev) = %q, want empty", got)
	}
}

func TestGetSignature(t *testing.T) {
	index := ReleaseIndex{
		"main": &ChannelInfo{
			Versions: []VersionInfo{
				{Version: "1.0.0", Signature: "ed25519:testSig"},
				{Version: "0.9.0"}, // 无签名
			},
		},
	}

	if got := index.GetSignature("main", "v1.0.0"); got != "ed25519:testSig" {
		t.Errorf("GetSignature(v1.0.0) = %q, want ed25519:testSig", got)
	}
	if got := index.GetSignature("main", "v0.9.0"); got != "" {
		t.Errorf("GetSignature(v0.9.0) = %q, want empty", got)
	}
	if got := index.GetSignature("main", "v9.9.9"); got != "" {
		t.Errorf("GetSignature(v9.9.9) = %q, want empty", got)
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
		{"v1.0.0-beta", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0-beta", 1},
		{"v1.0.0-alpha", "v1.0.0-beta", -1},
		{"v1.0.0-beta", "v1.0.0-beta", 0},
		{"v0.1.1-beta", "v0.1.0", 1},
		{"1.0.0", "v1.0.0", 0},
		{"v0.9.0", "v1.0.0", -1},
		{"v10.0.0", "v9.0.0", 1},
		{"v1.10.0", "v1.9.0", 1},
		{"", "", 0},
		{"v1", "v1.0.0", 0},
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
	expected := ReleaseIndex{
		"main": &ChannelInfo{
			Latest: "1.0.0",
			Versions: []VersionInfo{
				{Version: "1.0.0", Checksums: map[string]string{"sslctl-linux-amd64.gz": "sha256:abc"}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	index, err := fetchReleaseInfoFrom(server.URL, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ch := index["main"]
	if ch == nil {
		t.Fatal("main channel is nil")
	}
	if ch.Latest != "1.0.0" {
		t.Errorf("Latest = %q, want %q", ch.Latest, "1.0.0")
	}
	if len(ch.Versions) != 1 {
		t.Fatalf("Versions len = %d, want 1", len(ch.Versions))
	}
	if index.GetChecksum("main", "v1.0.0", "sslctl-linux-amd64.gz") != "sha256:abc" {
		t.Error("checksum mismatch")
	}
}

func TestFetchReleaseInfo_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
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
