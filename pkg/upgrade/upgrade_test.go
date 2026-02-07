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
	"os"
	"strings"
	"testing"
)

func TestExecute_AlreadyLatest(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v1.0.0",
		LatestDev:    "v1.1.0-beta",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false for same version")
	}
}

func TestExecute_CheckOnly(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v2.0.0",
		LatestDev:    "v2.1.0-beta",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
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
	info := &ReleaseInfo{
		LatestStable: "v1.0.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
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

func TestExecute_MinClientVersion_Blocked(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for old client version")
	}
	if !strings.Contains(err.Error(), "过旧") {
		t.Errorf("error should mention version too old, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}

func TestExecute_MinClientVersion_Allowed(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	// v1.5.0 满足 min_client_version，CheckOnly 不触发下载
	result, err := executeWithClient(Options{
		CurrentVersion: "v1.5.0",
		Channel:        "stable",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
}

func TestExecute_CheckOnly_MinClientVersion_WithUpgradePath(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable:     "v3.0.0",
		MinClientVersion: "v2.0.0",
		UpgradePath:      []string{"v2.0.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	// 确保不会触发安装/exec
	installCalled := false
	execCalled := false
	oldInstall := installFunc
	oldExec := execFunc
	installFunc = func(gzData []byte) (string, error) {
		installCalled = true
		return "/tmp/sslctl-test", nil
	}
	execFunc = func(argv0 string, argv []string, envv []string) error {
		execCalled = true
		return nil
	}
	defer func() {
		installFunc = oldInstall
		execFunc = oldExec
	}()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for old client in check-only mode")
	}
	if !strings.Contains(err.Error(), "链式升级") {
		t.Errorf("error should mention chain upgrade, got: %v", err)
	}
	if result == nil || !result.NeedUpgrade {
		t.Errorf("expected NeedUpgrade=true, got: %#v", result)
	}
	if installCalled || execCalled {
		t.Errorf("check-only should not install/exec, install=%v exec=%v", installCalled, execCalled)
	}
}

func TestExecute_MinClientVersion_Empty(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v2.0.0",
		// MinClientVersion 为空，不做限制
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v0.1.0",
		Channel:        "stable",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
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

func TestExecute_CheckOnly_WithMinClientVersion(t *testing.T) {
	// CheckOnly 模式不应触发链式升级，即使 min_client_version 检查不通过
	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
		UpgradePath:      []string{"v1.5.0"},
		Versions: map[string]VersionInfo{
			"v1.5.0": {},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for old client in check-only mode")
	}
	if !strings.Contains(err.Error(), "链式升级") {
		t.Errorf("error should mention chain upgrade, got: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
}

// --- 链式升级测试 ---

// signAndChecksum 为 gzData 生成签名和校验和
func signAndChecksum(t *testing.T, priv ed25519.PrivateKey, keyID string, gzData []byte) (string, string) {
	t.Helper()
	sig := ed25519.Sign(priv, gzData)
	sigStr := fmt.Sprintf("ed25519:%s:%s", keyID, base64.StdEncoding.EncodeToString(sig))
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])
	return sigStr, checksum
}

func TestChainUpgrade_SingleStep(t *testing.T) {
	saveAndRestoreKeys(t)
	pub1, priv1 := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	gzData := makeGzipData(t, []byte("transit binary"))
	filename := GetDownloadFilename()
	sigStr, checksum := signAndChecksum(t, priv1, "key-1", gzData)

	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
		UpgradePath:      []string{"v1.5.0"},
		Versions: map[string]VersionInfo{
			"v1.5.0": {
				Checksums:  map[string]string{filename: checksum},
				Signatures: map[string]string{filename: sigStr},
			},
		},
	}

	// 下载服务器
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		// 返回 gzData 作为二进制
		w.Write(gzData)
	}))
	defer server.Close()

	// 替换 installFunc 避免写入 /usr/local/bin
	oldInstall := installFunc
	installFunc = func(gzData []byte) (string, error) {
		return "/tmp/sslctl-test", nil
	}
	defer func() { installFunc = oldInstall }()

	// 替换 execFunc 来捕获调用而非真正替换进程
	var execCalled bool
	var execArgs []string
	oldExec := execFunc
	execFunc = func(argv0 string, argv []string, envv []string) error {
		execCalled = true
		execArgs = argv
		return nil
	}
	defer func() { execFunc = oldExec }()

	// 清除升级深度环境变量
	os.Unsetenv(upgradeDepthEnvKey)

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())

	// tryChainUpgrade 返回 execFunc 的结果（nil），被 executeWithClient 当作 error 返回
	// 实际上 execFunc 返回 nil 表示"成功替换进程"
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !execCalled {
		t.Error("expected execFunc to be called for chain upgrade")
	}
	// 验证 execArgs 包含 "upgrade" 命令
	hasUpgrade := false
	for _, arg := range execArgs {
		if arg == "upgrade" {
			hasUpgrade = true
			break
		}
	}
	if !hasUpgrade {
		t.Errorf("execArgs should contain 'upgrade', got: %v", execArgs)
	}
}

func TestChainUpgrade_PreservesUserArgs(t *testing.T) {
	saveAndRestoreKeys(t)
	pub1, priv1 := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	gzData := makeGzipData(t, []byte("transit binary"))
	filename := GetDownloadFilename()
	sigStr, checksum := signAndChecksum(t, priv1, "key-1", gzData)

	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
		UpgradePath:      []string{"v1.5.0"},
		Versions: map[string]VersionInfo{
			"v1.5.0": {
				Checksums:  map[string]string{filename: checksum},
				Signatures: map[string]string{filename: sigStr},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		w.Write(gzData)
	}))
	defer server.Close()

	oldInstall := installFunc
	installFunc = func(gzData []byte) (string, error) {
		return "/tmp/sslctl-test", nil
	}
	defer func() { installFunc = oldInstall }()

	var execArgs []string
	oldExec := execFunc
	execFunc = func(argv0 string, argv []string, envv []string) error {
		execArgs = argv
		return nil
	}
	defer func() { execFunc = oldExec }()

	os.Unsetenv(upgradeDepthEnvKey)

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "dev",
		TargetVersion:  "v3.0.0",
		Force:          true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 验证用户参数被保留
	argsStr := strings.Join(execArgs, " ")
	if !strings.Contains(argsStr, "--channel dev") {
		t.Errorf("execArgs should contain '--channel dev', got: %v", execArgs)
	}
	if !strings.Contains(argsStr, "--version v3.0.0") {
		t.Errorf("execArgs should contain '--version v3.0.0', got: %v", execArgs)
	}
	if !strings.Contains(argsStr, "--force") {
		t.Errorf("execArgs should contain '--force', got: %v", execArgs)
	}
}

func TestChainUpgrade_DepthExceeded(t *testing.T) {
	// 设置深度超限
	os.Setenv(upgradeDepthEnvKey, "5")
	defer os.Unsetenv(upgradeDepthEnvKey)

	info := &ReleaseInfo{
		LatestStable:     "v3.0.0",
		MinClientVersion: "v2.5.0",
		UpgradePath:      []string{"v1.5.0", "v2.5.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for depth exceeded")
	}
	if !strings.Contains(err.Error(), "超过限制") {
		t.Errorf("error should mention depth limit, got: %v", err)
	}
	if !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("error should suggest reinstall, got: %v", err)
	}
}

func TestChainUpgrade_NoUpgradePath_FallbackReinstall(t *testing.T) {
	// min_client_version 触发但无 upgrade_path → 提示重装
	info := &ReleaseInfo{
		LatestStable:     "v2.0.0",
		MinClientVersion: "v1.5.0",
		// 无 UpgradePath
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for old client without upgrade path")
	}
	if !strings.Contains(err.Error(), "过旧") {
		t.Errorf("error should mention version too old, got: %v", err)
	}
}

func TestChainUpgrade_NoMatchingTransitVersion(t *testing.T) {
	// upgrade_path 中所有版本都 <= 当前版本
	os.Unsetenv(upgradeDepthEnvKey)

	info := &ReleaseInfo{
		LatestStable:     "v3.0.0",
		MinClientVersion: "v2.5.0",
		UpgradePath:      []string{"v0.5.0", "v0.8.0"}, // 都小于 v1.0.0
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error when no matching transit version")
	}
	if !strings.Contains(err.Error(), "无可用的过渡版本") {
		t.Errorf("error should mention no transit version, got: %v", err)
	}
}

func TestChainUpgrade_MissingVersionInfo(t *testing.T) {
	// upgrade_path 中的过渡版本在 Versions 中不存在
	os.Unsetenv(upgradeDepthEnvKey)

	info := &ReleaseInfo{
		LatestStable:     "v3.0.0",
		MinClientVersion: "v2.5.0",
		UpgradePath:      []string{"v1.5.0"},
		Versions:         map[string]VersionInfo{}, // v1.5.0 不在里面
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Fatal("expected error for missing version info")
	}
	if !strings.Contains(err.Error(), "缺少版本信息") {
		t.Errorf("error should mention missing version info, got: %v", err)
	}
}

func TestGetUpgradeDepth(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{"empty", "", 0},
		{"zero", "0", 0},
		{"positive", "3", 3},
		{"negative", "-1", maxUpgradeDepth},
		{"invalid", "abc", maxUpgradeDepth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env == "" {
				os.Unsetenv(upgradeDepthEnvKey)
			} else {
				os.Setenv(upgradeDepthEnvKey, tt.env)
			}
			defer os.Unsetenv(upgradeDepthEnvKey)

			got := getUpgradeDepth()
			if got != tt.want {
				t.Errorf("getUpgradeDepth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExecute_SignatureKeyNotFound_ReinstallHint(t *testing.T) {
	saveAndRestoreKeys(t)
	pub1, _ := generateTestKeyPair(t)
	_, priv2 := generateTestKeyPair(t)
	SetReleasePublicKeys(map[string]ed25519.PublicKey{"key-1": pub1})

	gzData := makeGzipData(t, []byte("new binary"))
	filename := GetDownloadFilename()
	// 用 key-2 签名（不在密钥环中）
	sig := ed25519.Sign(priv2, gzData)
	sigStr := "ed25519:key-2:" + base64.StdEncoding.EncodeToString(sig)
	hash := sha256.Sum256(gzData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	info := &ReleaseInfo{
		LatestStable: "v2.0.0",
		Versions: map[string]VersionInfo{
			"v2.0.0": {
				Checksums:  map[string]string{filename: checksum},
				Signatures: map[string]string{filename: sigStr},
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases.json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		w.Write(gzData)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
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

func TestDownloadVerifyInstall_InvalidChannel(t *testing.T) {
	// 非法通道应被拒绝（防止路径遍历）
	info := &ReleaseInfo{}
	err := downloadVerifyInstall("v1.0.0", "../evil", info, nil, nil, "https://example.com")
	if err == nil {
		t.Fatal("expected error for invalid channel")
	}
	if !strings.Contains(err.Error(), "不支持的发布通道") {
		t.Errorf("error should mention unsupported channel, got: %v", err)
	}
}

func TestValidChannels(t *testing.T) {
	// stable 和 dev 应该通过通道校验
	for _, ch := range []string{"stable", "dev"} {
		if !validChannels[ch] {
			t.Errorf("channel %q should be valid", ch)
		}
	}
	// 非法通道
	for _, ch := range []string{"", "../hack", "nightly", "stable/../../etc"} {
		if validChannels[ch] {
			t.Errorf("channel %q should be invalid", ch)
		}
	}
}
