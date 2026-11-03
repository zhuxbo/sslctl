package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
)

func TestServerRootFromConfigContent(t *testing.T) {
	base := t.TempDir()
	want := filepath.Join(base, "runtime")
	content := "# ServerRoot /ignored\nServerRoot \"runtime\"\n"

	got, ok := serverRootFromConfigContent(content, base)
	if !ok || got != want {
		t.Fatalf("serverRootFromConfigContent() = %q, %v，期望 %q, true", got, ok, want)
	}
}

func TestServerRootFromConfigContentDefine(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "Apache Root")
	for _, tt := range []struct {
		name, content, want string
		ok                  bool
	}{
		{"定义路径", "Define SRVROOT \"" + root + "\"\nServerRoot \"${SRVROOT}\"", root, true},
		{"相对路径", "Define SRVROOT runtime\nServerRoot ${SRVROOT}", filepath.Join(base, "runtime"), true},
		{"顺序覆盖", "Define SRVROOT old\nDefine SRVROOT new\nServerRoot ${SRVROOT}", filepath.Join(base, "new"), true},
		{"引用先前定义", "Define BASE runtime\nDefine SRVROOT ${BASE}/apache\nServerRoot ${SRVROOT}", filepath.Join(base, "runtime", "apache"), true},
		{"未定义", "ServerRoot ${MISSING}", "", false},
		{"未定义变量带子目录", "ServerRoot ${MISSING}/apache", "", false},
		{"空变量", "Define SRVROOT \"\"\nServerRoot ${SRVROOT}", "", false},
		{"定义在后", "ServerRoot ${SRVROOT}\nDefine SRVROOT runtime", "", false},
		{"注释", "# Define SRVROOT runtime\nServerRoot ${SRVROOT}", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := serverRootFromConfigContent(tt.content, base)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("got (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestApacheDefinedServerRootFindsIncludedSites(t *testing.T) {
	root := t.TempDir()
	confDir := filepath.Join(root, "conf", "extra")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "conf", "httpd.conf")
	content := "Define SRVROOT \"" + root + "\"\nServerRoot \"${SRVROOT}\"\nInclude conf/extra/httpd-vhosts.conf\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	vhost := "<VirtualHost *:80>\nServerName example.com\nDocumentRoot htdocs\n</VirtualHost>\n"
	if err := os.WriteFile(filepath.Join(confDir, "httpd-vhosts.conf"), []byte(vhost), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(configPath)
	s.serverRoot = root
	s.prepareServerRoot(configPath)
	sites, err := s.scanAllConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].ServerName != "example.com" {
		t.Fatalf("未扫描到被包含的站点: %+v", sites)
	}
	sites, err = s.resolveSitePaths(sites)
	if err != nil {
		t.Fatal(err)
	}
	if sites[0].Webroot != filepath.Join(root, "htdocs") {
		t.Fatalf("错误的站点目录: %q", sites[0].Webroot)
	}
}

func TestApacheEffectiveServerRootOverridesDetectedRoot(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	s := New()
	s.serverRoot = "/compiled/root"
	s.setEffectiveServerRoot("/configured/root")

	prefix, _, ok := s.getApachePrefix("")
	if !ok || prefix != "/configured/root" {
		t.Fatalf("getApachePrefix() = %q, %v，期望配置生效的 ServerRoot", prefix, ok)
	}
}

func TestParseServerRootFromApacheCtlOutput(t *testing.T) {
	output := "VirtualHost configuration:\nServerRoot: \"/runtime/apache\"\n"
	if got := parseServerRootFromApacheCtlOutput(output); got != "/runtime/apache" {
		t.Fatalf("parseServerRootFromApacheCtlOutput() = %q", got)
	}
}

func TestApacheConfigServerRootResolvesRelativeSitePaths(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	dir := t.TempDir()
	root := filepath.Join(dir, "apache-root")
	configPath := filepath.Join(dir, "httpd.conf")
	content := `ServerRoot "` + root + `"
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile ssl/cert.pem
    SSLCertificateKeyFile ssl/key.pem
    SSLCertificateChainFile ssl/chain.pem
    DocumentRoot htdocs
</VirtualHost>
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewWithConfig(configPath)
	s.prepareServerRoot(configPath)
	sites, err := s.scanAllConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	sites, err = s.resolveSitePaths(sites)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("站点数 = %d", len(sites))
	}
	if sites[0].CertificatePath != filepath.Join(root, "ssl/cert.pem") ||
		sites[0].PrivateKeyPath != filepath.Join(root, "ssl/key.pem") ||
		sites[0].ChainPath != filepath.Join(root, "ssl/chain.pem") ||
		sites[0].Webroot != filepath.Join(root, "htdocs") {
		t.Fatalf("相对路径解析错误: %+v", sites[0])
	}
}

func TestApacheTokenizeCmdline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"空串", "", nil},
		{"单 token", "httpd", []string{"httpd"}},
		{"空格分隔", "httpd -d /etc/httpd", []string{"httpd", "-d", "/etc/httpd"}},
		{"带引号路径", `httpd -d "/etc/httpd root"`, []string{"httpd", "-d", `"/etc/httpd root"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenizeCmdline(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("token[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseServerRootFromCmdline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", ""},
		{"无 -d", "httpd -f httpd.conf", ""},
		{"-d 空格形式", "httpd -d /etc/httpd", "/etc/httpd"},
		{"-d 紧挨形式", "httpd -d/etc/httpd", "/etc/httpd"},
		{"带引号", `httpd -d "/etc/apache2"`, "/etc/apache2"},
		{"混合参数", "httpd -f conf/httpd.conf -d /etc/httpd -k start", "/etc/httpd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseServerRootFromCmdline(tt.in)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApachePrefixOverride(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)

	SetPrefixOverride("/custom/apache")
	if got := getPrefixOverride(); got != "/custom/apache" {
		t.Errorf("getPrefixOverride() = %q", got)
	}

	// override 应直接命中 getApachePrefix 第 1 步
	s := New()
	prefix, _, ok := s.getApachePrefix("")
	if !ok || prefix != "/custom/apache" {
		t.Errorf("getApachePrefix 未命中 override: prefix=%q ok=%v", prefix, ok)
	}

	SetPrefixOverride("")
}

func TestApachePrefixFromScannerServerRoot(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	s := New()
	s.serverRoot = "/etc/apache2"

	prefix, _, ok := s.getApachePrefix("")
	if !ok || prefix != "/etc/apache2" {
		t.Errorf("getApachePrefix 未命中 scanner.serverRoot: prefix=%q ok=%v", prefix, ok)
	}
}

func TestApacheHasRelativeSitePath(t *testing.T) {
	tests := []struct {
		name string
		site *Site
		want bool
	}{
		{"全绝对", &Site{CertificatePath: "/a", PrivateKeyPath: "/b", ChainPath: "/c"}, false},
		{"相对证书", &Site{CertificatePath: "cert/a"}, true},
		{"相对私钥", &Site{PrivateKeyPath: "cert/b"}, true},
		{"相对 chain", &Site{ChainPath: "cert/c"}, true},
		{"相对 Webroot", &Site{Webroot: "htdocs"}, true},
		{"全空", &Site{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRelativeSitePath(tt.site); got != tt.want {
				t.Errorf("hasRelativeSitePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApachePrefixCandidates(t *testing.T) {
	got := prefixCandidates("/usr/local/apache2/bin/httpd")
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(got), got)
	}
	if got := prefixCandidates("httpd"); got != nil {
		t.Errorf("相对路径应返回 nil，实际 %v", got)
	}
}

func TestApacheResolveSitePaths_Absolute(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	s := New()
	s.serverRoot = "/etc/apache2"

	sites := []*Site{
		{
			ServerName:      "example.com",
			CertificatePath: "/etc/ssl/example.crt",
			PrivateKeyPath:  "/etc/ssl/example.key",
		},
	}

	resolved, err := s.resolveSitePaths(sites)
	if err != nil {
		t.Fatalf("resolveSitePaths 失败: %v", err)
	}
	if resolved[0].CertificatePath != "/etc/ssl/example.crt" {
		t.Errorf("绝对路径被改写: %q", resolved[0].CertificatePath)
	}
}

func TestApacheResolveSitePaths_Relative(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	s := New()
	s.serverRoot = "/etc/apache2"

	sites := []*Site{
		{
			ServerName:      "example.com",
			CertificatePath: "ssl/example.crt",
			PrivateKeyPath:  "ssl/example.key",
		},
	}

	resolved, err := s.resolveSitePaths(sites)
	if err != nil {
		t.Fatalf("resolveSitePaths 失败: %v", err)
	}
	if resolved[0].CertificatePath != "/etc/apache2/ssl/example.crt" {
		t.Errorf("证书路径解析错误: %q", resolved[0].CertificatePath)
	}
	if resolved[0].PrivateKeyPath != "/etc/apache2/ssl/example.key" {
		t.Errorf("私钥路径解析错误: %q", resolved[0].PrivateKeyPath)
	}
}

func TestApacheResolveSitePaths_UnknownPrefix(t *testing.T) {
	old := getPrefixOverride()
	defer SetPrefixOverride(old)
	SetPrefixOverride("")

	// serverRoot 为空且没有 override：在非 Windows 上其它源也大概率拿不到
	// 这里构造一个"绝对拿不到 prefix"的场景直接传相对路径看是否返回 PrefixUnknownError
	s := New()
	s.serverRoot = "" // 显式清空

	// 构造一个 Site，但调用 getApachePrefix 可能会成功（比如机器上真的跑着 Apache）
	// 所以这个测试主要是验证 resolveSitePaths 返回错误类型的结构，而非严格断言触发路径
	// 如果本机正好有 Apache 安装且能拿到 HTTPD_ROOT，这个测试会跳过断言
	sites := []*Site{
		{ServerName: "example.com", CertificatePath: "ssl/x.crt"},
	}
	_, err := s.resolveSitePaths(sites)
	if err != nil {
		var prefixErr *sslerrors.PrefixUnknownError
		if !errors.As(err, &prefixErr) {
			t.Errorf("期望 PrefixUnknownError，实际 %T: %v", err, err)
		} else if prefixErr.ServerKind != sslerrors.ServerKindApache {
			t.Errorf("ServerKind = %q, want apache", prefixErr.ServerKind)
		}
	}
	// 没有错误意味着本机 httpd -V 成功返回了 prefix，这也是合法路径，不做硬断言
}
