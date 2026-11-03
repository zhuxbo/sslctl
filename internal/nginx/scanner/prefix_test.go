package scanner

import (
	"errors"
	"testing"

	sslerrors "github.com/zhuxbo/sslctl/pkg/errors"
)

func TestTokenizeCmdline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"空串", "", nil},
		{"单 token", "nginx", []string{"nginx"}},
		{"空格分隔", "nginx -p C:\\nginx", []string{"nginx", "-p", "C:\\nginx"}},
		{"带引号路径", `nginx -p "C:\Program Files\nginx"`, []string{"nginx", "-p", `"C:\Program Files\nginx"`}},
		{"多空白压缩", "nginx   -p    C:\\nginx", []string{"nginx", "-p", "C:\\nginx"}},
		{"tab 分隔", "nginx\t-p\tC:\\nginx", []string{"nginx", "-p", "C:\\nginx"}},
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

func TestParsePrefixFromCmdline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", ""},
		{"无 -p", "nginx -c nginx.conf", ""},
		{"-p 空格形式", "nginx -p C:\\nginx\\", "C:\\nginx\\"},
		{"-p 紧挨形式", "nginx -pC:\\nginx\\", "C:\\nginx\\"},
		{"带引号路径", `nginx -p "C:\Program Files\nginx"`, `C:\Program Files\nginx`},
		{"混合参数", "nginx -c nginx.conf -p C:\\nginx\\conf -g daemon off", "C:\\nginx\\conf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePrefixFromCmdline(tt.in)
			if got != tt.want {
				t.Errorf("parsePrefixFromCmdline(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPrefixOverride(t *testing.T) {
	// 保存并在测试后恢复，避免污染其它测试
	old := getPrefixOverride()
	defer SetPrefixOverride(old)

	SetPrefixOverride("C:\\custom\\prefix\\")
	if got := getPrefixOverride(); got != "C:\\custom\\prefix\\" {
		t.Errorf("getPrefixOverride() = %q, want %q", got, "C:\\custom\\prefix\\")
	}

	// override 应让 getNginxPrefix 直接命中第 1 步
	prefix, _, ok := getNginxPrefix("")
	if !ok {
		t.Errorf("getNginxPrefix 未命中 override")
	}
	if prefix != "C:\\custom\\prefix\\" {
		t.Errorf("prefix = %q, want %q", prefix, "C:\\custom\\prefix\\")
	}

	SetPrefixOverride("")
	if getPrefixOverride() != "" {
		t.Errorf("清空 override 失败")
	}
}

func TestHasRelativeCertPath(t *testing.T) {
	tests := []struct {
		name string
		site *Site
		want bool
	}{
		{"绝对证书 + 绝对私钥", &Site{CertificatePath: "/etc/ssl/cert.pem", PrivateKeyPath: "/etc/ssl/key.pem"}, false},
		{"相对证书", &Site{CertificatePath: "cert/a.pem", PrivateKeyPath: "/etc/ssl/key.pem"}, true},
		{"相对私钥", &Site{CertificatePath: "/etc/ssl/cert.pem", PrivateKeyPath: "cert/a.key"}, true},
		{"全空", &Site{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRelativeCertPath(tt.site); got != tt.want {
				t.Errorf("hasRelativeCertPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrefixCandidates(t *testing.T) {
	// 绝对路径
	got := prefixCandidates("/usr/local/nginx/sbin/nginx")
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(got), got)
	}
	// 相对路径应返回 nil
	if got := prefixCandidates("nginx"); got != nil {
		t.Errorf("相对路径应返回 nil，实际 %v", got)
	}
}

func TestWindowsConfigPathForExecutableKeepsInstanceDirectory(t *testing.T) {
	got := windowsConfigPathForExecutable(`G:\soft\nginx-1.26.3\nginx.exe`)
	want := `G:\soft\nginx-1.26.3\conf\nginx.conf`
	if got != want {
		t.Fatalf("windowsConfigPathForExecutable() = %q, want %q", got, want)
	}
}

// TestPrefixUnknownErrorWrapping 验证 errors.As 能捕获 PrefixUnknownError
func TestPrefixUnknownErrorWrapping(t *testing.T) {
	orig := &sslerrors.PrefixUnknownError{
		ServerKind: sslerrors.ServerKindNginx,
		BinaryPath: "C:\\nginx\\nginx.exe",
		Candidates: []string{"C:\\nginx\\", "C:\\nginx\\conf\\"},
		Sites: []sslerrors.AffectedSite{
			{ServerName: "example.com", ConfigFile: "C:\\nginx\\conf\\vhost\\example.conf", CertificatePath: "cert/a.pem", PrivateKeyPath: "cert/a.key"},
		},
	}

	// 验证 errors.As
	var caught *sslerrors.PrefixUnknownError
	if !errors.As(orig, &caught) {
		t.Fatalf("errors.As 未捕获 PrefixUnknownError")
	}
	if caught.BinaryPath != "C:\\nginx\\nginx.exe" {
		t.Errorf("BinaryPath mismatch: %q", caught.BinaryPath)
	}
	if caught.ServerKind != sslerrors.ServerKindNginx {
		t.Errorf("ServerKind mismatch: %q", caught.ServerKind)
	}
	if len(caught.Sites) != 1 {
		t.Errorf("Sites 长度 = %d", len(caught.Sites))
	}
}
