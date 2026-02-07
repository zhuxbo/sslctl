// Package util Shell 工具测试
package util

import "testing"

// TestShellQuote 测试 Shell 参数转义
func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"空字符串", "", "''"},
		{"普通字符串", "hello", "'hello'"},
		{"包含空格", "hello world", "'hello world'"},
		{"包含单引号", "it's", "'it'\\''s'"},
		{"多个单引号", "a'b'c", "'a'\\''b'\\''c'"},
		{"仅单引号", "'", "''\\'''"},
		{"特殊字符", "hello; rm -rf /", "'hello; rm -rf /'"},
		{"反引号", "$(whoami)", "'$(whoami)'"},
		{"双引号", `"hello"`, `'"hello"'`},
		{"换行符", "line1\nline2", "'line1\nline2'"},
		{"制表符", "col1\tcol2", "'col1\tcol2'"},
		{"路径", "/etc/nginx/nginx.conf", "'/etc/nginx/nginx.conf'"},
		{"管道符号", "echo hello | grep h", "'echo hello | grep h'"},
		{"连续单引号", "''", "''\\'''\\'''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShellQuote(tt.input)
			if got != tt.want {
				t.Errorf("ShellQuote(%q) = %q, 期望 %q", tt.input, got, tt.want)
			}
		})
	}
}
