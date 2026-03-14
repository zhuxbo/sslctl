// Package util 内部工具函数测试
package util

import (
	"testing"
)

// TestMaskToken 测试 Token 掩码
func TestMaskToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{"空字符串", "", "****"},
		{"短 token (4字符)", "abcd", "****"},
		{"短 token (8字符)", "abcdefgh", "****"},
		{"正常 token (9字符)", "abcdefghi", "abcd****fghi"},
		{"正常 token (16字符)", "abcdefghijklmnop", "abcd****mnop"},
		{"长 token (32字符)", "abcdefghijklmnopqrstuvwxyz123456", "abcd****3456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskToken(tt.token)
			if got != tt.expected {
				t.Errorf("MaskToken(%q) = %q, 期望 %q", tt.token, got, tt.expected)
			}
		})
	}
}

// TestMaskToken_Security 测试掩码安全性
func TestMaskToken_Security(t *testing.T) {
	// 真实 token
	token := "sk-abc123456789xyz"

	masked := MaskToken(token)

	// 验证掩码后不包含完整 token
	if masked == token {
		t.Error("掩码后不应等于原始 token")
	}

	// 验证包含掩码字符
	contains := false
	for i := 0; i < len(masked)-3; i++ {
		if masked[i:i+4] == "****" {
			contains = true
			break
		}
	}
	if !contains {
		t.Error("掩码结果应包含 ****")
	}
}
