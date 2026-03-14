// Package util 内部工具函数
package util

// MaskToken 掩码 Token，用于日志显示
func MaskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}
