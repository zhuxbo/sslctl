// Package util 内部工具函数
package util

// MaskReferID 掩码 ReferID，用于日志显示
func MaskReferID(referID string) string {
	if len(referID) <= 8 {
		return "****"
	}
	return referID[:4] + "****" + referID[len(referID)-4:]
}
