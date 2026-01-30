// Package util 提供通用工具函数
package util

import "strings"

// ShellQuote 对 shell 命令参数进行安全转义
// 使用单引号包裹，并转义内部的单引号
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
