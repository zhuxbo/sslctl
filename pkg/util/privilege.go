// Package util 提供权限检查工具
package util

import (
	"fmt"
	"os"
	"runtime"
)

// CheckRootPrivilege 检查是否具有 root/管理员权限
// Windows 系统不检查（Windows 服务运行时不一定需要管理员）
// Linux/macOS 系统检查 euid == 0
func CheckRootPrivilege() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("请使用 root 权限运行此命令")
	}
	return nil
}
