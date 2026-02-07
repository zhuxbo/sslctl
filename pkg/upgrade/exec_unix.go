//go:build !windows

package upgrade

import "syscall"

// defaultExecFunc 使用 syscall.Exec 替换当前进程（Unix）
func defaultExecFunc(argv0 string, argv []string, envv []string) error {
	return syscall.Exec(argv0, argv, envv)
}
