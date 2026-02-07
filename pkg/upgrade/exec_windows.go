//go:build windows

package upgrade

import (
	"os"
	"os/exec"
)

// defaultExecFunc Windows 上无法使用 syscall.Exec，启动新进程后退出
func defaultExecFunc(argv0 string, argv []string, envv []string) error {
	cmd := exec.Command(argv0, argv[1:]...)
	cmd.Env = envv
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil // unreachable
}
