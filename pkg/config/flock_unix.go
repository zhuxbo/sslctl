//go:build !windows

package config

import (
	"os"
	"syscall"
)

// lockFile 获取文件排他锁（Unix 实现）
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile 释放文件锁（Unix 实现）
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
