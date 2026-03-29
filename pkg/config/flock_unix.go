//go:build !windows

package config

import (
	"os"
	"syscall"
)

// lockFile 获取文件排他锁（Unix 实现，阻塞）
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile 释放文件锁（Unix 实现）
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// TryLockFile 尝试获取文件排他锁（非阻塞，Unix 实现）
// 返回 true 表示获取成功，false 表示锁已被占用
func TryLockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if err == syscall.EWOULDBLOCK {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
