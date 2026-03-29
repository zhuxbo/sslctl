//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile 获取文件排他锁（Windows 实现，阻塞）
func lockFile(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0,
		&windows.Overlapped{},
	)
}

// unlockFile 释放文件锁（Windows 实现）
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0, 1, 0,
		&windows.Overlapped{},
	)
}

// TryLockFile 尝试获取文件排他锁（非阻塞，Windows 实现）
// 返回 true 表示获取成功，false 表示锁已被占用
func TryLockFile(f *os.File) (bool, error) {
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0,
		&windows.Overlapped{},
	)
	if err != nil {
		// ERROR_LOCK_VIOLATION (33) 表示锁已被占用
		if err == windows.ERROR_LOCK_VIOLATION {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
