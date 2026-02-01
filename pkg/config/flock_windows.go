//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile 获取文件排他锁（Windows 实现）
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
