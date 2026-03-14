//go:build !windows

package util

import (
	"os"
	"syscall"
)

// sameInode 比较两个 FileInfo 是否指向同一个 inode
// 在 Unix 系统上使用 Dev 和 Ino 比较，比 Size/ModTime 更可靠
func sameInode(info1, info2 os.FileInfo) bool {
	stat1, ok1 := info1.Sys().(*syscall.Stat_t)
	stat2, ok2 := info2.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return info1.Size() == info2.Size() && info1.ModTime() == info2.ModTime()
	}
	return stat1.Dev == stat2.Dev && stat1.Ino == stat2.Ino
}
