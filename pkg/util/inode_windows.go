package util

import "os"

// sameInode Windows 上回退到 Size/ModTime 比较
func sameInode(info1, info2 os.FileInfo) bool {
	return info1.Size() == info2.Size() && info1.ModTime() == info2.ModTime()
}
