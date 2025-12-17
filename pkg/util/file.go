// Package util 工具函数
package util

import (
	"fmt"
	"io"
	"os"
)

// AtomicWrite 原子写入文件
func AtomicWrite(path string, content []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"

	// 写入临时文件
	if err := os.WriteFile(tmpPath, content, perm); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// 原子替换(rename 是原子操作)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	// 打开源文件
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// 获取源文件信息
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// 创建目标文件
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// 复制内容
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDir 确保目录存在
func EnsureDir(dir string, perm os.FileMode) error {
	return os.MkdirAll(dir, perm)
}
