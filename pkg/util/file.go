// Package util 工具函数
package util

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// CopyFile 复制文件（带符号链接保护）
func CopyFile(src, dst string) error {
	// 先检查源文件是否为符号链接（Lstat 不跟随符号链接）
	srcLstat, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("failed to lstat source file: %w", err)
	}
	if srcLstat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source is a symbolic link, not allowed for security")
	}
	if !srcLstat.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}

	// 打开源文件
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	// 通过文件描述符再次验证（防止 TOCTOU）
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("source changed to non-regular file (TOCTOU detected)")
	}

	// 创建目标文件
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

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

// SafeReadFile 安全读取文件（带符号链接和 TOCTOU 保护）
// 用于读取敏感文件（如证书、私钥），拒绝符号链接以防止路径劫持
func SafeReadFile(path string, maxSize int64) ([]byte, error) {
	// 先检查是否为符号链接（Lstat 不跟随符号链接）
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to lstat file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic links not allowed for security")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if maxSize > 0 && info.Size() > maxSize {
		return nil, fmt.Errorf("file too large (max %d bytes)", maxSize)
	}

	// 打开文件
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// 通过文件描述符再次验证（防止 TOCTOU）- 使用 inode 比较
	fdInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file descriptor: %w", err)
	}
	if !fdInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("file changed to non-regular (TOCTOU detected)")
	}

	// 使用 inode 比较（比 Size/ModTime 更可靠）
	if !sameInode(info, fdInfo) {
		return nil, fmt.Errorf("file changed between check and open (TOCTOU detected)")
	}

	// 读取文件内容
	return io.ReadAll(file)
}

// sameInode 比较两个 FileInfo 是否指向同一个 inode
// 在 Unix 系统上使用 Dev 和 Ino 比较，比 Size/ModTime 更可靠
func sameInode(info1, info2 os.FileInfo) bool {
	stat1, ok1 := info1.Sys().(*syscall.Stat_t)
	stat2, ok2 := info2.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		// 非 Unix 系统回退到 Size/ModTime 比较
		return info1.Size() == info2.Size() && info1.ModTime() == info2.ModTime()
	}
	return stat1.Dev == stat2.Dev && stat1.Ino == stat2.Ino
}

// EnsureDir 确保目录存在
func EnsureDir(dir string, perm os.FileMode) error {
	return os.MkdirAll(dir, perm)
}

// JoinUnderDir 将一个可能来自 URL 的路径安全拼接到 baseDir 下。
//
// 典型场景：DCV file/http/https 验证返回的 path 往往以 "/" 开头（URL Path），
// 直接 filepath.Join(baseDir, "/.well-known/...") 会导致 baseDir 被丢弃，进而写入到系统根目录。
// 该函数会：
// - 去掉前导的 / 或 \，确保拼接结果始终位于 baseDir 下
// - 使用 filepath.Clean 归一化路径，并拒绝 ".." 目录穿越
func JoinUnderDir(baseDir, path string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		return "", fmt.Errorf("baseDir is empty")
	}

	p := strings.TrimSpace(path)
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}

	// 兼容 URL Path：去掉前导分隔符，避免 Join 时 baseDir 被丢弃
	p = strings.TrimLeft(p, "/\\")
	p = filepath.FromSlash(p)
	p = filepath.Clean(p)

	if p == "." || p == "" {
		return "", fmt.Errorf("invalid path: %q", path)
	}
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("absolute path not allowed: %q", path)
	}
	if p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal not allowed: %q", path)
	}

	full := filepath.Join(baseDir, p)

	// 二次校验：确保 full 仍然位于 baseDir 内（防御性检查）
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve baseDir: %w", err)
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("failed to resolve joined path: %w", err)
	}
	rel, err := filepath.Rel(baseAbs, fullAbs)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes baseDir: %q", path)
	}

	return full, nil
}

// RunCommand 执行命令（仅用于内部固定命令）
func RunCommand(command string) error {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	// 安全检查：拒绝包含危险字符的命令
	for _, p := range parts {
		if strings.ContainsAny(p, ";|&$`\\") {
			return fmt.Errorf("invalid characters in command")
		}
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s\noutput: %s", err, string(output))
	}
	return nil
}
