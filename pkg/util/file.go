// Package util 工具函数
package util

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	// 打开源文件
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

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
