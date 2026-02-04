// Package upgrade 安装逻辑
package upgrade

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// 下载配置常量
const (
	downloadTimeout     = 5 * time.Minute // 下载超时时间
	maxDownloadSize     = 100 * 1024 * 1024 // 最大下载大小 100MB
)

// secureHTTPClient 创建安全的 HTTP 客户端
// - 强制 TLS 1.2+
// - 设置下载超时
func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// DownloadBinary 下载二进制文件
// 返回 gzip 压缩后的原始数据（用于校验和验证）
// 安全措施：
// - 强制 HTTPS（防止中间人攻击）
// - TLS 1.2+ （防止降级攻击）
// - 下载超时（防止资源耗尽）
// - 大小限制（防止内存耗尽）
func DownloadBinary(url string) ([]byte, error) {
	// 安全校验：强制 HTTPS
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("下载失败: 仅允许 HTTPS 协议")
	}

	client := secureHTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("下载失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}

	// 限制读取大小，防止内存耗尽
	limitReader := io.LimitReader(resp.Body, maxDownloadSize)
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("读取下载数据失败: %w", err)
	}

	// 检查是否达到大小限制
	if int64(len(data)) >= maxDownloadSize {
		return nil, fmt.Errorf("下载失败: 文件大小超过限制 (%d bytes)", maxDownloadSize)
	}

	return data, nil
}

// VerifyChecksum 验证文件校验和
// expected 格式: "sha256:hexstring"
func VerifyChecksum(data []byte, expected string) error {
	if expected == "" {
		return nil // 无校验和则跳过（兼容旧版本）
	}
	hash := sha256.Sum256(data)
	actual := "sha256:" + hex.EncodeToString(hash[:])
	if actual != expected {
		return fmt.Errorf("校验失败: 期望 %s, 实际 %s", expected, actual)
	}
	return nil
}

// Install 安装二进制文件
// gzData: gzip 压缩的二进制数据
// 返回安装路径
func Install(gzData []byte) (string, error) {
	// 解压 gzip
	gzReader, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return "", fmt.Errorf("解压失败: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	// 写入临时文件
	tmpFile, err := os.CreateTemp("", "sslctl-*")
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, gzReader); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("写入文件失败: %w", err)
	}
	_ = tmpFile.Close()

	// 设置执行权限
	if err := os.Chmod(tmpPath, 0755); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("设置权限失败: %w", err)
	}

	// 确定目标路径
	binPath := GetBinaryPath()

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("创建目录失败: %w", err)
	}

	// 移动文件到目标位置
	if err := os.Rename(tmpPath, binPath); err != nil {
		// 跨文件系统移动，使用复制
		if copyErr := copyFile(tmpPath, binPath); copyErr != nil {
			_ = os.Remove(tmpPath)
			return "", copyErr
		}
		_ = os.Remove(tmpPath)
	}

	return binPath, nil
}

// GetBinaryPath 获取二进制安装路径
func GetBinaryPath() string {
	if runtime.GOOS == "windows" {
		// Windows: 使用当前可执行文件路径或 %LOCALAPPDATA%\sslctl
		if exePath, err := os.Executable(); err == nil {
			return exePath
		}
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "sslctl", "sslctl.exe")
	}
	return "/usr/local/bin/sslctl"
}

// GetDownloadFilename 获取下载文件名
func GetDownloadFilename() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	if osName == "windows" {
		return fmt.Sprintf("sslctl-%s-%s.exe.gz", osName, arch)
	}
	return fmt.Sprintf("sslctl-%s-%s.gz", osName, arch)
}

// GetDownloadURL 获取下载 URL
func GetDownloadURL(channel, version string) string {
	filename := GetDownloadFilename()
	return fmt.Sprintf("%s/%s/%s/%s", ReleaseURL, channel, version, filename)
}

// copyFile 复制文件（用于跨文件系统移动）
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开临时文件失败: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("安装失败: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("复制失败: %w", err)
	}

	if err := os.Chmod(dst, 0755); err != nil {
		return fmt.Errorf("设置权限失败: %w", err)
	}

	return nil
}
