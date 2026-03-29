// Package upgrade 安装逻辑
package upgrade

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// 下载配置常量
const (
	downloadTimeout = 5 * time.Minute   // 下载超时时间
	maxDownloadSize = 100 * 1024 * 1024 // 最大下载大小 100MB
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
	return downloadBinaryWithClient(url, secureHTTPClient())
}

// downloadBinaryWithClient 内部实现，接受 client 参数（便于测试）
func downloadBinaryWithClient(url string, client *http.Client) ([]byte, error) {
	// 安全校验：强制 HTTPS
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("下载失败: 仅允许 HTTPS 协议")
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("下载失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}

	// 限制读取大小，防止内存耗尽
	// 多读 1 字节用于检测是否超限（与 installTo 保持一致）
	limitReader := io.LimitReader(resp.Body, maxDownloadSize+1)
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("读取下载数据失败: %w", err)
	}

	// 检查是否超出大小限制
	if int64(len(data)) > maxDownloadSize {
		return nil, fmt.Errorf("下载失败: 文件大小超过限制 (%d bytes)", maxDownloadSize)
	}

	return data, nil
}

// ErrKeyNotFound 签名使用的密钥不在本地密钥环中
// 通常表示发生了密钥轮换，客户端需要重新安装以获取新公钥
type ErrKeyNotFound struct {
	KeyID string
}

func (e *ErrKeyNotFound) Error() string {
	return fmt.Sprintf("签名密钥 %q 不在本地密钥环中，请重新安装以获取最新公钥", e.KeyID)
}

// ErrNoPublicKeys 未配置发布公钥
// 当发布包提供签名但本地缺少公钥时返回
type ErrNoPublicKeys struct{}

func (e *ErrNoPublicKeys) Error() string {
	return "未配置发布公钥，无法验证签名"
}

// releasePublicKeys 发布签名公钥环（Ed25519）
// key ID → 公钥，支持多密钥轮换
// 使用 build/generate-keys.sh 生成密钥对，私钥离线保管
// 公钥更新时需要重新编译发布
var releasePublicKeys = map[string]ed25519.PublicKey{}

// init 注册发布签名公钥（由 build/generate-keys.sh 生成）
func init() {
	releasePublicKeys["key-1"] = ed25519.PublicKey{0x3d, 0xca, 0xc7, 0x05, 0xf4, 0xce, 0xe9, 0x86, 0xa0, 0x8d, 0x8c, 0xd5, 0xb5, 0x90, 0x42, 0xe3, 0x1f, 0x37, 0xbf, 0x5a, 0x4c, 0x36, 0x50, 0x65, 0xa4, 0xd2, 0x2d, 0x50, 0xe0, 0x26, 0x23, 0x8a}
}

// releaseKeysMu 保护 releasePublicKeys 的并发访问（SetReleasePublicKeys/AddReleasePublicKey 仅用于测试）
var releaseKeysMu sync.RWMutex

// SetReleasePublicKeys 设置发布签名公钥环（仅用于测试）
func SetReleasePublicKeys(keys map[string]ed25519.PublicKey) {
	releaseKeysMu.Lock()
	defer releaseKeysMu.Unlock()
	releasePublicKeys = keys
}

// AddReleasePublicKey 添加单个发布签名公钥（仅用于测试）
func AddReleasePublicKey(id string, key ed25519.PublicKey) {
	releaseKeysMu.Lock()
	defer releaseKeysMu.Unlock()
	releasePublicKeys[id] = key
}

// hasReleasePublicKeys 检查是否配置了公钥
func hasReleasePublicKeys() bool {
	releaseKeysMu.RLock()
	defer releaseKeysMu.RUnlock()
	return len(releasePublicKeys) > 0
}

// VerifySignature 验证 Ed25519 签名
// 签名格式: "ed25519:<key_id>:<base64_signature>" — 按 key ID 查找公钥验证
// 签名对象为 gzip 压缩后的原始数据（与校验和一致）
func VerifySignature(data []byte, expected string) error {
	if expected == "" {
		if hasReleasePublicKeys() {
			// 已配置公钥但版本未提供签名，拒绝安装（防止降级攻击）
			return fmt.Errorf("该版本未提供数字签名，已配置签名公钥时拒绝安装未签名版本")
		}
		// 未配置公钥且无签名：兼容旧版本，跳过验证
		return nil
	}

	if !strings.HasPrefix(expected, "ed25519:") {
		return fmt.Errorf("不支持的签名格式: %s", expected)
	}

	if !hasReleasePublicKeys() {
		// 发布包有签名但未配置公钥，拒绝继续
		return &ErrNoPublicKeys{}
	}

	// 解析签名格式：去掉 "ed25519:" 前缀后按 ":" 分割为 key_id 和 base64
	remainder := strings.TrimPrefix(expected, "ed25519:")
	parts := strings.SplitN(remainder, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return fmt.Errorf("签名格式无效，期望 ed25519:<key_id>:<base64>")
	}

	keyID := parts[0]
	sigB64 := parts[1]

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("签名 base64 解码失败: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("签名长度无效: 期望 %d 字节, 实际 %d 字节", ed25519.SignatureSize, len(sig))
	}

	// 按 key ID 查找公钥
	releaseKeysMu.RLock()
	pubKey, ok := releasePublicKeys[keyID]
	releaseKeysMu.RUnlock()
	if !ok {
		return &ErrKeyNotFound{KeyID: keyID}
	}
	if !ed25519.Verify(pubKey, data, sig) {
		return fmt.Errorf("签名验证失败: 文件可能被篡改")
	}
	return nil
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
	return installTo(gzData, GetBinaryPath())
}

// installTo 内部实现，接受目标路径参数（便于测试）
func installTo(gzData []byte, binPath string) (string, error) {
	// 解压 gzip
	gzReader, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		return "", fmt.Errorf("解压失败: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	// 写入临时文件（限制解压大小，防止 gzip 炸弹）
	tmpFile, err := os.CreateTemp("", "sslctl-*")
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()

	written, err := io.Copy(tmpFile, io.LimitReader(gzReader, maxDownloadSize+1))
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("写入文件失败: %w", err)
	}
	_ = tmpFile.Close()
	if written > maxDownloadSize {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("解压后文件大小超过限制 (%d bytes)", maxDownloadSize)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("创建目录失败: %w", err)
	}

	// 移动文件到目标位置（临时文件保持 0600，在最终路径设置权限）
	// 设计说明：Rename 和 Chmod 非原子，微秒级窗口内二进制为 0600 不可执行。
	// 这是有意的安全取舍：避免在 /tmp 中出现 0755 的可执行文件。
	// 若进程在窗口期崩溃，下次升级会覆盖。
	if err := os.Rename(tmpPath, binPath); err != nil {
		// 跨文件系统移动，使用复制（copyFile 内部设置 0755 权限）
		if copyErr := copyFile(tmpPath, binPath); copyErr != nil {
			_ = os.Remove(tmpPath)
			return "", copyErr
		}
		_ = os.Remove(tmpPath)
	} else {
		// Rename 成功后在最终路径设置执行权限
		if err := os.Chmod(binPath, 0755); err != nil {
			return "", fmt.Errorf("设置权限失败: %w", err)
		}
	}

	return binPath, nil
}

// GetBinaryPath 获取二进制安装路径
func GetBinaryPath() string {
	if runtime.GOOS == "windows" {
		// Windows: 使用当前可执行文件路径，fallback 到统一目录 C:\sslctl
		if exePath, err := os.Executable(); err == nil {
			return exePath
		}
		return `C:\sslctl\sslctl.exe`
	}
	return "/usr/local/bin/sslctl"
}

// GetDownloadFilename 获取下载文件名（不含版本号，版本在目录路径中体现）
// 格式: sslctl-{os}-{arch}.gz
func GetDownloadFilename() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	if osName == "windows" {
		return fmt.Sprintf("sslctl-%s-%s.exe.gz", osName, arch)
	}
	return fmt.Sprintf("sslctl-%s-%s.gz", osName, arch)
}

// GetDownloadURL 获取下载 URL
// 格式: {baseURL}/{channel}/v{version}/{filename}
func GetDownloadURL(baseURL, channel, version string) string {
	filename := GetDownloadFilename()
	ver := NormalizeVersion(version)
	return fmt.Sprintf("%s/%s/%s/%s", baseURL, channel, ver, filename)
}

// copyFile 复制文件（用于跨文件系统移动）
func copyFile(src, dst string) error {
	// 安全检查：目标路径不能是符号链接（防止任意文件覆盖）
	if info, err := os.Lstat(dst); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("安装失败: 目标路径是符号链接: %s", dst)
	}

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
