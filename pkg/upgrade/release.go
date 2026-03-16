// Package upgrade 版本升级模块
package upgrade

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// 版本信息配置常量
const (
	maxReleaseInfoSize = 1 * 1024 * 1024 // 最大版本信息大小 1MB
)

// VersionInfo 版本详细信息
type VersionInfo struct {
	Checksums  map[string]string `json:"checksums"`            // 文件名 -> sha256:hash
	Signatures map[string]string `json:"signatures,omitempty"` // 文件名 -> ed25519:<base64_signature>
}

// ReleaseInfo 发布信息
type ReleaseInfo struct {
	LatestMain string                 `json:"latest_main"`
	LatestDev    string                 `json:"latest_dev"`
	Versions     map[string]VersionInfo `json:"versions,omitempty"`
}

// FetchReleaseInfo 获取远程版本信息
func FetchReleaseInfo(baseURL string) (*ReleaseInfo, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("未配置升级地址，请重新安装或在配置文件中设置 release_url")
	}
	// 安全校验：强制 HTTPS（与 downloadBinaryWithClient 保持一致）
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("升级地址必须使用 HTTPS 协议")
	}
	return fetchReleaseInfoFrom(baseURL+"/releases.json", secureHTTPClient())
}

// fetchReleaseInfoFrom 内部实现，接受 URL 和 client 参数（便于测试）
func fetchReleaseInfoFrom(url string, client *http.Client) (*ReleaseInfo, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("获取版本信息失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取版本信息失败: HTTP %d", resp.StatusCode)
	}

	// 限制响应体大小，防止恶意服务器返回超大 JSON
	limitReader := io.LimitReader(resp.Body, maxReleaseInfoSize)
	var info ReleaseInfo
	if err := json.NewDecoder(limitReader).Decode(&info); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %w", err)
	}

	return &info, nil
}

// ResolveTarget 确定目标版本和通道
// 返回: 目标版本, 通道, 错误
func ResolveTarget(targetVersion, channel string, info *ReleaseInfo) (string, string, error) {
	var target string
	var ch string

	if targetVersion != "" {
		target = NormalizeVersion(targetVersion)
		if channel != "" {
			ch = channel
		} else if strings.Contains(target, "-") {
			ch = "dev"
		} else {
			ch = "main"
		}
	} else {
		if channel == "dev" {
			target = info.LatestDev
			ch = "dev"
		} else {
			target = info.LatestMain
			ch = "main"
			if target == "" {
				target = info.LatestDev
				ch = "dev"
			}
		}
	}

	if target == "" {
		return "", "", fmt.Errorf("未找到可用版本")
	}

	return target, ch, nil
}

// NormalizeVersion 规范化版本号（确保带 v 前缀）
func NormalizeVersion(ver string) string {
	if !strings.HasPrefix(ver, "v") {
		return "v" + ver
	}
	return ver
}

// CompareVersions 比较两个语义化版本号
// 返回: -1 (a < b), 0 (a == b), 1 (a > b)
// 遵循 semver 规范：主版本号优先比较，pre-release 版本低于同号正式版
func CompareVersions(a, b string) int {
	parseVer := func(v string) ([3]int, string) {
		v = strings.TrimPrefix(v, "v")
		pre := ""
		if idx := strings.Index(v, "-"); idx >= 0 {
			pre = v[idx+1:]
			v = v[:idx]
		}
		parts := strings.Split(v, ".")
		var result [3]int
		for i := 0; i < 3 && i < len(parts); i++ {
			n, _ := strconv.Atoi(parts[i])
			result[i] = n
		}
		return result, pre
	}

	va, preA := parseVer(a)
	vb, preB := parseVer(b)

	// 先比较主版本号
	for i := 0; i < 3; i++ {
		if va[i] < vb[i] {
			return -1
		}
		if va[i] > vb[i] {
			return 1
		}
	}

	// 主版本号相同，比较 pre-release
	// semver: 有 pre-release 的版本 < 无 pre-release 的版本
	if preA == "" && preB == "" {
		return 0
	}
	if preA != "" && preB == "" {
		return -1
	}
	if preA == "" && preB != "" {
		return 1
	}

	// 都有 pre-release 时按字典序比较
	if preA < preB {
		return -1
	}
	if preA > preB {
		return 1
	}
	return 0
}

// GetChecksum 获取指定版本文件的校验和
func (info *ReleaseInfo) GetChecksum(version, filename string) string {
	if info.Versions == nil {
		return ""
	}
	if verInfo, ok := info.Versions[version]; ok {
		return verInfo.Checksums[filename]
	}
	return ""
}

// GetSignature 获取指定版本文件的签名
func (info *ReleaseInfo) GetSignature(version, filename string) string {
	if info.Versions == nil {
		return ""
	}
	if verInfo, ok := info.Versions[version]; ok {
		return verInfo.Signatures[filename]
	}
	return ""
}
