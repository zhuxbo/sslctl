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
	LatestStable     string                 `json:"latest_stable"`
	LatestDev        string                 `json:"latest_dev"`
	MinClientVersion string                 `json:"min_client_version,omitempty"` // 最低客户端版本，低于此版本需重新安装
	UpgradePath      []string               `json:"upgrade_path,omitempty"`       // 链式升级路径（过渡版本列表）
	Versions         map[string]VersionInfo `json:"versions,omitempty"`
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
			ch = "stable"
		}
	} else {
		if channel == "dev" {
			target = info.LatestDev
			ch = "dev"
		} else {
			target = info.LatestStable
			ch = "stable"
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
// 仅比较主版本号部分（忽略 -beta/-dev 等预发布标识）
func CompareVersions(a, b string) int {
	parseVer := func(v string) [3]int {
		v = strings.TrimPrefix(v, "v")
		// 截取 - 之前的部分
		if idx := strings.Index(v, "-"); idx >= 0 {
			v = v[:idx]
		}
		parts := strings.Split(v, ".")
		var result [3]int
		for i := 0; i < 3 && i < len(parts); i++ {
			n, _ := strconv.Atoi(parts[i])
			result[i] = n
		}
		return result
	}

	va, vb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if va[i] < vb[i] {
			return -1
		}
		if va[i] > vb[i] {
			return 1
		}
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
