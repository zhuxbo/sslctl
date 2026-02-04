// Package upgrade 版本升级模块
package upgrade

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ReleaseURL 发布信息 URL
const ReleaseURL = "https://sslctl.cnssl.com"

// VersionInfo 版本详细信息
type VersionInfo struct {
	Checksums map[string]string `json:"checksums"` // 文件名 -> sha256:hash
}

// ReleaseInfo 发布信息
type ReleaseInfo struct {
	LatestStable string                 `json:"latest_stable"`
	LatestDev    string                 `json:"latest_dev"`
	Versions     map[string]VersionInfo `json:"versions,omitempty"`
}

// FetchReleaseInfo 获取远程版本信息
func FetchReleaseInfo() (*ReleaseInfo, error) {
	resp, err := http.Get(ReleaseURL + "/releases.json")
	if err != nil {
		return nil, fmt.Errorf("获取版本信息失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var info ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
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
