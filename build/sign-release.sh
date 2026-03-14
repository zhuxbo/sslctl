#!/bin/bash

# 发布包签名脚本
# 使用 Ed25519 私钥对 .gz 文件签名，并更新 releases.json
#
# 用法:
#   ./sign-release.sh --key <私钥文件> --dir <发布目录> --version <版本号> --key-id <key_id>
#
# 支持从 build/release.conf 读取 SIGN_KEY 和 SIGN_KEY_ID 作为默认值（命令行参数优先）
#
# 示例:
#   ./sign-release.sh --key ~/release-key.pem --dir /var/www/sslctl --version v1.0.0 --key-id key-1

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

KEY_FILE=""
RELEASE_DIR=""
VERSION=""
KEY_ID=""

# 从 release.conf 读取默认值（如果存在）
CONF_FILE="$SCRIPT_DIR/release.conf"
if [ -f "$CONF_FILE" ]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
    KEY_FILE="${SIGN_KEY:-}"
    KEY_ID="${SIGN_KEY_ID:-}"
fi

# 解析参数（命令行参数优先于 release.conf）
while [ $# -gt 0 ]; do
    case "$1" in
        --key)
            KEY_FILE="$2"
            shift 2
            ;;
        --dir)
            RELEASE_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --key-id)
            KEY_ID="$2"
            shift 2
            ;;
        -h|--help)
            echo "用法: $0 --key <私钥文件> --dir <发布目录> --version <版本号> --key-id <key_id>"
            echo ""
            echo "选项:"
            echo "  --key      私钥文件路径"
            echo "  --dir      发布目录路径"
            echo "  --version  版本号（如 v1.0.0）"
            echo "  --key-id   密钥 ID（如 key-1）"
            echo ""
            echo "支持从 build/release.conf 读取 SIGN_KEY 和 SIGN_KEY_ID 作为默认值"
            exit 0
            ;;
        *)
            log_error "未知参数: $1"
            exit 1
            ;;
    esac
done

if [ -z "$KEY_FILE" ] || [ -z "$RELEASE_DIR" ] || [ -z "$VERSION" ] || [ -z "$KEY_ID" ]; then
    log_error "缺少必要参数"
    echo "用法: $0 --key <私钥文件> --dir <发布目录> --version <版本号> --key-id <key_id>"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    log_error "私钥文件不存在: $KEY_FILE"
    exit 1
fi

# 确保版本号带 v 前缀
if [[ "$VERSION" != v* ]]; then
    VERSION="v$VERSION"
fi

RELEASES_FILE="$RELEASE_DIR/releases.json"

if [ ! -f "$RELEASES_FILE" ]; then
    log_error "releases.json 不存在: $RELEASES_FILE"
    exit 1
fi

# 检查 Go 是否可用
if ! command -v go &> /dev/null; then
    log_error "需要 Go 环境"
    exit 1
fi

log_info "签名版本: $VERSION"
log_info "发布目录: $RELEASE_DIR"
log_info "Key ID: $KEY_ID"

# 使用 Go 签名并更新 releases.json
SIGN_GO=$(mktemp /tmp/sign-XXXXXX.go)
trap 'rm -f "$SIGN_GO"' EXIT
cat > "$SIGN_GO" << 'GOEOF'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type VersionInfo struct {
	Checksums  map[string]string `json:"checksums"`
	Signatures map[string]string `json:"signatures,omitempty"`
}

type ReleaseInfo struct {
	LatestMain string                    `json:"latest_main"`
	LatestDev    string                    `json:"latest_dev"`
	Channels     json.RawMessage           `json:"channels,omitempty"`
	Versions     map[string]VersionInfo    `json:"versions,omitempty"`
}

func main() {
	keyFile := os.Args[1]
	releasesFile := os.Args[2]
	version := os.Args[3]
	keyID := ""
	if len(os.Args) > 4 {
		keyID = os.Args[4]
	}

	// 读取私钥
	seedB64, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取私钥失败: %v\n", err)
		os.Exit(1)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "解码私钥失败: %v\n", err)
		os.Exit(1)
	}
	privKey := ed25519.NewKeyFromSeed(seed)

	// 读取 releases.json
	data, err := os.ReadFile(releasesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取 releases.json 失败: %v\n", err)
		os.Exit(1)
	}

	var info ReleaseInfo
	if err := json.Unmarshal(data, &info); err != nil {
		fmt.Fprintf(os.Stderr, "解析 releases.json 失败: %v\n", err)
		os.Exit(1)
	}

	if info.Versions == nil {
		info.Versions = make(map[string]VersionInfo)
	}

	verInfo, ok := info.Versions[version]
	if !ok {
		fmt.Fprintf(os.Stderr, "版本 %s 不存在于 releases.json\n", version)
		os.Exit(1)
	}

	if verInfo.Signatures == nil {
		verInfo.Signatures = make(map[string]string)
	}

	// 确定通道
	channel := "main"
	if strings.Contains(version, "-") {
		channel = "dev"
	}

	// 对每个 .gz 文件签名
	releasesDir := filepath.Dir(releasesFile)
	for filename := range verInfo.Checksums {
		filePath := filepath.Join(releasesDir, channel, version, filename)
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取文件 %s 失败: %v\n", filename, err)
			os.Exit(1)
		}

		sig := ed25519.Sign(privKey, fileData)
		sigB64 := base64.StdEncoding.EncodeToString(sig)

		verInfo.Signatures[filename] = fmt.Sprintf("ed25519:%s:%s", keyID, sigB64)

		fmt.Printf("已签名: %s\n", filename)
	}

	info.Versions[version] = verInfo

	// 写回 releases.json
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化 releases.json 失败: %v\n", err)
		os.Exit(1)
	}

	// 原子写入：先写临时文件再 rename，防止崩溃导致文件损坏
	tmpFile, err := os.CreateTemp(filepath.Dir(releasesFile), ".releases-*.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "创建临时文件失败: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(output); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "写入临时文件失败: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()
	if err := os.Rename(tmpPath, releasesFile); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "替换 releases.json 失败: %v\n", err)
		os.Exit(1)
	}
	// 确保 Web 服务器可读
	os.Chmod(releasesFile, 0644)

	fmt.Println("签名完成，releases.json 已更新")
}
GOEOF
go run "$SIGN_GO" "$KEY_FILE" "$RELEASES_FILE" "$VERSION" "$KEY_ID"

log_success "签名完成"
