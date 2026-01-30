#!/bin/bash
# 构建脚本 - 多平台交叉编译
# 用法: ./build.sh [version]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_DIR}/dist"

# 检测 Go 路径
if command -v go &>/dev/null; then
    GO_CMD="go"
elif [ -x "/usr/local/go/bin/go" ]; then
    GO_CMD="/usr/local/go/bin/go"
else
    echo "Error: Go not found"
    exit 1
fi

# 读取版本号
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(cat "${PROJECT_DIR}/version.json" | grep '"version"' | sed 's/.*: "\(.*\)".*/\1/')
fi

BUILD_TIME=$(date -u +%Y-%m-%d)
LDFLAGS="-s -w -X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}'"

echo "Building cert-deploy ${VERSION} (${BUILD_TIME})"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 构建目标
TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
)

for target in "${TARGETS[@]}"; do
    GOOS="${target%/*}"
    GOARCH="${target#*/}"

    OUTPUT_NAME="cert-deploy-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "  Building ${GOOS}/${GOARCH}..."

    cd "$PROJECT_DIR"
    GOOS="$GOOS" GOARCH="$GOARCH" $GO_CMD build -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/${OUTPUT_NAME}" ./cmd/main.go

    # 压缩
    if [ "$GOOS" = "windows" ]; then
        gzip -kf "${OUTPUT_DIR}/${OUTPUT_NAME}"
    else
        gzip -kf "${OUTPUT_DIR}/${OUTPUT_NAME}"
    fi

    echo "    -> ${OUTPUT_NAME}.gz"
done

echo ""
echo "Build complete! Output: ${OUTPUT_DIR}"
ls -lh "$OUTPUT_DIR"
