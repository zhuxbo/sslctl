#!/bin/bash
# sslctl 本地构建测试脚本
#
# 用途: 本地测试构建，验证代码是否能正常编译
# 发布请使用 GitHub Actions (推送 tag 自动触发)
#
# 用法: ./scripts/build.sh [版本号]
# 示例: ./scripts/build.sh v0.3.0

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# 版本号
VERSION="${1:-dev}"

info "版本: $VERSION"

# Step 1: 运行测试
info "Step 1/2: 运行测试..."
if ! go test ./... 2>&1; then
    error "测试失败"
fi
info "✓ 测试通过"

# Step 2: 构建所有平台
info "Step 2/2: 构建所有平台..."
BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
LDFLAGS="-s -w -X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}'"

rm -rf dist
mkdir -p dist

# Linux
info "  构建 Linux..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/sslctl-linux-amd64 ./cmd
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o dist/sslctl-linux-arm64 ./cmd

# Windows
info "  构建 Windows..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/sslctl-windows-amd64.exe ./cmd

info "✓ 构建完成"
echo ""
ls -lh dist/
echo ""
info "发布请推送 tag 到 GitHub 触发 CI:"
info "  git tag v0.x.0"
info "  git push github v0.x.0"
