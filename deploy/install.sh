#!/bin/bash
# cert-deploy 安装脚本
# 自动检测系统、架构和 Web 服务，下载对应的部署工具

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo_error "请使用 root 权限运行此脚本"
    exit 1
fi

# 检测系统
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ] && [ "$OS" != "darwin" ]; then
    echo_error "不支持的操作系统: $OS"
    exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo_error "不支持的架构: $ARCH"
        exit 1
        ;;
esac

echo_info "系统: $OS, 架构: $ARCH"

# 检测 Web 服务
detect_webservers() {
    local servers=""

    if command -v nginx >/dev/null 2>&1; then
        servers="$servers nginx"
    fi

    if command -v apache2ctl >/dev/null 2>&1 || \
       command -v apachectl >/dev/null 2>&1 || \
       command -v httpd >/dev/null 2>&1; then
        servers="$servers apache"
    fi

    echo "$servers" | xargs
}

TOOLS=$(detect_webservers)

if [ -z "$TOOLS" ]; then
    echo_warn "未检测到 Nginx 或 Apache，将安装 nginx 版本"
    TOOLS="nginx"
fi

echo_info "将安装: $TOOLS"

# 获取最新版本号
get_latest_version() {
    local version=""

    # 优先 Gitee
    version=$(curl -s --connect-timeout 5 "https://gitee.com/api/v5/repos/zhuxbo/cert-deploy/releases/latest" 2>/dev/null | grep -o '"tag_name":"[^"]*' | cut -d'"' -f4)

    # 回退 GitHub
    if [ -z "$version" ]; then
        version=$(curl -s --connect-timeout 5 "https://api.github.com/repos/zhuxbo/cert-deploy/releases" 2>/dev/null | grep -o '"tag_name": "[^"]*' | head -1 | cut -d'"' -f4)
    fi

    echo "$version"
}

echo_info "获取最新版本..."
VERSION=$(get_latest_version)

if [ -z "$VERSION" ]; then
    echo_error "无法获取版本信息"
    exit 1
fi

echo_info "最新版本: $VERSION"

# 下载函数
download_file() {
    local filename=$1
    local gitee_url="https://gitee.com/zhuxbo/cert-deploy/releases/download/$VERSION/$filename"
    local github_url="https://github.com/zhuxbo/cert-deploy/releases/download/$VERSION/$filename"
    local output="/tmp/$filename"

    if curl -fsSL --connect-timeout 10 "$gitee_url" -o "$output" 2>/dev/null; then
        return 0
    fi

    echo_warn "Gitee 下载失败，尝试 GitHub..."
    if curl -fsSL --connect-timeout 10 "$github_url" -o "$output" 2>/dev/null; then
        return 0
    fi

    return 1
}

# 下载并安装
for TOOL in $TOOLS; do
    FILENAME="cert-deploy-${TOOL}-${OS}-${ARCH}.gz"
    BINARY_NAME="cert-deploy-${TOOL}-${OS}-${ARCH}"

    echo_info "下载 cert-deploy-${TOOL}..."

    if ! download_file "$FILENAME"; then
        echo_error "下载 $FILENAME 失败"
        exit 1
    fi

    # 解压
    gunzip -f "/tmp/$FILENAME"

    # 安装
    mv "/tmp/$BINARY_NAME" "/usr/local/bin/cert-deploy-${TOOL}"
    chmod +x "/usr/local/bin/cert-deploy-${TOOL}"

    echo_info "已安装 cert-deploy-${TOOL} 到 /usr/local/bin/"
done

echo ""
echo_info "安装完成！"
echo ""
echo "使用方法:"
for TOOL in $TOOLS; do
    echo "  cert-deploy-${TOOL} -help    # 查看帮助"
    echo "  cert-deploy-${TOOL} -scan    # 扫描站点"
done
