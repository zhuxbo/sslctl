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
if [ "$OS" != "linux" ]; then
    echo_error "不支持的操作系统: $OS (仅支持 Linux)"
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

# 检测 Web 服务（优先 nginx）
detect_webserver() {
    if command -v nginx >/dev/null 2>&1; then
        echo "nginx"
        return
    fi

    if command -v apache2ctl >/dev/null 2>&1 || \
       command -v apachectl >/dev/null 2>&1 || \
       command -v httpd >/dev/null 2>&1; then
        echo "apache"
        return
    fi

    # 默认 nginx
    echo "nginx"
}

TOOL=$(detect_webserver)
echo_info "检测到 Web 服务: $TOOL"

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

# 下载
FILENAME="cert-deploy-${TOOL}-${OS}-${ARCH}.gz"
GITEE_URL="https://gitee.com/zhuxbo/cert-deploy/releases/download/$VERSION/$FILENAME"
GITHUB_URL="https://github.com/zhuxbo/cert-deploy/releases/download/$VERSION/$FILENAME"

echo_info "下载 $FILENAME..."

if ! curl -fsSL --connect-timeout 10 "$GITEE_URL" -o "/tmp/$FILENAME" 2>/dev/null; then
    echo_warn "Gitee 下载失败，尝试 GitHub..."
    if ! curl -fsSL --connect-timeout 10 "$GITHUB_URL" -o "/tmp/$FILENAME" 2>/dev/null; then
        echo_error "下载失败"
        exit 1
    fi
fi

# 解压并安装
echo_info "安装中..."
gunzip -f "/tmp/$FILENAME"
mv "/tmp/cert-deploy-${TOOL}-${OS}-${ARCH}" /usr/local/bin/cert-deploy
chmod +x /usr/local/bin/cert-deploy

# 创建工作目录
mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

# 安装 systemd 服务
if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/cert-deploy.service << 'EOF'
[Unit]
Description=Certificate Deploy Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cert-deploy -daemon
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=/opt/cert-deploy
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/cert-deploy /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo_info "已安装 systemd 服务: cert-deploy"
fi

echo ""
echo_info "安装完成！"
echo ""
echo "使用方法:"
echo "  cert-deploy -scan              # 扫描 SSL 站点"
echo "  cert-deploy -site example.com  # 部署证书"
echo "  cert-deploy -h                 # 查看帮助"
echo ""
echo "启动守护进程:"
echo "  systemctl enable cert-deploy   # 开机自启"
echo "  systemctl start cert-deploy    # 启动服务"
echo ""
echo "配置目录: /opt/cert-deploy/sites/"
