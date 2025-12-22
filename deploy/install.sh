#!/bin/bash
# cert-deploy 安装脚本

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo_error "请使用 root 权限运行此脚本"
    exit 1
fi

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    echo_info "检测到操作系统: $OS"
}

# 创建目录
create_dirs() {
    echo_info "创建工作目录..."
    mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}
    chmod 755 /opt/cert-deploy
    chmod 700 /opt/cert-deploy/backup
}

# 安装二进制文件
install_binaries() {
    echo_info "安装二进制文件..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    BIN_DIR="$SCRIPT_DIR/../bin"

    if [ -f "$BIN_DIR/cert-deploy-nginx" ]; then
        cp "$BIN_DIR/cert-deploy-nginx" /usr/local/bin/
        chmod +x /usr/local/bin/cert-deploy-nginx
        echo_info "已安装 cert-deploy-nginx"
    else
        echo_warn "未找到 cert-deploy-nginx 二进制文件"
    fi

    if [ -f "$BIN_DIR/cert-deploy-apache" ]; then
        cp "$BIN_DIR/cert-deploy-apache" /usr/local/bin/
        chmod +x /usr/local/bin/cert-deploy-apache
        echo_info "已安装 cert-deploy-apache"
    else
        echo_warn "未找到 cert-deploy-apache 二进制文件"
    fi

    if [ -f "$BIN_DIR/cert-deploy-iis" ]; then
        cp "$BIN_DIR/cert-deploy-iis" /usr/local/bin/
        chmod +x /usr/local/bin/cert-deploy-iis
        echo_info "已安装 cert-deploy-iis"
    else
        echo_warn "未找到 cert-deploy-iis 二进制文件"
    fi
}

# 安装 systemd 服务
install_systemd() {
    echo_info "安装 systemd 服务..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SYSTEMD_DIR="$SCRIPT_DIR/systemd"

    if [ -f "$SYSTEMD_DIR/cert-deploy-nginx.service" ]; then
        cp "$SYSTEMD_DIR/cert-deploy-nginx.service" /etc/systemd/system/
        echo_info "已安装 cert-deploy-nginx.service"
    fi

    if [ -f "$SYSTEMD_DIR/cert-deploy-apache.service" ]; then
        cp "$SYSTEMD_DIR/cert-deploy-apache.service" /etc/systemd/system/
        echo_info "已安装 cert-deploy-apache.service"
    fi

    systemctl daemon-reload
}

# 启用服务
enable_service() {
    local service=$1

    if [ -f "/etc/systemd/system/$service.service" ]; then
        echo_info "启用 $service 服务..."
        systemctl enable "$service"
        systemctl start "$service"
        echo_info "$service 服务已启动"
    else
        echo_warn "$service 服务文件不存在"
    fi
}

# 显示使用帮助
show_help() {
    echo "
cert-deploy 安装完成！

使用方法:
  # 扫描 Nginx SSL 站点
  cert-deploy-nginx -scan

  # 部署指定站点
  cert-deploy-nginx -site example.com

  # 启动守护进程
  cert-deploy-nginx -daemon

  # 使用 systemd 管理
  systemctl start cert-deploy-nginx
  systemctl enable cert-deploy-nginx
  systemctl status cert-deploy-nginx

配置目录: /opt/cert-deploy/
  - sites/    站点配置 (*.json)
  - logs/     日志文件
  - backup/   证书备份
  - certs/    临时证书

日志查看:
  journalctl -u cert-deploy-nginx -f
  cat /opt/cert-deploy/logs/nginx-*.log
"
}

# 主流程
main() {
    echo "========================================"
    echo "    cert-deploy 安装脚本"
    echo "========================================"
    echo ""

    detect_os
    create_dirs
    install_binaries
    install_systemd

    echo ""
    echo_info "安装完成！"
    show_help

    echo ""
    echo -n "是否启用 Nginx 证书部署服务？[y/N] "
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        enable_service "cert-deploy-nginx"
    fi
}

main "$@"
