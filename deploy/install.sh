#!/bin/bash
# sslctl 安装脚本
# 自动检测系统和架构，下载部署工具

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Release 服务器（由发布脚本自动替换）
RELEASE_URL="__RELEASE_URL__"
# 去掉末尾斜杠，避免拼接出错
RELEASE_URL="${RELEASE_URL%/}"

# 检测占位符未被替换（直接运行源码中的脚本）
if [[ "$RELEASE_URL" != https://* ]]; then
    echo_error "安装脚本未正确配置，请从官方渠道下载安装脚本"
    exit 1
fi

# 参数解析
CHANNEL=""          # 空=自动，main/dev=指定
TARGET_VERSION=""   # 空=最新，指定=使用该版本
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)
            CHANNEL="dev"
            shift
            ;;
        --main)
            CHANNEL="main"
            shift
            ;;
        --version)
            TARGET_VERSION="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help|-h)
            echo "用法: install.sh [选项]"
            echo ""
            echo "选项:"
            echo "  --dev          安装测试版（dev 通道）"
            echo "  --main       安装稳定版（main 通道，默认）"
            echo "  --version VER  安装指定版本"
            echo "  --force        强制重新安装（即使版本相同）"
            echo "  --help         显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  install.sh                      # 安装最新稳定版"
            echo "  install.sh --dev                # 安装最新测试版"
            echo "  install.sh --version 1.0.0      # 安装指定版本"
            echo "  install.sh --dev --version 1.0.1-dev  # 安装指定测试版"
            echo "  install.sh --force              # 强制重新安装"
            exit 0
            ;;
        *)
            echo_error "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
done

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

# 检测 Web 服务
detect_webserver() {
    local services=""
    if command -v nginx >/dev/null 2>&1; then
        services="nginx"
    fi

    if command -v apache2ctl >/dev/null 2>&1 || \
       command -v apachectl >/dev/null 2>&1 || \
       command -v httpd >/dev/null 2>&1; then
        if [ -n "$services" ]; then
            services="$services, apache"
        else
            services="apache"
        fi
    fi

    echo "$services"
}

SERVICES=$(detect_webserver)
if [ -n "$SERVICES" ]; then
    echo_info "检测到 Web 服务: $SERVICES"
else
    echo_warn "未检测到 nginx 或 apache，仍可继续安装"
fi

# 规范化版本号（确保带 v 前缀）
normalize_version() {
    local ver="$1"
    if [[ "$ver" != v* ]]; then
        echo "v$ver"
    else
        echo "$ver"
    fi
}

# 获取目标版本
get_target_version() {
    # 如果指定了版本，直接使用
    if [ -n "$TARGET_VERSION" ]; then
        # 自动推断通道（除非已指定）
        if [ -z "$CHANNEL" ]; then
            if [[ "$TARGET_VERSION" == *"-"* ]]; then
                CHANNEL="dev"
            else
                CHANNEL="main"
            fi
        fi
        # 规范化版本号
        echo "$(normalize_version "$TARGET_VERSION")"
        return
    fi

    # 获取最新版本
    local json
    json=$(curl -s --connect-timeout 10 "$RELEASE_URL/releases.json" 2>/dev/null)
    if [ -z "$json" ]; then
        echo ""
        return
    fi

    local version=""
    if [ "$CHANNEL" = "dev" ]; then
        version=$(echo "$json" | grep -o '"latest_dev" *: *"[^"]*"' | cut -d'"' -f4)
    elif [ "$CHANNEL" = "main" ]; then
        version=$(echo "$json" | grep -o '"latest_main" *: *"[^"]*"' | cut -d'"' -f4)
    else
        # 默认：优先 main
        version=$(echo "$json" | grep -o '"latest_main" *: *"[^"]*"' | cut -d'"' -f4)
        [ -z "$version" ] && version=$(echo "$json" | grep -o '"latest_dev" *: *"[^"]*"' | cut -d'"' -f4)
    fi

    # 自动推断通道
    if [ -z "$CHANNEL" ] && [ -n "$version" ]; then
        if [[ "$version" == *"-"* ]]; then
            CHANNEL="dev"
        else
            CHANNEL="main"
        fi
    fi

    echo "$version"
}

echo_info "获取目标版本..."
VERSION=$(get_target_version)

if [ -z "$VERSION" ]; then
    echo_error "无法获取版本信息"
    exit 1
fi

# 子 shell 中设置的 CHANNEL 不会传回，在此推断
if [ -z "$CHANNEL" ]; then
    if [[ "$VERSION" == *"-"* ]]; then
        CHANNEL="dev"
    else
        CHANNEL="main"
    fi
fi

# 显示通道信息
if [ "$CHANNEL" = "dev" ]; then
    echo_info "目标版本: $VERSION (测试版)"
else
    echo_info "目标版本: $VERSION (稳定版)"
fi

# 检测已安装版本
CURRENT_VERSION=""
if [ -x /usr/local/bin/sslctl ]; then
    CURRENT_VERSION=$(/usr/local/bin/sslctl --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?' || echo "")
    # 规范化为带 v 前缀
    [ -n "$CURRENT_VERSION" ] && CURRENT_VERSION=$(normalize_version "$CURRENT_VERSION")
fi

# 版本比较
if [ -n "$CURRENT_VERSION" ]; then
    if [ "$CURRENT_VERSION" = "$VERSION" ]; then
        if [ "$FORCE" = true ]; then
            echo_info "当前版本: $CURRENT_VERSION，强制重新安装"
        else
            echo_info "当前版本 $CURRENT_VERSION 已是目标版本，使用 --force 强制重新安装"
            exit 0
        fi
    else
        echo_info "升级: $CURRENT_VERSION → $VERSION"
    fi
fi

# 下载
FILENAME="sslctl-${OS}-${ARCH}.gz"
DOWNLOAD_URL="$RELEASE_URL/$CHANNEL/$VERSION/$FILENAME"

echo_info "下载 $FILENAME..."

if ! curl -fsSL --connect-timeout 30 "$DOWNLOAD_URL" -o "/tmp/$FILENAME" 2>/dev/null; then
    echo_error "下载失败: $DOWNLOAD_URL"
    exit 1
fi

# SHA256 校验（从 versions.$VERSION.checksums.$FILENAME 精确提取）
EXPECTED_HASH=""
if command -v python3 >/dev/null 2>&1; then
    EXPECTED_HASH=$(curl -s --connect-timeout 10 "$RELEASE_URL/releases.json" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    h = d.get('versions',{}).get('$VERSION',{}).get('checksums',{}).get('$FILENAME','')
    if h.startswith('sha256:'):
        print(h[7:])
except: pass
" 2>/dev/null)
fi
if [ -n "$EXPECTED_HASH" ]; then
    ACTUAL_HASH=$(sha256sum "/tmp/$FILENAME" 2>/dev/null | cut -d' ' -f1)
    [ -z "$ACTUAL_HASH" ] && ACTUAL_HASH=$(shasum -a 256 "/tmp/$FILENAME" 2>/dev/null | cut -d' ' -f1)
    if [ -z "$ACTUAL_HASH" ]; then
        echo_error "无法计算 SHA256，中止安装"
        rm -f "/tmp/$FILENAME"
        exit 1
    fi
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo_error "SHA256 校验失败: 文件可能被篡改"
        echo_error "  期望: $EXPECTED_HASH"
        echo_error "  实际: $ACTUAL_HASH"
        rm -f "/tmp/$FILENAME"
        exit 1
    fi
    echo_info "SHA256 校验通过"
else
    echo_warn "无法获取校验和（需要 python3），跳过 SHA256 校验"
fi

# 解压并安装
echo_info "安装中..."
gunzip -f "/tmp/$FILENAME"
mv "/tmp/sslctl-${OS}-${ARCH}" /usr/local/bin/sslctl
chmod +x /usr/local/bin/sslctl

# 创建工作目录
mkdir -p /opt/sslctl/{logs,backup,certs}

# 写入 release_url 到配置文件
CONFIG_FILE="/opt/sslctl/config.json"
if [ -f "$CONFIG_FILE" ]; then
    # 配置已存在，合并 release_url（不覆盖其他字段）
    if command -v python3 >/dev/null 2>&1; then
        # 使用 python3 解析并原子写回，解析失败不覆盖原文件
        if ! python3 - "$CONFIG_FILE" "$RELEASE_URL" << 'PYEOF'
import json
import os
import sys
import tempfile

config_path = sys.argv[1]
release_url = sys.argv[2]

try:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except json.JSONDecodeError:
    print("配置解析失败，未修改 release_url", file=sys.stderr)
    sys.exit(1)
except FileNotFoundError:
    print("配置文件不存在", file=sys.stderr)
    sys.exit(1)

cfg["release_url"] = release_url

dir_path = os.path.dirname(config_path) or "."
with tempfile.NamedTemporaryFile("w", delete=False, dir=dir_path, encoding="utf-8") as tmp:
    json.dump(cfg, tmp, indent=2, ensure_ascii=False)
    tmp_path = tmp.name

os.replace(tmp_path, config_path)
PYEOF
        then
            echo_error "写入 release_url 失败，配置未修改"
            exit 1
        fi
        chmod 600 "$CONFIG_FILE"
    elif command -v jq >/dev/null 2>&1; then
        # 使用 jq 解析并原子写回，解析失败不覆盖原文件
        tmp_file=$(mktemp)
        if jq --arg url "$RELEASE_URL" '.release_url = $url' "$CONFIG_FILE" > "$tmp_file"; then
            mv "$tmp_file" "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
        else
            rm -f "$tmp_file"
            echo_error "配置解析失败，未修改 release_url"
            exit 1
        fi
    else
        echo_error "未找到 python3 或 jq，无法写入 release_url"
        exit 1
    fi
else
    # 首次安装，创建最小配置
    cat > "$CONFIG_FILE" << CFGEOF
{
  "release_url": "$RELEASE_URL"
}
CFGEOF
    chmod 600 "$CONFIG_FILE"
fi

# 检测 init 系统
detect_init_system() {
    # 检测 systemd
    if [ -d /run/systemd/system ]; then
        echo "systemd"
        return
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-system-running >/dev/null 2>&1; then
            echo "systemd"
            return
        fi
    fi

    # 检测 OpenRC
    if command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
        return
    fi
    if [ -f /sbin/openrc ]; then
        echo "openrc"
        return
    fi

    # 检测 SysVinit
    if [ -d /etc/init.d ]; then
        echo "sysvinit"
        return
    fi

    echo "unknown"
}

INIT_SYSTEM=$(detect_init_system)
echo_info "检测到 init 系统: $INIT_SYSTEM"

# 安装服务（仅首次安装时创建，升级时保留现有配置）
install_service() {
    local DAEMON_CMD="/usr/local/bin/sslctl daemon"

    case "$INIT_SYSTEM" in
        systemd)
            if [ ! -f /etc/systemd/system/sslctl.service ]; then
                cat > /etc/systemd/system/sslctl.service << EOF
[Unit]
Description=SSL Certificate Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DAEMON_CMD
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=/opt/sslctl
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/sslctl /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable sslctl
                systemctl start sslctl
                echo_info "已安装并启动 systemd 服务"
            fi
            ;;
        openrc)
            if [ ! -f /etc/init.d/sslctl ]; then
                cat > /etc/init.d/sslctl << 'EOF'
#!/sbin/openrc-run

name="sslctl"
description="SSL Certificate Manager"
command="/usr/local/bin/sslctl"
command_args="daemon"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/opt/sslctl"

depend() {
    need net
    after firewall
}
EOF
                chmod +x /etc/init.d/sslctl
                rc-update add sslctl default
                rc-service sslctl start
                echo_info "已安装并启动 OpenRC 服务"
            fi
            ;;
        sysvinit)
            if [ ! -f /etc/init.d/sslctl ]; then
                cat > /etc/init.d/sslctl << 'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sslctl
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SSL Certificate Manager
# Description:       SSL 证书自动部署服务
### END INIT INFO

NAME="sslctl"
DAEMON="/usr/local/bin/sslctl"
DAEMON_ARGS="daemon"
PIDFILE="/var/run/${NAME}.pid"
WORKDIR="/opt/sslctl"

read_pid() {
    local pid=""
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null)
        # 验证 PID 为纯数字
        if [ -n "$pid" ] && [ "$pid" -eq "$pid" ] 2>/dev/null; then
            echo "$pid"
        fi
    fi
}

start() {
    echo "Starting $NAME..."
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is already running"
        return 1
    fi
    cd "$WORKDIR"
    nohup "$DAEMON" $DAEMON_ARGS > /dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "$NAME started"
}

stop() {
    echo "Stopping $NAME..."
    if [ ! -f "$PIDFILE" ]; then
        echo "$NAME is not running"
        return 1
    fi
    local pid=$(read_pid)
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null
    fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
}

status() {
    local pid=$(read_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$NAME is running (PID: $pid)"
        return 0
    else
        echo "$NAME is not running"
        return 1
    fi
}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    *)       echo "Usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF
                chmod +x /etc/init.d/sslctl

                # Debian/Ubuntu
                if command -v update-rc.d >/dev/null 2>&1; then
                    update-rc.d sslctl defaults
                # CentOS/RHEL
                elif command -v chkconfig >/dev/null 2>&1; then
                    chkconfig --add sslctl
                    chkconfig sslctl on
                fi

                /etc/init.d/sslctl start
                echo_info "已安装并启动 SysVinit 服务"
            fi
            ;;
        *)
            echo_warn "未知的 init 系统，跳过服务安装"
            echo_warn "请手动运行: sslctl daemon"
            ;;
    esac
}

install_service

echo ""
echo_info "安装完成！"
echo ""
echo "使用方法:"
echo "  sslctl scan                           # 扫描站点"
echo "  sslctl deploy --site example.com      # 部署证书"
echo "  sslctl status                         # 查看服务状态"
echo "  sslctl upgrade                        # 升级工具"
echo "  sslctl service repair                 # 修复服务"
echo "  sslctl --debug scan                   # 调试模式"
echo "  sslctl help                           # 查看帮助"
echo ""
echo "配置文件: /opt/sslctl/config.json"
