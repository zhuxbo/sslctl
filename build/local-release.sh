#!/bin/bash

# cert-deploy 本地发布脚本
# 构建并发布到本地目录
#
# 用法:
#   ./local-release.sh              # 发布 version.json 中的版本
#   ./local-release.sh 0.0.10-beta  # 发布指定版本
#   ./local-release.sh --upload-only # 只复制，跳过构建

set -e

# ========================================
# 配置
# ========================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/local-release.conf"
DIST_DIR="$PROJECT_ROOT/dist"

# 默认配置
KEEP_VERSIONS=5

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "\n${GREEN}==>${NC} $1"; }

# ========================================
# 加载配置
# ========================================
load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在: $CONFIG_FILE"
        log_info "请复制 local-release.conf.example 并配置:"
        log_info "  cp $SCRIPT_DIR/local-release.conf.example $CONFIG_FILE"
        exit 1
    fi

    source "$CONFIG_FILE"

    if [ -z "$RELEASE_DIR" ]; then
        log_error "未配置 RELEASE_DIR"
        exit 1
    fi
}

# ========================================
# 确定发布通道
# ========================================
get_channel() {
    local version="$1"
    if [[ "$version" == *"-"* ]]; then
        echo "dev"
    else
        echo "stable"
    fi
}

# ========================================
# 更新 releases.json
# ========================================
update_releases_json() {
    local version="$1"
    local channel="$2"

    log_info "更新 releases.json..."

    local releases_file="$RELEASE_DIR/releases.json"
    local version_dir="$channel/v$version"

    python3 << PYEOF
import json
import os
from datetime import datetime

releases_file = '$releases_file'
version = '$version'
channel = '$channel'
version_dir = '$version_dir'

# 读取现有数据
data = {'channels': {}}
if os.path.exists(releases_file):
    try:
        with open(releases_file, 'r') as f:
            data = json.load(f)
    except:
        pass

if 'channels' not in data:
    data['channels'] = {}

if channel not in data['channels']:
    data['channels'][channel] = {'versions': []}

# 添加新版本
versions = data['channels'][channel]['versions']
version_entry = {
    'version': version,
    'date': datetime.now().strftime('%Y-%m-%d'),
    'path': version_dir,
    'files': {
        'linux-amd64': f'{version_dir}/cert-deploy-linux-amd64.gz',
        'linux-arm64': f'{version_dir}/cert-deploy-linux-arm64.gz',
        'windows-amd64': f'{version_dir}/cert-deploy-windows-amd64.exe.gz'
    }
}

# 检查版本是否已存在
existing = [i for i, v in enumerate(versions) if v['version'] == version]
if existing:
    versions[existing[0]] = version_entry
else:
    versions.insert(0, version_entry)

# 更新 latest
data['channels'][channel]['latest'] = version

# 更新顶级 latest 字段（便于简单解析）
data['latest_stable'] = data['channels'].get('stable', {}).get('latest', '')
data['latest_dev'] = data['channels'].get('dev', {}).get('latest', '')

# 写入文件
with open(releases_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f'已更新 releases.json: {channel}/{version}')
PYEOF
}

# ========================================
# 清理旧版本
# ========================================
cleanup_old_versions() {
    local channel="$1"

    log_info "清理旧版本（保留 $KEEP_VERSIONS 个）..."

    local channel_dir="$RELEASE_DIR/$channel"
    if [ -d "$channel_dir" ]; then
        cd "$channel_dir"
        # 安全的目录清理：逐行处理避免文件名解析问题
        local count=0
        ls -dt v* 2>/dev/null | while IFS= read -r dir; do
            count=$((count + 1))
            if [ "$count" -gt "$KEEP_VERSIONS" ] && [ -d "$dir" ]; then
                rm -rf "$dir"
            fi
        done
        # 同步更新 releases.json
        sync_releases_json "$channel"
    fi
}

# ========================================
# 同步 releases.json（移除已删除版本）
# ========================================
sync_releases_json() {
    local channel="$1"
    local releases_file="$RELEASE_DIR/releases.json"
    local channel_dir="$RELEASE_DIR/$channel"

    if [ ! -f "$releases_file" ]; then
        return
    fi

    python3 << PYEOF
import json
import os

releases_file = '$releases_file'
channel = '$channel'
channel_dir = '$channel_dir'

with open(releases_file, 'r') as f:
    data = json.load(f)

if 'channels' not in data or channel not in data['channels']:
    exit(0)

# 获取实际存在的版本目录
existing = set()
if os.path.isdir(channel_dir):
    for d in os.listdir(channel_dir):
        if d.startswith('v'):
            existing.add(d[1:])  # 去掉 v 前缀

# 过滤掉已删除的版本
versions = data['channels'][channel].get('versions', [])
data['channels'][channel]['versions'] = [v for v in versions if v['version'] in existing]

# 更新顶级 latest 字段
data['latest_stable'] = data['channels'].get('stable', {}).get('latest', '')
data['latest_dev'] = data['channels'].get('dev', {}).get('latest', '')

with open(releases_file, 'w') as f:
    json.dump(data, f, indent=2)
PYEOF
}

# ========================================
# 更新符号链接
# ========================================
update_symlinks() {
    local version="$1"
    local channel="$2"

    log_info "更新符号链接..."

    local latest_dir="$RELEASE_DIR/latest"
    [ "$channel" = "dev" ] && latest_dir="$RELEASE_DIR/dev-latest"

    local version_dir="$RELEASE_DIR/$channel/v$version"

    mkdir -p "$latest_dir"
    cd "$latest_dir"

    for pkg in "$version_dir"/*.gz; do
        if [ -f "$pkg" ]; then
            filename=$(basename "$pkg")
            rm -f "$filename"
            ln -s "../$channel/v$version/$filename" "$filename"
        fi
    done
}

# ========================================
# 发布到本地
# ========================================
deploy_local() {
    local version="$1"
    local channel="$2"

    log_step "发布到本地目录..."

    local version_dir="$RELEASE_DIR/$channel/v$version"

    # 创建目录
    log_info "创建目录: $version_dir"
    mkdir -p "$version_dir"
    rm -f "$version_dir"/*.gz

    # 复制文件
    log_info "复制文件..."
    for pkg in "$DIST_DIR"/*.gz; do
        if [ -f "$pkg" ]; then
            filename=$(basename "$pkg")
            log_info "  复制: $filename"
            cp "$pkg" "$version_dir/"
        fi
    done

    # 复制 install.sh
    log_info "复制 install.sh..."
    cp "$PROJECT_ROOT/deploy/install.sh" "$RELEASE_DIR/"

    # 更新 releases.json
    update_releases_json "$version" "$channel"

    # 更新符号链接
    update_symlinks "$version" "$channel"

    # 清理旧版本
    cleanup_old_versions "$channel"

    log_success "本地发布完成"
}

# ========================================
# 显示帮助
# ========================================
show_help() {
    cat << EOF
用法: $0 [选项] [版本号]

选项:
  --upload-only     只复制，跳过构建
  -h, --help        显示帮助

示例:
  $0                    发布 version.json 中的版本
  $0 0.0.10-beta        发布指定版本
  $0 --upload-only      只复制已构建的文件
EOF
}

# ========================================
# 主流程
# ========================================
main() {
    local version=""
    local upload_only=false

    # 解析参数
    while [ $# -gt 0 ]; do
        case "$1" in
            --upload-only)
                upload_only=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
            *)
                version="$1"
                shift
                ;;
        esac
    done

    echo ""
    echo "========================================"
    echo "  cert-deploy 本地发布脚本"
    echo "========================================"
    echo ""

    # 加载配置
    load_config

    # 获取版本号
    if [ -z "$version" ]; then
        if [ -f "$PROJECT_ROOT/version.json" ]; then
            version=$(cat "$PROJECT_ROOT/version.json" | grep '"version"' | sed 's/.*: "\(.*\)".*/\1/')
        fi
        if [ -z "$version" ]; then
            log_error "无法获取版本号，请指定版本或检查 version.json"
            exit 1
        fi
    fi

    # 确定通道
    local channel=$(get_channel "$version")

    log_info "版本号: $version"
    log_info "发布通道: $channel"
    log_info "发布目录: $RELEASE_DIR"

    # 构建
    if [ "$upload_only" = false ]; then
        log_step "运行构建..."
        "$SCRIPT_DIR/build.sh" "$version"
    else
        log_info "跳过构建，使用已有包"
    fi

    # 检查构建产物
    if [ ! -d "$DIST_DIR" ] || [ -z "$(ls -A $DIST_DIR/*.gz 2>/dev/null)" ]; then
        log_error "构建产物不存在: $DIST_DIR"
        exit 1
    fi

    # 发布
    deploy_local "$version" "$channel"

    echo ""
    log_success "发布完成！"
    echo ""
    log_info "发布路径: $RELEASE_DIR/$channel/v$version"
    if [ -n "$RELEASE_URL" ]; then
        log_info "下载地址: $RELEASE_URL/releases.json"
    fi
}

main "$@"
