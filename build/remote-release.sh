#!/bin/bash

# cert-deploy 远程发布脚本
# 将构建产物部署到远程 Linux 服务器
#
# 用法:
#   ./remote-release.sh              # 发布 version.json 中的版本
#   ./remote-release.sh 0.0.10-beta  # 发布指定版本
#   ./remote-release.sh --server cn  # 只发布到指定服务器
#   ./remote-release.sh --test       # 测试 SSH 连接
#   ./remote-release.sh --upload-only # 只上传，跳过构建

set -e

# ========================================
# 配置
# ========================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/remote-release.conf"
DIST_DIR="$PROJECT_ROOT/dist"

# 默认配置
KEEP_VERSIONS=5
SSH_TIMEOUT=10

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
        log_info "请复制 remote-release.conf.example 并配置:"
        log_info "  cp $SCRIPT_DIR/remote-release.conf.example $CONFIG_FILE"
        exit 1
    fi

    # 检查配置文件权限（应为 600）
    local perms=$(stat -c %a "$CONFIG_FILE" 2>/dev/null || stat -f %OLp "$CONFIG_FILE" 2>/dev/null || echo "")
    if [ -n "$perms" ] && [ "$perms" != "600" ]; then
        log_warning "配置文件权限不安全（当前: $perms），建议设置为 600:"
        log_info "  chmod 600 $CONFIG_FILE"
    fi

    # 加载配置
    source "$CONFIG_FILE"

    # 验证必要配置
    if [ ${#SERVERS[@]} -eq 0 ]; then
        log_error "未配置服务器列表 SERVERS"
        exit 1
    fi

    if [ -z "$SSH_USER" ]; then
        log_error "未配置 SSH_USER"
        exit 1
    fi

    if [ -z "$SSH_KEY" ]; then
        log_error "未配置 SSH_KEY"
        exit 1
    fi

    # 展开 SSH_KEY 路径中的 ~
    SSH_KEY="${SSH_KEY/#\~/$HOME}"

    if [ ! -f "$SSH_KEY" ]; then
        log_error "SSH 密钥文件不存在: $SSH_KEY"
        exit 1
    fi
}

# ========================================
# 解析服务器配置
# 格式: "名称,主机,端口,目录,URL"
# ========================================
parse_server() {
    local server_str="$1"
    IFS=',' read -r SERVER_NAME SERVER_HOST SERVER_PORT SERVER_DIR SERVER_URL <<< "$server_str"
    SERVER_PORT=${SERVER_PORT:-22}
}

# ========================================
# SSH 命令封装
# ========================================
ssh_cmd() {
    local host="$1"
    local port="$2"
    shift 2
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
        -p "$port" "$SSH_USER@$host" "$@"
}

rsync_cmd() {
    local src="$1"
    local host="$2"
    local port="$3"
    local dest="$4"
    rsync -avz --progress -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no -p $port" \
        "$src" "$SSH_USER@$host:$dest"
}

# ========================================
# 测试 SSH 连接
# ========================================
test_ssh_connection() {
    local server_str="$1"
    parse_server "$server_str"

    log_info "测试连接: $SERVER_NAME ($SERVER_HOST:$SERVER_PORT)"

    if ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "echo 'SSH 连接成功'" 2>/dev/null; then
        log_success "$SERVER_NAME: 连接成功"
        return 0
    else
        log_error "$SERVER_NAME: 连接失败"
        return 1
    fi
}

test_all_connections() {
    log_step "测试所有服务器连接..."
    local failed=0

    for server in "${SERVERS[@]}"; do
        if ! test_ssh_connection "$server"; then
            failed=$((failed + 1))
        fi
    done

    if [ $failed -gt 0 ]; then
        log_error "$failed 个服务器连接失败"
        return 1
    fi

    log_success "所有服务器连接正常"
    return 0
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
# 远程更新 releases.json
# ========================================
update_releases_json_remote() {
    local server_str="$1"
    local version="$2"
    local channel="$3"

    parse_server "$server_str"

    log_info "更新 releases.json..."

    local releases_file="$SERVER_DIR/releases.json"
    local version_dir="$channel/$version"

    ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "python3 << 'PYEOF'
import json
import os
from datetime import datetime

releases_file = '$releases_file'
version = '$version'
channel = '$channel'
version_dir = '$version_dir'

# 版本号已带 v 前缀
v_version = version if version.startswith('v') else f'v{version}'

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
    'version': v_version,
    'date': datetime.now().strftime('%Y-%m-%d'),
    'path': version_dir,
    'files': {
        'linux-amd64': f'{version_dir}/cert-deploy-linux-amd64.gz',
        'linux-arm64': f'{version_dir}/cert-deploy-linux-arm64.gz',
        'windows-amd64': f'{version_dir}/cert-deploy-windows-amd64.exe.gz'
    }
}

# 检查版本是否已存在（兼容旧版本号格式）
# 比较时去掉 v 前缀
def strip_v(s):
    return s[1:] if s.startswith('v') else s
existing = [i for i, v in enumerate(versions) if strip_v(v['version']) == strip_v(v_version)]
if existing:
    versions[existing[0]] = version_entry
else:
    versions.insert(0, version_entry)

# 更新 latest
data['channels'][channel]['latest'] = v_version

# 更新顶级 latest 字段（便于简单解析）
data['latest_stable'] = data['channels'].get('stable', {}).get('latest', '')
data['latest_dev'] = data['channels'].get('dev', {}).get('latest', '')

# 写入文件
with open(releases_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f'已更新 releases.json: {channel}/{v_version}')
PYEOF"
}

# ========================================
# 远程清理旧版本
# ========================================
cleanup_old_versions_remote() {
    local server_str="$1"
    local channel="$2"

    parse_server "$server_str"

    log_info "清理旧版本（保留 $KEEP_VERSIONS 个）..."

    ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "
        cd $SERVER_DIR/$channel 2>/dev/null || exit 0
        removed=\$(ls -dt v* 2>/dev/null | tail -n +$((KEEP_VERSIONS + 1)))
        if [ -n \"\$removed\" ]; then
            echo \"\$removed\" | xargs -r rm -rf
        fi
    "

    # 同步更新 releases.json
    sync_releases_json_remote "$server_str" "$channel"
}

# ========================================
# 远程同步 releases.json（移除已删除版本）
# ========================================
sync_releases_json_remote() {
    local server_str="$1"
    local channel="$2"

    parse_server "$server_str"

    ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "python3 << 'PYEOF'
import json
import os

releases_file = '$SERVER_DIR/releases.json'
channel = '$channel'
channel_dir = '$SERVER_DIR/$channel'

if not os.path.exists(releases_file):
    exit(0)

with open(releases_file, 'r') as f:
    data = json.load(f)

if 'channels' not in data or channel not in data['channels']:
    exit(0)

# 获取实际存在的版本目录
existing = set()
if os.path.isdir(channel_dir):
    for d in os.listdir(channel_dir):
        if d.startswith('v'):
            existing.add(d[1:])

# 过滤掉已删除的版本
versions = data['channels'][channel].get('versions', [])
data['channels'][channel]['versions'] = [v for v in versions if v['version'] in existing]

# 更新顶级 latest 字段
data['latest_stable'] = data['channels'].get('stable', {}).get('latest', '')
data['latest_dev'] = data['channels'].get('dev', {}).get('latest', '')

with open(releases_file, 'w') as f:
    json.dump(data, f, indent=2)
PYEOF"
}

# ========================================
# 上传到服务器
# ========================================
upload_to_server() {
    local server_str="$1"
    local version="$2"
    local channel="$3"

    parse_server "$server_str"

    log_step "部署到 $SERVER_NAME ($SERVER_HOST)..."

    local remote_version_dir="$SERVER_DIR/$channel/$version"

    # 创建远程目录
    log_info "创建目录: $remote_version_dir"
    ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "mkdir -p $remote_version_dir && rm -f $remote_version_dir/*.gz"

    # 上传包文件
    log_info "上传包文件..."
    for pkg in "$DIST_DIR"/*.gz; do
        if [ -f "$pkg" ]; then
            local filename=$(basename "$pkg")
            log_info "  上传: $filename"
            rsync_cmd "$pkg" "$SERVER_HOST" "$SERVER_PORT" "$remote_version_dir/"
        fi
    done

    # 上传 install.sh
    log_info "上传 install.sh..."
    rsync_cmd "$PROJECT_ROOT/deploy/install.sh" "$SERVER_HOST" "$SERVER_PORT" "$SERVER_DIR/"

    # 更新 releases.json
    update_releases_json_remote "$server_str" "$version" "$channel"

    # 更新 latest 符号链接
    log_info "更新符号链接..."
    local latest_dir="$SERVER_DIR/latest"
    [ "$channel" = "dev" ] && latest_dir="$SERVER_DIR/dev-latest"

    ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "
        mkdir -p $latest_dir
        cd $latest_dir
        for pkg in $remote_version_dir/*.gz; do
            if [ -f \"\$pkg\" ]; then
                filename=\$(basename \"\$pkg\")
                rm -f \"\$filename\"
                ln -s \"../$channel/$version/\$filename\" \"\$filename\"
            fi
        done
    "

    # 清理旧版本
    cleanup_old_versions_remote "$server_str" "$channel"

    log_success "$SERVER_NAME: 部署完成"
}

# ========================================
# 部署到所有服务器
# ========================================
deploy_to_all() {
    local version="$1"
    local channel="$2"
    local target_server="$3"

    local success=0
    local failed=0

    for server in "${SERVERS[@]}"; do
        parse_server "$server"

        # 如果指定了服务器，只部署到该服务器
        if [ -n "$target_server" ] && [ "$SERVER_NAME" != "$target_server" ]; then
            continue
        fi

        if upload_to_server "$server" "$version" "$channel"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
            log_error "$SERVER_NAME: 部署失败"
        fi
    done

    echo ""
    log_step "部署结果汇总"
    log_info "成功: $success 个服务器"
    [ $failed -gt 0 ] && log_error "失败: $failed 个服务器"

    return $failed
}

# ========================================
# 显示帮助
# ========================================
show_help() {
    cat << EOF
用法: $0 [选项] [版本号]

选项:
  --test            测试所有服务器 SSH 连接
  --server NAME     只部署到指定服务器
  --upload-only     只上传，跳过构建
  -h, --help        显示帮助

示例:
  $0                    发布 version.json 中的版本
  $0 0.0.10-beta        发布指定版本
  $0 --server cn        只发布到 cn 服务器
  $0 --test             测试连接
EOF
}

# ========================================
# 主流程
# ========================================
main() {
    local version=""
    local target_server=""
    local upload_only=false
    local test_only=false

    # 解析参数
    while [ $# -gt 0 ]; do
        case "$1" in
            --test)
                test_only=true
                shift
                ;;
            --server)
                target_server="$2"
                shift 2
                ;;
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
    echo "  cert-deploy 远程发布脚本"
    echo "========================================"
    echo ""

    # 加载配置
    load_config

    # 测试模式
    if [ "$test_only" = true ]; then
        test_all_connections
        exit $?
    fi

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

    # 确保版本号带 v 前缀
    if [[ "$version" != v* ]]; then
        version="v$version"
    fi

    log_info "版本号: $version"
    log_info "发布通道: $channel"
    log_info "目标服务器: ${target_server:-全部}"

    # 测试连接
    if ! test_all_connections; then
        log_error "请先解决连接问题"
        exit 1
    fi

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

    # 部署
    deploy_to_all "$version" "$channel" "$target_server"
    local result=$?

    echo ""
    if [ $result -eq 0 ]; then
        log_success "发布完成！"
        echo ""
        log_info "验证命令:"
        for server in "${SERVERS[@]}"; do
            parse_server "$server"
            if [ -z "$target_server" ] || [ "$SERVER_NAME" = "$target_server" ]; then
                echo "  curl $SERVER_URL/releases.json | jq ."
            fi
        done
    else
        log_error "部分服务器发布失败"
    fi

    return $result
}

main "$@"
