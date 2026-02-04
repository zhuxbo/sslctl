#!/bin/bash
# sslctl 测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查参数
DISTRO="${1:-ubuntu}"
REFER_ID="${2:-}"

VALID_DISTROS="ubuntu debian centos alpine"

if [[ -z "$REFER_ID" ]]; then
    log_error "用法: $0 <distro> <refer_id>"
    log_error "  distro: $VALID_DISTROS"
    log_error "  refer_id: 32 位订单引用 ID"
    exit 1
fi

if [[ ! " $VALID_DISTROS " =~ " $DISTRO " ]]; then
    log_error "不支持的发行版: $DISTRO"
    log_error "可用: $VALID_DISTROS"
    exit 1
fi

# 检查二进制文件
BINARY="$DIST_DIR/sslctl-nginx-linux-amd64"
if [[ ! -f "$BINARY" ]]; then
    log_warn "二进制文件不存在，正在构建..."
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    make build-linux
fi

# 准备测试目录
TEST_DIR="$SCRIPT_DIR/$DISTRO-nginx"
if [[ ! -d "$TEST_DIR" ]]; then
    log_error "测试目录不存在: $TEST_DIR"
    exit 1
fi

# 复制二进制文件
cp "$BINARY" "$TEST_DIR/"

# 创建站点配置
mkdir -p "$TEST_DIR/sites"
cat > "$TEST_DIR/sites/test.local.json" << EOF
{
  "version": "1.0",
  "site_name": "test.local",
  "enabled": true,
  "server_type": "nginx",
  "api": {
    "url": "http://ssl-manager-nginx/api/auto/cert",
    "refer_id": "$REFER_ID"
  },
  "domains": ["test.local"],
  "paths": {
    "certificate": "/etc/nginx/ssl/fullchain.pem",
    "private_key": "/etc/nginx/ssl/privkey.pem"
  },
  "reload": {
    "test_command": "nginx -t",
    "reload_command": "nginx -s reload"
  },
  "validation": {
    "verify_domain": false,
    "ignore_domain_mismatch": true
  },
  "backup": {
    "enabled": true,
    "keep_versions": 3
  }
}
EOF

log_info "站点配置已创建"

# 构建镜像
IMAGE_NAME="sslctl-test-$DISTRO-nginx"
log_info "构建镜像: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" "$TEST_DIR"

# 停止并删除旧容器
docker rm -f "$IMAGE_NAME" 2>/dev/null || true

# 启动容器（连接到 cert-manager 网络）
log_info "启动测试容器..."
docker run -d \
    --name "$IMAGE_NAME" \
    --network cert-manager_cert-net \
    -v "$TEST_DIR/sites:/opt/sslctl/sites" \
    "$IMAGE_NAME"

# 等待容器启动
sleep 2

# 执行部署测试
log_info "执行证书部署..."
docker exec "$IMAGE_NAME" sslctl -site test.local

log_info "测试完成"
log_info "查看日志: docker logs $IMAGE_NAME"
log_info "进入容器: docker exec -it $IMAGE_NAME sh"
