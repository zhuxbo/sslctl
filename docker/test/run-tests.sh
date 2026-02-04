#!/bin/bash
# 多发行版测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
echo_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
echo_error() { echo -e "${RED}[FAIL]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# 构建二进制文件
build_binary() {
    echo_info "构建 sslctl-nginx (Linux amd64)..."
    cd "$PROJECT_ROOT"

    # 检查 Go 是否可用
    if command -v go &> /dev/null; then
        GO_CMD="go"
    elif [ -f "/usr/local/go/bin/go" ]; then
        GO_CMD="/usr/local/go/bin/go"
    else
        echo_error "Go 未安装"
        exit 1
    fi

    # 动态编译（适用于 glibc 系统：Ubuntu/Debian/Rocky）
    GOOS=linux GOARCH=amd64 $GO_CMD build -o bin/sslctl-nginx-linux-amd64 ./cmd/nginx/

    # 静态编译（适用于 musl libc 系统：Alpine）
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $GO_CMD build -o bin/sslctl-nginx-linux-amd64-static ./cmd/nginx/

    # 复制到各个测试目录
    for dist in ubuntu debian rocky; do
        cp bin/sslctl-nginx-linux-amd64 "$SCRIPT_DIR/$dist/sslctl-nginx"
    done

    # Alpine 使用静态编译版本
    cp bin/sslctl-nginx-linux-amd64-static "$SCRIPT_DIR/alpine/sslctl-nginx"

    echo_success "构建完成"
}

# 构建 Docker 镜像
build_images() {
    echo_info "构建 Docker 镜像..."
    cd "$SCRIPT_DIR"
    docker compose build
    echo_success "镜像构建完成"
}

# 测试单个发行版
test_distro() {
    local distro=$1
    local container="sslctl-test-$distro"

    echo ""
    echo "========================================"
    echo_info "测试 $distro"
    echo "========================================"

    # 启动容器
    docker compose up -d "${distro}-nginx"
    sleep 2

    # 测试 1: 扫描功能
    echo_info "[$distro] 测试扫描功能..."
    if docker exec "$container" /usr/local/bin/sslctl-nginx -scan 2>&1 | tee /tmp/scan-$distro.log; then
        if grep -q "检测到 Nginx 配置" /tmp/scan-$distro.log; then
            echo_success "[$distro] 配置检测成功"
        else
            echo_error "[$distro] 配置检测失败"
        fi

        if grep -q "发现.*SSL 站点" /tmp/scan-$distro.log; then
            echo_success "[$distro] SSL 站点扫描成功"
        else
            echo_warn "[$distro] 未发现 SSL 站点（检查配置）"
        fi
    else
        echo_error "[$distro] 扫描命令执行失败"
    fi

    # 测试 2: 验证 Nginx 配置路径检测
    echo_info "[$distro] 验证 Nginx 配置路径..."
    local nginx_conf=$(docker exec "$container" nginx -t 2>&1 | grep "configuration file" | sed 's/.*configuration file \(.*\) syntax.*/\1/')
    echo_info "[$distro] Nginx 配置路径: $nginx_conf"

    # 测试 3: 检查证书文件
    echo_info "[$distro] 检查证书文件..."
    if docker exec "$container" ls /etc/nginx/ssl/ 2>/dev/null; then
        echo_success "[$distro] SSL 目录存在"
    else
        echo_warn "[$distro] SSL 目录不存在"
    fi

    # 测试 4: 版本信息
    echo_info "[$distro] 检查版本..."
    docker exec "$container" /usr/local/bin/sslctl-nginx -version

    # 测试 5: 工作目录
    echo_info "[$distro] 检查工作目录..."
    if docker exec "$container" ls /opt/sslctl/ 2>/dev/null; then
        echo_success "[$distro] 工作目录正常"
    else
        echo_error "[$distro] 工作目录不存在"
    fi

    echo_success "[$distro] 测试完成"
}

# 清理
cleanup() {
    echo_info "清理容器..."
    cd "$SCRIPT_DIR"
    docker compose down -v 2>/dev/null || true
}

# 显示测试结果
show_summary() {
    echo ""
    echo "========================================"
    echo_info "测试结果汇总"
    echo "========================================"

    for dist in ubuntu debian rocky alpine; do
        if [ -f "/tmp/scan-$dist.log" ]; then
            if grep -q "检测到 Nginx 配置" /tmp/scan-$dist.log && grep -q "发现.*SSL 站点" /tmp/scan-$dist.log; then
                echo_success "$dist: 通过"
            elif grep -q "检测到 Nginx 配置" /tmp/scan-$dist.log; then
                echo_warn "$dist: 配置检测通过，SSL 扫描需检查"
            else
                echo_error "$dist: 失败"
            fi
        fi
    done
}

# 主流程
main() {
    echo "========================================"
    echo "  sslctl 多发行版测试"
    echo "========================================"
    echo ""

    # 清理之前的测试
    cleanup

    # 构建
    build_binary
    build_images

    # 测试各个发行版
    for dist in ubuntu debian rocky alpine; do
        test_distro "$dist"
    done

    # 显示汇总
    show_summary

    # 询问是否清理
    echo ""
    read -p "是否清理测试容器？[Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        cleanup
    fi
}

# 运行
main "$@"
