#!/bin/bash
# sslctl 端到端测试脚本
# 使用真实 API 进行完整功能测试

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# ==============================================================================
# 配置
# ==============================================================================

# API 配置（可通过环境变量覆盖）
SSLCTL_API_URL="${SSLCTL_API_URL:-https://manager.test.pzo.cn/api/deploy}"
SSLCTL_API_TOKEN="${SSLCTL_API_TOKEN:-}"

# 测试选项
TEST_DISTRO="${TEST_DISTRO:-ubuntu}"  # ubuntu, debian, alpine, rocky
TEST_SERVER="${TEST_SERVER:-nginx}"   # nginx, apache
TEST_ORDER_ID="${TEST_ORDER_ID:-}"    # 手动指定订单 ID
SKIP_BUILD="${SKIP_BUILD:-false}"     # 跳过构建

# 容器配置
CONTAINER_PREFIX="sslctl-e2e"
E2E_DIR="${DOCKER_TEST_DIR}/e2e"

# ==============================================================================
# 参数解析
# ==============================================================================

print_usage() {
    cat << EOF
用法: $0 [选项]

选项:
  --url <url>           API URL (默认: $SSLCTL_API_URL)
  --token <token>       API Token (必需，或设置 SSLCTL_API_TOKEN 环境变量)
  --order-id <id>       指定订单 ID (不指定则自动获取第一个活跃订单)
  --distro <name>       测试发行版: ubuntu, debian, alpine, rocky (默认: ubuntu)
  --server <type>       服务器类型: nginx, apache (默认: nginx)
  --all                 测试所有发行版和服务器组合
  --skip-build          跳过二进制构建
  -h, --help            显示帮助

示例:
  # 使用环境变量
  export SSLCTL_API_TOKEN="your-token"
  $0

  # 命令行参数
  $0 --token your-token --distro ubuntu --server nginx

  # 测试所有组合
  $0 --token your-token --all
EOF
}

TEST_ALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            SSLCTL_API_URL="$2"
            shift 2
            ;;
        --token)
            SSLCTL_API_TOKEN="$2"
            shift 2
            ;;
        --order-id)
            TEST_ORDER_ID="$2"
            shift 2
            ;;
        --distro)
            TEST_DISTRO="$2"
            shift 2
            ;;
        --server)
            TEST_SERVER="$2"
            shift 2
            ;;
        --all)
            TEST_ALL=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "未知参数: $1"
            print_usage
            exit 1
            ;;
    esac
done

# 验证必需参数
if [ -z "$SSLCTL_API_TOKEN" ]; then
    log_error "API Token 未设置"
    log_error "请设置环境变量 SSLCTL_API_TOKEN 或使用 --token 参数"
    exit 1
fi

# ==============================================================================
# 准备工作
# ==============================================================================

prepare_test_env() {
    log_info "=========================================="
    log_info "sslctl 端到端测试"
    log_info "=========================================="
    log_info "API URL: $SSLCTL_API_URL"
    log_info "测试发行版: $TEST_DISTRO"
    log_info "服务器类型: $TEST_SERVER"
    log_info ""

    # 检查 Docker
    check_docker

    # 检测架构
    local arch=$(detect_arch)
    log_info "当前架构: $arch"

    # 构建二进制
    if [ "$SKIP_BUILD" != "true" ]; then
        build_binary "$arch"
        build_mock_api "$arch"
    fi

    # 检查 API 可达性
    if ! check_api_reachable "$SSLCTL_API_URL" "$SSLCTL_API_TOKEN"; then
        log_error "无法连接到 API，请检查网络和凭证"
        exit 1
    fi
}

# 获取测试订单信息
get_test_order() {
    log_step "获取测试订单..."

    local order_json

    if [ -n "$TEST_ORDER_ID" ]; then
        # 使用指定的订单 ID
        log_info "使用指定订单 ID: $TEST_ORDER_ID"
        order_json=$(curl -sf \
            -H "Authorization: Bearer $SSLCTL_API_TOKEN" \
            -H "Content-Type: application/json" \
            "${SSLCTL_API_URL}?order_id=${TEST_ORDER_ID}" 2>/dev/null)

        if [ -z "$order_json" ]; then
            log_error "获取订单失败"
            return 1
        fi

        # 从响应中提取数据（data 是数组，取第一个元素）
        order_json=$(echo "$order_json" | jq -r '.data[0]')
    else
        # 自动获取第一个活跃订单
        order_json=$(get_first_active_order "$SSLCTL_API_URL" "$SSLCTL_API_TOKEN")
    fi

    if [ -z "$order_json" ] || [ "$order_json" = "null" ]; then
        log_error "未找到可用订单"
        return 1
    fi

    # 解析订单信息
    ORDER_ID=$(echo "$order_json" | jq -r '.order_id // .id // empty')
    ORDER_DOMAINS=$(echo "$order_json" | jq -r '.domains // empty')
    ORDER_STATUS=$(echo "$order_json" | jq -r '.status // empty')

    if [ -z "$ORDER_ID" ]; then
        log_error "订单 ID 为空"
        return 1
    fi

    log_info "订单 ID: $ORDER_ID"
    log_info "域名: $ORDER_DOMAINS"
    log_info "状态: $ORDER_STATUS"

    # 保存订单信息供后续使用
    export ORDER_ID ORDER_DOMAINS ORDER_STATUS
}

# ==============================================================================
# 测试执行
# ==============================================================================

# 运行单个发行版+服务器组合的测试
run_single_test() {
    local distro="$1"
    local server="$2"

    local container_name="${CONTAINER_PREFIX}-${distro}-${server}"
    local dockerfile_dir="${E2E_DIR}/${server}-e2e"
    local arch=$(detect_arch)

    start_test_suite "${distro}-${server}"

    log_step "启动测试容器: $container_name"

    # 清理旧容器
    docker rm -f "$container_name" 2>/dev/null || true

    # 构建并启动容器
    cd "$dockerfile_dir"

    # 复制二进制文件
    cp "${PROJECT_DIR}/dist/sslctl-linux-${arch}" ./sslctl
    cp "${DOCKER_TEST_DIR}/mock-api/mock-api-linux-${arch}" ./mock-api 2>/dev/null || true

    # 构建镜像
    docker build -t "${container_name}:test" \
        --build-arg DISTRO="$distro" \
        -f Dockerfile . || {
        log_error "构建镜像失败"
        record_test "TC-E2E-BUILD" "构建测试镜像" "fail" "Docker 构建失败"
        return 1
    }

    # 启动容器
    docker run -d \
        --name "$container_name" \
        -e SSLCTL_API_URL="$SSLCTL_API_URL" \
        -e SSLCTL_API_TOKEN="$SSLCTL_API_TOKEN" \
        -e TEST_ORDER_ID="$ORDER_ID" \
        -e TEST_DOMAINS="$ORDER_DOMAINS" \
        "${container_name}:test" \
        tail -f /dev/null

    # 等待容器就绪
    wait_for_container "$container_name" 30 || {
        log_error "容器启动失败"
        record_test "TC-E2E-STARTUP" "容器启动" "fail" "容器未能正常启动"
        return 1
    }

    # 为证书域名创建匹配的站点配置
    log_step "创建测试站点配置 (域名: $ORDER_DOMAINS)..."
    local test_domain
    test_domain=$(echo "$ORDER_DOMAINS" | tr ',' '\n' | head -1 | tr -d ' ')
    if [ -n "$test_domain" ]; then
        if [ "$server" = "nginx" ]; then
            # 生成证书
            docker exec "$container_name" mkdir -p "/etc/nginx/ssl/${test_domain}"
            docker exec "$container_name" openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
                -keyout "/etc/nginx/ssl/${test_domain}/privkey.pem" \
                -out "/etc/nginx/ssl/${test_domain}/fullchain.pem" \
                -subj "/CN=${test_domain}/O=Test/C=CN" 2>/dev/null

            # 生成站点配置
            local nginx_conf="server {
    listen 443 ssl;
    server_name ${test_domain};
    ssl_certificate /etc/nginx/ssl/${test_domain}/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/${test_domain}/privkey.pem;
    location / {
        return 200 'Hello from E2E Test';
        add_header Content-Type text/plain;
    }
}"
            # 写入所有可能的 include 目录
            for dir in /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/http.d; do
                if docker exec "$container_name" test -d "$dir" 2>/dev/null; then
                    echo "$nginx_conf" | docker exec -i "$container_name" tee "${dir}/${test_domain}.conf" >/dev/null
                fi
            done
            docker exec "$container_name" sh -c "nginx -t 2>/dev/null && nginx -s reload 2>/dev/null || nginx 2>/dev/null || true"
        else
            docker exec "$container_name" bash -c "
                if [ -d /etc/httpd ]; then
                    SSL_DIR=/etc/httpd/ssl
                    CONF_DIR=/etc/httpd/conf.d
                else
                    SSL_DIR=/etc/apache2/ssl
                    if [ -d /etc/apache2/sites-available ]; then
                        CONF_DIR=/etc/apache2/sites-enabled
                    else
                        CONF_DIR=/etc/apache2/conf.d
                    fi
                fi
                mkdir -p \${SSL_DIR}/${test_domain}
                openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
                    -keyout \${SSL_DIR}/${test_domain}/privkey.pem \
                    -out \${SSL_DIR}/${test_domain}/fullchain.pem \
                    -subj '/CN=${test_domain}/O=Test/C=CN' 2>/dev/null
                cat > \${CONF_DIR}/${test_domain}.conf << SITEEOF
<VirtualHost *:443>
    ServerName ${test_domain}
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile \${SSL_DIR}/${test_domain}/fullchain.pem
    SSLCertificateKeyFile \${SSL_DIR}/${test_domain}/privkey.pem
    <Directory /var/www/html>
        Require all granted
    </Directory>
</VirtualHost>
SITEEOF
                apachectl -t 2>/dev/null || httpd -t 2>/dev/null || true
            "
        fi
        log_info "站点配置已创建: ${test_domain}"
    fi

    # 运行测试脚本
    log_step "运行 setup 测试..."
    bash "${SCRIPT_DIR}/test-setup.sh" "$container_name" "$server"

    log_step "运行 deploy 测试..."
    bash "${SCRIPT_DIR}/test-deploy.sh" "$container_name" "$server"

    log_step "运行 deploy local 测试..."
    bash "${SCRIPT_DIR}/test-deploy-local.sh" "$container_name" "$server"

    log_step "运行 scan 测试..."
    bash "${SCRIPT_DIR}/test-scan.sh" "$container_name" "$server"

    # 清理容器
    log_step "清理容器..."
    docker rm -f "$container_name" 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
}

# 运行所有测试
run_all_tests() {
    local distros=("ubuntu" "debian" "alpine" "rocky")
    local servers=("nginx" "apache")

    for distro in "${distros[@]}"; do
        for server in "${servers[@]}"; do
            log_info ""
            log_info ">>> 测试组合: $distro + $server <<<"
            log_info ""

            run_single_test "$distro" "$server" || {
                log_warn "测试组合 $distro-$server 失败，继续下一个..."
            }

            # 清理释放内存
            cleanup_containers "$CONTAINER_PREFIX"
            sleep 2
        done
    done
}

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    # 准备测试环境
    prepare_test_env

    # 获取测试订单
    get_test_order || exit 1

    # 运行测试
    if [ "$TEST_ALL" = "true" ]; then
        run_all_tests
    else
        run_single_test "$TEST_DISTRO" "$TEST_SERVER"
    fi

    # 生成报告
    generate_report "e2e"

    # 打印总结
    print_summary

    # 清理
    cleanup_containers "$CONTAINER_PREFIX"

    # 返回退出码
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    fi
}

main "$@"
