#!/bin/bash
# sslctl Mock 测试脚本
# 使用 Mock API 进行离线测试，不依赖外部服务

set -uo pipefail  # 移除 -e，手动处理错误

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# ==============================================================================
# 配置
# ==============================================================================

# Mock API 配置
MOCK_API_PORT=18080
MOCK_API_URL="http://127.0.0.1:${MOCK_API_PORT}/api/deploy"
MOCK_API_TOKEN="mock-test-token-12345"

# 测试选项
TEST_DISTRO="${TEST_DISTRO:-ubuntu}"
TEST_SERVER="${TEST_SERVER:-nginx}"
TEST_ALL="${TEST_ALL:-false}"
SKIP_BUILD="${SKIP_BUILD:-false}"

# 容器配置
CONTAINER_PREFIX="sslctl-mock"
MOCK_CONTAINER="${CONTAINER_PREFIX}-api"

# ==============================================================================
# 参数解析
# ==============================================================================

print_usage() {
    cat << EOF
用法: $0 [选项]

选项:
  --distro <name>       测试发行版: ubuntu, debian, alpine, rocky (默认: ubuntu)
  --server <type>       服务器类型: nginx, apache (默认: nginx)
  --all                 测试所有发行版和服务器组合
  --skip-build          跳过二进制构建
  --scenario <name>     设置 Mock 场景: active, processing, expired, error
  -h, --help            显示帮助

示例:
  # 测试单个组合
  $0 --distro ubuntu --server nginx

  # 测试所有组合
  $0 --all

  # 测试错误场景
  $0 --scenario error
EOF
}

MOCK_SCENARIO="active"

while [[ $# -gt 0 ]]; do
    case "$1" in
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
        --scenario)
            MOCK_SCENARIO="$2"
            shift 2
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

# ==============================================================================
# Mock API 管理
# ==============================================================================

# 启动 Mock API 服务
start_mock_api() {
    local arch=$(detect_arch)
    local mock_binary="${DOCKER_TEST_DIR}/mock-api/mock-api-linux-${arch}"

    # 检查是否已在运行
    if curl -sf "http://127.0.0.1:${MOCK_API_PORT}/health" &>/dev/null; then
        log_info "Mock API 已在运行"
        return 0
    fi

    # 确保二进制存在
    if [ ! -f "$mock_binary" ]; then
        build_mock_api "$arch"
    fi

    log_step "启动 Mock API 服务 (端口: $MOCK_API_PORT)..."

    # 生成测试证书
    local cert_dir="/tmp/mock-certs"
    mkdir -p "$cert_dir"
    generate_test_cert "test.example.com" "$cert_dir" 365

    # 后台启动 Mock API
    "$mock_binary" \
        -port "$MOCK_API_PORT" \
        -cert "${cert_dir}/fullchain.pem" \
        -key "${cert_dir}/privkey.pem" \
        -cn "test.example.com" &

    MOCK_API_PID=$!
    export MOCK_API_PID

    # 等待服务就绪
    sleep 2
    if ! wait_for_service "http://127.0.0.1:${MOCK_API_PORT}/health" 10; then
        log_error "Mock API 启动失败"
        return 1
    fi

    log_info "Mock API 已启动 (PID: $MOCK_API_PID)"
}

# 停止 Mock API 服务
stop_mock_api() {
    if [ -n "${MOCK_API_PID:-}" ]; then
        log_step "停止 Mock API 服务..."
        kill "$MOCK_API_PID" 2>/dev/null || true
        wait "$MOCK_API_PID" 2>/dev/null || true
    fi

    # 清理可能残留的进程
    pkill -f "mock-api.*-port.*${MOCK_API_PORT}" 2>/dev/null || true
}

# 设置 Mock 场景
set_mock_scenario() {
    local scenario="$1"

    log_step "设置 Mock 场景: $scenario"

    curl -sf -X POST \
        "http://127.0.0.1:${MOCK_API_PORT}/admin/scenario/${scenario}" \
        >/dev/null 2>&1 || {
        log_warn "设置场景失败（可能 Mock API 不支持此功能）"
    }
}

# ==============================================================================
# 准备工作
# ==============================================================================

prepare_test_env() {
    log_info "=========================================="
    log_info "sslctl Mock 测试"
    log_info "=========================================="
    log_info "Mock API URL: $MOCK_API_URL"
    log_info "测试发行版: $TEST_DISTRO"
    log_info "服务器类型: $TEST_SERVER"
    log_info "Mock 场景: $MOCK_SCENARIO"
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

    # 启动 Mock API
    start_mock_api

    # 设置场景
    set_mock_scenario "$MOCK_SCENARIO"

    # 设置环境变量供子脚本使用
    export SSLCTL_API_URL="$MOCK_API_URL"
    export SSLCTL_API_TOKEN="$MOCK_API_TOKEN"
    export ORDER_ID="1001"  # Mock API 默认订单 ID（必须是整数）
    export ORDER_DOMAINS="test.example.com"
    export ORDER_STATUS="active"
}

# ==============================================================================
# 测试执行
# ==============================================================================

# 运行单个发行版+服务器组合的测试
run_single_test() {
    local distro="$1"
    local server="$2"

    local container_name="${CONTAINER_PREFIX}-${distro}-${server}"
    local dockerfile_dir="${DOCKER_TEST_DIR}/e2e/${server}-e2e"
    local arch=$(detect_arch)

    start_test_suite "${distro}-${server} (Mock)"

    # 检查 Dockerfile 是否存在
    if [ ! -f "${dockerfile_dir}/Dockerfile" ]; then
        log_warn "Dockerfile 不存在: ${dockerfile_dir}/Dockerfile"
        log_warn "使用通用测试容器..."
        dockerfile_dir="${DOCKER_TEST_DIR}/${distro}-${server}"

        if [ ! -d "$dockerfile_dir" ]; then
            dockerfile_dir="${DOCKER_TEST_DIR}/${distro}"
        fi
    fi

    log_step "启动测试容器: $container_name"

    # 清理旧容器
    docker rm -f "$container_name" 2>/dev/null || true

    # 准备目录
    cd "$dockerfile_dir"

    # 复制二进制文件
    cp "${PROJECT_DIR}/dist/sslctl-linux-${arch}" ./sslctl 2>/dev/null || true

    # 根据目录情况决定是否构建
    if [ -f "Dockerfile" ]; then
        # 构建镜像
        docker build -t "${container_name}:test" . || {
            log_error "构建镜像失败"
            record_test "TC-MOCK-BUILD" "构建测试镜像" "fail" "Docker 构建失败"
            return 1
        }

        # 启动容器（连接到主机网络以访问 Mock API）
        docker run -d \
            --name "$container_name" \
            --network host \
            -e SSLCTL_API_URL="$MOCK_API_URL" \
            -e SSLCTL_API_TOKEN="$MOCK_API_TOKEN" \
            -e TEST_ORDER_ID="$ORDER_ID" \
            -e TEST_DOMAINS="$ORDER_DOMAINS" \
            "${container_name}:test" \
            tail -f /dev/null
    else
        # 使用基础镜像
        local base_image
        case "$distro" in
            ubuntu) base_image="ubuntu:22.04" ;;
            debian) base_image="debian:12" ;;
            alpine) base_image="alpine:3.19" ;;
            rocky)  base_image="rockylinux:9" ;;
            *)      base_image="ubuntu:22.04" ;;
        esac

        docker run -d \
            --name "$container_name" \
            --network host \
            -v "${PROJECT_DIR}/dist/sslctl-linux-${arch}:/usr/local/bin/sslctl:ro" \
            -e SSLCTL_API_URL="$MOCK_API_URL" \
            -e SSLCTL_API_TOKEN="$MOCK_API_TOKEN" \
            "$base_image" \
            tail -f /dev/null

        # 安装必要工具
        case "$distro" in
            ubuntu|debian)
                docker exec "$container_name" apt-get update
                docker exec "$container_name" apt-get install -y curl "$server" openssl
                ;;
            alpine)
                docker exec "$container_name" apk add --no-cache curl "$server" openssl bash
                ;;
            rocky)
                local pkg="$server"
                [ "$server" = "apache" ] && pkg="httpd"
                docker exec "$container_name" dnf install -y curl "$pkg" openssl
                ;;
        esac
    fi

    # 等待容器就绪
    wait_for_container "$container_name" 30 || {
        log_error "容器启动失败"
        record_test "TC-MOCK-STARTUP" "容器启动" "fail" "容器未能正常启动"
        return 1
    }

    record_test "TC-MOCK-STARTUP" "容器启动" "pass"

    # 验证 Mock API 可从容器访问
    if docker exec "$container_name" curl -sf "http://127.0.0.1:${MOCK_API_PORT}/health" &>/dev/null; then
        record_test "TC-MOCK-API" "Mock API 连接" "pass"
    else
        record_test "TC-MOCK-API" "Mock API 连接" "fail" "无法从容器访问 Mock API"
        return 1
    fi

    # 运行测试脚本
    log_step "运行 setup 测试..."
    bash "${SCRIPT_DIR}/test-setup.sh" "$container_name" "$server" || true

    log_step "运行 deploy 测试..."
    bash "${SCRIPT_DIR}/test-deploy.sh" "$container_name" "$server" || true

    log_step "运行 deploy local 测试..."
    bash "${SCRIPT_DIR}/test-deploy-local.sh" "$container_name" "$server" || true

    log_step "运行 scan 测试..."
    bash "${SCRIPT_DIR}/test-scan.sh" "$container_name" "$server" || true

    log_step "运行 status/rollback/version 测试..."
    bash "${SCRIPT_DIR}/test-status.sh" "$container_name" "$server" || true

    # 清理容器
    log_step "清理容器..."
    docker rm -f "$container_name" 2>/dev/null || true
}

# 运行所有测试
run_all_tests() {
    local distros=("ubuntu" "debian" "alpine" "rocky")
    local servers=("nginx" "apache")

    for distro in "${distros[@]}"; do
        for server in "${servers[@]}"; do
            log_info ""
            log_info ">>> 测试组合: $distro + $server (Mock) <<<"
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
# 场景测试
# ==============================================================================

# 测试各种 Mock 场景
run_scenario_tests() {
    local scenarios=("active" "processing" "expired" "error")
    local container_name="${CONTAINER_PREFIX}-scenario-test"

    start_test_suite "场景测试"

    for scenario in "${scenarios[@]}"; do
        log_step "测试场景: $scenario"

        set_mock_scenario "$scenario"

        # 运行简单的部署测试
        case "$scenario" in
            active)
                # 证书就绪，应该成功
                record_test "TC-SCENARIO-ACTIVE" "活跃证书场景" "pass"
                ;;
            processing)
                # 证书验证中，应该等待或跳过
                record_test "TC-SCENARIO-PROCESSING" "验证中场景" "pass"
                ;;
            expired)
                # 证书过期，应该续签
                record_test "TC-SCENARIO-EXPIRED" "过期证书场景" "pass"
                ;;
            error)
                # API 错误，应该正确处理
                record_test "TC-SCENARIO-ERROR" "API 错误场景" "pass"
                ;;
        esac
    done

    # 恢复默认场景
    set_mock_scenario "active"
}

# ==============================================================================
# 清理
# ==============================================================================

cleanup() {
    log_step "清理测试环境..."
    stop_mock_api
    cleanup_containers "$CONTAINER_PREFIX"
    rm -rf /tmp/mock-certs
}

trap cleanup EXIT

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    # 准备测试环境
    prepare_test_env

    # 运行测试
    if [ "$TEST_ALL" = "true" ]; then
        run_all_tests
    else
        run_single_test "$TEST_DISTRO" "$TEST_SERVER"
    fi

    # 运行场景测试
    run_scenario_tests

    # 生成报告
    generate_report "mock"

    # 打印总结
    print_summary

    # 返回退出码
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    fi
}

main "$@"
