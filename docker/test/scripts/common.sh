#!/bin/bash
# sslctl 容器测试公共函数
# 提供测试框架、断言函数、报告生成等

set -uo pipefail  # 不使用 -e，由调用脚本控制错误处理

# ==============================================================================
# 颜色和输出
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }
log_test()  { echo -e "${CYAN}[TEST]${NC} $1"; }

# ==============================================================================
# 路径常量
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_TEST_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$(dirname "$DOCKER_TEST_DIR")")"
REPORTS_DIR="${DOCKER_TEST_DIR}/reports"

# 确保报告目录存在
mkdir -p "$REPORTS_DIR"

# ==============================================================================
# 测试结果存储
# ==============================================================================

TEST_LOG=()
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
CURRENT_TEST_SUITE=""

# 开始测试套件
start_test_suite() {
    local suite_name="$1"
    CURRENT_TEST_SUITE="$suite_name"
    log_info "=========================================="
    log_info "测试套件: $suite_name"
    log_info "=========================================="
}

# 记录测试结果
record_test() {
    local test_id="$1"
    local test_name="$2"
    local result="$3"  # pass/fail
    local message="${4:-}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$result" = "pass" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_test "✅ $test_id: $test_name"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "❌ $test_id: $test_name"
        [ -n "$message" ] && log_error "   原因: $message"
    fi

    TEST_LOG[${#TEST_LOG[@]}]="$test_id|$test_name|$result|$message"
}

# ==============================================================================
# 断言函数
# ==============================================================================

# 断言命令成功
assert_command_success() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        return 0
    else
        log_error "断言失败: $desc"
        return 1
    fi
}

# 断言文件存在
assert_file_exists() {
    local file="$1"
    local container="${2:-}"

    if [ -n "$container" ]; then
        if docker exec "$container" test -f "$file" 2>/dev/null; then
            return 0
        fi
    else
        if [ -f "$file" ]; then
            return 0
        fi
    fi

    log_error "断言失败: 文件不存在 $file"
    return 1
}

# 断言目录存在
assert_dir_exists() {
    local dir="$1"
    local container="${2:-}"

    if [ -n "$container" ]; then
        if docker exec "$container" test -d "$dir" 2>/dev/null; then
            return 0
        fi
    else
        if [ -d "$dir" ]; then
            return 0
        fi
    fi

    log_error "断言失败: 目录不存在 $dir"
    return 1
}

# 断言输出包含
assert_output_contains() {
    local output="$1"
    local pattern="$2"

    if echo "$output" | grep -q "$pattern"; then
        return 0
    fi

    log_error "断言失败: 输出不包含 '$pattern'"
    return 1
}

# 断言退出码
assert_exit_code() {
    local expected="$1"
    local actual="$2"

    if [ "$actual" -eq "$expected" ]; then
        return 0
    fi

    log_error "断言失败: 期望退出码 $expected，实际 $actual"
    return 1
}

# ==============================================================================
# Docker 工具函数
# ==============================================================================

# 检查 Docker 环境
check_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker 未安装"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        log_error "Docker 服务未运行或无权限"
        exit 1
    fi

    log_info "Docker 版本: $(docker version --format '{{.Server.Version}}')"
}

# 检测当前架构
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unknown" ;;
    esac
}

# 等待容器健康
wait_for_container() {
    local container="$1"
    local max_wait="${2:-30}"
    local waited=0

    while [ $waited -lt $max_wait ]; do
        if docker exec "$container" echo "ready" &>/dev/null; then
            return 0
        fi
        sleep 1
        ((waited++))
    done

    log_error "容器 $container 未就绪"
    return 1
}

# 等待服务可用
wait_for_service() {
    local url="$1"
    local max_wait="${2:-30}"
    local waited=0

    while [ $waited -lt $max_wait ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((waited++))
    done

    log_error "服务 $url 未就绪"
    return 1
}

# 清理测试容器
cleanup_containers() {
    local prefix="${1:-sslctl-e2e}"
    log_step "清理测试容器 (前缀: $prefix)..."
    docker ps -a --filter "name=${prefix}" -q | xargs -r docker rm -f 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
}

# 在容器中执行命令
container_exec() {
    local container="$1"
    shift
    docker exec "$container" "$@"
}

# ==============================================================================
# API 工具函数
# ==============================================================================

# 检查 API 可达性
check_api_reachable() {
    local api_url="$1"
    local api_token="$2"

    log_step "检查 API 可达性: $api_url"

    local response
    local http_code

    http_code=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $api_token" \
        "$api_url" 2>/dev/null) || http_code="000"

    if [ "$http_code" = "200" ]; then
        log_info "API 可达"
        return 0
    else
        log_error "API 不可达 (HTTP $http_code)"
        return 1
    fi
}

# 获取订单列表
get_orders() {
    local api_url="$1"
    local api_token="$2"

    curl -sf \
        -H "Authorization: Bearer $api_token" \
        -H "Content-Type: application/json" \
        "$api_url" 2>/dev/null
}

# 获取第一个活跃订单
get_first_active_order() {
    local api_url="$1"
    local api_token="$2"

    local response
    response=$(get_orders "$api_url" "$api_token")

    if [ -z "$response" ]; then
        log_error "无法获取订单列表"
        return 1
    fi

    # 解析 JSON，获取第一个 status=active 的订单
    local order
    order=$(echo "$response" | jq -r '[.data[] | select(.status == "active")] | first // empty')

    if [ -z "$order" ] || [ "$order" = "null" ]; then
        # 如果没有 active，尝试获取第一个订单
        order=$(echo "$response" | jq -r '.data[0]')
    fi

    echo "$order"
}

# ==============================================================================
# 构建工具函数
# ==============================================================================

# 构建测试二进制
build_binary() {
    local arch="${1:-$(detect_arch)}"
    local output="${PROJECT_DIR}/dist/sslctl-linux-${arch}"

    if [ -f "$output" ]; then
        log_info "使用已存在的二进制: $output"
        return 0
    fi

    log_step "构建 linux/${arch} 二进制..."

    cd "$PROJECT_DIR"

    local GO_CMD="go"
    if [ -x "/usr/local/go/bin/go" ]; then
        GO_CMD="/usr/local/go/bin/go"
    fi

    local version
    version=$($GO_CMD run ./build/version.go 2>/dev/null || echo "dev")
    local build_time=$(date -u +%Y-%m-%d)
    local ldflags="-s -w -X 'main.version=${version}' -X 'main.buildTime=${build_time}'"

    mkdir -p "${PROJECT_DIR}/dist"
    GOOS=linux GOARCH="$arch" $GO_CMD build -trimpath -ldflags "$ldflags" -o "$output" ./cmd/

    log_info "构建完成: $output"
}

# 构建 Mock API
build_mock_api() {
    local arch="${1:-$(detect_arch)}"
    local output="${DOCKER_TEST_DIR}/mock-api/mock-api-linux-${arch}"

    if [ -f "$output" ]; then
        log_info "使用已存在的 Mock API: $output"
        return 0
    fi

    log_step "构建 Mock API (linux/${arch})..."

    cd "${DOCKER_TEST_DIR}/mock-api"

    local GO_CMD="go"
    if [ -x "/usr/local/go/bin/go" ]; then
        GO_CMD="/usr/local/go/bin/go"
    fi

    GOOS=linux GOARCH="$arch" $GO_CMD build -o "$output" main.go

    log_info "构建完成: $output"
}

# ==============================================================================
# 证书工具函数
# ==============================================================================

# 生成测试证书
generate_test_cert() {
    local domain="$1"
    local output_dir="$2"
    local days="${3:-365}"

    mkdir -p "$output_dir"

    openssl req -x509 -nodes -days "$days" -newkey rsa:2048 \
        -keyout "${output_dir}/privkey.pem" \
        -out "${output_dir}/fullchain.pem" \
        -subj "/CN=${domain}/O=TestCert/C=CN" 2>/dev/null
}

# 验证证书域名
verify_cert_domain() {
    local cert_file="$1"
    local expected_domain="$2"
    local container="${3:-}"

    local cn
    if [ -n "$container" ]; then
        cn=$(docker exec "$container" openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+')
    else
        cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+')
    fi

    if [ "$cn" = "$expected_domain" ]; then
        return 0
    fi

    log_error "证书域名不匹配: 期望 $expected_domain，实际 $cn"
    return 1
}

# 获取证书序列号
get_cert_serial() {
    local cert_file="$1"
    local container="${2:-}"

    if [ -n "$container" ]; then
        docker exec "$container" openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | cut -d= -f2
    else
        openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | cut -d= -f2
    fi
}

# ==============================================================================
# 报告生成
# ==============================================================================

# 生成测试报告
generate_report() {
    local report_file="${REPORTS_DIR}/test-report-$(date +%Y%m%d-%H%M%S).md"
    local test_mode="${1:-e2e}"

    local host_os=$(uname -s)
    local host_kernel=$(uname -r)
    local docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    local test_arch=$(detect_arch)
    local test_time=$(date '+%Y-%m-%d %H:%M:%S')
    local pass_rate=0

    if [ $TOTAL_TESTS -gt 0 ]; then
        pass_rate=$(awk "BEGIN {printf \"%.1f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")
    fi

    cat > "$report_file" << EOF
# sslctl 容器测试报告

生成时间: $test_time

## 测试环境

- 主机系统: $host_os $host_kernel
- Docker 版本: $docker_version
- 测试架构: $test_arch
- 测试模式: $test_mode

## 测试结果汇总

| 指标 | 数值 |
|------|------|
| 总测试数 | $TOTAL_TESTS |
| 通过 | $PASSED_TESTS |
| 失败 | $FAILED_TESTS |
| 通过率 | ${pass_rate}% |

## 详细测试结果

| 测试 ID | 测试名称 | 结果 | 备注 |
|---------|----------|------|------|
EOF

    for entry in ${TEST_LOG[@]+"${TEST_LOG[@]}"}; do
        IFS='|' read -r test_id test_name result message <<< "$entry"
        local status_icon
        if [ "$result" = "pass" ]; then
            status_icon="✅ 通过"
        else
            status_icon="❌ 失败"
        fi
        echo "| $test_id | $test_name | $status_icon | $message |" >> "$report_file"
    done

    cat >> "$report_file" << EOF

## 测试用例说明

### Setup 命令测试 (TC-SETUP-*)

| 用例 ID | 用例名称 | 测试内容 |
|---------|----------|----------|
| TC-SETUP-01 | Nginx 一键部署 | \`setup --url --token --order --yes\` |
| TC-SETUP-02 | Apache 一键部署 | 同上，Apache 容器 |
| TC-SETUP-03 | 本地私钥模式 | \`--local-key\` 参数 |
| TC-SETUP-04 | 跳过服务安装 | \`--no-service\` 参数 |
| TC-SETUP-05 | API 错误处理 | Mock 返回错误码 |
| TC-SETUP-06 | 证书未就绪 | Mock 返回 processing |

### Deploy 命令测试 (TC-DEPLOY-*)

| 用例 ID | 用例名称 | 测试内容 |
|---------|----------|----------|
| TC-DEPLOY-01 | 部署指定证书 | \`deploy --cert <name>\` |
| TC-DEPLOY-02 | 部署所有证书 | \`deploy --all\` |
| TC-DEPLOY-03 | Nginx 重载验证 | nginx -t && nginx -s reload |
| TC-DEPLOY-04 | Apache 重载验证 | apachectl -t |
| TC-DEPLOY-05 | 备份创建验证 | 检查 backup/ 目录 |

### Deploy Local 命令测试 (TC-LOCAL-*)

| 用例 ID | 用例名称 | 测试内容 |
|---------|----------|----------|
| TC-LOCAL-01 | Nginx 本地部署 | \`deploy local --cert --key --site\` |
| TC-LOCAL-02 | Apache 本地部署 | 添加 \`--ca\` 参数 |
| TC-LOCAL-03 | 无效证书处理 | 损坏的 PEM 文件 |

### Scan 命令测试 (TC-SCAN-*)

| 用例 ID | 用例名称 | 测试内容 |
|---------|----------|----------|
| TC-SCAN-01 | 扫描所有站点 | \`scan\` |
| TC-SCAN-02 | 仅扫描 SSL | \`scan --ssl-only\` |
| TC-SCAN-03 | Nginx 路径检测 | 各发行版配置路径 |
| TC-SCAN-04 | Apache 路径检测 | 各发行版配置路径 |

---
*报告由 sslctl 容器测试框架自动生成*
EOF

    log_info "测试报告已生成: $report_file"

    # 创建最新报告的符号链接
    ln -sf "$(basename "$report_file")" "${REPORTS_DIR}/test-report.md"
}

# 打印测试总结
print_summary() {
    echo ""
    log_info "=========================================="
    log_info "测试总结"
    log_info "=========================================="
    log_info "总测试数: $TOTAL_TESTS"
    log_info "通过: $PASSED_TESTS"
    if [ $FAILED_TESTS -gt 0 ]; then
        log_error "失败: $FAILED_TESTS"
    else
        log_info "失败: 0"
    fi

    if [ $TOTAL_TESTS -gt 0 ]; then
        local pass_rate=$(awk "BEGIN {printf \"%.1f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")
        log_info "通过率: ${pass_rate}%"
    fi
}

# ==============================================================================
# 配置文件生成
# ==============================================================================

# 生成站点配置
generate_site_config() {
    local site_name="$1"
    local server_type="$2"
    local api_url="$3"
    local api_token="$4"
    local order_id="$5"
    local domains="$6"
    local cert_path="$7"
    local key_path="$8"
    local config_path="$9"

    local reload_test reload_cmd
    if [ "$server_type" = "nginx" ]; then
        reload_test="nginx -t"
        reload_cmd="nginx -s reload"
    else
        reload_test="apachectl -t"
        reload_cmd="apachectl graceful"
    fi

    cat << EOF
{
  "version": "1.0",
  "site_name": "$site_name",
  "enabled": true,
  "server_type": "$server_type",
  "api": {
    "url": "$api_url",
    "refer_id": "$api_token",
    "order_id": "$order_id",
    "callback_url": ""
  },
  "domains": $(echo "$domains" | jq -R 'split(",")'),
  "paths": {
    "certificate": "$cert_path",
    "private_key": "$key_path",
    "config_file": "$config_path"
  },
  "reload": {
    "test_command": "$reload_test",
    "reload_command": "$reload_cmd"
  },
  "schedule": {
    "check_interval_hours": 12,
    "renew_before_days": 30
  },
  "validation": {
    "verify_domain": false,
    "test_https": false,
    "ignore_domain_mismatch": true
  },
  "backup": {
    "enabled": true,
    "keep_versions": 3
  },
  "metadata": {}
}
EOF
}

# 生成 Nginx 站点配置
generate_nginx_site() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    cat << EOF
server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate $cert_path;
    ssl_certificate_key $key_path;

    location / {
        return 200 "Hello from $domain";
        add_header Content-Type text/plain;
    }
}
EOF
}

# 生成 Apache 站点配置
generate_apache_site() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"
    local ca_path="${4:-}"

    cat << EOF
<VirtualHost *:443>
    ServerName $domain
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile $cert_path
    SSLCertificateKeyFile $key_path
EOF

    if [ -n "$ca_path" ]; then
        echo "    SSLCACertificateFile $ca_path"
    fi

    cat << EOF

    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
}
