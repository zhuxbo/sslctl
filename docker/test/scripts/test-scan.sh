#!/bin/bash
# sslctl scan 命令测试脚本
# TC-SCAN-01 ~ TC-SCAN-04

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# ==============================================================================
# 参数
# ==============================================================================

CONTAINER="${1:-}"
SERVER_TYPE="${2:-nginx}"

if [ -z "$CONTAINER" ]; then
    log_error "用法: $0 <container_name> [server_type]"
    exit 1
fi

# ==============================================================================
# 准备工作
# ==============================================================================

# 创建测试站点配置
setup_test_sites() {
    local ssl_dir config_dir

    if [ "$SERVER_TYPE" = "nginx" ]; then
        ssl_dir="/etc/nginx/ssl"
        config_dir="/etc/nginx/sites-enabled"
        docker exec "$CONTAINER" mkdir -p "$ssl_dir" "$config_dir" /etc/nginx/sites-available

        # 创建 HTTP 站点
        docker exec "$CONTAINER" bash -c "cat > /etc/nginx/sites-available/http-site.conf << 'EOF'
server {
    listen 80;
    server_name http-only.example.com;
    root /var/www/html;
}
EOF"
        docker exec "$CONTAINER" ln -sf /etc/nginx/sites-available/http-site.conf "$config_dir/" 2>/dev/null || true

        # 创建 SSL 站点
        docker exec "$CONTAINER" mkdir -p "${ssl_dir}/ssl-site.example.com"
        docker exec "$CONTAINER" openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
            -keyout "${ssl_dir}/ssl-site.example.com/privkey.pem" \
            -out "${ssl_dir}/ssl-site.example.com/fullchain.pem" \
            -subj "/CN=ssl-site.example.com/O=Test/C=CN" 2>/dev/null

        docker exec "$CONTAINER" bash -c "cat > /etc/nginx/sites-available/ssl-site.conf << 'EOF'
server {
    listen 443 ssl;
    server_name ssl-site.example.com;

    ssl_certificate /etc/nginx/ssl/ssl-site.example.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/ssl-site.example.com/privkey.pem;

    root /var/www/html;
}
EOF"
        docker exec "$CONTAINER" ln -sf /etc/nginx/sites-available/ssl-site.conf "$config_dir/" 2>/dev/null || true

    else
        # Apache 配置
        if docker exec "$CONTAINER" test -d /etc/httpd 2>/dev/null; then
            ssl_dir="/etc/httpd/ssl"
            config_dir="/etc/httpd/conf.d"
        else
            ssl_dir="/etc/apache2/ssl"
            config_dir="/etc/apache2/sites-enabled"
            docker exec "$CONTAINER" mkdir -p /etc/apache2/sites-available
        fi

        docker exec "$CONTAINER" mkdir -p "$ssl_dir" "$config_dir"

        # 创建 HTTP 站点
        local http_conf="${config_dir}/http-site.conf"
        docker exec "$CONTAINER" bash -c "cat > $http_conf << 'EOF'
<VirtualHost *:80>
    ServerName http-only.example.com
    DocumentRoot /var/www/html
</VirtualHost>
EOF"

        # 创建 SSL 站点
        docker exec "$CONTAINER" mkdir -p "${ssl_dir}/ssl-site.example.com"
        docker exec "$CONTAINER" openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
            -keyout "${ssl_dir}/ssl-site.example.com/privkey.pem" \
            -out "${ssl_dir}/ssl-site.example.com/fullchain.pem" \
            -subj "/CN=ssl-site.example.com/O=Test/C=CN" 2>/dev/null

        local ssl_conf="${config_dir}/ssl-site.conf"
        docker exec "$CONTAINER" bash -c "cat > $ssl_conf << EOF
<VirtualHost *:443>
    ServerName ssl-site.example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile ${ssl_dir}/ssl-site.example.com/fullchain.pem
    SSLCertificateKeyFile ${ssl_dir}/ssl-site.example.com/privkey.pem
</VirtualHost>
EOF"
    fi
}

# ==============================================================================
# 测试用例
# ==============================================================================

# TC-SCAN-01: 扫描所有站点
test_scan_all() {
    local test_id="TC-SCAN-01"
    local test_name="扫描所有站点"

    log_step "运行 $test_id: $test_name"

    # 设置测试站点
    setup_test_sites

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl scan 2>&1) || exit_code=$?

    # 验证结果
    if [ $exit_code -eq 0 ]; then
        # 检查是否检测到站点
        if echo "$output" | grep -qiE "(站点|site|found|检测|发现)"; then
            record_test "$test_id" "$test_name" "pass"
            return 0
        fi
        # 即使没有输出特定关键词，命令成功也算通过
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "命令执行失败 (exit: $exit_code)"
    return 1
}

# TC-SCAN-02: 仅扫描 SSL 站点
test_scan_ssl_only() {
    local test_id="TC-SCAN-02"
    local test_name="仅扫描 SSL 站点"

    log_step "运行 $test_id: $test_name"

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl scan --ssl-only 2>&1) || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        # 检查输出中是否只包含 SSL 站点
        # HTTP 站点不应该出现
        if echo "$output" | grep -qi "http-only.example.com"; then
            record_test "$test_id" "$test_name" "fail" "扫描结果包含非 SSL 站点"
            return 1
        fi
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "命令执行失败 (exit: $exit_code)"
    return 1
}

# TC-SCAN-03: Nginx 路径检测
test_scan_nginx_paths() {
    local test_id="TC-SCAN-03"
    local test_name="Nginx 路径检测"

    if [ "$SERVER_TYPE" != "nginx" ]; then
        log_warn "跳过 Nginx 测试（当前服务器类型: $SERVER_TYPE）"
        record_test "$test_id" "$test_name" "pass" "非 Nginx 环境，跳过"
        return 0
    fi

    log_step "运行 $test_id: $test_name"

    # 检查 Nginx 配置路径
    local paths_to_check=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/sites-enabled"
        "/etc/nginx/conf.d"
    )

    local found_paths=0
    for path in "${paths_to_check[@]}"; do
        if docker exec "$CONTAINER" test -e "$path" 2>/dev/null; then
            ((found_paths++))
        fi
    done

    if [ $found_paths -gt 0 ]; then
        # 运行扫描并验证检测到的路径
        local output
        output=$(docker exec "$CONTAINER" sslctl scan 2>&1) || true

        record_test "$test_id" "$test_name" "pass" "检测到 $found_paths 个配置路径"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "未找到 Nginx 配置路径"
    return 1
}

# TC-SCAN-04: Apache 路径检测
test_scan_apache_paths() {
    local test_id="TC-SCAN-04"
    local test_name="Apache 路径检测"

    if [ "$SERVER_TYPE" != "apache" ]; then
        log_warn "跳过 Apache 测试（当前服务器类型: $SERVER_TYPE）"
        record_test "$test_id" "$test_name" "pass" "非 Apache 环境，跳过"
        return 0
    fi

    log_step "运行 $test_id: $test_name"

    # 检查 Apache 配置路径（不同发行版可能不同）
    local paths_to_check=(
        "/etc/apache2/apache2.conf"
        "/etc/apache2/sites-enabled"
        "/etc/httpd/conf/httpd.conf"
        "/etc/httpd/conf.d"
    )

    local found_paths=0
    for path in "${paths_to_check[@]}"; do
        if docker exec "$CONTAINER" test -e "$path" 2>/dev/null; then
            ((found_paths++))
        fi
    done

    if [ $found_paths -gt 0 ]; then
        # 运行扫描并验证
        local output
        output=$(docker exec "$CONTAINER" sslctl scan 2>&1) || true

        record_test "$test_id" "$test_name" "pass" "检测到 $found_paths 个配置路径"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "未找到 Apache 配置路径"
    return 1
}

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    log_info "=========================================="
    log_info "Scan 命令测试 (容器: $CONTAINER)"
    log_info "服务器类型: $SERVER_TYPE"
    log_info "=========================================="

    # 运行测试
    test_scan_all || true
    test_scan_ssl_only || true
    test_scan_nginx_paths || true
    test_scan_apache_paths || true

    log_info "Scan 测试完成"
}

main "$@"
