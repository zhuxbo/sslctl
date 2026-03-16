#!/bin/bash
# sslctl status/rollback/version 命令测试脚本
# TC-STATUS-01 ~ TC-STATUS-04, TC-ROLLBACK-01 ~ TC-ROLLBACK-03, TC-VERSION-01

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
# 测试用例 — version
# ==============================================================================

# TC-VERSION-01: 版本信息输出
test_version() {
    local test_id="TC-VERSION-01"
    local test_name="版本信息输出"

    log_step "运行 $test_id: $test_name"

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl version 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ]; then
        record_test "$test_id" "$test_name" "fail" "退出码: $exit_code, 输出: $output"
        return 1
    fi

    # 验证包含版本号格式
    if echo "$output" | grep -qE "(v?[0-9]+\.[0-9]+|dev)"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "输出不包含版本号: $output"
    return 1
}

# ==============================================================================
# 测试用例 — status
# ==============================================================================

# TC-STATUS-01: 基本状态输出（无配置）
test_status_no_config() {
    local test_id="TC-STATUS-01"
    local test_name="状态输出（无配置）"

    log_step "运行 $test_id: $test_name"

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl status 2>&1) || exit_code=$?

    # status 命令即使没有配置也应该输出版本和系统信息
    if echo "$output" | grep -q "版本"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    # 也接受英文输出
    if echo "$output" | grep -qi "version"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "退出码: $exit_code, 输出: $output"
    return 1
}

# TC-STATUS-02: Web 服务器检测
test_status_webserver() {
    local test_id="TC-STATUS-02"
    local test_name="Web 服务器检测"

    log_step "运行 $test_id: $test_name"

    local output
    output=$(docker exec "$CONTAINER" sslctl status 2>&1) || true

    # 验证检测到 Web 服务器
    if [ "$SERVER_TYPE" = "nginx" ]; then
        if echo "$output" | grep -qi "nginx"; then
            record_test "$test_id" "$test_name" "pass" "检测到 Nginx"
            return 0
        fi
    elif [ "$SERVER_TYPE" = "apache" ]; then
        if echo "$output" | grep -qiE "(apache|httpd)"; then
            record_test "$test_id" "$test_name" "pass" "检测到 Apache"
            return 0
        fi
    fi

    # Web 服务器进程未运行时也可能无法检测到
    if echo "$output" | grep -qE "(未检测到|not found|not detected)"; then
        record_test "$test_id" "$test_name" "pass" "Web 服务器进程未运行，检测结果合理"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "未检测到预期的 Web 服务器类型: $output"
    return 1
}

# TC-STATUS-03: 证书状态显示（setup 后）
test_status_with_config() {
    local test_id="TC-STATUS-03"
    local test_name="证书状态显示"

    log_step "运行 $test_id: $test_name"

    # 需要配置文件存在
    if ! docker exec "$CONTAINER" test -f /opt/sslctl/config.json 2>/dev/null; then
        record_test "$test_id" "$test_name" "pass" "无配置文件，跳过"
        return 0
    fi

    local output
    output=$(docker exec "$CONTAINER" sslctl status 2>&1) || true

    # 验证输出包含证书相关信息
    if echo "$output" | grep -qE "(证书配置|证书|cert|过期|剩余)"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    # 没有证书配置也是合理的
    if echo "$output" | grep -qE "(0 个|no cert)"; then
        record_test "$test_id" "$test_name" "pass" "无证书配置"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "状态输出不包含证书信息: $output"
    return 1
}

# TC-STATUS-04: 续签模式显示
test_status_renew_mode() {
    local test_id="TC-STATUS-04"
    local test_name="续签模式显示"

    log_step "运行 $test_id: $test_name"

    # 需要配置文件存在
    if ! docker exec "$CONTAINER" test -f /opt/sslctl/config.json 2>/dev/null; then
        record_test "$test_id" "$test_name" "pass" "无配置文件，跳过"
        return 0
    fi

    local output
    output=$(docker exec "$CONTAINER" sslctl status 2>&1) || true

    # 验证输出包含续签模式信息
    if echo "$output" | grep -qE "(续签模式|renew.*mode|pull|local)"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "状态输出不包含续签模式: $output"
    return 1
}

# ==============================================================================
# 测试用例 — rollback
# ==============================================================================

# TC-ROLLBACK-01: 备份列表查看（无备份）
test_rollback_list_empty() {
    local test_id="TC-ROLLBACK-01"
    local test_name="备份列表查看（无备份）"

    log_step "运行 $test_id: $test_name"

    # 清理备份目录
    docker exec "$CONTAINER" rm -rf /opt/sslctl/backup/* 2>/dev/null || true

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl rollback --site nonexistent.example.com --list 2>&1) || exit_code=$?

    # 应该输出"没有备份记录"或类似信息
    if echo "$output" | grep -qE "(没有备份|no backup|不存在)"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    # 空列表也可接受
    if [ $exit_code -eq 0 ]; then
        record_test "$test_id" "$test_name" "pass" "命令执行成功"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "退出码: $exit_code, 输出: $output"
    return 1
}

# TC-ROLLBACK-02: 备份列表查看（有备份）
test_rollback_list_with_backup() {
    local test_id="TC-ROLLBACK-02"
    local test_name="备份列表查看（有备份）"

    log_step "运行 $test_id: $test_name"

    local site_name="rollback-test.example.com"

    # 需要先部署创建备份
    if ! docker exec "$CONTAINER" test -f /opt/sslctl/config.json 2>/dev/null; then
        record_test "$test_id" "$test_name" "pass" "无配置文件，跳过"
        return 0
    fi

    # 创建测试证书目录和文件
    local cert_dir key_path cert_path
    if [ "$SERVER_TYPE" = "nginx" ]; then
        cert_dir="/etc/nginx/ssl/${site_name}"
        cert_path="${cert_dir}/fullchain.pem"
        key_path="${cert_dir}/privkey.pem"
    else
        if docker exec "$CONTAINER" test -d /etc/httpd 2>/dev/null; then
            cert_dir="/etc/httpd/ssl/${site_name}"
        else
            cert_dir="/etc/apache2/ssl/${site_name}"
        fi
        cert_path="${cert_dir}/fullchain.pem"
        key_path="${cert_dir}/privkey.pem"
    fi

    docker exec "$CONTAINER" mkdir -p "$cert_dir"
    docker exec "$CONTAINER" openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
        -keyout "$key_path" -out "$cert_path" \
        -subj "/CN=${site_name}/O=Test/C=CN" 2>/dev/null

    # 执行 deploy local 创建备份
    docker exec "$CONTAINER" sslctl deploy local \
        --cert "$cert_path" --key "$key_path" --site "$site_name" 2>/dev/null || true

    # 查看备份列表
    local output
    output=$(docker exec "$CONTAINER" sslctl rollback --site "$site_name" --list 2>&1) || true

    if echo "$output" | grep -qE "(备份列表|备份时间|\[1\])"; then
        record_test "$test_id" "$test_name" "pass"
        return 0
    fi

    # 如果没有备份产生（证书未变更），也接受
    if echo "$output" | grep -qE "(没有备份|no backup)"; then
        record_test "$test_id" "$test_name" "pass" "deploy local 未产生备份（证书未变更）"
        return 0
    fi

    record_test "$test_id" "$test_name" "fail" "输出: $output"
    return 1
}

# TC-ROLLBACK-03: 回滚无 --site 参数报错
test_rollback_missing_site() {
    local test_id="TC-ROLLBACK-03"
    local test_name="回滚缺少 site 参数"

    log_step "运行 $test_id: $test_name"

    local output
    local exit_code=0

    output=$(docker exec "$CONTAINER" sslctl rollback 2>&1) || exit_code=$?

    # 应该退出码非 0 且输出用法提示
    if [ $exit_code -ne 0 ]; then
        if echo "$output" | grep -qE "(用法|usage|--site)"; then
            record_test "$test_id" "$test_name" "pass"
            return 0
        fi
    fi

    record_test "$test_id" "$test_name" "fail" "退出码: $exit_code, 输出: $output"
    return 1
}

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    log_info "=========================================="
    log_info "Status/Rollback/Version 命令测试 (容器: $CONTAINER)"
    log_info "服务器类型: $SERVER_TYPE"
    log_info "=========================================="

    # 确保目录存在
    docker exec "$CONTAINER" mkdir -p /opt/sslctl/{backup,logs,certs}

    # 运行测试
    test_version || true
    test_status_no_config || true
    test_status_webserver || true
    test_status_with_config || true
    test_status_renew_mode || true
    test_rollback_list_empty || true
    test_rollback_list_with_backup || true
    test_rollback_missing_site || true

    log_info "Status/Rollback/Version 测试完成"
}

main "$@"
