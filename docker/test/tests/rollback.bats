#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset || true
  mock_set_scenario active || true
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  # 1. 初始 setup
  run_initial_setup
  # 验证 setup 成功并提取证书名
  if [ ! -f "$SSLCTL_CONFIG_DIR/config.json" ]; then
    echo "setup_file FAILED: config.json not created" >&2
    return 1
  fi
  local cert_name
  cert_name=$(jq -r '.certificates[0].cert_name' "$SSLCTL_CONFIG_DIR/config.json")
  if [ -z "$cert_name" ] || [ "$cert_name" = "null" ]; then
    echo "setup_file FAILED: no cert_name in config.json" >&2
    return 1
  fi
  echo "$cert_name" > /tmp/rollback-test-cert-name
  # 2. 第一次 deploy（创建初始状态）
  sslctl deploy --cert "$cert_name" --yes
  sleep 1
  # 3. 第二次 deploy（创建备份）
  sslctl deploy --cert "$cert_name" --yes
}

setup() {
  common_setup
  CERT_NAME=$(cat /tmp/rollback-test-cert-name 2>/dev/null || echo "")
}

# ==============================================================================
# rollback 命令测试
# ==============================================================================

@test "rollback: 列出备份" {
  run sslctl rollback --site test.example.com --list
  assert_success
  # 输出应包含时间戳格式 YYYYMMDD-HHMMSS
  [[ "$output" =~ [0-9]{8}-[0-9]{6} ]]
}

@test "rollback: 回滚到最新" {
  run sslctl rollback --site test.example.com
  assert_success
  assert_output_contains "文件恢复完成"
}

@test "rollback: 指定版本回滚" {
  # 先获取备份列表，提取第一个时间戳
  local list_output
  list_output=$(sslctl rollback --site test.example.com --list 2>&1)
  # 时间戳格式: 20060102-150405
  local ts
  ts=$(echo "$list_output" | grep -oE '[0-9]{8}-[0-9]{6}(\.[0-9]+)?' | head -1)
  if [ -z "$ts" ]; then
    echo "Failed to extract timestamp from list output"
    echo "Output: $list_output"
    return 1
  fi

  run sslctl rollback --site test.example.com --version "$ts"
  assert_success
}

@test "rollback: 回滚后配置有效" {
  # 先执行回滚
  sslctl rollback --site test.example.com 2>&1 || true
  # 验证 Web 服务器配置仍然有效
  run test_webserver_config
  assert_success
}

@test "rollback: 恢复后的证书私钥仍配对" {
  run sslctl rollback --site test.example.com
  assert_success
  local cert_path key_path
  cert_path=$(binding_value '.paths.certificate')
  key_path=$(binding_value '.paths.private_key')
  assert_cert_key_match "$cert_path" "$key_path"
}
