#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_webserver_running
  mock_reset
  mock_set_scenario active
  rm -f "$SSLCTL_CONFIG_DIR/config.json"
  run_initial_setup
  generate_test_cert
}

setup() {
  common_setup
  CERT_PATH=$(binding_value '.paths.certificate')
  KEY_PATH=$(binding_value '.paths.private_key')
  CHAIN_PATH=$(binding_value '.paths.chain_file // empty')
  cp "$SSLCTL_CONFIG_DIR/config.json" /tmp/symlink-config.json
  for path in "$CERT_PATH" "$KEY_PATH" "$CHAIN_PATH"; do
    [ -n "$path" ] || continue
    mv "$path" "$path.original"
    cp "$path.original" "$path.archive1"
    ln -s "$(basename "$path").archive1" "$path"
  done
}

teardown() {
  for path in "$CERT_PATH" "$KEY_PATH" "$CHAIN_PATH"; do
    [ -n "$path" ] || continue
    rm -f "$path" "$path.archive1" "$path.archive2"
    mv "$path.original" "$path"
  done
  cp /tmp/symlink-config.json "$SSLCTL_CONFIG_DIR/config.json"
  reload_webserver
}

@test "symlink: 部署、TLS 生效和手动回滚均保留链接" {
  local before version after
  before=$(cert_fingerprint "$CERT_PATH")
  # 输入文件本身也可以是软链接。
  ln -sf /tmp/test.crt /tmp/symlink-input.crt
  ln -sf /tmp/test.key /tmp/symlink-input.key
  run sslctl deploy local --cert /tmp/symlink-input.crt --key /tmp/symlink-input.key --site test.example.com
  assert_success
  [ "$(readlink "$CERT_PATH")" = "$(basename "$CERT_PATH").archive1" ]
  [ "$(readlink "$KEY_PATH")" = "$(basename "$KEY_PATH").archive1" ]
  assert_cert_key_match "$CERT_PATH" "$KEY_PATH"
  after=$(cert_fingerprint /tmp/test.crt)
  [ "$before" != "$after" ]
  wait_for_tls_fingerprint 127.0.0.1:443 test.example.com "$after"
  version=$(ls -1 "$SSLCTL_CONFIG_DIR/backup/test.example.com" | sort | tail -1)
  run sslctl rollback --site test.example.com --version "$version"
  assert_success
  [ -L "$CERT_PATH" ]
  [ -L "$KEY_PATH" ]
  [ "$(cert_fingerprint "$CERT_PATH")" = "$before" ]
  assert_cert_key_match "$CERT_PATH" "$KEY_PATH"
  # rollback 命令恢复文件，使用真实服务重载验证旧证书。
  reload_webserver
  wait_for_tls_fingerprint 127.0.0.1:443 test.example.com "$before"

  # 模拟外部续签切换 live 链接，旧备份不可覆盖新版本。
  cp /tmp/test.crt "$CERT_PATH.archive2"
  rm "$CERT_PATH"
  ln -s "$(basename "$CERT_PATH").archive2" "$CERT_PATH"
  run sslctl rollback --site test.example.com --version "$version"
  assert_failure
  assert_output_contains "目标已变化"
  [ "$(cert_fingerprint "$CERT_PATH")" = "$after" ]
}
