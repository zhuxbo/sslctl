#!/usr/bin/env bats

load 'helpers/common'

setup_file() {
  ensure_mock_proxy
  mock_reset
  mock_set_scenario active

  mkdir -p /tmp/docker-deploy-conf /tmp/docker-deploy-ssl
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/docker-deploy-ssl/key.pem \
    -out /tmp/docker-deploy-ssl/cert.pem \
    -subj "/CN=seed.example.com" 2>/dev/null
  cat > /tmp/docker-deploy-conf/default.conf <<'CONF'
server {
    listen 443 ssl;
    server_name test.example.com;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    location / { return 200 "ok"; }
}
CONF

  docker run -d --name e2e-volume-nginx \
    -v /tmp/docker-deploy-conf/default.conf:/etc/nginx/conf.d/default.conf:ro \
    -v /tmp/docker-deploy-ssl:/etc/nginx/ssl \
    nginx:1.27-alpine

  for _ in $(seq 1 20); do
    docker exec e2e-volume-nginx nginx -t &>/dev/null && return 0
    sleep 1
  done
  echo "e2e-volume-nginx failed to start" >&2
  return 1
}

teardown_file() {
  docker rm -f e2e-volume-nginx e2e-copy-nginx e2e-copy-volume e2e-setup-nginx 2>/dev/null || true
  docker volume rm e2e-certificates 2>/dev/null || true
  rm -rf /tmp/docker-deploy-conf /tmp/docker-deploy-ssl /tmp/docker-copy-conf
}

setup() {
  rm -f "$SSLCTL_CONFIG_DIR/config.json" "$SSLCTL_CONFIG_DIR/scan-result.json"
  mock_reset
  mock_set_scenario active
}

write_docker_config() {
  local mode="$1"
  local container_name="$2"
  local cert_path="$3"
  local key_path="$4"
  local config_path="$5"
  jq -n \
    --arg api_url "$MOCK_URL" \
    --arg token "$TOKEN" \
    --arg mode "$mode" \
    --arg container "$container_name" \
    --arg cert "$cert_path" \
    --arg key "$key_path" \
    --arg config "$config_path" '
      {
        schedule: {renew_before_days: 14},
        certificates: [{
          cert_name: "docker-e2e",
          order_id: 1001,
          enabled: true,
          domains: ["test.example.com"],
          api: {url: $api_url, token: $token},
          bindings: [{
            server_name: "test.example.com",
            server_type: "docker-nginx",
            enabled: true,
            paths: {certificate: $cert, private_key: $key, config_file: $config},
            reload: {
              test_command: ("docker exec " + $container + " nginx -t"),
              reload_command: ("docker exec " + $container + " nginx -s reload")
            },
            docker: {container_name: $container, deploy_mode: $mode}
          }]
        }]
      }
    ' > "$SSLCTL_CONFIG_DIR/config.json"
}

@test "docker-deploy: volume 模式写入宿主卷并在容器 TLS 生效" {
  local seed_fp disk_fp live_fp child_ip
  seed_fp=$(cert_fingerprint /tmp/docker-deploy-ssl/cert.pem)
  write_docker_config volume e2e-volume-nginx \
    /tmp/docker-deploy-ssl/cert.pem \
    /tmp/docker-deploy-ssl/key.pem \
    /tmp/docker-deploy-conf/default.conf

  run sslctl deploy --cert docker-e2e
  assert_success

  [ "$(binding_value '.server_type')" = "docker-nginx" ]
  [ "$(binding_value '.docker.deploy_mode')" = "volume" ]
  assert_cert_key_match /tmp/docker-deploy-ssl/cert.pem /tmp/docker-deploy-ssl/key.pem

  disk_fp=$(cert_fingerprint /tmp/docker-deploy-ssl/cert.pem)
  if [ "$disk_fp" = "$seed_fp" ]; then
    echo "volume certificate was not replaced"
    return 1
  fi

  child_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' e2e-volume-nginx)
  live_fp=""
  for _ in $(seq 1 40); do
    live_fp=$(tls_fingerprint "$child_ip:443" "test.example.com")
    [ "$disk_fp" = "$live_fp" ] && break
    sleep 0.25
  done
  if [ -z "$live_fp" ] || [ "$disk_fp" != "$live_fp" ]; then
    echo "container TLS certificate mismatch: disk=$disk_fp live=$live_fp"
    return 1
  fi
}

@test "docker-deploy: copy 模式部署与手动回滚在容器 TLS 生效" {
  docker rm -f e2e-volume-nginx >/dev/null 2>&1
  docker run -d --name e2e-copy-nginx nginx:1.27-alpine
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/docker-deploy-ssl/key.pem \
    -out /tmp/docker-deploy-ssl/cert.pem \
    -subj "/CN=seed.example.com" 2>/dev/null
  local seed_fp disk_fp live_fp child_ip
  seed_fp=$(cert_fingerprint /tmp/docker-deploy-ssl/cert.pem)
  docker exec e2e-copy-nginx mkdir -p /etc/nginx/ssl
  docker cp /tmp/docker-deploy-ssl/cert.pem e2e-copy-nginx:/etc/nginx/ssl/cert.pem
  docker cp /tmp/docker-deploy-ssl/key.pem e2e-copy-nginx:/etc/nginx/ssl/key.pem
  cat > /tmp/docker-copy-conf <<'CONF'
server {
    listen 443 ssl;
    server_name test.example.com;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
}
CONF
  docker cp /tmp/docker-copy-conf e2e-copy-nginx:/etc/nginx/conf.d/default.conf
  docker exec e2e-copy-nginx nginx -s reload
  write_docker_config copy e2e-copy-nginx \
    /etc/nginx/ssl/cert.pem \
    /etc/nginx/ssl/key.pem \
    /etc/nginx/conf.d/default.conf

  cat > /tmp/copy-nginx-wrapper <<'SH'
#!/bin/sh
if [ "$1" = "-t" ] && [ -f /tmp/sslctl-fail-test-once ]; then
  rm /tmp/sslctl-fail-test-once
  exit 1
fi
exec /usr/sbin/nginx "$@"
SH
  docker exec e2e-copy-nginx mkdir -p /usr/local/sbin
  docker cp /tmp/copy-nginx-wrapper e2e-copy-nginx:/usr/local/sbin/nginx
  docker exec e2e-copy-nginx chmod 755 /usr/local/sbin/nginx
  docker exec e2e-copy-nginx touch /tmp/sslctl-fail-test-once
  mkdir -p /etc/nginx/ssl
  printf 'host-cert-sentinel' > /etc/nginx/ssl/cert.pem
  printf 'host-key-sentinel' > /etc/nginx/ssl/key.pem
  run sslctl deploy --cert docker-e2e
  assert_failure
  assert_output_contains "已回滚"
  docker cp e2e-copy-nginx:/etc/nginx/ssl/cert.pem /tmp/copy-cert.pem
  [ "$(cert_fingerprint /tmp/copy-cert.pem)" = "$seed_fp" ]
  child_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' e2e-copy-nginx)
  for _ in $(seq 1 40); do
    live_fp=$(tls_fingerprint "$child_ip:443" "test.example.com")
    [ "$seed_fp" = "$live_fp" ] && break
    sleep 0.25
  done
  [ "$seed_fp" = "$live_fp" ]
  rm -f /tmp/copy-nginx-wrapper

  run sslctl deploy --cert "$(jq -r '.certificates[0].cert_name' "$SSLCTL_CONFIG_DIR/config.json")"
  assert_success
  docker cp e2e-copy-nginx:/etc/nginx/ssl/cert.pem /tmp/copy-cert.pem
  docker cp e2e-copy-nginx:/etc/nginx/ssl/key.pem /tmp/copy-key.pem
  assert_cert_key_match /tmp/copy-cert.pem /tmp/copy-key.pem
  disk_fp=$(cert_fingerprint /tmp/copy-cert.pem)
  [ "$disk_fp" != "$seed_fp" ]
  child_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' e2e-copy-nginx)
  for _ in $(seq 1 40); do
    live_fp=$(tls_fingerprint "$child_ip:443" "test.example.com")
    [ "$disk_fp" = "$live_fp" ] && break
    sleep 0.25
  done
  [ "$disk_fp" = "$live_fp" ]

  run sslctl rollback --site test.example.com
  assert_success
  for _ in $(seq 1 40); do
    live_fp=$(tls_fingerprint "$child_ip:443" "test.example.com")
    [ "$seed_fp" = "$live_fp" ] && break
    sleep 0.25
  done
  [ "$seed_fp" = "$live_fp" ]
  run sslctl deploy --cert "$(jq -r '.certificates[0].cert_name' "$SSLCTL_CONFIG_DIR/config.json")"
  assert_success
  [ "$(cat /etc/nginx/ssl/cert.pem)" = host-cert-sentinel ]
  [ "$(cat /etc/nginx/ssl/key.pem)" = host-key-sentinel ]
  run sslctl rollback --site missing-site
  assert_failure
  [ "$(cat /etc/nginx/ssl/cert.pem)" = host-cert-sentinel ]
  rm -f /tmp/copy-cert.pem /tmp/copy-key.pem
}

@test "docker-deploy: copy 支持命名卷并拒绝只读目录卷" {
  docker volume create e2e-certificates >/dev/null
  docker run -d --name e2e-copy-volume -v e2e-certificates:/etc/nginx/ssl nginx:1.27-alpine
  docker cp /tmp/docker-deploy-ssl/cert.pem e2e-copy-volume:/etc/nginx/ssl/cert.pem
  docker cp /tmp/docker-deploy-ssl/key.pem e2e-copy-volume:/etc/nginx/ssl/key.pem
  docker cp /tmp/docker-deploy-conf/default.conf e2e-copy-volume:/etc/nginx/conf.d/default.conf
  docker exec e2e-copy-volume nginx -s reload
  write_docker_config copy e2e-copy-volume /etc/nginx/ssl/cert.pem /etc/nginx/ssl/key.pem /etc/nginx/conf.d/default.conf
  run sslctl deploy --cert docker-e2e
  assert_success
  docker cp e2e-copy-volume:/etc/nginx/ssl/cert.pem /tmp/named-cert.pem
  local child_ip disk_fp live_fp
  child_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' e2e-copy-volume)
  disk_fp=$(cert_fingerprint /tmp/named-cert.pem)
  for _ in $(seq 1 40); do
    live_fp=$(tls_fingerprint "$child_ip:443" "test.example.com")
    [ "$disk_fp" = "$live_fp" ] && break
    sleep 0.25
  done
  [ "$disk_fp" = "$live_fp" ]
  docker rm -f e2e-copy-volume >/dev/null
  docker run -d --name e2e-copy-volume \
    -v e2e-certificates:/etc/nginx/ssl:ro \
    -v /tmp/docker-deploy-conf/default.conf:/etc/nginx/conf.d/default.conf:ro nginx:1.27-alpine
  write_docker_config copy e2e-copy-volume /etc/nginx/ssl/cert.pem /etc/nginx/ssl/key.pem /etc/nginx/conf.d/default.conf
  run sslctl deploy --cert docker-e2e
  assert_failure
  assert_output_contains "只读"
  docker cp e2e-copy-volume:/etc/nginx/ssl/cert.pem /tmp/named-cert.pem
  [ "$(cert_fingerprint /tmp/named-cert.pem)" = "$disk_fp" ]
  rm -f /tmp/named-cert.pem
}

@test "docker-deploy: setup 支持已有 HTTPS copy 并拒绝文件验证和新 HTTPS 配置" {
  docker rm -f e2e-volume-nginx e2e-copy-nginx e2e-copy-volume >/dev/null 2>&1 || true
  docker run -d --name e2e-setup-nginx nginx:1.27-alpine
  docker exec e2e-setup-nginx mkdir -p /etc/nginx/ssl
  docker cp /tmp/docker-deploy-ssl/cert.pem e2e-setup-nginx:/etc/nginx/ssl/cert.pem
  docker cp /tmp/docker-deploy-ssl/key.pem e2e-setup-nginx:/etc/nginx/ssl/key.pem
  docker cp /tmp/docker-deploy-conf/default.conf e2e-setup-nginx:/etc/nginx/conf.d/default.conf
  docker exec e2e-setup-nginx nginx -s reload
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_success
  [ "$(binding_value '.docker.deploy_mode')" = copy ]
  [ "$(binding_value '.paths.certificate')" = /etc/nginx/ssl/cert.pem ]
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes --file-validation
  assert_failure
  assert_output_contains "暂不支持文件验证"
  docker exec e2e-setup-nginx sh -c 'printf "%s\n" "server {" "listen 80;" "server_name test.example.com;" "}" > /etc/nginx/conf.d/default.conf'
  docker exec e2e-setup-nginx nginx -s reload
  run sslctl setup --url "$MOCK_URL" --token "$TOKEN" --order 1001 --no-service --yes
  assert_failure
  assert_output_contains "仅支持已有 HTTPS"
  docker exec e2e-setup-nginx sh -c '! grep -q ssl_certificate /etc/nginx/conf.d/default.conf'
}
