#!/usr/bin/env bats

load 'helpers/common'

setup() {
  [ -f /etc/apache2/apache2.conf ] && command -v apache2ctl >/dev/null || skip "仅 Debian/Ubuntu Apache 配置布局"
  common_setup
  cp /etc/apache2/apache2.conf /tmp/sslctl-define-main.conf
}

teardown() {
  if [ -f /tmp/sslctl-define-main.conf ]; then
    cp /tmp/sslctl-define-main.conf /etc/apache2/apache2.conf
    rm -f /tmp/sslctl-define-main.conf
    rm -rf /etc/apache2/sslctl-define /tmp/sslctl-define-bin
    apache2ctl restart 3>&- >/dev/null 2>&1
  fi
}

@test "apache-define: 变量 ServerRoot 的文件回退扫描、部署和 TLS 生效" {
  mkdir -p /etc/apache2/sslctl-define /tmp/sslctl-define-bin
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/apache2/sslctl-define/key.pem -out /etc/apache2/sslctl-define/cert.pem \
    -subj /CN=define.example.com 2>/dev/null
  cat > /etc/apache2/sslctl-define/vhost.conf <<'CONF'
<VirtualHost *:443>
    ServerName define.example.com
    SSLEngine on
    SSLCertificateFile sslctl-define/cert.pem
    SSLCertificateKeyFile sslctl-define/key.pem
    DocumentRoot /var/www/html
</VirtualHost>
CONF
  {
    printf 'Define SRVROOT "/etc/apache2"\nServerRoot "${SRVROOT}"\n'
    cat /tmp/sslctl-define-main.conf
    printf '\nInclude sslctl-define/vhost.conf\n'
  } > /etc/apache2/apache2.conf
  run apache2ctl -t
  assert_success
  run apache2ctl -S
  assert_success
  assert_output_contains define.example.com

  # 停止进程以避免从 /proc 直接找到真实二进制；仅屏蔽 -S，确保扫描走文件回退。
  apache2ctl stop
  for _ in $(seq 1 40); do
    [ ! -e /var/run/apache2/apache2.pid ] && break
    sleep 0.25
  done
  [ ! -e /var/run/apache2/apache2.pid ]
  cat > /tmp/sslctl-define-bin/apache2ctl <<'SH'
#!/bin/sh
if [ "$1" = "-S" ]; then
  touch /tmp/sslctl-define-bin/fallback-used
  exit 1
fi
exec /usr/sbin/apache2ctl "$@"
SH
  chmod +x /tmp/sslctl-define-bin/apache2ctl
  run env PATH="/tmp/sslctl-define-bin:$PATH" sslctl scan
  assert_success
  [ -f /tmp/sslctl-define-bin/fallback-used ]
  assert_output_contains define.example.com
  run jq -er '.sites[] | select(.server_name == "define.example.com") | .certificate_path' "$SSLCTL_CONFIG_DIR/scan-result.json"
  assert_success
  [ "$output" = /etc/apache2/sslctl-define/cert.pem ]

  apache2ctl start 3>&- >/dev/null 2>&1
  seed_fp=$(cert_fingerprint /etc/apache2/sslctl-define/cert.pem)
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /tmp/sslctl-define-bin/new.key -out /tmp/sslctl-define-bin/new.crt \
    -subj /CN=define.example.com 2>/dev/null
  run sslctl deploy local --cert /tmp/sslctl-define-bin/new.crt --key /tmp/sslctl-define-bin/new.key --site define.example.com
  assert_success
  assert_cert_key_match /etc/apache2/sslctl-define/cert.pem /etc/apache2/sslctl-define/key.pem
  new_fp=$(cert_fingerprint /tmp/sslctl-define-bin/new.crt)
  [ "$new_fp" != "$seed_fp" ]
  [ "$(cert_fingerprint /etc/apache2/sslctl-define/cert.pem)" = "$new_fp" ]
  wait_for_tls_fingerprint 127.0.0.1:443 define.example.com "$new_fp"
}
