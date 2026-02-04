# sslctl Apache E2E 测试容器
# 支持多发行版构建

ARG DISTRO=ubuntu

# ==============================================================================
# Ubuntu 基础镜像
# ==============================================================================
FROM ubuntu:22.04 AS ubuntu-base

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod ssl

# ==============================================================================
# Debian 基础镜像
# ==============================================================================
FROM debian:12 AS debian-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod ssl

# ==============================================================================
# Alpine 基础镜像
# ==============================================================================
FROM alpine:3.19 AS alpine-base

RUN apk add --no-cache \
    apache2 \
    apache2-ssl \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    gcompat

# ==============================================================================
# Rocky Linux 基础镜像
# ==============================================================================
FROM rockylinux:9 AS rocky-base

RUN dnf install -y \
    httpd \
    mod_ssl \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    && dnf clean all

# ==============================================================================
# 最终镜像（根据 DISTRO 参数选择基础）
# ==============================================================================
FROM ${DISTRO}-base AS final

# 创建目录结构（适配不同发行版）
RUN mkdir -p \
    /opt/sslctl/sites \
    /opt/sslctl/logs \
    /opt/sslctl/backup \
    /opt/sslctl/certs \
    /reports

# 创建 SSL 目录（处理不同发行版差异）
RUN mkdir -p /etc/apache2/ssl 2>/dev/null || \
    mkdir -p /etc/httpd/ssl 2>/dev/null || \
    true

# 生成初始自签名证书
RUN SSL_DIR=$([ -d /etc/apache2 ] && echo "/etc/apache2/ssl" || echo "/etc/httpd/ssl") && \
    openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
        -keyout ${SSL_DIR}/default.key \
        -out ${SSL_DIR}/default.crt \
        -subj "/CN=test.example.com/O=Test/C=CN"

# 创建默认 SSL VirtualHost 配置（Ubuntu/Debian）
RUN if [ -d /etc/apache2/sites-available ]; then \
    SSL_DIR="/etc/apache2/ssl" && \
    printf '%s\n' \
        '<VirtualHost *:443>' \
        '    ServerName test.example.com' \
        '    DocumentRoot /var/www/html' \
        '' \
        '    SSLEngine on' \
        "    SSLCertificateFile ${SSL_DIR}/default.crt" \
        "    SSLCertificateKeyFile ${SSL_DIR}/default.key" \
        '' \
        '    <Directory /var/www/html>' \
        '        Options Indexes FollowSymLinks' \
        '        AllowOverride All' \
        '        Require all granted' \
        '    </Directory>' \
        '</VirtualHost>' > /etc/apache2/sites-available/test.example.com.conf && \
    a2ensite test.example.com.conf 2>/dev/null || true; \
    fi

# 创建默认 SSL VirtualHost 配置（Rocky/RHEL）
RUN if [ -d /etc/httpd/conf.d ]; then \
    SSL_DIR="/etc/httpd/ssl" && \
    printf '%s\n' \
        '<VirtualHost *:443>' \
        '    ServerName test.example.com' \
        '    DocumentRoot /var/www/html' \
        '' \
        '    SSLEngine on' \
        "    SSLCertificateFile ${SSL_DIR}/default.crt" \
        "    SSLCertificateKeyFile ${SSL_DIR}/default.key" \
        '' \
        '    <Directory /var/www/html>' \
        '        Options Indexes FollowSymLinks' \
        '        AllowOverride All' \
        '        Require all granted' \
        '    </Directory>' \
        '</VirtualHost>' > /etc/httpd/conf.d/test.example.com.conf; \
    fi

# 创建默认 SSL VirtualHost 配置（Alpine）
RUN if [ -f /etc/apache2/httpd.conf ] && [ ! -d /etc/apache2/sites-available ]; then \
    SSL_DIR="/etc/apache2/ssl" && \
    mkdir -p /etc/apache2/conf.d && \
    printf '%s\n' \
        '<VirtualHost *:443>' \
        '    ServerName test.example.com' \
        '    DocumentRoot /var/www/localhost/htdocs' \
        '' \
        '    SSLEngine on' \
        "    SSLCertificateFile ${SSL_DIR}/default.crt" \
        "    SSLCertificateKeyFile ${SSL_DIR}/default.key" \
        '' \
        '    <Directory /var/www/localhost/htdocs>' \
        '        Options Indexes FollowSymLinks' \
        '        AllowOverride All' \
        '        Require all granted' \
        '    </Directory>' \
        '</VirtualHost>' > /etc/apache2/conf.d/test.example.com.conf; \
    fi

# 复制 sslctl 二进制
COPY sslctl /usr/local/bin/sslctl
RUN chmod +x /usr/local/bin/sslctl

# 复制 Mock API（可选）
COPY mock-api /usr/local/bin/mock-api
RUN chmod +x /usr/local/bin/mock-api 2>/dev/null || true

# 创建测试启动脚本
RUN printf '%s\n' '#!/bin/bash' \
    'set -e' \
    '' \
    'echo "=== sslctl E2E Test (Apache) ==="' \
    'echo "API URL: ${SSLCTL_API_URL}"' \
    'echo "Order ID: ${TEST_ORDER_ID}"' \
    'echo "Domains: ${TEST_DOMAINS}"' \
    'echo ""' \
    '' \
    '# 启动 Apache (处理不同发行版)' \
    'echo "[1] Starting Apache..."' \
    'if command -v apachectl &>/dev/null; then' \
    '    apachectl start || apache2ctl start || httpd -k start' \
    'elif command -v httpd &>/dev/null; then' \
    '    httpd -k start' \
    'fi' \
    'sleep 1' \
    '' \
    '# 获取 SSL 目录' \
    'SSL_DIR="/etc/apache2/ssl"' \
    '[ -d /etc/httpd/ssl ] && SSL_DIR="/etc/httpd/ssl"' \
    '' \
    '# 显示当前证书信息' \
    'echo "[2] Current certificate:"' \
    'openssl x509 -in ${SSL_DIR}/default.crt -noout -subject -dates 2>/dev/null || echo "No cert"' \
    'echo ""' \
    '' \
    '# 验证 sslctl' \
    'echo "[3] sslctl version:"' \
    'sslctl --version || echo "Version check failed"' \
    'echo ""' \
    '' \
    '# 运行测试' \
    'echo "[4] Running tests..."' \
    'if [ -n "${RUN_TESTS}" ]; then' \
    '    ${RUN_TESTS}' \
    'else' \
    '    echo "No tests specified, keeping container running..."' \
    '    tail -f /dev/null' \
    'fi' \
    > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt/sslctl

# 默认保持容器运行
CMD ["tail", "-f", "/dev/null"]
