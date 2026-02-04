# sslctl Nginx E2E 测试容器
# 支持多发行版构建

ARG DISTRO=ubuntu

# ==============================================================================
# Ubuntu 基础镜像
# ==============================================================================
FROM ubuntu:22.04 AS ubuntu-base

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Debian 基础镜像
# ==============================================================================
FROM debian:12 AS debian-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssl \
    curl \
    jq \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Alpine 基础镜像
# ==============================================================================
FROM alpine:3.19 AS alpine-base

RUN apk add --no-cache \
    nginx \
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
    nginx \
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

# 创建目录结构
RUN mkdir -p \
    /etc/nginx/ssl \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled \
    /opt/sslctl/sites \
    /opt/sslctl/logs \
    /opt/sslctl/backup \
    /opt/sslctl/certs \
    /reports

# 生成初始自签名证书
RUN openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/default.key \
    -out /etc/nginx/ssl/default.crt \
    -subj "/CN=test.example.com/O=Test/C=CN"

# 创建默认 SSL 站点配置
RUN printf '%s\n' \
    'server {' \
    '    listen 443 ssl;' \
    '    server_name test.example.com;' \
    '' \
    '    ssl_certificate /etc/nginx/ssl/default.crt;' \
    '    ssl_certificate_key /etc/nginx/ssl/default.key;' \
    '' \
    '    location / {' \
    '        return 200 "Hello from E2E Test";' \
    '        add_header Content-Type text/plain;' \
    '    }' \
    '}' > /etc/nginx/sites-available/test.example.com.conf

# 启用站点（处理不同发行版的差异）
RUN ln -sf /etc/nginx/sites-available/test.example.com.conf /etc/nginx/sites-enabled/ 2>/dev/null || \
    (mkdir -p /etc/nginx/conf.d && \
     cp /etc/nginx/sites-available/test.example.com.conf /etc/nginx/conf.d/)

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
    'echo "=== sslctl E2E Test (Nginx) ==="' \
    'echo "API URL: ${SSLCTL_API_URL}"' \
    'echo "Order ID: ${TEST_ORDER_ID}"' \
    'echo "Domains: ${TEST_DOMAINS}"' \
    'echo ""' \
    '' \
    '# 启动 Nginx' \
    'echo "[1] Starting Nginx..."' \
    'nginx' \
    'sleep 1' \
    '' \
    '# 显示当前证书信息' \
    'echo "[2] Current certificate:"' \
    'openssl x509 -in /etc/nginx/ssl/default.crt -noout -subject -dates 2>/dev/null || echo "No cert"' \
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
