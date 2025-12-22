# Ubuntu 22.04 + Nginx 测试容器
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建 SSL 目录
RUN mkdir -p /etc/nginx/ssl

# 复制 cert-deploy 客户端
COPY cert-deploy-nginx-linux-amd64 /usr/local/bin/cert-deploy
RUN chmod +x /usr/local/bin/cert-deploy

# 创建工作目录
RUN mkdir -p /opt/cert-deploy/sites /opt/cert-deploy/logs /opt/cert-deploy/backup

WORKDIR /opt/cert-deploy

# 默认命令：启动 Nginx
CMD ["nginx", "-g", "daemon off;"]
