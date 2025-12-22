# Alpine 3.19 + Nginx 测试容器 (OpenRC)
FROM alpine:3.19

RUN apk add --no-cache \
    nginx \
    curl \
    ca-certificates

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
