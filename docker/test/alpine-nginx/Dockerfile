# Alpine 3.19 + Nginx 测试容器 (OpenRC)
FROM alpine:3.19

RUN apk add --no-cache \
    nginx \
    curl \
    ca-certificates

# 创建 SSL 目录
RUN mkdir -p /etc/nginx/ssl

# 复制 sslctl 客户端
COPY sslctl-nginx-linux-amd64 /usr/local/bin/sslctl
RUN chmod +x /usr/local/bin/sslctl

# 创建工作目录
RUN mkdir -p /opt/sslctl/sites /opt/sslctl/logs /opt/sslctl/backup

WORKDIR /opt/sslctl

# 默认命令：启动 Nginx
CMD ["nginx", "-g", "daemon off;"]
