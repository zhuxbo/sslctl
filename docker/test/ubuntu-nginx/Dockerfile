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

# 复制 sslctl 客户端
COPY sslctl-nginx-linux-amd64 /usr/local/bin/sslctl
RUN chmod +x /usr/local/bin/sslctl

# 创建工作目录
RUN mkdir -p /opt/sslctl/sites /opt/sslctl/logs /opt/sslctl/backup

WORKDIR /opt/sslctl

# 默认命令：启动 Nginx
CMD ["nginx", "-g", "daemon off;"]
