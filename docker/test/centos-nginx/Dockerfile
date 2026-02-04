# CentOS Stream 9 + Nginx 测试容器
FROM quay.io/centos/centos:stream9

RUN dnf install -y nginx curl ca-certificates \
    && dnf clean all

# 创建 SSL 目录
RUN mkdir -p /etc/nginx/ssl

# 复制 sslctl 客户端
COPY sslctl-nginx-linux-amd64 /usr/local/bin/sslctl
RUN chmod +x /usr/local/bin/sslctl

# 创建工作目录
RUN mkdir -p /opt/sslctl/sites /opt/sslctl/logs /opt/sslctl/backup

WORKDIR /opt/sslctl

CMD ["nginx", "-g", "daemon off;"]
