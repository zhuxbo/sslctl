# Rocky Linux 9 (CentOS replacement) with Nginx
FROM rockylinux:9

# Install EPEL and Nginx
RUN dnf install -y epel-release && \
    dnf install -y --allowerasing nginx openssl curl && \
    dnf clean all

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/nginx/ssl/api.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/api.example.com/privkey.pem \
    -out /etc/nginx/ssl/api.example.com/fullchain.pem \
    -subj "/CN=api.example.com/O=Test/C=CN"

# Create SSL site config (Rocky uses conf.d)
RUN printf '%s\n' \
    'server {' \
    '    listen 443 ssl;' \
    '    server_name api.example.com;' \
    '' \
    '    ssl_certificate /etc/nginx/ssl/api.example.com/fullchain.pem;' \
    '    ssl_certificate_key /etc/nginx/ssl/api.example.com/privkey.pem;' \
    '' \
    '    location / {' \
    '        return 200 "Hello from Rocky Nginx SSL";' \
    '        add_header Content-Type text/plain;' \
    '    }' \
    '}' > /etc/nginx/conf.d/api.example.com.conf

# Create work directory
RUN mkdir -p /opt/sslctl/{sites,logs,backup,certs}

COPY sslctl-nginx /usr/local/bin/
RUN chmod +x /usr/local/bin/sslctl-nginx

CMD ["nginx", "-g", "daemon off;"]
