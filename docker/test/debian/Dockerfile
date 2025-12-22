# Debian 12 with Nginx
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

# Install Nginx
RUN apt-get update && apt-get install -y \
    nginx \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/nginx/ssl/test.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/test.example.com/privkey.pem \
    -out /etc/nginx/ssl/test.example.com/fullchain.pem \
    -subj "/CN=test.example.com/O=Test/C=CN"

# Create SSL site config
RUN printf '%s\n' \
    'server {' \
    '    listen 443 ssl;' \
    '    server_name test.example.com;' \
    '' \
    '    ssl_certificate /etc/nginx/ssl/test.example.com/fullchain.pem;' \
    '    ssl_certificate_key /etc/nginx/ssl/test.example.com/privkey.pem;' \
    '' \
    '    location / {' \
    '        return 200 "Hello from Debian Nginx SSL";' \
    '        add_header Content-Type text/plain;' \
    '    }' \
    '}' > /etc/nginx/sites-available/test.example.com.conf && \
    ln -s /etc/nginx/sites-available/test.example.com.conf /etc/nginx/sites-enabled/

# Create work directory
RUN mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

COPY cert-deploy-nginx /usr/local/bin/
RUN chmod +x /usr/local/bin/cert-deploy-nginx

CMD ["nginx", "-g", "daemon off;"]
