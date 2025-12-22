# Ubuntu 22.04 with Nginx
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Nginx
RUN apt-get update && apt-get install -y \
    nginx \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create SSL directory and generate self-signed cert for testing
RUN mkdir -p /etc/nginx/ssl/example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/example.com/privkey.pem \
    -out /etc/nginx/ssl/example.com/fullchain.pem \
    -subj "/CN=example.com/O=Test/C=CN"

# Create SSL site config
RUN printf '%s\n' \
    'server {' \
    '    listen 443 ssl;' \
    '    server_name example.com;' \
    '' \
    '    ssl_certificate /etc/nginx/ssl/example.com/fullchain.pem;' \
    '    ssl_certificate_key /etc/nginx/ssl/example.com/privkey.pem;' \
    '' \
    '    location / {' \
    '        return 200 "Hello from Ubuntu Nginx SSL";' \
    '        add_header Content-Type text/plain;' \
    '    }' \
    '}' > /etc/nginx/sites-available/example.com.conf && \
    ln -s /etc/nginx/sites-available/example.com.conf /etc/nginx/sites-enabled/

# Create work directory
RUN mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

# Copy cert-deploy binary (will be mounted or copied)
COPY cert-deploy-nginx /usr/local/bin/
RUN chmod +x /usr/local/bin/cert-deploy-nginx

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
