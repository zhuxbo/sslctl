# Alpine Linux with Nginx
FROM alpine:3.19

# Install Nginx
RUN apk add --no-cache nginx openssl curl

# Create necessary directories
RUN mkdir -p /run/nginx

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/nginx/ssl/cdn.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/cdn.example.com/privkey.pem \
    -out /etc/nginx/ssl/cdn.example.com/fullchain.pem \
    -subj "/CN=cdn.example.com/O=Test/C=CN"

# Create SSL site config
RUN mkdir -p /etc/nginx/http.d && \
    printf '%s\n' \
    'server {' \
    '    listen 443 ssl;' \
    '    server_name cdn.example.com;' \
    '' \
    '    ssl_certificate /etc/nginx/ssl/cdn.example.com/fullchain.pem;' \
    '    ssl_certificate_key /etc/nginx/ssl/cdn.example.com/privkey.pem;' \
    '' \
    '    location / {' \
    '        return 200 "Hello from Alpine Nginx SSL";' \
    '        add_header Content-Type text/plain;' \
    '    }' \
    '}' > /etc/nginx/http.d/cdn.example.com.conf

# Create work directory
RUN mkdir -p /opt/sslctl/{sites,logs,backup,certs}

COPY sslctl-nginx /usr/local/bin/
RUN chmod +x /usr/local/bin/sslctl-nginx

CMD ["nginx", "-g", "daemon off;"]
