# Alpine Linux with Apache
FROM alpine:3.19

# Install Apache with SSL module
RUN apk add --no-cache apache2 apache2-ssl openssl curl

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/apache2/ssl/static.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/static.example.com/privkey.pem \
    -out /etc/apache2/ssl/static.example.com/fullchain.pem \
    -subj "/CN=static.example.com/O=Test/C=CN"

# Create SSL VirtualHost config
RUN mkdir -p /etc/apache2/conf.d && \
    printf '%s\n' \
    '<VirtualHost *:443>' \
    '    ServerName static.example.com' \
    '    DocumentRoot /var/www/localhost/htdocs' \
    '' \
    '    SSLEngine on' \
    '    SSLCertificateFile /etc/apache2/ssl/static.example.com/fullchain.pem' \
    '    SSLCertificateKeyFile /etc/apache2/ssl/static.example.com/privkey.pem' \
    '' \
    '    <Directory /var/www/localhost/htdocs>' \
    '        Options Indexes FollowSymLinks' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '</VirtualHost>' > /etc/apache2/conf.d/static.example.com.conf

# Create work directory
RUN mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

COPY cert-deploy-apache /usr/local/bin/
RUN chmod +x /usr/local/bin/cert-deploy-apache

# Start Apache in foreground
CMD ["httpd", "-D", "FOREGROUND"]
