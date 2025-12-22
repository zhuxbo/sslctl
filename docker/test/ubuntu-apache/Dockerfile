# Ubuntu 22.04 with Apache
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache with SSL module
RUN apt-get update && apt-get install -y \
    apache2 \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Enable SSL module
RUN a2enmod ssl

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/apache2/ssl/shop.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/shop.example.com/privkey.pem \
    -out /etc/apache2/ssl/shop.example.com/fullchain.pem \
    -subj "/CN=shop.example.com/O=Test/C=CN"

# Create SSL VirtualHost config
RUN printf '%s\n' \
    '<VirtualHost *:443>' \
    '    ServerName shop.example.com' \
    '    DocumentRoot /var/www/html' \
    '' \
    '    SSLEngine on' \
    '    SSLCertificateFile /etc/apache2/ssl/shop.example.com/fullchain.pem' \
    '    SSLCertificateKeyFile /etc/apache2/ssl/shop.example.com/privkey.pem' \
    '' \
    '    <Directory /var/www/html>' \
    '        Options Indexes FollowSymLinks' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '</VirtualHost>' > /etc/apache2/sites-available/shop.example.com.conf && \
    a2ensite shop.example.com.conf

# Create work directory
RUN mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

COPY cert-deploy-apache /usr/local/bin/
RUN chmod +x /usr/local/bin/cert-deploy-apache

# Start Apache in foreground
CMD ["apachectl", "-D", "FOREGROUND"]
