# Rocky Linux 9 with Apache (httpd)
FROM rockylinux:9

# Install Apache (httpd) with SSL module
RUN dnf install -y epel-release && \
    dnf install -y --allowerasing httpd mod_ssl openssl curl && \
    dnf clean all

# Create SSL directory and generate self-signed cert
RUN mkdir -p /etc/httpd/ssl/admin.example.com && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/httpd/ssl/admin.example.com/privkey.pem \
    -out /etc/httpd/ssl/admin.example.com/fullchain.pem \
    -subj "/CN=admin.example.com/O=Test/C=CN"

# Generate default SSL cert for mod_ssl (required by ssl.conf)
RUN mkdir -p /etc/pki/tls/certs /etc/pki/tls/private && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/pki/tls/private/localhost.key \
    -out /etc/pki/tls/certs/localhost.crt \
    -subj "/CN=localhost/O=Test/C=CN"

# Create SSL VirtualHost config (Rocky uses conf.d)
RUN printf '%s\n' \
    '<VirtualHost *:443>' \
    '    ServerName admin.example.com' \
    '    DocumentRoot /var/www/html' \
    '' \
    '    SSLEngine on' \
    '    SSLCertificateFile /etc/httpd/ssl/admin.example.com/fullchain.pem' \
    '    SSLCertificateKeyFile /etc/httpd/ssl/admin.example.com/privkey.pem' \
    '' \
    '    <Directory /var/www/html>' \
    '        Options Indexes FollowSymLinks' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '</VirtualHost>' > /etc/httpd/conf.d/admin.example.com.conf

# Create work directory
RUN mkdir -p /opt/cert-deploy/{sites,logs,backup,certs}

COPY cert-deploy-apache /usr/local/bin/
RUN chmod +x /usr/local/bin/cert-deploy-apache

# Start httpd in foreground
CMD ["httpd", "-D", "FOREGROUND"]
