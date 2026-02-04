# Apache 部署测试容器
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Apache and tools
RUN apt-get update && apt-get install -y \
    apache2 \
    openssl \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Enable SSL module
RUN a2enmod ssl

# Create SSL directories
RUN mkdir -p /etc/apache2/ssl/apache-test.example.com \
             /etc/apache2/ssl/new-cert

# Generate initial self-signed cert (to be replaced by deployment)
RUN openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/apache-test.example.com/privkey.pem \
    -out /etc/apache2/ssl/apache-test.example.com/fullchain.pem \
    -subj "/CN=apache-test.example.com/O=OldCert/C=CN"

# Generate new certificate for deployment test
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/new-cert/privkey.pem \
    -out /etc/apache2/ssl/new-cert/fullchain.pem \
    -subj "/CN=apache-test.example.com/O=NewCert/C=CN"

# Create SSL VirtualHost config
RUN printf '%s\n' \
    '<VirtualHost *:443>' \
    '    ServerName apache-test.example.com' \
    '    DocumentRoot /var/www/html' \
    '' \
    '    SSLEngine on' \
    '    SSLCertificateFile /etc/apache2/ssl/apache-test.example.com/fullchain.pem' \
    '    SSLCertificateKeyFile /etc/apache2/ssl/apache-test.example.com/privkey.pem' \
    '' \
    '    <Directory /var/www/html>' \
    '        Options Indexes FollowSymLinks' \
    '        AllowOverride All' \
    '        Require all granted' \
    '    </Directory>' \
    '</VirtualHost>' > /etc/apache2/sites-available/apache-test.example.com.conf && \
    a2ensite apache-test.example.com.conf

# Copy binaries
COPY sslctl-apache /usr/local/bin/
COPY mock-api /usr/local/bin/
RUN chmod +x /usr/local/bin/sslctl-apache /usr/local/bin/mock-api

# Create work directory and site configuration
RUN mkdir -p /opt/sslctl/sites /opt/sslctl/logs /opt/sslctl/backup /opt/sslctl/certs && \
    echo '{"version":"1.0","site_name":"apache-test.example.com","enabled":true,"server_type":"apache","api":{"url":"http://127.0.0.1:8080/api/cert","refer_id":"test-token-12345","callback_url":"http://127.0.0.1:8080/api/callback"},"domains":["apache-test.example.com"],"paths":{"certificate":"/etc/apache2/ssl/apache-test.example.com/fullchain.pem","private_key":"/etc/apache2/ssl/apache-test.example.com/privkey.pem","config_file":"/etc/apache2/sites-enabled/apache-test.example.com.conf"},"reload":{"test_command":"apache2ctl -t","reload_command":"apache2ctl graceful"},"schedule":{"check_interval_hours":12,"renew_before_days":30},"validation":{"verify_domain":false,"test_https":false,"ignore_domain_mismatch":true},"backup":{"enabled":true,"keep_versions":3},"metadata":{}}' > /opt/sslctl/sites/apache-test.example.com.json

# Create test script
RUN printf '%s\n' '#!/bin/bash' \
    'set -e' \
    '' \
    'echo "=== Apache Deploy Test Script ==="' \
    'echo ""' \
    '' \
    '# Start Apache' \
    'echo "[1/6] Starting Apache..."' \
    'apachectl start' \
    'sleep 1' \
    '' \
    '# Show current cert info' \
    'echo "[2/6] Current certificate (before deploy):"' \
    'openssl x509 -in /etc/apache2/ssl/apache-test.example.com/fullchain.pem -noout -subject -dates' \
    'echo ""' \
    '' \
    '# Start mock API in background' \
    'echo "[3/6] Starting mock API server..."' \
    'mock-api -port 8080 \' \
    '  -cert /etc/apache2/ssl/new-cert/fullchain.pem \' \
    '  -key /etc/apache2/ssl/new-cert/privkey.pem \' \
    '  -cn apache-test.example.com &' \
    'sleep 2' \
    '' \
    '# Verify API is running' \
    'echo "[4/6] Verifying mock API..."' \
    'curl -s http://127.0.0.1:8080/health' \
    'echo ""' \
    '' \
    '# Run deployment' \
    'echo "[5/6] Running certificate deployment..."' \
    'sslctl-apache -site apache-test.example.com' \
    'echo ""' \
    '' \
    '# Show new cert info' \
    'echo "[6/6] New certificate (after deploy):"' \
    'openssl x509 -in /etc/apache2/ssl/apache-test.example.com/fullchain.pem -noout -subject -dates' \
    'echo ""' \
    '' \
    '# Show backup' \
    'echo "=== Backup files ==="' \
    'ls -la /opt/sslctl/backup/ 2>/dev/null || echo "No backup dir"' \
    'find /opt/sslctl/backup -type f 2>/dev/null || echo "No backup files"' \
    'echo ""' \
    '' \
    '# Show logs' \
    'echo "=== Deploy logs ==="' \
    'cat /opt/sslctl/logs/*.log 2>/dev/null | tail -20 || echo "No logs"' \
    'echo ""' \
    '' \
    'echo "=== Test Complete ===" ' \
    > /usr/local/bin/run-deploy-test.sh && \
    chmod +x /usr/local/bin/run-deploy-test.sh

CMD ["/usr/local/bin/run-deploy-test.sh"]
