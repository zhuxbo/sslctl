# Nginx/Apache 证书部署规范

## Nginx

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/nginx/nginx.conf` | `/etc/nginx/sites-enabled/` |
| CentOS/RHEL | `/etc/nginx/nginx.conf` | `/etc/nginx/conf.d/` |
| 宝塔面板 | `/www/server/nginx/conf/nginx.conf` | `/www/server/panel/vhost/nginx/` |

### 证书配置

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # 推荐配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}
```

### 配置解析

站点扫描时提取的关键信息：

- `server_name`: 域名列表
- `ssl_certificate`: 证书路径
- `ssl_certificate_key`: 私钥路径
- `listen`: 端口和 SSL 标志

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/cert-deploy/internal/executor"

// 白名单中的命令
executor.Run("nginx -t")
executor.Run("nginx -s reload")
executor.Run("systemctl reload nginx")
```

支持的 Nginx 命令：
- `nginx -t`, `nginx -s reload`
- `systemctl reload/restart nginx`
- `service nginx reload/restart`
- `rc-service nginx reload/restart`

---

## Apache

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/apache2/apache2.conf` | `/etc/apache2/sites-enabled/` |
| CentOS/RHEL | `/etc/httpd/conf/httpd.conf` | `/etc/httpd/conf.d/` |
| 宝塔面板 | `/www/server/apache/conf/httpd.conf` | `/www/server/panel/vhost/apache/` |

### 证书配置

```apache
<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem

    # 推荐配置
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
</VirtualHost>
```

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/cert-deploy/internal/executor"

executor.Run("apachectl -t")
executor.Run("apachectl graceful")
executor.Run("systemctl reload apache2")
```

支持的 Apache 命令：
- `apachectl -t/graceful/restart`
- `apache2ctl -t/graceful/restart`
- `httpd -t`
- `systemctl reload/restart apache2/httpd`
- `service apache2/httpd reload/restart`
- `rc-service apache2/httpd reload/restart`

---

## 证书文件

### 文件类型

| 文件 | 内容 | 用途 |
|-----|------|------|
| `cert.pem` | 服务器证书 | 主证书 |
| `privkey.pem` | 私钥 | 解密 |
| `chain.pem` | 中间证书链 | 验证链 |
| `fullchain.pem` | 证书 + 中间链 | Nginx 推荐 |

### 默认存储路径

```
/opt/cert-deploy/certs/{domain}/
├── cert.pem
├── privkey.pem
├── chain.pem
└── fullchain.pem
```

### 权限设置

```bash
chmod 644 cert.pem chain.pem fullchain.pem
chmod 600 privkey.pem
chown root:root /opt/cert-deploy/certs/
```

---

## 部署流程

1. 从 API 获取证书（PEM 格式）
2. 保存证书文件到本地
3. 更新 Web 服务器配置（如需要）
4. 测试配置语法
5. 重载服务
6. 验证证书生效
7. 发送回调通知

### 回滚

部署前备份旧证书：

```bash
/opt/cert-deploy/backup/{domain}/{timestamp}/
├── cert.pem
├── privkey.pem
└── ...
```

---

## 常见问题

### 证书链不完整

症状：浏览器报证书错误，但证书本身有效

解决：确保 `fullchain.pem` 包含中间证书

### 权限问题

症状：Nginx/Apache 无法读取证书

解决：检查文件权限，私钥应为 600

### 配置语法错误

症状：重载失败

解决：先执行 `nginx -t` 或 `apachectl configtest`
