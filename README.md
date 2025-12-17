# cert-deploy

SSL 证书自动部署工具，支持 Nginx、Apache、IIS 三种 Web 服务器。

## 特性

- 支持 Nginx、Apache、IIS 三种 Web 服务器
- 守护进程模式，自动检测并部署证书
- 支持证书有效期检查和自动续期
- 支持域名验证（包括通配符证书）
- 原子文件写入，避免部署失败导致服务中断
- 部署前自动测试配置，失败自动回滚
- 跨平台支持 (Linux/Windows/macOS)

## 目录结构

```
cert-deploy/
├── cmd/
│   ├── nginx/       # Nginx 客户端入口
│   ├── apache/      # Apache 客户端入口
│   └── iis/         # IIS 客户端入口
├── pkg/             # 共享代码
│   ├── errors/      # 错误码
│   ├── util/        # 工具函数
│   ├── csr/         # CSR 生成
│   ├── validator/   # 证书验证
│   ├── fetcher/     # API 客户端
│   ├── backup/      # 备份管理
│   └── config/      # 基础配置
├── internal/
│   ├── nginx/       # Nginx 平台代码
│   ├── apache/      # Apache 平台代码
│   └── iis/         # IIS 平台代码
├── Makefile
└── go.mod
```

## 构建

### 前置要求

- Go 1.21+

### 构建命令

```bash
# 下载依赖
make deps

# 构建当前平台所有版本
make build

# 仅构建特定版本
make build-nginx
make build-apache
make build-iis

# 构建 Linux amd64
make build-linux

# 构建 Windows amd64
make build-windows

# 构建所有平台
make build-all

# 启用 UPX 压缩（需要安装 upx）
UPX=1 make build
```

### 构建产物

构建后的二进制文件位于 `dist/` 目录：

| 文件 | 说明 | 大小 |
|------|------|------|
| cert-deploy-nginx | Nginx 部署客户端 | ~5.0M |
| cert-deploy-apache | Apache 部署客户端 | ~5.0M |
| cert-deploy-iis | IIS 部署客户端 | ~5.2M |

## 使用方法

### 目录结构

将程序放置到任意目录，首次运行会自动创建工作目录：

```
/path/to/
├── cert-deploy-nginx          # 可执行文件
└── cert-deploy/               # 工作目录（自动创建）
    ├── sites/                 # 站点配置
    │   ├── example.com.json
    │   └── api.example.com.json
    ├── logs/                  # 日志
    ├── backup/                # 证书备份
    └── certs/                 # 临时证书
```

### 站点配置

在 `cert-deploy/sites/` 目录创建站点配置文件（JSON 格式）：

```json
{
  "version": "1.0",
  "site_name": "example.com",
  "enabled": true,
  "server_type": "nginx",
  "api": {
    "url": "https://api.example.com/cert/auto",
    "refer_id": "your-refer-id"
  },
  "domains": ["example.com", "www.example.com"],
  "paths": {
    "certificate": "/etc/nginx/ssl/example.com/fullchain.pem",
    "private_key": "/etc/nginx/ssl/example.com/privkey.pem",
    "config_file": "/etc/nginx/sites-enabled/example.com.conf"
  },
  "reload": {
    "test_command": "nginx -t",
    "reload_command": "systemctl reload nginx"
  },
  "schedule": {
    "check_interval_hours": 12,
    "renew_before_days": 30
  },
  "validation": {
    "verify_domain": true,
    "ignore_domain_mismatch": false
  },
  "backup": {
    "enabled": true,
    "keep_versions": 3
  }
}
```

#### Apache 配置示例

Apache 使用分离的证书和链文件：

```json
{
  "server_type": "apache",
  "paths": {
    "certificate": "/etc/apache2/ssl/example.com/cert.pem",
    "private_key": "/etc/apache2/ssl/example.com/privkey.pem",
    "chain_file": "/etc/apache2/ssl/example.com/chain.pem"
  },
  "reload": {
    "test_command": "apachectl -t",
    "reload_command": "systemctl reload apache2"
  }
}
```

### 命令行参数

```bash
# 显示版本
./cert-deploy-nginx -version

# 部署单个站点
./cert-deploy-nginx -site example.com

# 守护进程模式（后台运行，自动检查和部署）
./cert-deploy-nginx -daemon
```

### 守护进程模式

守护进程模式下，程序会：

1. 启动时立即检查所有启用的站点
2. 每 10 分钟检查一次
3. 对于即将到期的证书（根据 `renew_before_days` 配置）自动续期
4. 支持优雅停止（SIGINT/SIGTERM）

```bash
# 前台运行
./cert-deploy-nginx -daemon

# 后台运行（Linux）
nohup ./cert-deploy-nginx -daemon > /var/log/cert-deploy.log 2>&1 &

# 使用 systemd 管理
sudo systemctl start cert-deploy
```

### Systemd 服务配置

创建 `/etc/systemd/system/cert-deploy.service`：

```ini
[Unit]
Description=SSL Certificate Auto Deploy
After=network.target

[Service]
Type=simple
ExecStart=/opt/cert-deploy/cert-deploy-nginx -daemon
Restart=always
RestartSec=10
User=root
WorkingDirectory=/opt/cert-deploy

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cert-deploy
sudo systemctl start cert-deploy
```

## 支持的命令白名单

为安全起见，reload 命令必须在白名单中：

### Nginx
- `nginx -t`
- `nginx -s reload`
- `systemctl reload nginx`
- `service nginx reload`

### Apache
- `apachectl -t`
- `apachectl graceful`
- `apache2ctl -t`
- `apache2ctl graceful`
- `httpd -t`
- `systemctl reload apache2`
- `systemctl reload httpd`
- `service apache2 reload`
- `service httpd reload`

## IIS 部署

IIS 版本使用 PowerShell 进行证书管理：

1. 将 PEM 证书转换为 PFX 格式
2. 导入到 Windows 证书存储
3. 绑定到 IIS 站点

### 环境变量

```bash
CERT_API_URL=https://api.example.com/cert/auto
CERT_REFER_ID=your-refer-id
IIS_SITE_NAME=Default Web Site
IIS_HOSTNAME=example.com
IIS_PORT=443
CERT_KEY_PATH=C:\ssl\privkey.pem
```

### 运行

```powershell
# 单次部署
.\cert-deploy-iis.exe

# 守护进程模式
.\cert-deploy-iis.exe -daemon
```

## 开发

```bash
# 运行测试
make test

# 代码检查（需要 golangci-lint）
make lint

# 清理构建产物
make clean
```

## License

MIT
