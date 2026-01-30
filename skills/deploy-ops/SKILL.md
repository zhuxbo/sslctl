# 部署运维规范

## 安装方式

### 一键安装

```bash
# Linux
curl -fsSL https://example.com/install.sh | sudo bash

# Windows (PowerShell)
irm https://example.com/install.ps1 | iex
```

### 手动安装

```bash
# 下载
wget https://example.com/releases/cert-deploy-linux-amd64.tar.gz
tar -xzf cert-deploy-linux-amd64.tar.gz

# 安装
sudo mv cert-deploy /usr/local/bin/
sudo chmod +x /usr/local/bin/cert-deploy

# 创建配置目录
sudo mkdir -p /opt/cert-deploy/{certs,logs,backup,sites}
```

---

## 目录结构

```
/opt/cert-deploy/
├── certs/              # 证书存储
│   └── {domain}/
│       ├── cert.pem
│       ├── privkey.pem
│       ├── chain.pem
│       └── fullchain.pem
├── sites/              # 站点配置
│   └── {site}.json
├── logs/               # 日志文件
│   ├── cert-deploy.log
│   └── debug-{date}.log
└── backup/             # 证书备份
    └── {domain}/{timestamp}/
```

---

## 运行模式

### 命令行模式

```bash
# 扫描站点
cert-deploy nginx scan

# 部署证书
cert-deploy nginx deploy --site example.com

# Debug 模式
cert-deploy --debug nginx deploy --site example.com
```

### Daemon 模式

```bash
# 前台运行
cert-deploy nginx daemon

# 后台运行（配合 systemd）
systemctl start cert-deploy
```

---

## Systemd 服务

### 服务文件

```ini
# /etc/systemd/system/cert-deploy.service
[Unit]
Description=CertDeploy Certificate Management
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cert-deploy nginx daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 管理命令

```bash
# 安装服务
sudo systemctl daemon-reload
sudo systemctl enable cert-deploy
sudo systemctl start cert-deploy

# 查看状态
sudo systemctl status cert-deploy

# 查看日志
sudo journalctl -u cert-deploy -f
```

---

## 日志

### 日志级别

| 级别 | 说明 | 输出条件 |
|------|------|---------|
| DEBUG | 详细调试信息 | `--debug` 模式 |
| INFO | 常规操作信息 | 始终 |
| WARN | 警告信息 | 始终 |
| ERROR | 错误信息 | 始终 |

### 日志文件

- 生产模式：`/opt/cert-deploy/logs/cert-deploy.log`
- Debug 模式：`/opt/cert-deploy/logs/debug-{date}.log`

### 日志轮转

建议配置 logrotate：

```
/opt/cert-deploy/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `CERT_DEPLOY_DEBUG` | 启用 debug 模式 | 0 |
| `CERT_DEPLOY_DIR` | 工作目录 | /opt/cert-deploy |
| `LOG_LEVEL` | 日志级别 | info |

---

## Manager API

### 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/deploy` | 查询订单，`?domain=xxx` 按域名查询 |
| POST | `/api/deploy` | 更新/续费证书 |
| POST | `/api/deploy/callback` | 部署结果回调 |

认证：`Authorization: Bearer {deploy_token}`

### 响应格式

```json
{
  "code": 1,
  "msg": "success",
  "data": [{
    "order_id": 123,
    "domain": "example.com",
    "domains": "example.com,www.example.com",
    "status": "active",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "private_key": "-----BEGIN PRIVATE KEY-----...",
    "ca_certificate": "-----BEGIN CERTIFICATE-----...",
    "expires_at": "2025-12-31",
    "file": {"path": "/.well-known/pki-validation/xxx.txt", "content": "..."}
  }]
}
```

### 证书状态

| 状态 | 说明 | cert-deploy 处理 |
|------|------|-----------------|
| `active` | 证书就绪 | 直接部署 |
| `processing` | 验证中 | 放置验证文件，轮询等待 |
| `pending` | 待提交 | POST 提交 CSR |
| `unpaid` | 待支付 | POST 触发支付 |

### 部署流程

```
cert-deploy                    Manager API                    CA
    │                              │                          │
    │ 1. GET /api/deploy?domain=   │                          │
    │ ────────────────────────────>│                          │
    │ <────────────────────────────│                          │
    │   {order_id, status, cert}   │                          │
    │                              │                          │
    │ [status=processing 时]       │                          │
    │ 写入验证文件到 webroot       │                          │
    │ 轮询等待 status=active       │                          │
    │                              │                          │
    │ [本地部署]                   │                          │
    │ - 验证证书                   │                          │
    │ - 备份旧证书                 │                          │
    │ - 写入新证书                 │                          │
    │ - nginx -t && reload        │                          │
    │                              │                          │
    │ 2. POST /api/deploy/callback │                          │
    │ {order_id, domain, status}   │                          │
    │ ────────────────────────────>│                          │
    │ <────────────────────────────│                          │
    │                              │                          │
```

---

## 常见问题

### 权限不足

症状：无法写入证书或重载服务

解决：使用 sudo 运行，或配置 sudoers

### 网络问题

症状：无法连接 API

解决：检查网络、防火墙、代理设置

### 服务重载失败

症状：证书已更新但服务未生效

解决：
1. 检查服务配置语法
2. 检查服务是否运行
3. 手动重载测试
