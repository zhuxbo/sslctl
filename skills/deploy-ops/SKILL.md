# 部署运维规范

## 安装方式

### 一键安装

```bash
# Linux（参数传域名，脚本自动拼接 https://<host>/sslctl）
curl -fsSL https://example.com/sslctl/install.sh | sudo bash -s -- example.com

# Windows (PowerShell)
.\install.ps1 -ReleaseHost example.com
# 管道模式
$env:SSLCTL_RELEASE_URL="https://example.com/sslctl"; irm https://example.com/sslctl/install.ps1 | iex
```

### 手动安装

```bash
# 下载
wget https://example.com/releases/sslctl-linux-amd64.tar.gz
tar -xzf sslctl-linux-amd64.tar.gz

# 安装
sudo mv sslctl /usr/local/bin/
sudo chmod +x /usr/local/bin/sslctl

# 创建配置目录
sudo mkdir -p /opt/sslctl/{certs,logs,backup,sites}
```

---

## 目录结构

```
/opt/sslctl/
├── certs/              # 证书存储
│   └── {domain}/
│       ├── cert.pem
│       ├── privkey.pem
│       ├── chain.pem
│       └── fullchain.pem
├── sites/              # 站点配置
│   └── {site}.json
├── logs/               # 日志文件
│   ├── sslctl.log
│   └── debug-{date}.log
└── backup/             # 证书备份
    └── {domain}/{timestamp}/
```

---

## 运行模式

### 命令行模式

```bash
# 扫描站点
sslctl nginx scan

# 部署证书
sslctl nginx deploy --site example.com

# Debug 模式
sslctl --debug nginx deploy --site example.com
```

### Daemon 模式

```bash
# 前台运行
sslctl nginx daemon

# 后台运行（配合 systemd）
systemctl start sslctl
```

---

## Systemd 服务

### 服务文件

```ini
# /etc/systemd/system/sslctl.service
[Unit]
Description=SSL Certificate Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sslctl daemon
Restart=always
RestartSec=30
User=root
Group=root
WorkingDirectory=/opt/sslctl
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/sslctl /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt

[Install]
WantedBy=multi-user.target
```

安全限制说明：
- `NoNewPrivileges=true` — 防止提权
- `ProtectSystem=strict` — 文件系统只读
- `ReadWritePaths` — 仅允许写入工作目录和 Web 服务器配置目录

### 管理命令

```bash
# 安装服务
sudo systemctl daemon-reload
sudo systemctl enable sslctl
sudo systemctl start sslctl

# 查看状态
sudo systemctl status sslctl

# 查看日志
sudo journalctl -u sslctl -f
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

- 生产模式：`/opt/sslctl/logs/sslctl.log`
- Debug 模式：`/opt/sslctl/logs/debug-{date}.log`

### JSON 日志模式

设置 `SSLCTL_LOG_FORMAT=json` 启用 JSON 输出，适合 ELK/Loki 聚合：

```json
{"level":"INFO","msg":"证书部署成功: domain=example.com","site":"sslctl","time":"2026-03-14T15:00:00+08:00"}
```

敏感信息过滤在两种模式下均生效。

### 日志轮转

内置自动轮转（保留 30 天/10 个文件），也可配置 logrotate：

```
/opt/sslctl/logs/*.log {
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
| `SSLCTL_API_TOKEN` | API Token（优先级高于配置文件） | - |
| `SSLCTL_API_URL` | API URL（优先级高于配置文件） | - |
| `SSLCTL_LOG_FORMAT` | 日志格式：`json` 启用 JSON 输出 | text |
| `LOG_LEVEL` | 日志级别（debug/info/warn/error） | info |

---

## Manager API

### 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/deploy?order_id=xxx` | 按订单 ID 查询（推荐） |
| GET | `/api/deploy?domain=xxx` | 按域名查询（首次获取 order_id） |
| POST | `/api/deploy` | 更新/续费证书（需要 order_id） |
| POST | `/api/deploy/callback` | 部署结果回调 |

认证：`Authorization: Bearer {deploy_token}`

### POST 请求参数

```json
{
  "order_id": 12345,           // 必需（重签/续费时）
  "csr": "-----BEGIN...",      // 可选：有=本地私钥，空=服务端生成
  "domains": "a.com,b.com",    // 可选
  "validation_method": "file"  // 可选
}
```

**关键逻辑**：`csr` 为空时服务端设置 `csr_generate=1` 自动生成私钥

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

**重要**：API 返回的 `ca_certificate` 字段为必需项（空则报错，等待下一周期重试）。`deploy local` 命令的 `--ca` 参数仍然可选。
```

### 证书状态

| 状态 | 说明 | sslctl 处理 |
|------|------|-----------------|
| `active` | 证书就绪 | 直接部署 |
| `processing` | 验证中 | 放置验证文件，轮询等待 |
| `pending` | 待提交 | POST 提交 CSR |
| `unpaid` | 待支付 | POST 触发支付 |

### 部署流程

```
sslctl                    Manager API                    CA
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

## 安全特性

- **HTTPS 强制**：远程 API 必须使用 HTTPS（仅 localhost 允许 HTTP）
- **SSRF 防护**：阻止访问内网 IP（10/172.16/192.168）和云元数据地址（169.254.169.254）
- **命令白名单**：统一的 `internal/executor` 包，只允许执行预定义的 Nginx/Apache 命令
- **日志脱敏**：自动过滤 PEM 私钥、Bearer Token、password/secret 参数
- **并发安全**：`Load()` 返回深拷贝，修改不影响内部缓存，需显式 `Save()`
- **路径验证**：Docker 容器路径参数严格验证，防止命令注入和 glob 展开
- **备份原子性**：检测源文件并发修改，确保备份一致性
- **临时目录安全**：临时目录权限设置为 0700
- **日志目录安全**：日志目录权限设置为 0700（防止日志泄露）
- **配置文件锁**：并发写入保护（跨平台支持）
- **部署回滚**：部署失败自动回滚到备份
- **升级校验**：下载二进制时验证 Ed25519 签名 + SHA256 校验和，已配置公钥时拒绝未签名版本
- **systemd 安全加固**：NoNewPrivileges + ProtectSystem=strict + ReadWritePaths 白名单
- **日志轮转**：自动清理旧日志文件（保留 30 天/10 个）
- **重试限制**：CSR 签发重试次数上限（10 次）
- **私钥保护**：本机提交下，新私钥先保存到临时位置，签发成功后再替换
- **环境变量**：支持通过环境变量配置敏感信息（优先级高于配置文件）

---

## 配置文件示例

```json
{
  "api": {
    "url": "https://api.example.com",
    "token": "xxx"
  },
  "schedule": {
    "check_interval_hours": 6,
    "renew_before_days": 13,
    "renew_mode": "pull"
  },
  "certificates": [
    {
      "cert_name": "example.com-12345",
      "order_id": 12345,
      "enabled": true,
      "domains": ["*.example.com", "example.com"],
      "renew_mode": "pull",
      "bindings": [
        {
          "server_name": "www.example.com",
          "server_type": "nginx",
          "enabled": true,
          "paths": {
            "certificate": "/opt/sslctl/certs/www.example.com/cert.pem",
            "private_key": "/opt/sslctl/certs/www.example.com/key.pem"
          }
        }
      ]
    }
  ]
}
```

### schedule 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `check_interval_hours` | int | 6 | 守护进程检查间隔（小时），0 使用默认值 |
| `renew_before_days` | int | pull:13, local:15 | 提前续期天数，0 使用默认值 |
| `renew_mode` | string | `pull` | 全局续签模式，证书级别 `certificates[].renew_mode` 可覆盖 |

### config.json.lock

保存配置时自动创建的文件锁（flock），防止多个 sslctl 进程同时写入 `config.json` 导致数据损坏。无需手动管理。

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

---

## 续签模式

服务端在证书到期前 **14 天**自动续签，本地需配合选择续签模式：

| 模式 | 说明 | 时间限制 | 默认值 |
|------|------|----------|--------|
| `local` | 本机提交，本地生成私钥和 CSR | `renew_before_days >= 15` | 15 天 |
| `pull` | 自动签发，从服务端拉取已签发证书 | `renew_before_days <= 13` | 13 天 |

### 配置级别

`renew_mode` 为**订单级别**配置，在 `certificates[].renew_mode` 中设置。不同证书可使用不同模式。

系统自动适配续签窗口：
- local 模式：若全局 `renew_before_days <= 14`，自动使用 15 天
- pull 模式：若全局 `renew_before_days >= 14`，自动使用 13 天

### 命令行启用

```bash
# 一键部署时启用本机提交
sslctl setup --url <url> --token <token> --order <id> --local-key
```

### 配置文件

```json
{
  "certificates": [{
    "cert_name": "example.com-12345",
    "renew_mode": "local"
  }]
}
```

### 本机提交流程

```
定时任务 → NeedsRenewal() == true
    │
    └─ renewLocalKeyMode() → issuer.CheckAndIssue()
        │
        ├─ OrderID > 0 → QueryOrder(order_id)
        │   ├─ processing → 跳过，等待下次
        │   ├─ active → 检查私钥匹配 → 部署
        │   └─ 失败/其他 → Update(order_id, csr) 重签
        │
        └─ OrderID == 0 → Update(0, csr) 首次提交
            └─ 保存返回的 order_id
```

关键方法：`issuer.CheckAndIssue()`

### 自动签发流程

```
定时任务 → NeedsRenewal() == true
    │
    └─ renewPullMode()
        │
        ├─ 保存 order_id（无论状态）
        │
        ├─ OrderID > 0 → QueryOrder(order_id)
        │   ├─ processing + File → 放置验证文件，等待下次
        │   ├─ processing 无 File → 等待下次
        │   ├─ 失败/非 active → 跳过
        │   └─ active → 部署
        │
        └─ OrderID == 0 → Query(domain)
            └─ 获取初始 order_id，保存并部署
```

### order_id 处理规则

1. **两种模式都保存 order_id** - 用于后续查询和重签
2. **通过 order_id 查询** - 优先使用 `QueryOrder(order_id)`
3. **本机提交 POST 带 order_id** - `Update(order_id, csr)` 用于重签/续费
4. **首次部署用域名查询** - `Query(domain)` 获取初始 order_id

### 验证方法校验

使用 `config.ValidateValidationMethod(domain, method)` 校验域名与验证方法的兼容性：

| 域名类型 | file 验证 | delegation 验证 |
|---------|----------|-----------------|
| 普通域名 | ✅ | ✅ |
| 通配符域名 | ❌ 报错 | ✅ |
| IP 地址 | ✅ | ❌ 报错 |

**注意**：不兼容时直接报错，不自动切换验证方式。校验函数位于 `pkg/config/base.go`
