# 部署运维规范

这是领域参考，按任务读取相关章节：CLI/服务、Manager API、部署链与回调、续签、集成测试。示例命令不表示执行授权；本地验证由 `skills/finish-check.md` 决定，外部写入测试需对应授权。

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
# 下载并解压实际发布资产（版本号仅作示例）
wget https://example.com/sslctl/main/v1.2.3/sslctl-linux-amd64.gz
gzip -dc sslctl-linux-amd64.gz > sslctl

# 安装
sudo install -m 0755 sslctl /usr/local/bin/sslctl

# 创建配置目录
sudo mkdir -p /opt/sslctl/{certs,pending-keys,logs,backup}
```

---

## 目录结构

```
/opt/sslctl/
├── config.json         # 统一配置
├── config.json.lock    # 配置写锁
├── scan-result.json    # 最近一次扫描结果
├── certs/              # 已转正证书与私钥
│   └── {server_name}/
│       ├── cert.pem
│       └── key.pem
├── pending-keys/       # local 模式待签发私钥
├── logs/               # {module}-YYYY-MM-DD.log
│   └── debug/          # Debug 模式日志
└── backup/             # 证书备份
    └── {server_name}/{timestamp}/
```

---

## 运行模式

### 命令行模式

```bash
# 扫描站点
sslctl scan

# 部署证书
sslctl deploy --cert <cert_name> --site example.com

# Debug 模式
sslctl --debug deploy --cert <cert_name> --site example.com
```

### Daemon 模式

```bash
# 前台运行
sslctl daemon

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
ReadWritePaths=/opt/sslctl
ReadWritePaths=-/etc/nginx
ReadWritePaths=-/etc/apache2
ReadWritePaths=-/etc/httpd
ReadWritePaths=-/etc/letsencrypt

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

- 生产模式：`/opt/sslctl/logs/{module}-YYYY-MM-DD.log`
- Debug 模式：`/opt/sslctl/logs/debug/{module}-YYYY-MM-DD.log`

### JSON 日志模式

设置 `SSLCTL_LOG_FORMAT=json` 启用 JSON 输出，适合 ELK/Loki 聚合：

```json
{"level":"INFO","msg":"证书部署成功: domain=example.com","module":"sslctl","time":"2026-03-14T15:00:00+08:00"}
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
| GET | `/api/deploy?order=123` | 按订单 ID 查询；批量用逗号分隔，上限 100 |
| POST | `/api/deploy` | 更新/续费证书（需要 order_id） |
| POST | `/api/deploy/callback` | 部署结果回调 |

认证：`Authorization: Bearer {deploy_token}`

### 超时与重试（`pkg/fetcher`）

- **单次尝试超时按方法套用**（deploy-spec §11）：GET 30s、POST 60s，与父 ctx deadline 取更早者。
  不使用 `http.Client.Timeout`——它是覆盖整个请求的单一上限、无法按方法区分，会把 POST 一并压到 GET 的时长。
- **超时作用域覆盖响应体读取**：`doAttempt` 在同一超时内读完 body 并关闭响应，`doWithRetry` 返回 `(statusCode, body, error)`，
  调用方**不再持有 `*http.Response`**。可重试请求走 `doWithRetry`；CSR 提交须走复用同等超时、响应体读取和大小限制的单次 helper，不得直连无超时保护的 `f.client.Do`。
- **响应体上限分级**：仅 `200` 按调用方给定的 `maxBodySize` 读（批量 5MB / 一般 512KB / 回调 64KB）；
  非 200 一律限 1KB，避免 5MB × 最多 4 次尝试让错误信息本身变成 MB 级字符串流进日志与回调 `message` 的脱敏正则。
- **响应体读取中断按可重试处理**：一次连接中断不应直接变成 JSON 解析失败并终止整条链路；
  但携带非空 `csr` 的提交 POST 例外，一旦可能送达即不做传输层重试，交由状态机 query-first 恢复。
- 退避：GET、部署回调与自动重签开关最多 3 次重试，指数退避 1s→2s→4s，带 ±25% 抖动；
  CSR 提交 POST 不重试。

### POST 请求参数

```json
{
  "order_id": 12345,
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "domains": "a.com,b.com",
  "validation_method": "file"
}
```

本节描述 local 模式：客户端先 GET 确认订单仍为 `active`，再提交本机生成的非空 CSR。

### 响应格式

GET 查询响应：

```json
{
  "code": 1,
  "msg": "success",
  "data": {
    "data": [{
      "order_id": 123,
      "domains": "example.com,www.example.com",
      "status": "active",
      "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
      "certificate": "-----BEGIN CERTIFICATE-----...",
      "private_key": "-----BEGIN PRIVATE KEY-----...",
      "ca_certificate": "-----BEGIN CERTIFICATE-----...",
      "expires_at": "2025-12-31"
    }],
    "renew_before_days": 14
  }
}
```

POST 成功响应中的 `data` 是单个 CertData，并在同层返回 `renew_before_days`。`certificate`、
`ca_certificate`、`private_key`、`issued_at`、`expires_at` 仅在 `active` 时返回；API 部署 active
证书时 `ca_certificate` 必须非空。`deploy local` 命令的 `--ca` 参数仍然可选。

### 证书状态

| 状态 | 说明 | sslctl 处理 |
|------|------|-----------------|
| `active` | 证书就绪 | 直接部署 |
| `processing` | 验证中 | 放置验证文件，轮询等待 |
| `pending` | 已提交但仍在处理 | 归一为 `processing`，后续只 GET 查询，不重复 POST |
| `approving` | 审批中（processing 与 active 之间的短暂中间态） | 归一为 `processing`，继续查询等待 |
| `unpaid` | 待支付 | 只查询等待，不提交 CSR |
| `cancelling` | 取消中 | 只查询等待，不提交 CSR |
| `failed` / `cancelled` / `revoked` / `expired` | 真终态 | 记录展示状态，停止本轮，后续仅查询自愈 |
| `renewed` / `reissued` | 续费链异常 | 按终态告警并停止本轮 |
| 其他未知状态 | 服务端扩展状态 | 按等待态处理，只 GET 查询 |

### 部署流程

```
sslctl                    Manager API                    CA
    │                              │                          │
    │ 1. GET /api/deploy?order=123 │                          │
    │ ────────────────────────────>│                          │
    │ <────────────────────────────│                          │
    │ {order_id,status,csr,cert}   │                          │
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
    │ {order_id,status,deployed_at}│                          │
    │ ────────────────────────────>│                          │
    │ <────────────────────────────│                          │
    │                              │                          │
```

---

## 部署链与回调契约

统一规范详见 `deploy-spec.md`，此处为 sslctl 侧要点。

### 回调契约（`pkg/certops`）

- 部署/续签结果通过 `POST /api/deploy/callback` 上报，属**非关键路径**：失败仅记录日志，传输层含指数退避重试。
- 请求体固定三字段 `order_id` / `status` / `deployed_at`，外加**可选** `message`（`omitempty`，仅 `status=failure` 携带）。
- `status` 仅 `success` / `failure`（`pending` 不上报回调）。
- `message` 为失败原因摘要：客户端复用 `logger.Sanitize` 脱敏后按 rune 截断 ≤256（`callbackMessageMaxLen=256`，服务端上限 500，超限整条被拒）。
- 客户端只上报明确的部署结果：每次部署成功或失败由编排层在结果落盘后尽力回调一次；签发失败不回调，触顶、过期和 policy 阻断均静默终止且不回调。
- 底层部署函数只返回结构化结果，不自行发送回调；传输失败仅由既有退避重试兜底，最终失败只记日志，不持久排队或补发。
- **零启用绑定不上报**：证书 enabled 却无任何启用绑定时零部署即无部署结果，落 `no_binding_blocked_at` 后静默等待人工处理（deploy-spec §2.8、§5.2 policy_blocked 同构）。
- **幽灵失败绑定不上报**：`failed_bindings` 与启用绑定交集为空时一个绑定都未重试，不报 success、不发回调。
- **绑定重试触顶**：仅"确实发生了部署且仍失败"的出口上报一次带「绑定重试已达上限」标注的 failure；查询失败、私钥不可读等未发生部署的出口按 deploy-spec §2.8 触顶静默；证书处于 `processing` 不计入配额也不上报。
- **手动 `sslctl deploy` 上报一次部署结果**（deploy-spec §5.1 步骤 6）：CLI 无 deadline，回调显式限定 `certops.CallbackFallbackBudget`（90s）。
- **回调脱离取消传播**（`certops.callbackContext`）：回调是部署结果的唯一出口，父 ctx 取消（daemon SIGTERM、检查超时）时沿用会让整轮结果凭空消失，因此基于 `context.WithoutCancel` 重建，并按四条分支定预算——已取消 → 90s 兜底（**必须先于余量判断**，`cancel()` 不改变 deadline，此时父预算余量可能仍有几十分钟）；余量 ≤90s → 90s 兜底；余量充裕 → 保留父 deadline；无 deadline → 不设限，由单次请求超时与重试上限兜底。90s ≈ 一次完整 POST + 约 1s 退避 + 被截断的第二次尝试，daemon 60s 关停预算可能将其截断。
- **`sslctl setup` 上报部署结果**（deploy-spec §5.1 步骤 6）：单证书尝试一次，批量中每个有资格的证书逐一尝试；本轮回调熔断后允许余下结果缺行并在汇总中说明。`success`/`failure` 由该证书是否有失败站点决定。调用位置有硬性要求——必须紧跟部署循环，早于全失败 `os.Exit(1)` 与保存门禁；放到保存阶段会被这两道关卡同时吃掉，而它们拦下的恰是最该上报的那批。三条未发生部署的 `continue`（无绑定、缺私钥、私钥验证失败）不上报，其中"需要私钥"按 deploy-spec §5.3 属区别于"失败"的第三类。
- **已知偏离**：`retryFailedBindings` 的 `QueryOrder` 失败出口在未发生部署时仍报 failure（查询失败不是部署结果，与 deploy-spec §2.8 不符）；触顶后停止。该现状不是统一契约的例外，涉及此路径时按当前代码核实。

### 部署链语义（setup/deploy/续签）

- **复用统一部署路径**：setup 部署走 `Service.DeployToBinding`，与 deploy/续签一致地做证书私钥校验、覆盖前备份现有证书、测试/reload 失败自动回滚，消除 setup 直接覆盖无备份的旧路径。
- **失败如实统计**：SSL 配置安装失败的绑定标记 `Enabled=false` 后跳过部署并计入失败，单证书与批量模式一致，不误报"部署成功"。
- **setup 部署失败按错误性质分流**（`sslerrors.IsPermanentDeployError`，判定取 `errors.As` 的最外层结构化错误）：
  只有 `Config@write_cert`（Docker 绑定校验不通过、创建部署器失败）与 `Validation@validate`（证书私钥不匹配）算**永久性**——绑定配置本身有问题，禁用绑定等人工重新 setup；
  其余（`Config@test_config`、`Config@rollback`、`Reload@*`、`Permission@*`、`Unknown@*`、非结构化错误）一律**保留绑定启用**并写入 `failed_bindings` 交给 daemon 每日重试。
  这不等于"一定会自愈"（`Permission` 多半要人工介入），但禁用会让 daemon 永不接手、站点静默过期；保持可重试至少能持续暴露问题，触顶后转 `stale_bindings` 告警。
  `nginx -t` 失败构造的正是 `Config@test_config`——最典型的可修复情形，判成永久会直接禁用，是本项要消除的洞。
- **错误码不随"有无备份"变化**（项 L）：`deployToBinding` 回滚成功后用 `%w` 包裹原错误而非重造 `Reload@reload`，
  否则同一根因在"有备份"与"首次部署无备份"两条路径上会得到相反分类。`IsPermanentDeployError` 因此必须穿透包裹层取根因。
- **批量保存门禁按 `SiteSuccess > 0`**：此前用"有没有启用的绑定"，二者等价仅仅因为部署失败一律置 `Enabled=false`。
  保留可重试绑定后该等价被打破，全失败的证书会被写入配置，进而由 `AddCert` 摘除其它证书的同名绑定。
- **退出码语义**（`hasDeployFailures`）：任一站点部署失败、任一证书失败、或存在需人工提供私钥而跳过的证书，进程即以退出码 1 结束（部分失败也算失败，先保存成功站点配置再退出），单证书与批量模式一致。
- **部署层贯通 context**：`webserver.Deployer` 的 `Deploy`/`Reload`/`Test`/`Rollback` 首参接收 ctx，一路传到 `executor.RunWithin`
  （在父 ctx 之下再套单命令上限，取二者更早者，上游无 deadline 时不丢默认保护）、Windows 服务停止轮询与 Apache reload 等待循环。
  目的是让检查超时与关停信号中断部署等待、缩短强杀窗口；**不解决**"新私钥 + 旧证书"的磁盘窗口——那来自两次非事务写入，仍由 `deploy_started_at` 重放兜底。
- **回滚必须脱离取消传播**（`certops.RollbackBudget`）：部署失败往往正是 ctx 被取消所致，回滚沿用同一个 ctx 会当场失败，
  直接落进"部署失败且回滚失败（服务可能不可用）"——比不贯通 ctx 更糟。回滚走 `WithoutCancel` + 独立预算，仍然有界。
  测试侧的 mock 部署器必须如实返回 `ctx.Err()`，否则这类用例永远是绿的、测不出任何东西。
- **pending 私钥转正时机**（local 续签，deploy-spec §3.8）：签发 active 后先校验服务端证书与 pending 私钥配对；任一绑定部署成功即接纳新证书并转正私钥，旧线上私钥由部署路径覆盖前备份。失败绑定写入独立有限重试状态，订单级回调仍为 failure；部署全失败时不得转正或更新到期元数据。

---

## 定向解除管理

- `sslctl cleanup --site <server_name>` 精确移除站点绑定、对应失败/陈旧状态和站点内部备份；证书失去最后一个绑定时同步删除证书记录及其 pending 私钥。
- `sslctl cleanup --cert <cert_name>` 删除全部同名证书记录、其 pending 私钥，以及没有被其它证书继续引用的站点内部备份。
- `sslctl cleanup --list` 只读列出全部证书记录（包括禁用和重复记录）及全部站点绑定，不加续签锁，也不清理数据；必须单独使用。
- 执行清理时两种目标必须二选一，默认交互确认，`--yes` 可用于非交互执行；cleanup 与 setup、deploy、rollback、daemon 续签共用 `renewal.lock`。
- cleanup 只解除 sslctl 管理，不修改 Web 配置、不重载服务，也不删除在线证书、私钥、证书链或外部验证文件；`certs/` 下的在线文件同样保留。
- 配置先原子落盘，再清理内部文件；内部文件删除失败时返回非零并报告残留，不能静默视为完全成功。

---

## 安全特性

- **HTTPS 强制**：远程 API 必须使用 HTTPS（仅 localhost 允许 HTTP）
- **续签/部署进程互斥**：`config.AcquireRenewalLock` 共享 `renewal.lock`，daemon 续签检查与手动 deploy/setup/rollback/cleanup 非阻塞互斥，手动侧被占用时退出（deploy-spec §3.7）
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
- **私钥保护**：本机提交下，新私钥先保存到临时位置（pending-keys/），证书私钥配对校验通过且部署成功后再转正；配对校验失败按失败处理，保留 pending 私钥、不动线上私钥
- **环境变量**：支持通过环境变量配置敏感信息（优先级高于配置文件）

---

## 配置文件示例

```json
{
  "schedule": {
    "renew_before_days": 14,
    "renew_mode": "pull"
  },
  "certificates": [
    {
      "cert_name": "example.com-12345",
      "order_id": 12345,
      "enabled": true,
      "domains": ["*.example.com", "example.com"],
      "renew_mode": "pull",
      "api": {
        "url": "https://api.example.com",
        "token": "xxx"
      },
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
| `renew_before_days` | int | 14 | 提前续期天数，上限 30，0 使用默认值 14；由服务端下发并在每次 API 交互后回写（`DefaultRenewBeforeDays=14`、`MaxRenewBeforeDays=30`，见 deploy-spec 2.9） |
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

两种模式统一：`renew_before_days` 默认 14 天、上限 30 天，由服务端下发并在每次 API 交互后回写本地配置。超过 30 视为服务端异常值，拒绝更新并保留本地现值，防止异常大值把全部证书拉入需续签状态、触发每日全量续签（`DefaultRenewBeforeDays=14`、`MaxRenewBeforeDays=30`，见 deploy-spec 2.9）。

| 模式 | 说明 | 默认续签阈值 |
|------|------|--------|
| `local` | 本机提交，本地生成私钥和 CSR | 14 天 |
| `pull` | 自动签发，从服务端拉取已签发证书 | 14 天 |

### 续签判定与调度

- **续签判定**（`NeedsRenewal`）：到期时间未知（元数据零值）返回 false，交由续签检查先查询 API 回填元数据后再判定；已过期证书不再触发续签（`IsExpired` 按时间点判定，过期不足 24 小时也算已过期，无整数天截断偏移）；否则 `DaysUntilExpiry() <= renew_before_days` 时续签。
- **到期时间未知不再静默跳过**：元数据零值（部署成功但保存失败、带外换证等）会自动查询 API 回填元数据后按正常逻辑判定；过期告警对该情况输出"到期时间未知"。
- **定时检查**：每天一次，随机选择明天 09:00~23:59 的时间点执行（服务端 0:00~7:59 续签，预留 1 小时签发）；启动即检查一次；运行中若 `LastCheckAt` 距今超 25 小时（停摆/睡眠/任务跳过）则在 30~60 分钟内补偿一轮。
- **单证书 panic 隔离**：续签循环中单证书处理 panic 记为该证书 failure（Error 日志 + 计入统计），不拖垮整轮。
- **多证书续签间隔**：按证书数动态计算 5~120 秒的随机延迟，整轮分散预算上限 600 秒。
- **陈旧绑定告警**（`stale_bindings`/`stale_since`，metadata 平台扩展字段）：该绑定当前未持有本证书的最新证书。
  证书级到期日只反映最新签发的证书，这些站点仍挂旧证书，按证书级判断永远看不出风险——因此 `CheckExpiry` 每轮单独 Error。
  迁入点：`parkExhaustedRetries`（主）与 `persistTerminalState`（终止态兜底）；迁移一律经 `retainableStaleNames` 过滤掉不在 `cert.Bindings` 中的名字，
  否则 `ClearStaleBinding` 的入参永远来自遍历 `cert.Bindings` 的部署循环，幽灵名字进去就再也出不来、告警无法消除。
  `StaleSince` 仅在从空变非空时设置。**已知未覆盖**：安全余量早退是裸 `return`、不经 `persistTerminalState`，该情形 ≤24h 后由过期路径补上。
- **证书过期告警**（守护进程 `CheckExpiry` 周期检查）：剩余不足 7 天输出 Error，不足 13 天输出 Warn，已过期输出 Error（阈值来自 `pkg/certops/service.go` 的 `7*24h`/`13*24h`）。
  该告警以 `defer` 覆盖 `checkAndDeploy` 的**全部**出口——未取到续签锁、`CheckAndRenewAll` 出错时同样告警，否则"另一个进程在跑"与"API 持续失败"会连告警一起静默，恰是最需要告警的场景。
  `CheckAndRenewAll` 被取消时会连同已完成证书的结果一起返回，daemon 先输出统计再报错，不丢这批结果。
- **尝试次数上限**：签发与部署分别计数；计数达到 10 只阻止建立下一次新尝试，已持久化或已被服务端接受的第 10 次尝试仍可查询、部署和崩溃恢复（不发送触顶回调；部署成功——含手动 `sslctl deploy`——会清零计数并解除停机）。
- **零启用绑定阻断**（`no_binding_blocked_at`，metadata 平台扩展字段）：证书 enabled 却无任何启用绑定（站点被改绑到其它证书、人工禁用、改名孤儿条目）时退出自动流程——**不发起任何 API 请求**、不部署、不计数、不回调，落标记等待人工处理；恢复启用绑定或重跑 setup 后自动解除，**计数不复位**。闸门内部先跑纯本地判定：已过期仍转 `EXPIRED`、部署触顶仍转 `CAPPED`（deploy-spec §3.2）。
- **零绑定 + 在途签发无终止态**：闸门命中且 `last_issue_state` 为 `processing`/`active` 时不会进入任何终止态，在途订单与 `pending-keys/` 私钥会滞留至人工处理（日志会额外标注）。
- **失败绑定重试用独立配额**（`retry_attempt_count`，metadata 平台扩展字段）：与证书级 `deploy_attempt_count` 分离，10 轮后把绑定转入 `stale_bindings` 并停止重试，**不会把整张证书打进 `CAPPED`**——共用公共计数时一个坏站点或一次 API 宕机就会连健康站点一起停掉续签。计数在入口递增（早于订单查询，保证 API 持续不可达时也能终止）；证书处于 `processing` 属上游在途状态，回滚本轮计数、不计入配额。

### processing / active 状态处理

- `processing`（含 `pending` / `approving` 归一）：保持查询等待，不自动重提交；返回 `file` 字段时放置验证文件后等待下次检查。
- 异常状态（订单终态）：持久化后停止，交人工处理；后续轮次仍只 GET 查询自愈，状态未变化不重复记录/落盘，绝不重新提交 CSR。
- 提交 CSR 遇明确业务拒绝（API code != 1）：属确定结果，清理在途 pending 私钥后停止；超时、断连、HTTP 5xx、响应读取或解析失败等不确定结果不做传输层重试，保留 pending 私钥与 CSR metadata，下轮只查询并比较服务端 CSR。CSR 与 pending 私钥配对表示本机提交已收敛；active 且不配对时清理旧状态，先尝试 API/正式本地私钥部署当前证书，全部不可用时才按门禁建立新的逻辑尝试并重新计数；在途状态且不配对时清理本机状态、只 GET 跟随服务端当前动作。
- `active` 时若 pending 私钥缺失，依次尝试 API 私钥和正式本地私钥；均与服务端证书不配对
  （历史改名残留 / 误删）时，才重置签发状态走新 CSR 尝试（递增 retry，受 10 次上限约束）。

### order_id 变更（订单续费）改名迁移

订单续费导致 `order_id` 变更、证书按 `{domain}-{order_id}` 改名时，同步迁移 `pending-keys/{cert_name}` 目录（`renamePendingKey`，不存在则跳过），确保 local 模式续签不丢失 pending 私钥。

### 配置级别

`renew_mode` 为**订单级别**配置，在 `certificates[].renew_mode` 中设置。不同证书可使用不同模式。

### 命令行启用

```bash
# 一键部署时启用本机提交
sslctl setup --url <url> --token <token> --order <id> --local-key

# 指定私钥文件 + 文件验证（隐含 --local-key）
sslctl setup --key /path/key.pem --file-validation --url <url> --token <token> --order <id>

# 指定 webroot（隐含 --file-validation --local-key）
sslctl setup --key /path/key.pem --webroot /var/www/html --url <url> --token <token> --order <id>
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
    └─ prepareLocalRenew()
        │
        ├─ OrderID <= 0 → 配置错误，停止并要求重新 setup
        └─ QueryOrder(order_id)
            ├─ processing/pending/approving/unpaid/cancelling/unknown → 只 GET 查询
            ├─ active + 可用私钥 → 按 deploy-spec 的私钥选择规则部署
            ├─ active + 需建立新尝试 → 生成 CSR，持久化 pending 私钥、CSR 哈希/提交时间与计数
            │   └─ 持久化成功后单次 POST；结果不确定时下轮只 GET
            └─ 明确终态 → 只展示并等待人工处理
```

关键方法：`prepareLocalRenew()`

### 自动签发流程

```
定时任务 → NeedsRenewal() == true
    │
    └─ preparePullRenew()
        │
        ├─ OrderID <= 0 → 配置错误，停止并要求重新 setup
        └─ QueryOrder(order_id)
            ├─ processing/pending/approving/unpaid/cancelling/unknown → 只 GET 查询
            ├─ active → 部署
            └─ 明确终态 → 只展示并等待人工处理
```

### order_id 处理规则

1. **order_id 必须为正整数** - setup 由用户提供，自动流程不通过域名发现或创建订单
2. **提交前必须先查询** - `QueryOrder(order_id)` 确认服务端仍为 `active`
3. **只有 active 可以提交** - waiting、终态和未知状态均不得 POST
4. **本机提交固定携带 order_id** - 每个逻辑尝试只提交一次 CSR；结果不确定时只 GET 收敛

### 验证方法校验

使用 `config.ValidateValidationMethod(domain, method)` 校验域名与验证方法的兼容性：

| 域名类型 | file 验证 | delegation 验证 |
|---------|----------|-----------------|
| 普通域名 | ✅ | ✅ |
| 通配符域名 | ❌ 报错 | ✅ |
| IP 地址 | ✅ | ❌ 报错 |

**注意**：不兼容时直接报错，不自动切换验证方式。校验函数位于 `pkg/config/base.go`

### 文件验证处理

当 API 返回 `status=processing` 且包含 `file` 字段时，自动放置验证文件：

1. 从 `cert.Bindings` 收集所有已启用绑定的 `Paths.Webroot`（去重）
2. 对每个 webroot：`util.JoinUnderDir(webroot, file.Path)` 防目录穿越 → `util.AtomicWrite` 写入（0644）
3. 记录已写入路径到 `cert.Metadata.ValidationFiles` → 持久化到 config.json
4. 返回等待下次检查（次日 CA 完成验证后 status 变为 active）
5. 签发完成后无论部署成败均由 `cleanupValidationFiles()` 删除文件并清理空目录，不残留 webroot

**全部放置失败按签发失败处理**：若无可用 webroot、或所有 webroot 写入均失败，记录错误并停止本轮，不发送部署结果回调。

**配置字段**：
- `certificates[].validation_method`：验证方法（`file` | `delegation`），传递给 API 的 `validation_method` 参数
- `certificates[].bindings[].paths.webroot`：Web 根目录，setup/deploy 时从扫描结果自动获取
- `certificates[].metadata.validation_files`：已写入的验证文件路径列表（部署成功后自动清空）

### IP 证书支持

- CSR 只写 CN（即使 CN 是 IP），CA 签发证书 SAN 必定包含 CN
- 证书验证：`validator.validateDomain()` 检查 `cert.IPAddresses`（`net.IP.Equal` 精确匹配）
- 域名覆盖：`ValidateDomainCoverage()` 和 `ExtractCertDomains()` 同时处理 DNS SAN 和 IP SAN
- 域名匹配：`matcher.MatchDomain()` 和 `validator.MatchDomain()` 对 IP 使用精确匹配，不走通配符逻辑
- 验证方法：IP 地址支持 `file` 验证，不支持 `delegation` 验证

---

## 集成测试

覆盖证书获取、更新、部署、回调、续签等核心业务流，并提供可控的写入型测试开关，避免误操作生产数据。

### 环境配置

在仓库根目录维护 `.env` 文件（已加入 `.gitignore`），集成测试会自动加载。

必填变量：
- `TEST_API_URL`：部署 API 地址（例：`https://xxx/api/deploy`）
- `TEST_API_TOKEN`：部署 Token
- `TEST_ORDER_ID`：正整数订单 ID
- `TEST_API_DOMAIN`：用于校验的域名（例：`*.example.com`）

可选变量（写入型测试）：
- `TEST_API_ALLOW_WRITE=1`：允许调用更新接口
- `TEST_API_METHOD`：更新时提交的验证方式，必须显式设为 `file` 或 `delegation`；当前代码默认
  `http` 不符合公开契约，属待修测试缺口
- `TEST_API_DOMAINS`：更新时提交的域名列表（逗号分隔）
- `TEST_API_ALLOW_CALLBACK=1`：允许回调接口测试

### 覆盖的业务流

只读/安全测试（默认执行）：
- 按订单号查询（QueryOrder）
- API 响应解析与字段格式校验
- 本地部署写入与权限校验
- 备份/回滚路径校验
- 扫描站点配置
- 续签流程（自动签发、本机提交）

写入型测试（需显式打开开关）：
- 更新/续费（Update + CSR 生成）
- 回调通知（CallbackNew）

### 运行方式

```bash
# 运行全部测试（包含集成测试，默认跳过写入型）
go test ./...

# 仅运行证书相关集成测试（只读）
go test ./pkg/certops -run TestIntegration

# 启用写入型集成测试（Update/Callback）
TEST_API_ALLOW_WRITE=1 TEST_API_ALLOW_CALLBACK=1 go test ./pkg/certops -run TestIntegration
```

### 风险控制

- 写入型测试必须显式设置 `TEST_API_ALLOW_WRITE=1`，否则自动跳过
- 回调测试需额外设置 `TEST_API_ALLOW_CALLBACK=1`
- 不建议在生产环境执行写入型测试
