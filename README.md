# sslctl

SSL 证书部署工具，支持 Nginx、Apache，支持 Docker 容器。

## 安装

```bash
# 安装最新稳定版
curl -fsSL https://release.cnssl.com/sslctl/install.sh | sudo bash

# 安装测试版
curl -fsSL https://release.cnssl.com/sslctl/install.sh | sudo bash -s -- --dev

# 安装指定版本
curl -fsSL https://release.cnssl.com/sslctl/install.sh | sudo bash -s -- --version 1.0.0

# 强制重新安装
curl -fsSL https://release.cnssl.com/sslctl/install.sh | sudo bash -s -- --force
```

Windows (PowerShell 管理员):

```powershell
# 安装最新稳定版
irm https://release.cnssl.com/sslctl/install.ps1 | iex

# 直接执行支持参数
.\install.ps1 -Dev                     # 安装测试版
.\install.ps1 -Version 1.0.0           # 安装指定版本
.\install.ps1 -Force                   # 强制重新安装
```

手动安装: 从 [Releases](https://release.cnssl.com/sslctl/releases.json) 下载解压，重命名为 `sslctl`。

## 使用

### 一键部署（推荐）

```bash
sslctl setup --url https://api.example.com --token your-token --order 12345
```

自动完成：
1. 检测 Web 服务器（Nginx/Apache）
2. 获取证书信息并匹配站点
3. 自动为未启用 SSL 的站点安装 HTTPS 配置（备份原配置，失败自动回滚）
4. 部署证书到匹配的站点
5. 安装守护服务（自动续签）

选项：
- `--local-key`: 使用本地私钥模式
- `--yes`: 跳过确认提示
- `--no-service`: 不安装守护服务

### 扫描站点

```bash
sslctl scan              # 扫描所有站点
sslctl scan --ssl-only   # 仅扫描 SSL 站点
```

### 本地证书部署

```bash
# 部署本地证书文件到站点
sslctl deploy local --cert cert.pem --key key.pem --site example.com

# 带 CA 证书链部署（Apache 配置了 SSLCertificateChainFile 时需要）
sslctl deploy local --cert cert.pem --key key.pem --ca chain.pem --site apache-site.com
```

选项：
- `--cert`: 证书文件路径（必需）
- `--key`: 私钥文件路径（必需）
- `--ca`: CA 证书链文件路径（Apache 配置了证书链路径时必需）
- `--site`: 目标站点名称（必需，需先运行 `sslctl scan`）

站点信息优先从 `config.json` 获取，回退到 `scan-result.json`。

### 证书回滚

```bash
sslctl rollback --site example.com              # 回滚到最新备份
sslctl rollback --site example.com --list       # 查看备份列表
sslctl rollback --site example.com --version 20240101-120000  # 回滚到指定版本
```

回滚前会自动备份当前文件，包含符号链接防护。

**其他命令:**

```bash
sslctl deploy --cert order-12345         # 部署指定证书
sslctl deploy --all                      # 部署所有证书
sslctl status                            # 查看服务状态（含证书过期详情）
sslctl upgrade                           # 升级到最新版本
sslctl upgrade --check                   # 检查更新
sslctl service repair                    # 修复 systemd 服务
sslctl --debug scan                      # 调试模式
sslctl uninstall                         # 卸载
sslctl uninstall --purge                 # 卸载并清理配置
```

## 平台支持

| 平台 | Nginx | Apache | 服务管理 |
|------|-------|--------|----------|
| Linux (systemd) | ✅ | ✅ | systemd |
| Linux (OpenRC) | ✅ | ✅ | OpenRC |
| Linux (SysVinit) | ✅ | ✅ | SysVinit |
| Windows | ✅ | ✅ | Windows Service |

CI 覆盖 linux/amd64、linux/arm64、windows/amd64 三平台交叉编译验证。

支持 Docker 容器 Nginx（挂载卷/docker cp 双模式），自动检测本地或容器环境。

## Debug 模式

```bash
# 启用调试模式
sslctl --debug deploy --site example.com
```

- 详细日志输出（请求/响应、配置解析、文件操作）
- 日志写入文件：`/opt/sslctl/logs/debug/`

## 工作目录

```
/opt/sslctl/
├── config.json     # 统一配置文件
├── certs/          # 证书存储
│   └── {site_name}/
│       ├── cert.pem
│       └── key.pem
├── pending-keys/   # 待确认私钥（本地私钥模式）
├── logs/           # 日志文件
├── backup/         # 证书备份
└── scan-result.json  # 扫描结果缓存
```

## 安全特性

- **HTTPS 强制**：远程 API 必须使用 HTTPS（仅 localhost 允许 HTTP）
- **SSRF 防护**：阻止访问内网 IP（10/172.16/192.168）和云元数据地址（169.254.169.254）
- **DNS Rebinding 防护**：自定义 DialContext 在 TCP 连接时二次校验目标 IP
- **命令白名单 + 超时**：统一的 executor 包，只允许预定义命令，默认 30 秒超时，支持 Context 取消
- **日志脱敏**：自动过滤私钥、Bearer Token、Basic Auth、JSON 敏感字段、URL 参数；错误消息使用相对路径
- **并发安全**：配置读取返回深拷贝，mtime 检测外部修改自动重载，防止并发修改污染
- **配置保存安全**：拒绝写入符号链接目标，防止任意文件覆盖
- **路径验证**：Docker 容器路径参数严格验证，防止命令注入；挂载路径精确匹配防止误匹配
- **备份 TOCTOU 保护**：使用文件哈希校验检测并发修改，确保备份一致性；恢复时内部备份跳过清理，防止目标备份被删除；备份源文件符号链接检查，拒绝备份符号链接目标
- **扫描防护**：Nginx/Apache 扫描器文件数量限制（1000）+ 文件大小限制（10MB），防止恶意配置耗尽资源
- **升级安全**：gzip 解压大小限制，防止 gzip 炸弹攻击；Ed25519 数字签名验证（密钥环支持多公钥 + key ID，空密钥环拒绝验证，已配置公钥时拒绝未签名版本防止降级攻击），防止供应链攻击；安装时符号链接防护；通道白名单防止路径遍历；密钥不匹配时提示用 install.sh 重装
- **临时目录安全**：临时目录权限设置为 0700
- **日志目录安全**：日志目录权限设置为 0700
- **配置文件锁**：文件锁在操作前获取，确保原子性和一致性
- **部署回滚**：部署失败自动回滚到备份（通过抽象层接口），回滚失败时提供手动恢复命令
- **私钥保护**：本地私钥模式下，新私钥先保存到临时位置，签发成功后再替换；所有私钥写入统一使用 AtomicWrite
- **SELinux 兼容**：部署后自动恢复文件安全上下文（restorecon），非 SELinux 环境静默跳过
- **IDN/Punycode 支持**：域名匹配器自动转换国际化域名
- **证书过期告警**：守护进程周期检查证书过期时间，7 天/14 天阈值输出告警日志
- **环境变量**：支持通过环境变量配置敏感信息，避免明文存储

## 环境变量

| 变量 | 说明 |
|------|------|
| `SSLCTL_API_TOKEN` | API Token（优先级高于配置文件） |
| `SSLCTL_API_URL` | API URL（优先级高于配置文件） |

使用示例：
```bash
export SSLCTL_API_TOKEN="your-secret-token"
sslctl status
```

## 配置结构

`config.json`:

```json
{
  "version": "1.0",
  "api": {
    "url": "https://api.example.com",
    "token": "your-deploy-token"
  },
  "release_url": "https://release.cnssl.com/sslctl",
  "schedule": {
    "check_interval_hours": 6,
    "renew_before_days": 13
  },
  "certificates": [
    {
      "cert_name": "order-12345",
      "order_id": 12345,
      "enabled": true,
      "domains": ["*.example.com", "example.com"],
      "renew_mode": "pull",
      "bindings": [
        {
          "site_name": "www.example.com",
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

## 续签模式

服务端在证书到期前 **14 天**自动续签，本地需配合选择续签模式：

| 模式 | 说明 | 时间限制 | 默认值 |
|------|------|----------|--------|
| `local` | 本地私钥模式，本地生成私钥和 CSR | `renew_before_days >= 15` | 15 天 |
| `pull` | 拉取模式，从服务端拉取已签发证书 | `renew_before_days <= 13` | 13 天 |

- **本地私钥模式**：在服务端自动续签之前发起，由本地控制私钥。通过 POST 部署接口提交本地生成的 CSR
- **拉取模式**：等待服务端完成自动续签后拉取证书。查询已签发的证书直接部署

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/deploy?order_id=xxx` | 按订单 ID 查询（推荐） |
| GET | `/api/deploy?domain=xxx` | 按域名查询（首次获取 order_id） |
| POST | `/api/deploy` | 更新/续费证书（需要 order_id） |
| POST | `/api/deploy/callback` | 部署结果回调 |

认证方式：`Authorization: Bearer {deploy_token}`

## Docker 支持

```bash
sslctl scan              # 自动检测本地或 Docker
sslctl deploy --site example.com  # 根据配置选择部署方式
```

Docker 站点配置添加 `docker` 字段：

```json
{
  "docker": {
    "enabled": true,
    "compose_file": "/opt/app/docker-compose.yml",
    "service_name": "nginx",
    "deploy_mode": "auto"
  }
}
```

部署模式：`volume`（挂载卷）、`copy`（docker cp）、`auto`（自动检测）

## 开发测试

```bash
# 运行单元测试
go test -v ./...

# 运行测试并查看覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total

# Linux 发行版服务管理测试（需要 Docker）
bash build/test-linux.sh
```

### 容器端到端测试

```bash
# Mock 测试（离线，不依赖外部 API）
bash docker/test/scripts/run-mock-tests.sh

# E2E 测试（使用真实 API）
export SSLCTL_API_TOKEN="your-token"
export SSLCTL_API_URL="https://api.example.com/api/deploy"
bash docker/test/scripts/run-e2e-tests.sh

# 测试所有发行版 + 服务器组合
bash docker/test/scripts/run-e2e-tests.sh --all

# 指定发行版和服务器类型
bash docker/test/scripts/run-e2e-tests.sh --distro ubuntu --server nginx
```

测试报告输出到 `docker/test/reports/test-report.md`。

**发行版服务管理测试**覆盖 5 种发行版 × 3 种 init 系统：
- systemd: Ubuntu 22.04, Debian 12, AlmaLinux 9
- OpenRC: Alpine 3.19
- SysVinit: Devuan 5

**E2E 测试**覆盖 4 种发行版 × 2 种服务器：
- Ubuntu, Debian, Alpine, Rocky × Nginx, Apache

## License

MIT
