# cert-deploy

[![GitHub Release](https://img.shields.io/github/v/release/zhuxbo/cert-deploy?include_prereleases)](https://github.com/zhuxbo/cert-deploy/releases)
[![CI](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml/badge.svg)](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/zhuxbo/cert-deploy)](LICENSE)

SSL 证书自动部署工具，支持 Nginx、Apache、IIS。

## 平台支持

| 工具 | Linux | Windows |
|------|-------|---------|
| cert-deploy-nginx | ✅ | ✅ |
| cert-deploy-apache | ✅ | ✅ |
| cert-deploy-iis | - | ✅ |

## 特性

- 智能配置检测，自动扫描 SSL 站点
- Docker 容器 Nginx 支持（挂载卷/docker cp 双模式）
- 守护进程模式，定时检测自动部署
- HTTP 文件验证，自动处理 DCV
- 证书备份与自动回滚
- 适配宝塔、1Panel、LNMP 等面板

## 安装

**Linux:**

```bash
curl -fsSL https://gitee.com/zhuxbo/cert-deploy/raw/main/deploy/install.sh | sudo bash
```

**Windows (PowerShell 管理员):**

```powershell
irm https://gitee.com/zhuxbo/cert-deploy/raw/main/deploy/install.ps1 | iex
```

**手动安装:** 从 [Releases](https://github.com/zhuxbo/cert-deploy/releases) 下载，解压后重命名为 `cert-deploy`。

## 使用

```bash
cert-deploy -scan                  # 扫描 SSL 站点
cert-deploy -init -url URL -refer_id ID   # 根据扫描结果生成配置
cert-deploy -site example.com      # 部署证书
cert-deploy -site example.com -issue       # 发起签发
cert-deploy -site example.com -install-https  # 安装 HTTPS 配置
cert-deploy -daemon                # 守护进程模式
```

## 快速配置

扫描站点并生成配置：

```bash
# 1. 扫描站点（结果保存到 scan-result.json）
cert-deploy -scan

# 2. 根据扫描结果生成配置（交互式选择站点）
cert-deploy -init -url https://api.example.com/cert -refer_id your-id

# 3. 指定站点名生成配置
cert-deploy -init example.com -url https://api.example.com/cert -refer_id your-id

# 4. 自定义域名（扫描结果域名为 _ 时）
cert-deploy -init _ -url https://api.example.com/cert -refer_id your-id -domains mail.example.com
```

## 工作目录

| 系统 | 路径 |
|------|------|
| Linux | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

```plain
/opt/cert-deploy/
├── sites/    # 站点配置 (*.json)
├── logs/     # 日志文件
├── backup/   # 证书备份
└── certs/    # 临时证书
```

## 站点配置

在 `sites/` 目录创建 `example.com.json`：

```json
{
  "version": "1.0",
  "site_name": "example.com",
  "enabled": true,
  "server_type": "nginx",
  "api": {
    "url": "https://cert-api.example.com/api/auto/cert",
    "refer_id": "your-refer-id"
  },
  "domains": ["example.com", "www.example.com"],
  "paths": {
    "certificate": "",
    "private_key": ""
  },
  "reload": {
    "test_command": "nginx -t",
    "reload_command": "systemctl reload nginx"
  },
  "schedule": {
    "check_interval_hours": 12,
    "renew_before_days": 30
  },
  "backup": {
    "enabled": true,
    "keep_versions": 3
  }
}
```

> `paths` 留空时自动从 Nginx 配置扫描获取。

## Docker 支持

Nginx 客户端自动检测 Docker 容器，使用方式与本地一致：

```bash
cert-deploy -scan           # 自动检测本地或 Docker
cert-deploy -site example.com  # 根据配置自动选择部署方式
```

**检测优先级：**

1. 配置 `docker.enabled=true` → Docker 模式
2. 本地有 nginx → 本地模式
3. 仅有 Docker 容器 → Docker 模式

**Docker 站点配置：**

```json
{
  "site_name": "example.com",
  "docker": {
    "enabled": true,
    "compose_file": "/opt/app/docker-compose.yml",
    "service_name": "nginx",
    "deploy_mode": "auto",
    "container_paths": {
      "certificate": "/etc/nginx/ssl/cert.pem",
      "private_key": "/etc/nginx/ssl/key.pem"
    }
  },
  "paths": {
    "certificate": "/opt/certs/fullchain.pem",
    "private_key": "/opt/certs/privkey.pem"
  }
}
```

部署模式：`volume`（挂载卷）、`copy`（docker cp）、`auto`（自动检测）

## Systemd 服务

```bash
systemctl enable cert-deploy
systemctl start cert-deploy
systemctl status cert-deploy
```

## 构建

```bash
make build          # 构建当前平台
make build-all      # 构建所有平台
make compress       # UPX 压缩
```

## License

MIT
