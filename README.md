# cert-deploy

[![GitHub Release](https://img.shields.io/github/v/release/zhuxbo/cert-deploy?include_prereleases)](https://github.com/zhuxbo/cert-deploy/releases)
[![CI](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml/badge.svg)](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml)

SSL 证书部署工具，支持 Nginx、Apache、IIS，支持 Docker 容器。

## 安装

**Linux:**

```bash
curl -fsSL https://gitee.com/zhuxbo/cert-deploy/raw/main/deploy/install.sh | sudo bash
```

**Windows (PowerShell 管理员):**

```powershell
irm https://gitee.com/zhuxbo/cert-deploy/raw/main/deploy/install.ps1 | iex
```

手动安装: 从 [Releases](https://github.com/zhuxbo/cert-deploy/releases) 下载解压，重命名为 `cert-deploy`。

## 使用

```bash
# 1. 扫描站点
cert-deploy -scan

# 2. 生成配置（交互式）
cert-deploy -init -url https://api.example.com/cert -refer_id your-id

# 3. 部署证书
cert-deploy -site example.com
```

**其他命令:**

```bash
cert-deploy -site example.com -issue          # 发起签发
cert-deploy -site example.com -install-https  # 安装 HTTPS 配置
cert-deploy -init _ -domains a.com,b.com ...  # 指定域名（扫描结果为 _ 时）
```

## 平台支持

| 平台 | Nginx | Apache | IIS |
|------|-------|--------|-----|
| Linux | ✅ | ✅ | - |
| Windows | ✅ | ✅ | ✅ |

支持 Docker 容器 Nginx（挂载卷/docker cp 双模式），自动检测本地或容器环境。

## 工作目录

| 系统 | 路径 |
|------|------|
| Linux | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

```
sites/    # 站点配置 (*.json)
logs/     # 日志文件
backup/   # 证书备份
```

## 站点配置

`sites/example.com.json`:

```json
{
  "site_name": "example.com",
  "server_type": "nginx",
  "api": {
    "url": "https://api.example.com/cert",
    "refer_id": "your-refer-id"
  },
  "domains": ["example.com", "www.example.com"],
  "reload": {
    "test_command": "nginx -t",
    "reload_command": "systemctl reload nginx"
  }
}
```

> `paths` 留空时自动从 Nginx/Apache 配置扫描获取。

## Docker 支持

```bash
cert-deploy -scan              # 自动检测本地或 Docker
cert-deploy -site example.com  # 根据配置选择部署方式
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

## License

MIT
