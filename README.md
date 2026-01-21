# cert-deploy

[![GitHub Release](https://img.shields.io/github/v/release/zhuxbo/cert-deploy?include_prereleases)](https://github.com/zhuxbo/cert-deploy/releases)
[![CI](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml/badge.svg)](https://github.com/zhuxbo/cert-deploy/actions/workflows/ci.yml)

SSL 证书部署工具，支持 Nginx、Apache，支持 Docker 容器。

## 安装

**Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/zhuxbo/cert-deploy/main/deploy/install.sh | sudo bash
```

**Windows (PowerShell 管理员):**

```powershell
irm https://raw.githubusercontent.com/zhuxbo/cert-deploy/main/deploy/install.ps1 | iex
```

手动安装: 从 [Releases](https://github.com/zhuxbo/cert-deploy/releases) 下载解压，重命名为 `cert-deploy`。

## 使用

```bash
# 1. 扫描站点
cert-deploy nginx scan
cert-deploy apache scan

# 2. 生成配置（交互式）
cert-deploy nginx init --url https://api.example.com/cert --refer_id your-id

# 3. 部署证书
cert-deploy nginx deploy --site example.com
```

**其他命令:**

```bash
cert-deploy nginx issue --site example.com          # 发起签发
cert-deploy nginx install-https --site example.com  # 安装 HTTPS 配置
cert-deploy nginx daemon                            # 守护进程模式
cert-deploy --debug nginx scan                      # 调试模式
```

## 平台支持

| 平台 | Nginx | Apache | IIS |
|------|-------|--------|-----|
| Linux | ✅ | ✅ | - |
| Windows | ✅ | ✅ | [cert-deploy-iis](https://github.com/cnssl/cert-deploy-iis) |

支持 Docker 容器 Nginx（挂载卷/docker cp 双模式），自动检测本地或容器环境。

## Debug 模式

```bash
# 启用调试模式
cert-deploy --debug nginx deploy --site example.com
```

- 详细日志输出（请求/响应、配置解析、文件操作）
- 日志写入文件：`/opt/cert-deploy/logs/debug/`

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
cert-deploy nginx scan              # 自动检测本地或 Docker
cert-deploy nginx deploy --site example.com  # 根据配置选择部署方式
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

## IIS 支持

IIS 版本已独立为 [cert-deploy-iis](https://github.com/cnssl/cert-deploy-iis) 项目，基于 .NET 8，提供 GUI 界面和 Windows 服务。

## License

MIT
