# cert-deploy

[![GitHub Release](https://img.shields.io/github/v/release/zhuxbo/cert-deploy?include_prereleases)](https://github.com/zhuxbo/cert-deploy/releases)
[![Build Status](https://github.com/zhuxbo/cert-deploy/actions/workflows/release.yml/badge.svg)](https://github.com/zhuxbo/cert-deploy/actions)
[![License](https://img.shields.io/github/license/zhuxbo/cert-deploy)](LICENSE)

SSL 证书自动部署工具，支持 Nginx、Apache、IIS 三种 Web 服务器。

**仓库地址**：
- GitHub: https://github.com/zhuxbo/cert-deploy
- Gitee (镜像): https://gitee.com/zhuxbo/cert-deploy

## 平台支持

| 工具 | Linux | Windows | macOS |
|------|-------|---------|-------|
| cert-deploy-nginx | ✅ | ✅ | ✅ |
| cert-deploy-apache | ✅ | ✅ | ✅ |
| cert-deploy-iis | ❌ | ✅ | ❌ |

## 特性

- **智能配置检测**: 通过 `nginx -t` / `apache2ctl -V` 自动检测配置路径
- **递归扫描**: 自动解析 include 指令，扫描所有站点配置
- **跨平台适配**: 适配宝塔、1Panel、LNMP 等各种面板和发行版
- **守护进程模式**: 后台运行，定时检测并自动部署证书
- **HTTP 文件验证**: 自动处理 DCV 文件验证，放置验证文件并等待签发完成
- **HTTPS 配置安装**: 自动为 HTTP 站点添加 SSL 配置 (`-install-https`)
- **交互式安装**: `-install-https` 无 `-site` 参数时进入交互模式，引导选择站点并输入路径
- **智能 HTTPS 检测**: 部署时检测站点是否已配置 HTTPS，如未配置则提示安装
- **证书备份**: 部署前自动备份旧证书，支持多版本保留
- **自动回滚**: 部署失败时自动回滚到备份证书
- **证书验证**: 证书/私钥配对验证，确保部署正确
- **网络重试**: API 请求支持自动重试，增强稳定性
- **日志记录**: 详细记录所有部署操作，按日期自动切分
- **原子写入**: 避免部署失败导致服务中断
- **配置测试**: 部署前自动测试配置，失败自动回滚

## 工作目录

程序使用固定的工作目录：

| 系统 | 工作目录 |
|------|----------|
| Linux/macOS | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

目录结构：

```
/opt/cert-deploy/
├── sites/          # 站点配置 (*.json)
├── logs/           # 日志文件 (nginx-2024-01-01.log)
├── backup/         # 证书备份
│   └── example.com/
│       └── 20240101-120000/
│           ├── cert.pem
│           ├── key.pem
│           └── metadata.json
└── certs/          # 临时证书
```

## 快速开始

### 安装

```bash
# 下载并安装
curl -fsSL https://example.com/cert-deploy/install.sh | sudo bash

# 或手动安装
sudo cp cert-deploy-nginx /usr/local/bin/
sudo chmod +x /usr/local/bin/cert-deploy-nginx
```

### 扫描 SSL 站点

程序会自动检测 Web 服务器配置路径：

```bash
# 扫描 Nginx 配置
cert-deploy-nginx -scan

# 扫描 Apache 配置
cert-deploy-apache -scan
```

**检测流程**：
1. 通过 `nginx -t` / `apache2ctl -V` 获取主配置文件路径
2. 解析主配置中的 `include` 指令
3. 递归扫描所有被包含的站点配置
4. 提取 SSL 证书路径

输出示例：
```
检测到 Nginx 配置: /www/server/nginx/conf/nginx.conf

发现 3 个 SSL 站点:

1. example.com
   配置文件: /www/server/panel/vhost/nginx/example.com.conf
   证书路径: /www/server/panel/vhost/cert/example.com/fullchain.pem
   私钥路径: /www/server/panel/vhost/cert/example.com/privkey.pem
   监听端口: [443 ssl]

2. api.example.com
   ...
```

### 创建站点配置

在 `/opt/cert-deploy/sites/` 目录创建配置文件：

```bash
cat > /opt/cert-deploy/sites/example.com.json << 'EOF'
{
  "version": "1.0",
  "site_name": "example.com",
  "enabled": true,
  "server_type": "nginx",
  "api": {
    "url": "https://cert-manager.example.com/api/auto",
    "refer_id": "your-refer-id"
  },
  "domains": ["example.com", "www.example.com"],
  "paths": {
    "certificate": "",
    "private_key": "",
    "config_file": ""
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
EOF
```

> **注意**: `paths.certificate` 和 `paths.private_key` 可以留空，程序会自动从 Nginx 配置中扫描获取。

### 部署证书

```bash
# 部署指定站点
cert-deploy-nginx -site example.com

# 启动守护进程（每 10 分钟检查一次）
cert-deploy-nginx -daemon

# 使用 systemd 管理
systemctl enable cert-deploy-nginx
systemctl start cert-deploy-nginx
```

## 命令行参数

### Nginx

```bash
cert-deploy-nginx -version                          # 显示版本
cert-deploy-nginx -scan                             # 扫描 SSL 站点
cert-deploy-nginx -site example.com                 # 部署指定站点
cert-deploy-nginx -site example.com -issue          # 发起证书签发（file 验证）
cert-deploy-nginx -site example.com -install-https  # 为 HTTP 站点安装 HTTPS 配置
cert-deploy-nginx -install-https                    # 交互式安装 HTTPS 配置
cert-deploy-nginx -daemon                           # 守护进程模式
```

### Apache

```bash
cert-deploy-apache -version                         # 显示版本
cert-deploy-apache -scan                            # 扫描 SSL 站点
cert-deploy-apache -site example.com                # 部署指定站点
cert-deploy-apache -site example.com -issue         # 发起证书签发
cert-deploy-apache -site example.com -install-https # 为 HTTP 站点安装 HTTPS 配置
cert-deploy-apache -install-https                   # 交互式安装 HTTPS 配置
cert-deploy-apache -daemon                          # 守护进程模式
```

### IIS (Windows)

```bash
cert-deploy-iis -version                            # 显示版本
cert-deploy-iis -scan                               # 扫描 IIS SSL 站点
cert-deploy-iis -site example.com                   # 部署指定站点
cert-deploy-iis -site example.com -issue            # 发起证书签发
cert-deploy-iis -site example.com -install-https    # 为 HTTP 站点安装 HTTPS 绑定
cert-deploy-iis -install-https                      # 交互式安装 HTTPS 绑定
cert-deploy-iis -daemon                             # 守护进程模式
```

## 站点配置详解

```json
{
  "version": "1.0",
  "site_name": "example.com",
  "enabled": true,
  "server_type": "nginx",
  "api": {
    "url": "https://cert-manager.example.com/api/auto",
    "refer_id": "your-refer-id"
  },
  "domains": ["example.com", "www.example.com"],
  "paths": {
    "certificate": "/etc/nginx/ssl/example.com/fullchain.pem",
    "private_key": "/etc/nginx/ssl/example.com/privkey.pem",
    "chain_file": "",
    "config_file": "/etc/nginx/sites-enabled/example.com.conf",
    "webroot": "/var/www/example.com"
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
  },
  "metadata": {
    "cert_expires_at": "2024-03-01T00:00:00Z",
    "last_deploy_at": "2024-01-01T12:00:00Z"
  }
}
```

| 字段 | 说明 |
|------|------|
| `site_name` | 站点名称，与文件名对应 |
| `enabled` | 是否启用 |
| `server_type` | nginx / apache |
| `api.url` | 证书管理 API 地址 |
| `api.refer_id` | API 认证 ID |
| `domains` | 域名列表（用于验证证书） |
| `paths.certificate` | 证书文件路径（留空则自动扫描） |
| `paths.private_key` | 私钥文件路径（留空则自动扫描） |
| `paths.chain_file` | 中间证书路径（Apache 需要） |
| `paths.webroot` | Web 根目录（用于 HTTP 文件验证） |
| `reload.test_command` | 配置测试命令 |
| `reload.reload_command` | 重载服务命令 |
| `schedule.renew_before_days` | 提前多少天续期 |
| `backup.enabled` | 是否备份旧证书 |
| `backup.keep_versions` | 保留备份版本数 |

## Systemd 服务

安装后会自动创建 systemd 服务文件：

```bash
# 启用开机自启
systemctl enable cert-deploy-nginx

# 启动服务
systemctl start cert-deploy-nginx

# 查看状态
systemctl status cert-deploy-nginx

# 查看日志
journalctl -u cert-deploy-nginx -f
```

## 日志

日志保存在 `/opt/cert-deploy/logs/` 目录，按日期和类型分文件：

```
logs/
├── nginx-2024-01-01.log
├── nginx-2024-01-02.log
└── apache-2024-01-01.log
```

日志格式：
```
[2024-01-01 12:00:00] [INFO] 开始检查证书...
[2024-01-01 12:00:01] [INFO] 配置扫描完成: path=Nginx 配置, sites_found=3
[2024-01-01 12:00:02] [INFO] 证书备份成功: src=/etc/nginx/ssl/example.com/fullchain.pem, backup=/opt/cert-deploy/backup/example.com/20240101-120002
[2024-01-01 12:00:03] [INFO] 证书部署成功: domain=example.com, cert=/etc/nginx/ssl/example.com/fullchain.pem
[2024-01-01 12:00:04] [INFO] 服务重载成功: command=systemctl reload nginx
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LOG_LEVEL` | 日志级别 (debug, info, warn, error) | info |

示例：

```bash
# 启用调试日志
LOG_LEVEL=debug cert-deploy-nginx -daemon
```

## 构建

### 前置要求

- Go 1.21+

### 构建命令

```bash
# 下载依赖
make deps

# 构建当前平台
make build

# 构建所有平台
make build-all

# 启用 UPX 压缩
UPX=1 make build
```

## 目录结构

```
cert-deploy/
├── cmd/
│   ├── nginx/       # Nginx 客户端入口
│   ├── apache/      # Apache 客户端入口
│   └── iis/         # IIS 客户端入口 (仅 Windows)
├── pkg/             # 共享代码
│   ├── backup/      # 备份管理
│   ├── config/      # 站点配置管理
│   ├── deployer/    # 部署器接口定义
│   ├── fetcher/     # API 客户端（含重试机制）
│   ├── logger/      # 日志记录
│   ├── scanner/     # 扫描器接口定义
│   ├── validator/   # 证书验证（含配对验证）
│   └── util/        # 工具函数
├── internal/
│   ├── nginx/       # Nginx 平台代码
│   │   ├── deployer/# 部署器实现
│   │   └── scanner/ # 配置扫描
│   ├── apache/      # Apache 平台代码
│   └── iis/         # IIS 平台代码
├── deploy/
│   ├── systemd/     # Systemd 服务文件
│   └── install.sh   # 安装脚本
├── Makefile
└── go.mod
```

## License

MIT
