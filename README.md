# cert-deploy

SSL 证书部署工具，支持 Nginx、Apache，支持 Docker 容器。

## 安装

```bash
# 安装最新稳定版
curl -fsSL https://cert-deploy-cn.cnssl.com/install.sh | sudo bash

# 安装测试版
curl -fsSL https://cert-deploy-cn.cnssl.com/install.sh | sudo bash -s -- --dev

# 安装指定版本
curl -fsSL https://cert-deploy-cn.cnssl.com/install.sh | sudo bash -s -- --version 1.0.0

# 强制重新安装
curl -fsSL https://cert-deploy-cn.cnssl.com/install.sh | sudo bash -s -- --force
```

手动安装: 从 [Releases](https://cert-deploy-cn.cnssl.com/releases.json) 下载解压，重命名为 `cert-deploy`。

## 使用

### 一键部署

```bash
cert-deploy setup --url https://api.example.com --token your-token --domain example.com
```

自动检测 Web 服务类型，扫描站点，生成配置并部署证书。

### 手动流程

```bash
# 1. 扫描站点（自动检测 Web 服务器类型）
cert-deploy scan              # 扫描所有站点
cert-deploy scan --ssl-only   # 仅扫描 SSL 站点

# 2. 生成配置
cert-deploy init --url https://api.example.com --token your-token

# 3. 部署证书
cert-deploy deploy --site example.com
```

**其他命令:**

```bash
cert-deploy issue --site example.com          # 发起签发
cert-deploy install-https --site example.com  # 安装 HTTPS 配置
cert-deploy status                            # 查看服务状态
cert-deploy upgrade                           # 升级到最新版本
cert-deploy upgrade --check                   # 检查更新
cert-deploy service repair                    # 修复 systemd 服务
cert-deploy --debug scan                      # 调试模式
cert-deploy uninstall                         # 卸载
cert-deploy uninstall --purge                 # 卸载并清理配置
```

## 平台支持

| 平台 | Nginx | Apache | 服务管理 |
|------|-------|--------|----------|
| Linux (systemd) | ✅ | ✅ | systemd |
| Linux (OpenRC) | ✅ | ✅ | OpenRC |
| Linux (SysVinit) | ✅ | ✅ | SysVinit |
| Windows | ✅ | ❌ | Windows Service |

支持 Docker 容器 Nginx（挂载卷/docker cp 双模式），自动检测本地或容器环境。

## Debug 模式

```bash
# 启用调试模式
cert-deploy --debug deploy --site example.com
```

- 详细日志输出（请求/响应、配置解析、文件操作）
- 日志写入文件：`/opt/cert-deploy/logs/debug/`

## 工作目录

```
/opt/cert-deploy/
├── sites/    # 站点配置 (*.json)
├── logs/     # 日志文件
└── backup/   # 证书备份
```

## 站点配置

`sites/example.com.json`:

```json
{
  "site_name": "example.com",
  "server_type": "nginx",
  "api": {
    "url": "https://api.example.com",
    "token": "your-deploy-token",
    "callback_url": "https://api.example.com/api/deploy/callback"
  },
  "domains": ["example.com", "www.example.com"],
  "reload": {
    "test_command": "nginx -t",
    "reload_command": "systemctl reload nginx"
  }
}
```

> `paths` 留空时自动从 Nginx/Apache 配置扫描获取。

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/deploy?domain=xxx` | 按域名查询订单 |
| POST | `/api/deploy` | 更新/续费证书 |
| POST | `/api/deploy/callback` | 部署结果回调 |

认证方式：`Authorization: Bearer {deploy_token}`

## Docker 支持

```bash
cert-deploy scan              # 自动检测本地或 Docker
cert-deploy deploy --site example.com  # 根据配置选择部署方式
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
# Linux 发行版容器测试（需要 Docker）
bash build/test-linux.sh
```

测试覆盖 5 种发行版 × 3 种 init 系统：
- systemd: Ubuntu 22.04, Debian 12, AlmaLinux 9
- OpenRC: Alpine 3.19
- SysVinit: Devuan 5

## License

MIT
