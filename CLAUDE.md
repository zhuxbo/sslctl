# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、Docker。

## 项目结构

```
cmd/           # CLI 入口
  main.go      # 主入口
  setup/       # 一键部署命令
  daemon/      # 守护进程
  deploy/      # 证书部署
  nginx/       # Nginx 命令（兼容）
  apache/      # Apache 命令（兼容）
pkg/           # 可复用包
  config/      # 配置管理（统一 config.json）
  matcher/     # 域名匹配
  fetcher/     # API 客户端
  backup/      # 备份管理
  service/     # 系统服务管理
  logger/      # 日志
internal/      # 内部实现（nginx/apache 扫描/部署）
build/         # 构建/发布脚本
skills/        # 开发规范
```

## 核心命令

```bash
# 一键部署（推荐）
cert-deploy setup --url <url> --token <token> --order <order_id>
cert-deploy setup --url <url> --token <token> --order <order_id> --local-key
cert-deploy setup --url <url> --token <token> --order <order_id> --yes --no-service

# 站点扫描
cert-deploy scan                       # 扫描站点（自动检测 Web 服务器）
cert-deploy scan --ssl-only            # 仅扫描 SSL 站点

# 证书部署
cert-deploy deploy --cert <name>       # 部署指定证书
cert-deploy deploy --all               # 部署所有证书

# 服务管理
cert-deploy status                     # 查看服务状态
cert-deploy service repair             # 修复服务
cert-deploy upgrade                    # 升级工具
cert-deploy uninstall                  # 卸载
```

## 配置结构

统一配置文件：`/opt/cert-deploy/config.json`

```json
{
  "version": "2.0",
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
      "cert_name": "order-12345",
      "order_id": 12345,
      "enabled": true,
      "domains": ["*.example.com", "example.com"],
      "bindings": [...]
    }
  ]
}
```

证书存储目录：`/opt/cert-deploy/certs/{site_name}/`

## 测试

```bash
# Linux 发行版容器测试（需要 Docker）
bash build/test-linux.sh
```

测试覆盖：Ubuntu、Debian、AlmaLinux (systemd)、Alpine (OpenRC)、Devuan (SysVinit)

## 续签模式

| 模式 | 说明 | 启用方式 |
|------|------|----------|
| `local` | 本地私钥模式 | `--local-key` 或配置 `renew_mode: "local"` |
| `pull` | 拉取模式（默认） | 默认行为 |

## 开发规范

详见 `skills/` 目录：
- `go-dev/` - Go 开发规范
- `nginx-apache/` - 配置解析、证书部署
- `deploy-ops/` - 部署运维、续签流程、API 接口
- `build-release/` - 构建发布
