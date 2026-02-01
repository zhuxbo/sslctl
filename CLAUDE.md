# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、Docker。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。

## 项目结构

```text
cmd/           # CLI 入口
  main.go      # 主入口
  setup/       # 一键部署命令
  daemon/      # 守护进程
  deploy/      # 证书部署
pkg/           # 可复用包
  certops/     # 证书操作服务层（扫描/部署/续签）
  webserver/   # Web 服务器抽象层
  config/      # 配置管理（统一 config.json）
  matcher/     # 域名匹配
  fetcher/     # API 客户端
  backup/      # 备份管理
  service/     # 系统服务管理
  logger/      # 日志
internal/      # 内部实现（nginx/apache 扫描/部署）
build/         # 构建/发布脚本
skills/        # 开发规范
testdata/      # 测试数据和工具
```

## 核心命令

```bash
# 一键部署（推荐）
cert-deploy setup --url <url> --token <token> --order <order_id>

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

## 配置文件

统一配置文件：`/opt/cert-deploy/config.json`

证书存储目录：`/opt/cert-deploy/certs/{site_name}/`

## 环境变量

| 变量                      | 说明                             |
|---------------------------|----------------------------------|
| `CERT_DEPLOY_API_TOKEN`   | API Token（优先级高于配置文件）  |
| `CERT_DEPLOY_API_URL`     | API URL（优先级高于配置文件）    |

## 测试

```bash
go test -v ./...                           # 运行单元测试
go test -coverprofile=coverage.out ./...   # 测试并生成覆盖率
bash build/test-linux.sh                   # Linux 容器测试
```

## 续签模式

| 模式    | 说明           | 启用方式                                   |
|---------|----------------|--------------------------------------------|
| `local` | 本地私钥模式   | `--local-key` 或配置 `renew_mode: "local"` |
| `pull`  | 拉取模式（默认）| 默认行为                                   |

## 开发规范

详见 `skills/` 目录：

- `go-dev/` - Go 开发规范
- `nginx-apache/` - 配置解析、证书部署
- `deploy-ops/` - 部署运维、续签流程、API 接口
- `build-release/` - 构建发布
