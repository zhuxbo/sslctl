# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、IIS。

## 技术栈

- Go 1.21+，支持 Linux/Windows/macOS
- GitHub Actions CI/CD，Systemd 服务管理

## 目录结构

```
cmd/
├── nginx/      # Nginx 客户端
├── apache/     # Apache 客户端
└── iis/        # IIS 客户端 (Windows)
pkg/
├── backup/     # 证书备份
├── config/     # 站点配置管理
├── fetcher/    # API 客户端（含重试）
├── issuer/     # 证书签发
├── logger/     # 日志记录
├── prompt/     # 交互式输入
└── validator/  # 证书验证
internal/
├── nginx/      # Nginx 扫描器/安装器
├── apache/     # Apache 扫描器/安装器
└── iis/        # IIS 扫描器/证书存储
```

## 工作目录

| 系统 | 路径 |
|------|------|
| Linux/macOS | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

## 命令行

```bash
# 扫描 SSL 站点
cert-deploy-nginx -scan

# 部署证书
cert-deploy-nginx -site example.com

# 发起签发（file 验证）
cert-deploy-nginx -site example.com -issue

# 安装 HTTPS 配置
cert-deploy-nginx -site example.com -install-https

# 守护进程模式
cert-deploy-nginx -daemon
```

Apache/IIS 命令格式相同，替换 `nginx` 为 `apache` 或 `iis`。

## 构建与测试

```bash
make build          # 构建当前平台
make build-all      # 构建所有平台
go test ./...       # 运行测试
```

## CI/CD

| Workflow | 触发条件 | 功能 |
|----------|----------|------|
| CI | push/PR 到 main/dev | 测试、Lint、构建检查 |
| Release | 推送 `v*` 标签 | 多平台构建、创建 Release |
| Sync | push 到 main/dev | 同步到 Gitee 镜像 |

## 开发计划

- [x] 多 Web 服务器支持 (Nginx/Apache/IIS)
- [x] 证书签发与 file 验证
- [x] HTTPS 配置安装
- [x] 交互式安装模式
- [x] 证书备份与自动回滚
- [ ] 部署前后 Hook 支持
- [ ] Web UI 管理界面
