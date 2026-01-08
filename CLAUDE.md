# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、IIS。

## 技术栈

- Go 1.21+，支持 Linux/Windows
- GitHub Actions CI/CD，Systemd 服务管理

## 目录结构

```plain
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
├── nginx/
│   ├── deployer/   # Nginx 部署器
│   ├── docker/     # Docker 容器支持
│   ├── installer/  # HTTPS 安装器
│   └── scanner/    # 配置扫描器
├── apache/     # Apache 扫描器/安装器
└── iis/        # IIS 扫描器/证书存储
```

## 工作目录

| 系统 | 路径 |
|------|------|
| Linux | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

## 命令行

```bash
cert-deploy -scan                  # 扫描 SSL 站点（保存到 scan-result.json）
cert-deploy -init -url URL -refer_id ID   # 根据扫描结果生成配置
cert-deploy -init _ -url URL -refer_id ID -domains a.com,b.com  # 指定域名
cert-deploy -site example.com      # 部署证书
cert-deploy -site example.com -issue       # 发起签发
cert-deploy -site example.com -install-https  # 安装 HTTPS 配置
cert-deploy -daemon                # 守护进程模式
```

## Docker 支持

Nginx 客户端支持自动检测 Docker 容器中的 Nginx，命令行使用方式与本地完全一致：

```bash
cert-deploy -scan           # 自动检测本地或 Docker 容器
cert-deploy -site example.com  # 根据配置自动选择部署方式
```

### 自动检测优先级

1. 站点配置中 `docker.enabled=true` → 使用 Docker 模式
2. 本地检测到 nginx → 使用本地模式
3. 本地无 nginx 但检测到 Docker 容器 → 使用 Docker 模式

### Docker 配置示例

```json
{
  "site_name": "example.com",
  "server_type": "nginx",
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
    "certificate": "/opt/certs/example.com/fullchain.pem",
    "private_key": "/opt/certs/example.com/privkey.pem"
  }
}
```

### 部署模式

- `volume`: 挂载卷模式，证书写入宿主机目录后自动同步到容器
- `copy`: docker cp 模式，通过 docker cp 复制到容器内
- `auto`: 自动检测（检测到挂载卷则用 volume，否则用 copy）

## 构建与测试

```bash
make build          # 构建当前平台
make build-all      # 构建所有平台
make compress       # gzip 压缩 (CI 使用)
go test ./...       # 运行测试
```

本地无 Go 环境时可用 Docker 构建：

```bash
docker run --rm -v "$(pwd)":/app -w /app golang:1.24-alpine \
  sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o dist/cert-deploy-nginx ./cmd/nginx"
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
- [x] Docker 容器 Nginx 支持
- [x] 扫描结果存储与配置初始化
- [ ] 部署前后 Hook 支持
- [ ] Web UI 管理界面
