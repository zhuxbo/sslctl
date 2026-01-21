# cert-deploy

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache。

## 项目结构

```
cmd/                    # CLI 入口
├── main.go             # 统一入口（nginx/apache 子命令）
├── nginx/nginx.go
└── apache/apache.go
pkg/                    # 可复用包
├── fetcher/            # API 客户端
├── config/             # 站点配置
└── logger/             # 日志
internal/               # 内部实现
├── nginx/              # Nginx 扫描/部署/Docker
└── apache/             # Apache 扫描/部署
skills/                 # 开发规范（详细文档）
```

## 核心命令

```bash
cert-deploy nginx scan                       # 扫描站点
cert-deploy nginx deploy --site example.com  # 部署证书
cert-deploy --debug nginx deploy ...         # Debug 模式
```

## 开发规范

详细规范见 `skills/SKILL.md`，按领域组织：

| Skill | 内容 |
|-------|------|
| `skills/go-dev/` | Go 代码规范、包结构 |
| `skills/nginx-apache/` | 配置解析、证书部署 |
| `skills/deploy-ops/` | 部署、systemd、daemon |
| `skills/build-release/` | 构建、CI/CD |

## 知识积累

开发中确定的信息写入对应 skill 文件。

## IIS 支持

IIS 版本独立为 [cert-deploy-iis](https://github.com/cnssl/cert-deploy-iis) 项目（.NET 8）。
