# cert-deploy 开发记录

## 项目概述

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、IIS。

**仓库地址**：
- GitHub: https://github.com/zhuxbo/cert-deploy (主仓库)
- Gitee: https://gitee.com/zhuxbo/cert-deploy (镜像)

**许可证**: MIT

## 技术栈

- Go 1.21+
- 支持 Linux/Windows/macOS
- Systemd 服务管理
- GitHub Actions CI/CD

## 工作目录

固定工作目录（不再依赖可执行文件位置）：

| 系统 | 工作目录 |
|------|----------|
| Linux/macOS | `/opt/cert-deploy/` |
| Windows | `C:\cert-deploy\` |

## 核心功能

### 1. 配置扫描 (`internal/nginx/scanner/`, `internal/apache/scanner/`, `internal/iis/scanner/`)

**智能检测配置路径**（不再使用固定路径）：

**Nginx:**
1. 通过 `nginx -t` 获取配置路径
2. 通过 `nginx -V` 获取编译时的 `--conf-path`
3. 尝试常见路径作为后备

**Apache:**
1. 通过 `apache2ctl -V` / `apachectl -V` / `httpd -V` 获取
2. 解析 `HTTPD_ROOT` 和 `SERVER_CONFIG_FILE`
3. 尝试常见路径作为后备

**IIS (Windows):**
1. 通过 PowerShell `WebAdministration` 模块获取站点列表
2. 返回站点名称、主机名、端口、证书指纹、过期时间

**递归扫描 Include 指令**：
- 从主配置文件开始
- 解析所有 `include` / `Include` / `IncludeOptional` 指令
- 支持 glob 模式 (如 `*.conf`, `sites-enabled/*`)
- 避免循环引用

**提取 SSL 站点信息**：
- 域名 (server_name / ServerName)
- 证书路径 (ssl_certificate / SSLCertificateFile)
- 私钥路径 (ssl_certificate_key / SSLCertificateKeyFile)
- 证书链路径 (Apache: SSLCertificateChainFile)
- 监听端口
- Web 根目录 (root / DocumentRoot / PhysicalPath)

### 2. 日志记录 (`pkg/logger/`)

- 按日期自动切分日志文件
- 同时输出到文件和控制台
- 记录部署、备份、重载等操作

### 3. 证书备份 (`pkg/backup/`)

- 部署前自动备份旧证书
- 按时间戳创建备份目录
- 支持多版本保留
- 保存备份元数据

### 4. 部署流程 (`cmd/nginx/main.go`)

1. 扫描 Nginx 配置，获取 SSL 站点
2. 加载站点配置，匹配域名
3. 检查证书有效期
4. 从 API 获取新证书
5. 备份旧证书
6. 原子写入新证书
7. 测试 Nginx 配置
8. 重载 Nginx 服务
9. 记录日志

## 命令行参数

```bash
# Nginx
cert-deploy-nginx -scan                             # 扫描 SSL 站点
cert-deploy-nginx -site example.com                 # 部署指定站点
cert-deploy-nginx -site example.com -issue          # 发起证书签发（file 验证）
cert-deploy-nginx -site example.com -install-https  # 为 HTTP 站点安装 HTTPS 配置
cert-deploy-nginx -daemon                           # 守护进程模式
cert-deploy-nginx -version                          # 显示版本

# Apache
cert-deploy-apache -scan                            # 扫描 SSL 站点
cert-deploy-apache -site example.com                # 部署指定站点
cert-deploy-apache -site example.com -issue         # 发起证书签发
cert-deploy-apache -site example.com -install-https # 为 HTTP 站点安装 HTTPS 配置
cert-deploy-apache -daemon                          # 守护进程模式

# IIS (Windows)
cert-deploy-iis -scan                               # 扫描 IIS SSL 站点
cert-deploy-iis -site example.com                   # 部署指定站点
cert-deploy-iis -site example.com -issue            # 发起证书签发
cert-deploy-iis -site example.com -install-https    # 为 HTTP 站点安装 HTTPS 绑定
cert-deploy-iis -daemon                             # 守护进程模式
```

## Systemd 服务

服务文件位于 `deploy/systemd/`：
- `cert-deploy-nginx.service`
- `cert-deploy-apache.service`

启用方式：
```bash
systemctl enable cert-deploy-nginx
systemctl start cert-deploy-nginx
```

## Docker 测试

多发行版测试环境位于 `docker/test/`。

### Nginx 测试

| 发行版 | 版本 | 配置目录 | 状态 |
|--------|------|----------|------|
| Ubuntu | 22.04 | sites-enabled/ | ✅ 通过 |
| Debian | 12 | sites-enabled/ | ✅ 通过 |
| Rocky Linux | 9 | conf.d/ | ✅ 通过 |
| Alpine | 3.19 | http.d/ | ✅ 通过 |

### Apache 测试

| 发行版 | 版本 | 配置路径 | ServerRoot | 状态 |
|--------|------|----------|------------|------|
| Ubuntu | 22.04 | /etc/apache2/apache2.conf | /etc/apache2 | ✅ 通过 |
| Rocky Linux | 9 | /etc/httpd/conf/httpd.conf | /etc/httpd | ✅ 通过 |
| Alpine | 3.19 | /etc/apache2/httpd.conf | /usr | ✅ 通过 |

运行测试：
```bash
cd docker/test
./run-tests.sh
```

注意：Alpine 需要静态编译（CGO_ENABLED=0）

### 部署流程测试

完整部署流程测试（模拟 API + 证书部署 + 备份 + 重载）：

```bash
# Nginx 部署测试
docker build -t cert-deploy-test docker/test/deploy-test/
docker run --rm cert-deploy-test

# Apache 部署测试
docker build -t cert-deploy-apache-test docker/test/deploy-test-apache/
docker run --rm cert-deploy-apache-test
```

测试验证：
- ✅ API 证书获取
- ✅ 证书文件原子写入
- ✅ 旧证书自动备份
- ✅ 配置测试 (nginx -t / apache2ctl -t)
- ✅ 服务优雅重载
- ✅ 日志记录

## 开发计划

- [x] 简化工作目录（固定路径）
- [x] 实现 Nginx 配置扫描
- [x] 实现日志记录
- [x] 集成扫描、备份、日志到主程序
- [x] 创建 Systemd 服务文件
- [x] 多发行版测试（Ubuntu/Debian/Rocky/Alpine）
- [x] Apache 配置扫描（Ubuntu/Rocky/Alpine）
- [x] 部署回调通知（通知 Manager 部署结果）
- [x] IIS 部署工具完善（扫描、配置管理、日志、回调）
- [x] 单元测试（validator、scanner、certstore）
- [x] 配置包重构移到 pkg/config
- [x] 定义 Deployer/Scanner 接口
- [x] 证书/私钥配对验证
- [x] 部署失败自动回滚
- [x] 网络请求自动重试
- [x] 日志级别可配置
- [x] HTTP 文件验证 (DCV) 支持
- [x] HTTPS 配置安装 (-install-https)
- [ ] 部署前后 Hook 支持
- [ ] Web UI 管理界面

## 单元测试

```bash
# 运行所有测试
go test ./...

# 运行指定包的测试
go test -v ./pkg/validator/...
go test -v ./internal/nginx/scanner/...
go test -v ./internal/apache/scanner/...
go test -v ./internal/iis/certstore/...
```

测试覆盖：
- `pkg/validator` - 证书解析、过期检测、域名匹配
- `internal/nginx/scanner` - 配置文件解析、include 指令
- `internal/apache/scanner` - VirtualHost 解析、SSL 配置提取
- `internal/iis/certstore` - PFX 转换、私钥解析

测试数据：
- `testdata/certs/generator.go` - 动态生成测试证书（有效、过期、通配符等）
- `testdata/nginx/` - Nginx 测试配置文件
- `testdata/apache/` - Apache 测试配置文件

## 构建

```bash
# 构建当前平台
make build

# 构建所有平台
make build-all

# 本地构建测试
./scripts/build.sh v0.3.0
```

## CI/CD

### GitHub Actions Workflows

| Workflow | 文件 | 触发条件 | 功能 |
|----------|------|----------|------|
| CI | `ci.yml` | push/PR 到 main/dev | 测试、Lint、构建检查 |
| Release | `release.yml` | 推送 `v*` 标签 | 构建发布、创建 Release |
| Sync to Gitee | `sync-to-gitee.yml` | push 到 main/dev | 同步代码到 Gitee 镜像 |

### CI 流程 (`.github/workflows/ci.yml`)

在 `main` 和 `dev` 分支的 push/PR 时自动运行：

1. **Test** - 运行 `go test -v -race ./...`
2. **Lint** - 运行 `golangci-lint`（staticcheck、errcheck 等）
3. **Build Check** - 验证多平台构建（依赖 Test 和 Lint 通过）

### 发布流程 (`.github/workflows/release.yml`)

推送 `v*` 标签自动触发：
1. 运行测试
2. 构建多平台二进制（Linux/Windows/macOS × amd64/arm64）
3. 创建 GitHub Release
4. 同步到 Gitee Release（上传附件）

### Gitee 同步 (`.github/workflows/sync-to-gitee.yml`)

- 自动同步 `main` 和 `dev` 分支代码到 Gitee
- 自动同步 `v*` 标签
- 排除 `-dev` 开发仓库避免循环

### 分支策略

- `main` 分支: 发布正式版
- `dev` 分支: 发布测试版 (Pre-release)

### 发布流程

```bash
# 发布测试版 (dev 分支)
git checkout dev
git tag v0.3.0-beta
git push origin v0.3.0-beta

# 发布正式版 (main 分支)
git checkout main
git merge dev
git tag v0.3.0
git push origin v0.3.0
```

### GitHub Secrets 配置

| Secret | 用途 |
|--------|------|
| `GITEE_TOKEN` | Gitee 访问令牌，用于同步代码和 Release |

## 最近更新

### 2025-12-20 (交互式 HTTPS 安装)

**交互式输入模块** (`pkg/prompt/`):
- 新增交互式命令行输入模块
- 支持确认提示、选择列表、文本输入、路径输入
- 自动检测终端模式，非交互模式使用默认值

**HTTP 站点扫描**:
- Nginx: 扫描未启用 SSL 的 server 块
- Apache: 扫描未启用 SSL 的 VirtualHost
- IIS: 扫描仅有 HTTP 绑定的站点

**交互式安装模式**:
- `-install-https` 无 `-site` 参数时进入交互模式
- 显示未启用 HTTPS 的站点列表供选择
- 引导输入证书路径、私钥路径等参数
- 确认后自动安装

**部署时 HTTPS 检测**:
- `-site example.com` 部署时检测站点是否已配置 HTTPS
- 如未配置，提示用户是否安装 HTTPS 配置
- 交互式引导完成安装后继续部署

**使用方式**:
```bash
# 交互式安装
cert-deploy-nginx -install-https
cert-deploy-apache -install-https
cert-deploy-iis -install-https

# 部署时自动提示（如未配置 HTTPS 会提示是否安装）
cert-deploy-nginx -site example.com
cert-deploy-apache -site example.com
cert-deploy-iis -site example.com
```

### 2025-12-20 (HTTPS 配置安装)

**HTTPS 配置安装模块** (`internal/*/installer/`):
- 新增 `-install-https` 命令行参数，为未启用 HTTPS 的站点添加 SSL 配置
- **Nginx**: 在现有 HTTP server 块中添加 SSL 指令 (`listen 443 ssl`, `ssl_certificate` 等)
- **Apache**: 基于 `:80` VirtualHost 生成 `:443` VirtualHost，添加 SSL 配置
- **IIS**: 通过 PowerShell 添加 HTTPS 绑定并关联证书

**安全措施**:
- 强制备份原配置文件
- 写入后自动测试配置 (`nginx -t` / `apache2ctl -t`)
- 测试失败自动回滚到备份

**使用方式**:
```bash
cert-deploy-nginx -site example.com -install-https
cert-deploy-apache -site example.com -install-https
cert-deploy-iis -site example.com -install-https
```

### 2025-12-19 (功能扩展)

**Webroot 自动提取**：
- Nginx: 解析 `root` 指令获取 Web 根目录
- Apache: 解析 `DocumentRoot` 指令
- IIS: 通过 PowerShell 获取站点 `PhysicalPath`
- 扫描输出显示 Web 根目录
- 部署时自动使用扫描到的 webroot（配置优先级更高）

**证书签发模块** (`pkg/issuer/`)：
- 新增 `-issue` 命令行参数，支持从客户端发起证书签发
- 自动生成私钥和 CSR（使用 `pkg/csr`）
- 调用 API 提交 CSR 发起签发
- 自动处理 file 验证（放置验证文件、等待签发、清理）
- 签发完成后自动部署证书

**签发流程**：
1. 生成私钥和 CSR
2. 调用 `POST /api/auto/cert` 提交 CSR
3. 如果返回 file 验证，在 webroot 放置验证文件
4. 轮询等待证书签发完成
5. 签发成功后部署证书

### 2025-12-19 (API 对接审核)

**cert-manager Auto API 对接审核修复**：

- **移除多余参数**: 从 `PostRequest` 结构体移除 `CommonName` 参数（后端不使用）
- **文件验证功能**: 实现 HTTP 文件验证（DCV），当证书状态为 `processing` 且返回 `file` 数据时：
  - 自动在 `webroot` 目录放置验证文件
  - 轮询等待证书签发完成（最多 5 分钟，每 10 秒检查一次）
  - 完成后自动清理验证文件
- **站点配置**: 新增 `paths.webroot` 配置项，用于指定站点的 Web 根目录

**API 兼容性**：
- GET `/api/auto/cert` - ✅ 完全兼容
- POST `/api/auto/cert` - ✅ 兼容（已移除多余参数）
- POST `/api/auto/callback` - ✅ 完全兼容
- 响应格式 (`msg` 字段) - ✅ 完全兼容

### 2025-12-19

**代码审核修复** - 修复代码审核中发现的 10 个问题：

- **配置包重构**: 将 `internal/nginx/config/` 移动到 `pkg/config/`，解决跨模块引用问题
- **接口定义**: 新增 `pkg/deployer/interface.go` 和 `pkg/scanner/interface.go`，定义统一接口
- **证书配对验证**: 新增 `ValidateCertKeyPair()` 方法验证证书和私钥是否匹配
- **自动回滚**: 部署失败时自动回滚到备份证书
- **备份错误处理**: `Backup()` 返回 `BackupResult` 包含清理错误信息
- **网络重试**: API 客户端支持自动重试（指数退避 + 随机抖动）
- **直接命令执行**: 命令改为直接执行，不再通过 shell
- **日志级别配置**: 支持 `LOG_LEVEL` 环境变量配置日志级别
- **PowerShell 转义**: 增加 `escapePSString()` 防止参数注入
- **API 常量**: 定义 `APICodeSuccess` 常量替代魔法数字

### 2025-12-18

- 工作目录改为固定路径 `/opt/cert-deploy` (Linux) 和 `C:\cert-deploy` (Windows)
- **智能配置检测**: 通过 `nginx -t` / `apache2ctl -V` 自动检测配置路径
- **递归扫描**: 解析 include 指令，递归扫描所有站点配置
- 新增 Apache 配置扫描功能
- 新增 `-scan` 参数用于扫描显示 SSL 站点
- 新增日志记录功能，按日期自动切分
- 部署前自动备份旧证书
- 创建 Systemd 服务文件
- 适配各种面板（宝塔、1Panel 等）和不同 Linux 发行版
- **部署回调通知**: 部署成功后通知 Manager API，支持配置 `callback_url`
- **IIS 部署工具完善**:
  - 新增 IIS 扫描器 (`internal/iis/scanner/`)，通过 PowerShell 获取 IIS SSL 站点
  - 重构 `cmd/iis/main.go`，使用统一配置管理器替代环境变量
  - 支持 `-scan`、`-site`、`-daemon` 参数，与 Nginx/Apache 保持一致
  - 集成日志记录和部署回调通知
- **单元测试**:
  - `pkg/validator` - 证书解析、过期检测、域名验证
  - `internal/nginx/scanner` - Nginx 配置解析、include 指令处理
  - `internal/apache/scanner` - Apache 配置解析、VirtualHost 提取
  - `internal/iis/certstore` - PFX 转换、私钥解析、证书验证
  - 测试数据生成器 (`testdata/certs/generator.go`)
