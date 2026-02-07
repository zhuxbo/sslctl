# sslctl

SSL 证书自动部署工具，Go 语言实现，支持 Nginx、Apache、Docker。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。

## 核心指令

- **不要自动提交** - 完成修改后等待用户确认"提交"再执行 git commit/push
- **测试发现 bug 必须修复代码** - 测试的目的是发现 bug 并修复，绝不修改测试去迎合错误的代码

## 项目结构

```text
cmd/           # CLI 入口
  main.go      # 主入口
  setup/       # 一键部署命令
  daemon/      # 守护进程
  deploy/      # 证书部署
pkg/           # 可复用包
  certops/     # 证书操作服务层（扫描/部署/续签/私钥管理），依赖 webserver 抽象层
  webserver/   # Web 服务器抽象层（统一 Scanner/Deployer/Rollback 接口）
  config/      # 配置管理（文件锁+内存锁双重保护，返回深拷贝确保并发安全，含 SSRF 防护）
  errors/      # 错误类型定义（含结构化部署错误 StructuredDeployError）
  matcher/     # 域名匹配
  fetcher/     # API 客户端（含 SSRF/DNS Rebinding 防护）
  backup/      # 备份管理（哈希校验 TOCTOU 保护）
  service/     # 系统服务管理
  upgrade/     # 升级模块（版本检查/下载/Ed25519签名验证/校验/安装）
  logger/      # 日志（含敏感信息过滤、路径脱敏、日志轮转）
  util/        # 工具函数（文件操作/权限检查）
internal/      # 内部实现
  nginx/       # Nginx 扫描/部署
  apache/      # Apache 扫描/部署
  executor/    # 统一命令执行器（白名单机制）
build/         # 构建/发布脚本
skills/        # 开发规范
testdata/      # 测试数据和工具
```

## 核心命令

```bash
# 一键部署（推荐）
sslctl setup --url <url> --token <token> --order <order_id>

# 站点扫描
sslctl scan                       # 扫描站点（自动检测 Web 服务器）
sslctl scan --ssl-only            # 仅扫描 SSL 站点

# 证书部署
sslctl deploy --cert <name>       # 部署指定证书
sslctl deploy --all               # 部署所有证书

# 本地证书部署（不依赖 API）
sslctl deploy local --cert <file> --key <file> --site <name>
sslctl deploy local --cert <file> --key <file> --ca <file> --site <name>  # Apache

# 证书回滚
sslctl rollback --site <name>              # 回滚到最新备份
sslctl rollback --site <name> --list       # 查看备份列表
sslctl rollback --site <name> --version <ts>  # 回滚到指定版本

# 服务管理
sslctl status                     # 查看服务状态（含证书过期详情）
sslctl service repair             # 修复服务
sslctl upgrade                    # 升级工具
sslctl uninstall                  # 卸载
```

## 配置文件

统一配置文件：`/opt/sslctl/config.json`

证书存储目录：`/opt/sslctl/certs/{site_name}/`

## 环境变量

| 变量                      | 说明                             |
|---------------------------|----------------------------------|
| `SSLCTL_API_TOKEN`   | API Token（优先级高于配置文件）  |
| `SSLCTL_API_URL`     | API URL（优先级高于配置文件）    |

## 测试

```bash
go test -v ./...                           # 运行单元测试
go test -coverprofile=coverage.out ./...   # 测试并生成覆盖率
bash build/test-linux.sh                   # Linux 发行版服务管理测试

# 容器端到端测试
bash docker/test/scripts/run-mock-tests.sh                # Mock API 离线测试
bash docker/test/scripts/run-e2e-tests.sh --token <token> # 真实 API 测试
bash docker/test/scripts/run-e2e-tests.sh --all           # 全发行版测试
```

## 容器测试目录

```text
docker/test/
├── scripts/           # 测试脚本
│   ├── common.sh      # 公共函数
│   ├── run-e2e-tests.sh    # E2E 测试主脚本
│   ├── run-mock-tests.sh   # Mock 测试主脚本
│   ├── test-setup.sh       # setup 命令测试
│   ├── test-deploy.sh      # deploy 命令测试
│   ├── test-deploy-local.sh # deploy local 测试
│   └── test-scan.sh        # scan 命令测试
├── e2e/               # E2E 测试环境
│   ├── docker-compose.e2e.yml
│   ├── nginx-e2e/     # Nginx E2E 容器
│   └── apache-e2e/    # Apache E2E 容器
├── mock-api/          # Mock API 服务
│   └── main.go        # 支持场景切换、请求记录
└── reports/           # 测试报告输出
```

## 续签模式

| 模式    | 说明           | 启用方式                 |
|---------|----------------|--------------------------|
| `local` | 本地私钥模式   | `--local-key` 或配置文件 |
| `pull`  | 拉取模式（默认）| 默认行为                 |

详见 `skills/deploy-ops/SKILL.md`

## 安全机制

详见 `skills/go-dev/SKILL.md` 安全开发规范章节：

- 命令执行白名单 + 超时控制（`internal/executor`，默认 30 秒超时，支持 Context 取消）
- SSRF/DNS Rebinding 防护（`pkg/fetcher`、`pkg/validator`）
- 中间证书校验（API 部署必须包含中间证书，`deploy local` 的 `--ca` 参数仍可选）
- 文件操作安全（符号链接防护、TOCTOU 保护、AtomicWrite O_EXCL 防护）
- 备份源文件符号链接检查（`pkg/backup` computeFileHash 拒绝符号链接）
- 备份恢复安全（Restore 内部备份跳过 cleanup，防止清理掉正在恢复的目标备份）
- 配置并发安全（深拷贝 + 双重锁 + mtime 检测外部修改）
- 配置保存符号链接防护（saveLocked 拒绝写入符号链接目标）
- 日志敏感信息过滤（私钥、Bearer Token、Basic Auth、JSON 敏感字段、URL 参数）
- 升级模块 TLS 安全（HTTPS + TLS 1.2+）
- 升级优雅重启（Stop + 等待停止 + Start）
- SELinux 兼容（部署后自动恢复文件安全上下文）
- IDN/Punycode 域名支持（`pkg/matcher`）
- 证书过期告警（守护进程周期检查，7 天/14 天阈值）
- 重试计数自动重置（CSR 提交超 7 天后重置计数）
- 配置扫描防护（Nginx/Apache 扫描器文件数量限制 1000 + 文件大小限制 10MB）
- Docker 挂载路径精确匹配（防止 `/etc/nginx` 匹配到 `/etc/nginx-backup`）
- 升级解压防护（gzip 解压大小限制，防止 gzip 炸弹攻击）
- 升级模块 Ed25519 签名验证（`pkg/upgrade`，密钥环支持多公钥，签名格式 `ed25519:<key_id>:<base64>` 带 key ID，兼容旧格式；空密钥环时拒绝验证而非静默跳过；已配置公钥时拒绝安装未签名版本，防止降级攻击）
- 升级安装符号链接防护（`copyFile` 写入前检查目标路径，拒绝覆盖符号链接）
- 升级签名密钥轮换（`ErrKeyNotFound` 专用错误类型，未知 key ID 提示重新安装而非"文件被篡改"）
- 升级通道白名单（`downloadVerifyInstall` 中 channel 参数仅允许 stable/dev，防止路径遍历）
- 升级链式升级深度防篡改（`getUpgradeDepth` 对非法环境变量值返回最大深度，防止绕过限制）
- 升级链式升级（`releases.json` 的 `upgrade_path` 字段，跨多次密钥轮换时自动经过过渡版本逐步升级，`syscall.Exec` 进程替换，最大 5 步深度限制，保留用户 `--channel`/`--version`/`--force` 参数）
- 升级最低客户端版本检查（`releases.json` 的 `min_client_version` 字段，配合 `upgrade_path` 实现平滑密钥轮换；`--check` 模式不触发链式升级）
- 部署/续签结果 API 回调（`pkg/certops`，非关键路径，失败仅记录日志，状态枚举统一使用 `success`/`failure`/`pending`）

## CSR 生成

- CSR 只需要 Common Name（CN），**不需要** SAN（Subject Alternative Name）
- 默认密钥类型：RSA 2048，支持 ECDSA

## 开发规范

详见 `skills/` 目录：

- `go-dev/` - Go 开发规范
- `nginx-apache/` - 配置解析、证书部署
- `deploy-ops/` - 部署运维、续签流程、API 接口
- `build-release/` - 构建发布
