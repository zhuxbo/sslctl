# 完成检查（finish-check）

在提交代码前，按以下清单逐项检查。每一步都必须实际执行命令并报告结果，不能跳过。

---

## 1. 编译检查

运行交叉编译，确认三个目标平台均能编译通过：

```bash
GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd && \
GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd && \
GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd
```

如果编译失败，修复后重新检查。

## 2. 单元测试

运行全部单元测试（含竞态检测）：

```bash
go test -race -count=1 ./...
```

- 所有测试必须通过
- 如果有失败，分析失败原因并修复代码（不要修改测试去迎合错误的代码）

## 3. Lint 检查

```bash
golangci-lint run ./... --timeout=5m
```

本项目启用的检查器：errcheck、govet、staticcheck、gosec、unused、ineffassign。
测试文件已排除 gosec 和 errcheck，`docker/test/mock-api/` 已排除 gosec。

- 如果有 lint 错误，修复代码
- 不要通过添加 `//nolint` 注释来绕过检查，除非有充分理由并加注释说明

## 4. Go 项目专项检查

### 4.1 平台兼容性

检查是否涉及平台相关代码。本项目使用 Build Tag 隔离平台实现：

- `pkg/util/inode_unix.go` / `inode_windows.go`
- `pkg/util/selinux_linux.go`
- `pkg/config/flock_unix.go` / `flock_windows.go`
- `cmd/console_windows.go`

如果修改了平台相关逻辑，确认：

- 对应的平台文件也做了相应修改
- Build Tag 正确（`//go:build linux`、`//go:build !windows` 等）
- Windows 和 Linux 编译均通过（已在步骤 1 覆盖）

### 4.2 命令执行白名单

如果新增了系统命令调用，检查：

- 是否通过 `internal/executor` 执行（禁止直接使用 `exec.Command`）
- 新命令是否已加入 `AllowedCommands` 或 `AllowedScanExecutables`/`AllowedScanArgs` 白名单
- 白名单测试（`executor_test.go`）是否覆盖了新命令

### 4.3 并发安全

如果修改了以下包，需特别注意并发安全：

- `pkg/config/` — 文件锁 + 内存锁 + 深拷贝，返回值不应持有内部引用
- `pkg/logger/` — `minLevel`/`jsonMode` 必须使用 `atomic` 类型
- `pkg/certops/` — 服务层操作可能被守护进程并发调用

### 4.4 安全检查

对照本项目已有的安全机制，检查改动是否引入新风险：

- **文件操作**：是否检查符号链接？是否有 TOCTOU 风险？是否使用 AtomicWrite？
- **路径处理**：用户输入的路径是否做了穿越防护？
- **SSRF**：如果涉及 HTTP 请求，是否经过 `pkg/fetcher` 的 SSRF 防护？
- **日志脱敏**：是否有私钥、Token、密码等敏感信息可能被记录到日志？
- **配置文件**：配置读写是否通过 `pkg/config`（自带文件锁和并发安全）？

### 4.5 接口一致性

如果修改了 `pkg/webserver/` 的接口定义（Scanner/Deployer/Rollback），确认：

- `internal/nginx/` 和 `internal/apache/` 的实现同步更新
- 接口参数命名一致（如 `Deploy` 方法的 `intermediate` 参数）

### 4.6 错误处理

- 新增的错误是否使用了 `pkg/errors` 的结构化错误类型（`StructuredDeployError`）？
- 错误是否包含类型分类、阶段定位和可重试判断？
- API 回调错误是否仅记录日志而非阻断主流程？

## 5. Git Diff 审查

运行以下命令查看完整改动：

```bash
git diff
git diff --cached
git status
```

逐项确认：

- **无意外文件**：没有不应提交的文件（临时文件、IDE 配置、.env、密钥文件）
- **无调试代码**：没有残留的 `fmt.Println`、`log.Println` 调试输出
- **无硬编码**：没有硬编码的 IP、URL、密码、Token
- **无意外删除**：没有误删原有代码或测试
- **testdata 变更**：如果修改了 `testdata/` 下的测试数据，确认是有意为之
- **go.mod/go.sum**：如果变更了依赖，确认是必要的且没有引入不必要的依赖

## 6. 测试覆盖率回归

如果新增或修改了核心逻辑，检查覆盖率是否下降：

```bash
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1
```

核心包的覆盖率基线：

- `pkg/errors` — 100%
- `pkg/config` — 76%
- `pkg/backup` — 75%
- 整体 — 48%+

新增代码应有对应的测试。覆盖率不应显著下降。

## 7. 已知局限性和潜在风险

对本次改动，按以下分类列出已知局限性和潜在风险：

### 安全风险

- 是否绕过了现有安全机制（白名单、SSRF 防护、符号链接检查）？
- 是否有新的用户输入未经校验直接使用？

### 兼容性风险

- 是否影响现有的配置文件格式（`/opt/sslctl/config.json`）？
- 是否影响 CLI 命令的参数或输出格式（可能破坏脚本集成）？
- 是否影响 systemd/SysVinit/OpenRC 服务文件？

### 运行时风险

- 是否有 goroutine 泄漏风险（未关闭的 channel、未取消的 context）？
- 是否有文件句柄泄漏（defer close 是否正确）？
- 守护进程场景下是否存在资源积累问题？

### 部署风险

- 升级模块变更是否保持了 Ed25519 签名验证的完整性？
- 是否影响了 `/opt/sslctl/certs/` 的目录结构？
- SELinux 环境下文件上下文是否会被破坏？

---

将以上所有检查结果汇总，明确标注：通过 / 不通过 / 不适用。
对于不通过的项，给出修复建议。
