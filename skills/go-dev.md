# Go 开发规范

只读取与本次修改相关的章节。检查范围和执行入口统一见 `skills/finish-check.md`，本文不追加全仓门禁。

## 项目约定

- CLI 入口为 `cmd/`，服务器实现为 `internal/nginx/`、`internal/apache/`，部署编排为 `pkg/certops/`，共享接口为 `pkg/webserver/`。从变更的调用链定位实现，避免泛读全仓。
- 沿用标准 `testing`、表驱动用例和现有 `testdata/` 辅助；只为需要证明的行为补回归，不为文案或机械改动写镜像测试。
- Go 版本与依赖以 `go.mod` 为准；仅确实引入依赖时运行 `go mod tidy`。
- 部署错误使用 `pkg/errors.StructuredDeployError`；回调传输失败只记录日志，不阻断主流程。日志使用 `pkg/logger`，不要输出完整配置或私钥。

## 测试资源

### 测试目录结构

```text
testdata/
├── certs/           # 证书生成器
│   └── generator.go # GenerateTestCert, GenerateExpiringCert, GenerateCertChain 等
├── testutil/        # 测试辅助工具
│   ├── mockapi.go   # HTTP Mock Server 封装
│   ├── fs.go        # 临时文件辅助（TempDir）
│   └── config.go    # 测试配置生成器
├── nginx/           # Nginx 测试配置
├── apache/          # Apache 测试配置
└── config/          # 配置文件示例
```

### 测试风格规范

- 使用标准 `testing` 包，不引入 testify
- 采用表驱动测试
- 使用 `t.TempDir()` 创建临时目录
- 使用 `t.Helper()` 标记辅助函数
- 中文注释保持一致

---

## 常见问题

### 交叉编译

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o sslctl ./cmd
GOOS=linux GOARCH=arm64 go build -o sslctl ./cmd

# Windows
GOOS=windows GOARCH=amd64 go build -o sslctl.exe ./cmd
```

平台相关代码使用 Build Tag 隔离，确保交叉编译通过：
- `pkg/util/inode_unix.go` / `inode_windows.go` — inode 比较（Unix 用 `syscall.Stat_t`，Windows 回退 Size/ModTime）
- `pkg/util/selinux_linux.go` / `selinux_other.go` — SELinux 上下文恢复（仅 Linux 生效）
- `pkg/config/flock_unix.go` / `flock_windows.go` — 文件锁
- `internal/executor/detach_unix.go` / `detach_windows.go` — 后台进程 detach
- `internal/deployer/signal_unix.go` / `signal_windows.go` — reload 信号（Unix SIGUSR1）
- `pkg/service/systemd.go` / `openrc.go` / `sysvinit.go`（`//go:build linux`）、`windows.go`、`linux_stub.go` / `windows_stub.go` — 系统服务管理
- `pkg/webserver/winservice_windows.go` / `winservice_other.go` — Windows 服务检测
- `cmd/console_windows.go` / `console_other.go` — 控制台分版本检测。Win10/Server2016+ 通过 `SetConsoleMode` 开 VT 后回读验证，确认成功才设 UTF-8 CP 并启用 ANSI 颜色；老系统（Server 2012 R2 等）完全不动控制台 CP 和字体，避免触发 Windows 把字体自动切回 Raster Font 覆盖用户手动设的 TrueType 字体；`supportsANSIColor()` 决定是否输出 ANSI 颜色码，`SSLCTL_CONSOLE_DEBUG=1` 开启启动期 stderr 诊断

> 升级模块的平台差异（Linux 先替换再重启零停机 / Windows 先停服务释放句柄再替换）在 `pkg/upgrade` 内以 `runtime.GOOS` 分支处理，无独立 build-tag 文件。

### 静态编译

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o sslctl ./cmd
```

---

## CI 与代码检查

### golangci-lint

配置文件 `.golangci.yml`，启用 errcheck、govet、staticcheck、gosec、unused、ineffassign。

排除的 gosec 规则（以 `.golangci.yml` 为准，项目级别合理误报）：
- **G101**：环境变量名常量（如 `SSLCTL_API_TOKEN`）被误报为硬编码凭据
- **G115**：`uintptr→int` 转换用于终端检测和文件锁，安全可控
- **G204**：通过 executor 白名单 + `exec.Command` 直接执行（非 shell）控制安全
- **G301/G302/G306**：服务脚本需 0755、systemd/nginx/apache 配置需 0644、临时目录需 0700
- **G304**：CLI 工具核心功能需通过变量路径读取配置/证书文件
- **G404**：退避抖动仅需统计随机性，不涉及安全
- **G703**：路径穿越污点分析，配置/证书路径由用户参数传入且已在配置层校验

`staticcheck` 关闭 `QF*`（quickfix 建议）。测试文件（`_test.go`）已排除 gosec 和 errcheck，`docker/test/mock-api/` 已排除 gosec。

本地使用 finish-check 规划的包集合进行 Linux/Windows lint；CI 保留全仓检查。不要在定向检查后再复制执行全仓命令。

`Windows Apache parser` job 在 Windows runner 原生执行 ServerRoot/Define 与包含文件回归，验证 Windows 路径解析；它不代表 Windows Apache 服务部署 E2E。

---

## 代码质量

- **CI 全绿**：Test + Lint + Build 三项，支持 linux/amd64、linux/arm64、windows/amd64 交叉编译。
- **接口参数命名统一**：`pkg/webserver.Deployer.Deploy` 接口参数名与 nginx/apache 实现一致使用 `intermediate`；修改 `pkg/webserver` 接口（Scanner/Deployer/Rollback）时须同步更新 `internal/nginx/` 与 `internal/apache/` 实现。
- **Windows 服务管理错误处理**：`Control` / `UpdateConfig` 等返回值均已检查，不吞错。

---

## 安全开发规范

### 命令执行

使用 `internal/executor` 包执行系统命令，不要直接使用 `exec.Command`：

```go
import "github.com/zhuxbo/sslctl/internal/executor"

// 正确：使用统一的 executor
if err := executor.Run("nginx -s reload"); err != nil {
    return err
}

// 错误：直接执行命令（可能被注入）
cmd := exec.Command("sh", "-c", userInput)
```

白名单命令定义在 `executor.AllowedCommands`，新增命令需要审核。默认 30 秒超时，支持 Context 取消。

**注意**：`util.RunCommand` 已删除，所有命令执行必须通过 executor。

### 配置并发安全

`ConfigManager.Load()` 返回深拷贝，修改不影响内部缓存：

```go
cfg, _ := cm.Load()
cfg.Certificates[0].API.Token = "new-token"  // 仅修改副本

// 需要显式保存
cm.Save(cfg)
// 或使用专用方法
cm.UpdateCert(&cert)
```

并发保障：深拷贝 + 双重锁（文件锁 + 内存锁）+ mtime + SHA256 哈希检测外部修改；写路径 `Update*` 统一走 `mutateLocked`——在文件锁内感知外部修改并基于最新盘上状态读-改-写，消除 CLI 与 daemon 跨进程丢更新窗口，修改应用于副本、失败不污染缓存。配置缓存未命中时，读取与迁移写回同样持有文件锁；迁移和保存共用 `O_EXCL` + `Lstat` 校验与原子替换，避免截断文件或覆盖并发更新。

### 日志脱敏

`pkg/logger` 自动过滤敏感信息（text 和 JSON 两种模式下均生效）：

- PEM 私钥 → `***REDACTED PRIVATE KEY***`
- Bearer Token → `Bearer ***REDACTED***`
- password/secret/token 参数（含 JSON 敏感字段复合词匹配、URL 参数） → `param=***REDACTED***`

JSON 模式通过 `SSLCTL_LOG_FORMAT=json` 环境变量启用，或调用 `SetJSONMode(true)`。记录器 `minLevel` / `jsonMode` 使用 `atomic` 类型，`SetLevel` / `SetJSONMode` 线程安全。

### SSRF 防护

`pkg/fetcher` / `pkg/validator` 阻止访问（含 DNS Rebinding 防护，`IsUnspecified()` 检查防止 `0.0.0.0` 绕过）：

- 内网 IP（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）
- 回环地址（127.0.0.0/8, ::1）
- 链路本地地址（169.254.0.0/16）
- 云元数据（169.254.169.254）

### 文件操作安全

使用 `pkg/util` 的安全文件操作函数：

```go
// 安全读取文件（符号链接防护 + TOCTOU 保护 + 大小限制）
data, err := util.SafeReadFile(path, maxSize)

// 安全复制文件
err := util.CopyFile(src, dst)

// 安全路径拼接（防止路径穿越）
safePath, err := util.JoinUnderDir(baseDir, userInput)
```

### 配置文件保存

配置保存使用 `O_EXCL` + `Lstat` 二次校验防止符号链接攻击：

```go
// pkg/config/unified.go saveLocked() 实现
// 1. O_CREATE|O_WRONLY|O_EXCL 创建临时文件（文件存在则失败）
// 2. Lstat 二次校验非符号链接
// 3. Rename 原子替换
```

### Docker 容器命令

容器内命令通过 `internal/nginx/docker/client.go` 执行：

- 命令白名单：nginx/apachectl/cat/test/ls
- 危险模式检测：`;` `|` `||` `$()` `${}` `` ` `` `\n` `\r`
- 允许 `&&`（用于 `test -f && echo ok`）和单引号（用于 `ShellQuote` 路径包裹）
- 路径校验：绝对路径 + 无 `..` + 无特殊字符

### 升级模块安全

`pkg/upgrade/installer.go` 下载二进制时：

- 强制 HTTPS 协议
- TLS 1.2+ 最低版本
- 5 分钟超时 + 100MB 大小限制
- gzip 解压大小限制（防 gzip 炸弹）
- Ed25519 签名验证：密钥环已内置 key-1 公钥，签名格式 `ed25519:<key_id>:<base64>` 带 key ID，`releases.json` 按文件名索引 `signatures` map；已配置公钥时拒绝安装未签名版本（防降级攻击）；密钥不匹配时提示用 `install.sh` 重装（`ErrKeyNotFound` / `ErrNoPublicKeys` 统一处理）
- SHA256 校验和验证
- `copyFile` 写入前检查目标路径，拒绝覆盖符号链接
- 临时文件保持 0600，仅在最终路径设置 0755
- 升级通道白名单：`upgrade_channel` 仅允许 main/dev，`releases.json` 通道名为顶层 key，每通道保留最近 5 个版本
- 平台差异化：Linux 先替换再重启（零停机）；Windows 先停服务释放 exe 句柄再替换再启动，失败恢复服务，rename 策略替换运行中 exe 并重试等待句柄释放

### 服务重载与守护进程（跨平台）

- **Windows 服务停止等待**：`Stop()` 轮询至 `Stopped` 状态，确保进程完全退出后才返回。
- **Windows 非服务模式重载**：reload 失败回退到精确实例重启（按扫描到的 `ExecutablePath` 查询并逐 PID 停止 → 等同一路径实例由守护进程拉起 → 否则保留 `-p`/`-d` 参数手动启动）；禁止 `taskkill /IM` 误停其他同名实例。进程路径查询失败时安全失败。回退白名单含 `Access is denied`，覆盖 sslctl 与 SYSTEM master 进程权限错配。
- **Windows 服务模式重载**：detector 检测到 nginx/apache 注册为 Windows 服务且 BinaryPath 与当前运行进程路径一致时，`ReloadCmd` 设为 `winsvc:<服务名>|<reload 命令>` 哨兵；`Base.ReloadService` 先走 SCM Stop+Start，SCM 失败回退执行哨兵编入的 reload 命令，再失败按白名单走进程重启。
- **守护进程优雅停止**：`RunAsService` 通过 context 通知 daemon，不依赖 SIGTERM；Windows SCM 停止立即生效。
- **SELinux 兼容**：部署后自动 `restorecon` 恢复文件安全上下文，失败返回错误。

### 备份安全

- 证书专用 `util.CertificateFile` 解析并固定软链接目标；备份记录原始路径与解析目标，保存普通文件内容。通用文件 API 和备份资产仍拒绝软链接，`computeFileHash` 只接收已解析的普通文件路径。
- 备份原子性：检测源文件并发修改（哈希校验 TOCTOU 保护），确保备份一致性。
- 备份恢复安全：`Restore` 内部备份跳过 cleanup，防止清理掉正在恢复的目标备份；`siteName` / `timestamp` 做路径穿越防护。

### 域名匹配

`matcher.MatchDomain` 是域名匹配的唯一正确实现（支持精确匹配、通配符单级子域名匹配和 IP 精确匹配），scanner 等模块应复用此函数，不要自行实现匹配逻辑。`validator.MatchDomain` 是同等语义的实现（两个包各自维护，逻辑一致）。IP 地址使用 `net.IP.Equal()` 精确比较，不走通配符逻辑。支持 IDN/Punycode 域名（`pkg/matcher`）。

### Token 安全

环境变量 Token 校验（`pkg/config/unified.go`）：

- 最小长度 32 字符（128 bit 安全性）
- 最大长度 512 字符
- 仅允许 `A-Za-z0-9-_.` 字符
