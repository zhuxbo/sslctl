# Go 开发规范

## 项目结构

```
sslctl/
├── cmd/
│   ├── main.go           # 统一入口
│   ├── setup/            # 一键部署命令
│   ├── daemon/           # 守护进程
│   └── deploy/           # 证书部署
├── internal/
│   ├── nginx/            # Nginx 扫描/部署
│   ├── apache/           # Apache 扫描/部署
│   └── executor/         # 统一命令执行器（白名单）
├── pkg/
│   ├── certops/          # 证书操作服务层（含私钥管理）
│   ├── config/           # 配置管理（深拷贝并发安全）
│   ├── fetcher/          # API 客户端（含 SSRF 防护）
│   ├── backup/           # 备份管理（原子性检查）
│   ├── logger/           # 日志模块（敏感信息过滤）
│   ├── matcher/          # 域名匹配
│   ├── validator/        # 证书验证
│   ├── service/          # 系统服务管理
│   ├── upgrade/          # 升级模块（版本检查/下载/安装）
│   └── util/             # 工具函数（文件操作/权限检查）
└── go.mod
```

---

## 代码风格

### 包命名

- 小写单词，不使用下划线或驼峰
- 包名应与目录名一致
- 避免使用 `common`、`util` 等通用名称

### 错误处理

```go
// 使用 errors.New 或 fmt.Errorf
if err != nil {
    return fmt.Errorf("failed to load config: %w", err)
}

// 不要忽略错误
result, _ := doSomething() // 错误
result, err := doSomething()
if err != nil {
    // 处理错误
}
```

### 日志

```go
// 使用 pkg/logger
logger.Info("starting deployment for site: %s", siteName)
logger.Debug("loaded config: %+v", config)
logger.Error("failed to reload nginx: %v", err)
```

---

## CLI 架构

### 子命令模式

```go
// cmd/main.go
switch cmd {
case "nginx":
    nginx.Run(subArgs, version, buildTime, debug)
case "apache":
    apache.Run(subArgs, version, buildTime, debug)
}
```

### 全局标志

- `--debug`: 启用 debug 模式，输出详细日志
- `--version`: 显示版本信息

### 子命令标志

每个子命令使用独立的 `flag.FlagSet`：

```go
func Run(args []string, version, buildTime string, debug bool) {
    fs := flag.NewFlagSet("nginx", flag.ExitOnError)
    site := fs.String("site", "", "Site name")
    fs.Parse(args)
}
```

---

## 依赖管理

### go.mod

```go
module github.com/example/sslctl

go 1.21

require (
    golang.org/x/crypto v0.17.0
)
```

### 添加依赖

```bash
go get github.com/example/package
go mod tidy
```

---

## 测试

### 单元测试

```go
// foo_test.go
func TestFoo(t *testing.T) {
    result := Foo()
    if result != expected {
        t.Errorf("expected %v, got %v", expected, result)
    }
}
```

### 运行测试

```bash
go test ./...                            # 运行全部测试
go test -v ./pkg/cert/                   # 运行指定包测试
go test -cover ./...                     # 显示覆盖率
go test -coverprofile=coverage.out ./... # 生成覆盖率文件
go tool cover -func=coverage.out         # 查看各函数覆盖率
go tool cover -html=coverage.out         # 生成 HTML 报告
```

### 测试覆盖率

| 包             | 覆盖率 |
|----------------|--------|
| pkg/matcher    | 96.8%  |
| pkg/csr        | 93.5%  |
| pkg/backup     | 87.2%  |
| pkg/util       | 84.1%  |
| pkg/fetcher    | 80.2%  |
| pkg/validator  | 69.7%  |
| pkg/config     | 33.8%  |

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

# Windows
GOOS=windows GOARCH=amd64 go build -o sslctl.exe ./cmd
```

### 静态编译

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o sslctl ./cmd
```

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

白名单命令定义在 `executor.AllowedCommands`，新增命令需要审核。

### 配置并发安全

`ConfigManager.Load()` 返回深拷贝，修改不影响内部缓存：

```go
cfg, _ := cm.Load()
cfg.API.Token = "new-token"  // 仅修改副本

// 需要显式保存
cm.Save(cfg)
// 或使用专用方法
cm.SetAPI(config.APIConfig{...})
```

### 日志脱敏

`pkg/logger` 自动过滤敏感信息：

- PEM 私钥 → `***REDACTED PRIVATE KEY***`
- Bearer Token → `Bearer ***REDACTED***`
- password/secret/token 参数 → `param=***REDACTED***`

### SSRF 防护

`pkg/fetcher` 阻止访问：

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
- SHA256 校验和验证

### Token 安全

环境变量 Token 校验（`pkg/config/unified.go`）：

- 最小长度 32 字符（128 bit 安全性）
- 最大长度 512 字符
- 仅允许 `A-Za-z0-9-_.` 字符
