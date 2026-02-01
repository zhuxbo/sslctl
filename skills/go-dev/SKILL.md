# Go 开发规范

## 项目结构

```
cert-deploy/
├── cmd/
│   ├── main.go           # 统一入口
│   ├── nginx/nginx.go    # Nginx 子命令
│   └── apache/apache.go  # Apache 子命令
├── internal/
│   ├── nginx/            # Nginx 内部实现
│   └── apache/           # Apache 内部实现
├── pkg/
│   ├── api/              # API 客户端（可复用）
│   ├── cert/             # 证书处理
│   ├── config/           # 配置管理
│   └── logger/           # 日志模块
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
module github.com/example/cert-deploy

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
GOOS=linux GOARCH=amd64 go build -o cert-deploy ./cmd

# Windows
GOOS=windows GOARCH=amd64 go build -o cert-deploy.exe ./cmd
```

### 静态编译

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o cert-deploy ./cmd
```
