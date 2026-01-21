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
go test ./...
go test -v ./pkg/cert/
go test -cover ./...
```

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
