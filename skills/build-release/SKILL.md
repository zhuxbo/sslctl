# 构建发布规范

## 构建命令

```bash
# 本地构建
make build

# 交叉编译所有平台
make build-all

# 清理
make clean
```

---

## Makefile 目标

| 目标 | 说明 |
|------|------|
| `build` | 构建当前平台二进制 |
| `build-all` | 构建所有平台 |
| `clean` | 清理构建产物 |
| `test` | 运行测试 |

---

## 交叉编译

### 支持平台

| OS | Arch | 输出文件 |
|----|------|---------|
| linux | amd64 | `cert-deploy-linux-amd64` |
| linux | arm64 | `cert-deploy-linux-arm64` |
| darwin | amd64 | `cert-deploy-darwin-amd64` |
| darwin | arm64 | `cert-deploy-darwin-arm64` |
| windows | amd64 | `cert-deploy-windows-amd64.exe` |

### 编译参数

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X main.version=${VERSION}" \
  -o dist/cert-deploy-linux-amd64 ./cmd
```

---

## 版本管理

### 版本号格式

- 正式版：`1.0.0`, `2.1.0`
- 测试版：`1.0.0-beta`, `1.0.0-rc.1`

### 版本注入

通过 `-ldflags` 注入：

```go
var (
    version   = "dev"
    buildTime = "unknown"
)
```

---

## GitHub Actions

### CI 工作流 (ci.yml)

触发条件：PR、push 到 main/dev

- 代码检查
- 构建测试
- 单元测试

### Release 工作流 (release.yml)

触发条件：推送 `v*` tag

- 构建所有平台
- 创建 GitHub Release
- 上传构建产物

---

## 发布流程

1. 更新版本号
2. 创建 tag：`git tag v1.0.0`
3. 推送 tag：`git push origin v1.0.0`
4. GitHub Actions 自动构建发布

### 手动发布

```bash
# 构建
make build-all

# 打包
cd dist && tar -czf cert-deploy-v1.0.0-linux-amd64.tar.gz cert-deploy-linux-amd64
```

---

## 安装脚本

### install.sh

- 检测系统架构
- 下载对应二进制
- 安装到 `/usr/local/bin`
- 创建配置目录
- 设置权限

### install.ps1

- Windows PowerShell 安装脚本
- 下载 Windows 二进制
- 添加到 PATH
