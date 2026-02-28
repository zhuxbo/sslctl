# 构建发布规范

## 构建命令

```bash
# 构建所有平台（从 version.json 或 git tag 读取版本号）
bash build/build.sh

# 构建指定版本
bash build/build.sh v0.0.7-beta
```

构建产物输出到 `dist/` 目录，每个平台生成二进制和 `.gz` 压缩包。

**注意**：构建目标使用 `./cmd/`（整个包），不能指定单文件 `./cmd/main.go`，否则同包的辅助文件（如 `rollback_helpers.go`）不会被编译。

---

## 交叉编译

### 支持平台

| OS | Arch | 输出文件 |
|----|------|---------|
| linux | amd64 | `sslctl-linux-amd64` |
| linux | arm64 | `sslctl-linux-arm64` |
| windows | amd64 | `sslctl-windows-amd64.exe` |

### 编译参数

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}'" \
  -o dist/sslctl-linux-amd64 ./cmd/
```

---

## 版本管理

### 版本号格式

- 正式版：`v1.0.0`, `v2.1.0`（发布到 stable 通道）
- 测试版：`v1.0.0-beta`, `v1.0.0-rc.1`（发布到 dev 通道）

通道自动判断：版本号含 `-` 则为 dev，否则为 stable。

### 版本注入

通过 `-ldflags` 注入：

```go
var (
    version   = "dev"
    buildTime = "unknown"
)
```

`version.json` 构建时自动生成，已加入 `.gitignore`，不提交到仓库。

---

## 发布流程

### 脚本概览

| 脚本 | 说明 |
|------|------|
| `build/build.sh` | 多平台交叉编译 |
| `build/release.sh` | 构建并发布到远程服务器（cn/us） |
| `build/sign-release.sh` | Ed25519 签名发布包 |
| `build/generate-keys.sh` | 生成 Ed25519 密钥对 |

### 标准发布步骤

```bash
# 1. 推送代码
git push origin dev

# 2. 构建并远程发布（自动测试 SSH → 构建 → 上传 → 更新 releases.json）
# 正式版在 main 分支上会自动创建/更新 tag 并 push
bash build/release.sh v1.0.0-beta

# 3. 可选：签名发布包
bash build/sign-release.sh --key ~/release-key.pem --dir /path/to/release --version v1.0.0-beta --key-id key-1
```

- **正式版**（不含 `-`）：在 main 分支发布时，脚本自动创建/更新 `v{版本号}` tag 并 push，无需手动操作
- **测试版**（含 `-`）：无需 tag，直接发布

### release.sh 选项

```bash
bash build/release.sh 0.0.10-beta                # 发布指定版本（必须指定）
bash build/release.sh --server cn 0.0.10-beta    # 只发布到 cn 服务器
bash build/release.sh --upload-only 0.0.10-beta  # 只上传，跳过构建（仍需版本号）
bash build/release.sh --test                     # 测试 SSH 连接
```

### 配置文件

- `build/release.conf` — 远程服务器 SSH 配置（权限应为 600）

配置文件不提交到仓库，从 `.example` 文件复制并填写。

---

## 发布服务器

| 标识 | 域名 | 说明 |
|------|------|------|
| cn | release-cn.cnssl.com | 中国区（分区解析） |
| us | release-us.cnssl.com | 美国区（分区解析） |

公网访问统一入口 `release.cnssl.com`，DNS 自动分区解析。

安装脚本中的下载地址为 `release.cnssl.com/sslctl`。

### 目录结构

```text
/sslctl/
├── releases.json          # 版本索引
├── install.sh             # 安装脚本
├── dev/                   # dev 通道
│   ├── v0.0.7-beta/
│   │   ├── sslctl-linux-amd64.gz
│   │   ├── sslctl-linux-arm64.gz
│   │   └── sslctl-windows-amd64.exe.gz
│   └── ...
├── stable/                # stable 通道
│   └── ...
├── dev-latest/            # dev 最新版符号链接
└── latest/                # stable 最新版符号链接
```

---

## GitHub Actions CI

### CI 工作流 (ci.yml)

触发条件：PR、push 到 main/dev

- golangci-lint 代码检查
- 单元测试（`go test -race ./...`）
- 三平台交叉编译验证（linux/amd64、linux/arm64、windows/amd64）

---

## 安装脚本

### install.sh

- 自动检测系统架构（amd64/arm64）
- 从 `releases.json` 获取最新版本
- 支持 `--dev`/`--stable`/`--version`/`--force` 参数
- 下载、校验、安装到 `/usr/local/bin/sslctl`
- 创建配置目录 `/opt/sslctl/`
