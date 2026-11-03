# sslctl

SSL 证书部署工具，支持 Nginx、Apache，支持 Docker 容器。

## 安装

```bash
# 安装最新稳定版（参数传域名，脚本自动拼接 https://<host>/sslctl）
curl -fsSL https://release.example.com/sslctl/install.sh | sudo bash -s -- release.example.com

# 安装测试版
curl -fsSL https://release.example.com/sslctl/install.sh | sudo bash -s -- release.example.com --dev

# 安装指定版本
curl -fsSL https://release.example.com/sslctl/install.sh | sudo bash -s -- release.example.com --version 1.0.0

# 强制重新安装
curl -fsSL https://release.example.com/sslctl/install.sh | sudo bash -s -- release.example.com --force
```

Windows (PowerShell 管理员):

```powershell
# 安装最新稳定版（一行命令）
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile("https://release.example.com/sslctl/install.ps1", "$pwd\install.ps1"); powershell -ExecutionPolicy Bypass -File install.ps1

# 或者分步执行
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
(New-Object Net.WebClient).DownloadFile("https://release.example.com/sslctl/install.ps1", "$pwd\install.ps1")
powershell -ExecutionPolicy Bypass -File install.ps1 -ReleaseHost release.example.com

# 更多参数
powershell -ExecutionPolicy Bypass -File install.ps1 -ReleaseHost release.example.com -Dev           # 安装测试版
powershell -ExecutionPolicy Bypass -File install.ps1 -ReleaseHost release.example.com -Version 1.0.0 # 安装指定版本
powershell -ExecutionPolicy Bypass -File install.ps1 -ReleaseHost release.example.com -Force         # 强制重新安装
```

> **注意**：
> - 第一行 `SecurityProtocol` 用于启用 TLS 1.2（PowerShell 5.1 默认未启用），Server 2019+ 可省略
> - 使用 `WebClient.DownloadFile` 而非 `irm -OutFile`，避免 PowerShell 5.1 编码转换导致中文乱码
> - `-ExecutionPolicy Bypass` 绕过脚本签名限制，仅影响当前执行
> - **Windows Server 2012 R2 等老系统若 PowerShell 中看到空白或中文乱码**：这是 PowerShell 默认 Raster Font（点阵字体）无法渲染 CJK 字符导致的，改字体即可修复——右键 PowerShell 窗口左上角图标 → 默认值 → 字体 → 选 Consolas 或 Lucida Console，关闭后重新打开窗口。cmd.exe 一般不受影响

手动安装: 从 [Releases](https://release.example.com/sslctl/releases.json) 下载解压，重命名为 `sslctl`。

## 使用

### 一键部署（推荐）

```bash
sslctl setup --url https://api.example.com --token your-token --order 12345
```

自动完成：

1. 检测 Web 服务器（Nginx/Apache）
2. 获取证书信息并匹配站点
3. 为未启用 SSL 的站点安装 HTTPS 配置（需确认，备份原配置，失败自动回滚）
4. 部署证书到匹配的站点
5. 安装守护服务（自动续签）

选项：

- `--local-key`: 使用本机提交
- `--key <path>`: 私钥文件路径（隐含 `--local-key`）
- `--file-validation`: 启用文件验证（隐含 `--local-key`）
- `--webroot <path>`: 文件验证的 Web 根目录（隐含 `--file-validation`）
- `--yes`: 跳过确认提示
- `--no-service`: 不安装守护服务

### 扫描站点

```bash
sslctl scan              # 扫描所有站点
sslctl scan --ssl-only   # 仅扫描 SSL 站点
```

### 本地证书部署

```bash
# 部署本地证书文件到站点
sslctl deploy local --cert cert.pem --key key.pem --site example.com

# 带 CA 证书链部署（Apache 配置了 SSLCertificateChainFile 时需要）
sslctl deploy local --cert cert.pem --key key.pem --ca chain.pem --site apache-site.com
```

选项：

- `--cert`: 证书文件路径（必需）
- `--key`: 私钥文件路径（必需）
- `--ca`: CA 证书链文件路径（Apache 配置了证书链路径时必需）
- `--site`: 目标站点名称（必需，需先运行 `sslctl scan`）

站点信息优先从 `config.json` 获取，回退到 `scan-result.json`。

### 证书回滚

```bash
sslctl rollback --site example.com              # 回滚到最新备份
sslctl rollback --site example.com --list       # 查看备份列表
sslctl rollback --site example.com --version 20240101-120000  # 回滚到指定版本
```

回滚前会自动备份当前文件。支持宿主机证书、私钥及 Apache 独立证书链的软链接（包括 Let’s Encrypt `live/` → `archive/` 布局）：备份保存实际内容，部署和回滚原子替换当前真实文件，保留链接及其指向，不修改 Certbot 续签配置。

若操作期间续签程序切换链接，或回滚时链接已指向与备份记录不同的版本，将报错中止，避免覆盖新版本；旧备份没有链接目标记录时不允许恢复到软链接。悬空链接、循环链接和特殊文件不支持。证书及私钥仍是逐文件写入，外部续签应与 sslctl 错开执行。

### 解除站点或证书管理

```bash
sslctl cleanup --site example.com              # 解除指定站点管理
sslctl cleanup --cert example.com-12345        # 解除指定证书管理
sslctl cleanup --site example.com --yes        # 跳过交互确认
sslctl cleanup --list                          # 列出全部受管证书和站点绑定
```

`--list` 是只读操作，单独使用时列出所有证书记录（包括禁用和重复记录）以及每一条站点绑定。执行清理时，`--site` 与 `--cert` 必须且只能指定一个。按站点清理会移除该站点绑定及相关失败、陈旧状态；如果证书因此失去最后一个绑定，该证书管理记录也会删除。按证书清理会移除证书管理记录、关联站点的内部备份及 pending 私钥。

清理只解除 sslctl 的管理关系，不修改 Web 服务器配置，也不删除当前部署的证书、私钥、证书链或外部验证文件；即使在线证书位于 `/opt/sslctl/certs/` 下也会保留。命令需要 root/管理员权限，且与 setup、deploy、daemon 续签共用互斥锁。

**其他命令:**

```bash
sslctl deploy --cert example.com-12345                     # 部署指定证书
sslctl deploy --cert example.com-12345 --site example.com  # 绑定站点并部署
sslctl deploy --all                                  # 部署所有证书
sslctl status                                        # 查看服务状态（含证书过期详情）
sslctl upgrade                                       # 升级到最新版本
sslctl upgrade --check                               # 检查更新
sslctl service repair                                # 修复 systemd 服务
sslctl cleanup --site example.com                    # 解除指定站点管理
sslctl cleanup --cert example.com-12345              # 解除指定证书管理
sslctl cleanup --list                                # 列出全部受管证书和站点绑定
sslctl --debug scan                                  # 调试模式
sslctl uninstall                                     # 卸载（交互确认是否清理配置）
```

## 平台支持

| 平台             | Nginx | Apache | 服务管理        |
| ---------------- | ----- | ------ | --------------- |
| Linux (systemd)  | ✅    | ✅     | systemd         |
| Linux (OpenRC)   | ✅    | ✅     | OpenRC          |
| Linux (SysVinit) | ✅    | ✅     | SysVinit        |
| Windows          | ✅    | ✅     | Windows Service |

CI 覆盖 linux/amd64、linux/arm64、windows/amd64 三平台交叉编译验证。

开发与发布的权威入口：项目规则见 `AGENTS.md`，任务路由见 `skills/SKILL.md`；构建/签名契约见 `skills/build-release.md`，远程发布与中断恢复见 `skills/remote-release.md`，分级完成检查与规则自进化见 `skills/finish-check.md`。脚本参数速查见 `build/README.md`。发布规则不在 README 中重复维护。

支持自动检测 Docker 容器 Nginx；setup/deploy/续签支持宿主机挂载卷和已有 HTTPS 站点的 copy 模式。

## Debug 模式

```bash
# 启用调试模式
sslctl --debug deploy --cert <cert_name> --site example.com
```

- 详细日志输出（请求/响应、配置解析、文件操作）
- 日志写入文件：`/opt/sslctl/logs/debug/`

## 工作目录

```
/opt/sslctl/
├── config.json     # 统一配置文件
├── certs/          # 证书存储
│   └── {server_name}/
│       ├── cert.pem
│       └── key.pem
├── pending-keys/   # 待确认私钥（本机提交）
├── logs/           # 日志文件
├── backup/         # 证书备份
└── scan-result.json  # 扫描结果缓存
```

## 安全特性

- **HTTPS 强制**：远程 API 必须使用 HTTPS（仅 localhost 允许 HTTP）
- **SSRF 防护**：阻止访问内网 IP（10/172.16/192.168）、未指定地址（0.0.0.0/::）和云元数据地址（169.254.169.254）
- **DNS Rebinding 防护**：自定义 DialContext 在 TCP 连接时二次校验目标 IP
- **命令白名单 + 超时**：统一的 executor 包，只允许预定义命令，默认 30 秒超时，支持 Context 取消
- **日志脱敏**：自动过滤私钥、Bearer Token、Basic Auth、JSON 敏感字段、URL 参数；错误消息使用相对路径
- **并发安全**：配置读取返回深拷贝，mtime + SHA256 哈希检测外部修改自动重载，防止并发修改污染
- **配置保存安全**：拒绝写入符号链接目标，防止任意文件覆盖
- **路径验证**：Docker 容器路径参数严格验证，防止命令注入；挂载路径精确匹配防止误匹配
- **备份 TOCTOU 保护**：使用文件哈希校验检测并发修改，确保备份一致性；恢复时内部备份跳过清理，防止目标备份被删除；证书软链接固定真实目标并保留链接，目标变化时中止；`siteName`/`timestamp` 路径穿越防护
- **扫描防护**：Nginx/Apache/Docker 扫描器文件数量限制（1000）+ 深度限制（100）+ 文件大小限制（10MB），防止恶意配置耗尽资源
- **升级安全**：gzip 解压大小限制，防止 gzip 炸弹攻击；Ed25519 数字签名验证（按文件名索引签名，密钥环支持多公钥 + key ID，空密钥环拒绝验证，已配置公钥时拒绝未签名版本防止降级攻击），防止供应链攻击；先停服务再替换二进制，失败时恢复服务；Windows 上 rename 策略替换运行中 exe；安装时符号链接防护；临时文件保持 0600 仅在最终路径设置 0755；通道白名单防止路径遍历；密钥不匹配时提示用 install.sh 重装
- **临时目录安全**：临时目录权限设置为 0700
- **日志目录安全**：日志目录权限设置为 0700
- **配置文件锁**：文件锁在操作前获取，确保原子性和一致性
- **部署回滚**：部署失败自动回滚到备份（通过抽象层接口），回滚失败时提供手动恢复命令
- **私钥保护**：本机提交下，新私钥先保存到临时位置，签发成功后再替换；私钥写入使用临时文件 + 原子替换（0600）
- **SELinux 兼容**：部署后自动恢复文件安全上下文（restorecon），非 SELinux 环境静默跳过
- **IDN/Punycode 支持**：域名匹配器自动转换国际化域名
- **证书过期告警**：守护进程周期检查证书过期时间，7 天/13 天阈值输出告警日志
- **环境变量**：支持通过环境变量配置敏感信息，避免明文存储

## 环境变量

| 变量                 | 说明                                              |
| -------------------- | ------------------------------------------------- |
| `SSLCTL_RELEASE_URL` | Release URL（安装脚本使用，完整 URL 含 https://） |
| `SSLCTL_API_TOKEN`   | API Token（覆盖所有证书的 API 配置）              |
| `SSLCTL_API_URL`     | API URL（覆盖所有证书的 API 配置）                |
| `SSLCTL_LOG_FORMAT`  | 日志格式：`json` 启用 JSON 输出                   |

使用示例：

```bash
export SSLCTL_API_TOKEN="your-secret-token"
sslctl status
```

## 配置结构

`config.json`:

```json
{
  "release_url": "https://release.example.com/sslctl",
  "schedule": {
    "renew_before_days": 14,
    "renew_mode": "pull"
  },
  "certificates": [
    {
      "cert_name": "example.com-12345",
      "order_id": 12345,
      "enabled": true,
      "domains": ["*.example.com", "example.com"],
      "api": {
        "url": "https://api.example.com",
        "token": "your-deploy-token"
      },
      "renew_mode": "pull",
      "bindings": [
        {
          "server_name": "www.example.com",
          "server_type": "nginx",
          "enabled": true,
          "paths": {
            "certificate": "/opt/sslctl/certs/www.example.com/cert.pem",
            "private_key": "/opt/sslctl/certs/www.example.com/key.pem"
          }
        }
      ]
    }
  ]
}
```

> **注意**：API 配置在证书级别，每个证书可以使用不同的 API 来源。

### schedule 字段说明

| 字段                   | 类型   | 默认值            | 说明                                   |
| ---------------------- | ------ | ----------------- | -------------------------------------- |
| `renew_before_days`    | int    | 14                | 提前续期天数，上限 30，0 使用默认值 14 |
| `renew_mode`           | string | `pull`            | 全局续签模式，证书级别可覆盖           |

### config.json.lock

保存配置时自动创建的文件锁（flock），防止多个 sslctl 进程同时写入 `config.json` 导致数据损坏。无需手动管理。

## 续签模式

两种模式统一：`renew_before_days` 默认 14 天、上限 30 天，由服务端下发并在每次 API 交互后回写。

| 模式    | 说明                             | 默认续签阈值 |
| ------- | -------------------------------- | ------------ |
| `local` | 本机提交，本地生成私钥和 CSR     | 14 天        |
| `pull`  | 自动签发，从服务端拉取已签发证书 | 14 天        |

- **本机提交**：由本地控制私钥，通过 POST 部署接口提交本地生成的 CSR
- **自动签发**：查询已签发的证书直接部署
- **定时检查**：每天一次，随机选择明天 09:00~23:59 的时间点执行；多证书续签按证书数动态分散 5~120 秒，整轮预算上限 600 秒
- **已过期证书**不再触发续签

### 自动停机与人工介入

自动部署遇到"重试也无法自愈"的情况时会主动停下来，而不是无限重试或误报成功。
以下状态都可以用 `sslctl status` 查看，也会在守护进程日志中告警。

| 状态       | 触发条件                                                   | 影响                                                         | 恢复方式                                     |
| ---------- | ---------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------- |
| **阻断**   | 证书已启用，但没有任何启用的站点绑定                       | 完全退出自动流程：不发起 API 请求、不部署、不上报回调         | 恢复绑定或重新 `setup` 后自动解除             |
| **停机**   | 准备新尝试时发现对应计数已达到 10                          | 不启动第 11 次尝试，进入静默停机                             | 修复问题后执行一次 `sslctl deploy`            |
| **重试中** | 部分站点部署失败但属于可修复错误                           | 保留绑定，守护进程每天重试一次并上报一次失败回调             | 修好站点后等待自动重试，或手动 `sslctl deploy` |
| **陈旧**   | 某站点重试 10 轮仍失败                                     | 停止重试该站点，每天告警；**证书本身继续正常续签**            | 修复站点后执行 `sslctl deploy`                |

几点需要留意：

- 对某个站点执行 `sslctl deploy local` 会把该站点从原有 API 证书上摘走。若原证书因此再无启用绑定，它会**当场转入阻断状态**。
- 阻断发生时如果证书正处于签发中，在途订单与待转正的私钥会保留到人工处理，日志会额外标注。
- `sslctl deploy` 成功后会清除停机状态与相关尝试计数，并上报一次部署结果。**不要把它挂进 cron**——那会反复复位停机保护，绕过尝试次数上限的约束。
- `sslctl setup` 对每个有资格的证书逐一尝试上报部署结果；本轮回调熔断后允许余下结果缺行。因缺少私钥而跳过的证书不上报，也不再写入配置。
- 配置中出现同名证书条目时会每轮告警并提示人工处理，自动改名遇到重名会放弃改名以免覆盖健康条目。

## API 接口

| 方法 | 路径                       | 说明                            |
| ---- | -------------------------- | ------------------------------- |
| GET  | `/api/deploy?order=xxx`    | 查询证书（订单 ID，批量用逗号分隔，上限 100） |
| POST | `/api/deploy`              | 更新/续费证书（需要 order_id）  |
| POST | `/api/deploy/callback`     | 部署结果回调                    |

认证方式：`Authorization: Bearer {deploy_token}`

## Docker 支持

Nginx 容器扫描直接按已发现的容器 ID 执行 `docker exec`，包括由 Compose 创建的容器，无需安装独立的 `docker-compose` 命令，也不依赖原始 Compose 文件。

```bash
sslctl scan              # 自动检测本地或 Docker
sslctl deploy --cert <cert_name> --site example.com  # 根据配置选择部署方式
```

Docker 站点绑定由通用路径、重载命令和 `docker` 字段共同描述：

```json
{
  "server_name": "example.com",
  "server_type": "docker-nginx",
  "enabled": true,
  "paths": {
    "certificate": "/opt/app/certs/cert.pem",
    "private_key": "/opt/app/certs/key.pem"
  },
  "reload": {
    "test_command": "docker exec nginx nginx -t",
    "reload_command": "docker exec nginx nginx -s reload"
  },
  "docker": {
    "container_name": "nginx",
    "deploy_mode": "volume"
  }
}
```

配置支持 `volume`（写入已验证的宿主机挂载路径）和 `copy`（通过 Docker 在容器内读写）。扫描优先选择可映射宿主机路径的 `volume`；Nginx 证书未挂载到宿主机或使用命名卷时，可使用 `copy`。

`copy` 模式的 `paths.certificate` 和 `paths.private_key` 必须是容器内已有证书、私钥的绝对路径；部署时持久备份原文件，两份新文件暂存成功后替换，再执行容器内 `nginx -t` 和 `nginx -s reload`。失败会恢复旧文件并重新检查、重载。API 不返回私钥时，从容器读取现有私钥；本地 CSR 续签也支持 pending 私钥。`sslctl rollback --site <站点>` 可以恢复容器备份。

第一阶段仅支持已有 HTTPS 配置的 Nginx，要求容器具有 `sh`、`stat`、`head`、`mktemp` 等标准工具，并允许通过 Docker 以 root 执行文件操作。证书文件及父目录不能是符号链接；只读、单文件和 tmpfs 挂载不支持 copy。暂不支持 Apache copy、新建容器 HTTPS 配置或容器内文件验证，请使用 DNS 委托验证。

容器可写层中的证书会随容器删除而消失；重建容器后需恢复原 HTTPS 文件布局并重新部署。命名卷中的文件可随卷保留，sslctl 不自动修复容器重建。

### 存量 Docker 绑定升级说明

重新执行 `sslctl setup` 可补齐容器名称、部署模式和容器内检查/重载命令。旧配置中若 copy 路径曾被写成宿主机路径，应重新扫描；缺少容器信息或命令的绑定会明确失败。

已知项：Apache 容器内若仅有 `httpd`/`apache2ctl` 而无 `apachectl`，容器重载会明确报错（不会误报成功），容器内命令自动探测待后续版本支持。

## 开发测试

```bash
# 运行单元测试
go test -v ./...

# 运行测试并查看覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total

# Linux 发行版服务管理测试（需要 Docker）
bash build/test-linux.sh
```

### 容器端到端测试

```bash
# 运行完整 E2E 门禁（常规矩阵 + Docker-in-Docker 扫描/部署）
bash docker/test/scripts/run-tests.sh

# 指定发行版和服务器
bash docker/test/scripts/run-tests.sh --distro ubuntu --server nginx

# 指定测试文件（不含 .bats 后缀）
bash docker/test/scripts/run-tests.sh --test scan

# 仅运行 Docker-in-Docker 部署测试
bash docker/test/scripts/run-tests.sh --test docker-deploy

# 调试时跳过 Docker-in-Docker（不属于完整门禁）
bash docker/test/scripts/run-tests.sh --no-dind

# 跳过构建（已构建过镜像）
bash docker/test/scripts/run-tests.sh --no-build
```

测试矩阵：Nginx/Apache × Ubuntu/Debian/Alpine/Rocky + DinD，使用 Mock API 离线运行。无参数命令默认同时执行常规矩阵和 DinD 测试。

测试用例：setup、deploy、deploy-local、renew-local、scan、status、rollback、daemon、upgrade、uninstall、docker-scan、docker-deploy（共 12 个 bats 文件；docker-* 在 DinD 容器中运行，uninstall 自动排最后执行）。

## License

MIT
