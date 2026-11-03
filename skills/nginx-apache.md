# Nginx/Apache 证书部署规范

按本次扫描、安装、重载或 Docker 变更定位对应章节；验证按 `skills/finish-check.md` 选择，不因阅读本文自动执行部署命令。

## Nginx

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/nginx/nginx.conf` | `/etc/nginx/sites-enabled/` |
| CentOS/RHEL | `/etc/nginx/nginx.conf` | `/etc/nginx/conf.d/` |
| 宝塔面板 | `/www/server/nginx/conf/nginx.conf` | `/www/server/panel/vhost/nginx/` |

### 证书配置

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # 推荐配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}
```

### 配置解析

站点扫描时提取的关键信息：

- `server_name`: 域名列表
- `ssl_certificate`: 证书路径
- `ssl_certificate_key`: 私钥路径
- `listen`: 端口和 SSL 标志

四个解析函数（`parseConfigFile`、`parseHTTPConfigFile`、`parseAllConfigFile`、`scanWithNginxT`）共用统一的 `parseServerBlocks()` 引擎，通过 `parseOptions` 参数化差异（如 nginx -T 模式的文件跟踪）。正则表达式在包级别编译一次。

### 相对路径解析

Web 服务器配置里的相对路径必须按具体指令区分基准，不能统一按进程 CWD 或当前被包含文件目录拼接：

- nginx 的 `ssl_certificate`、`ssl_certificate_key` 与 `include`：基准 = 实际主 `nginx.conf` 所在目录（configuration prefix）。默认布局的主配置为 `<prefix>/conf/nginx.conf`，因此 `ssl/cert.pem` 通常解析为 `<prefix>/conf/ssl/cert.pem`；若通过 `-c /custom/nginx.conf` 启动，则解析为 `/custom/ssl/cert.pem`。被 include 文件中的相对路径仍以主 `nginx.conf` 目录为准。
- nginx 的 `root` 等普通路径：基准 = nginx `prefix`（`nginx -p <path>` / 编译时 `--prefix=<path>` / CWD）。
- Apache 的证书路径、`DocumentRoot` 与 `Include`：基准 = 最终有效的 `ServerRoot`。`httpd -d <path>` 或编译时 `HTTPD_ROOT` 提供初始值，主配置中的 `ServerRoot` 指令可以覆盖；配置文件位于 `conf/` 并不意味着相对路径自动基于 `conf/`。

扫描器必须探测实际主配置路径及所需 prefix，按指令分别转成绝对路径，否则证书会被写到错位置导致**静默失败**（部署"成功"但 nginx/Apache 读的仍是旧证书）。

#### nginx 主配置与普通 prefix 探测

证书、私钥和 include 使用 `DetectNginx()` 得到的实际主配置路径，优先读取 `nginx -t` 输出，再读取 `nginx -V --conf-path`，最后检查默认位置；`nginx -T` 扫描从同一次输出记录实际主配置路径。`NewWithConfig()` 的显式路径直接作为主配置。

`root` 等普通路径的 prefix 由 `internal/nginx/scanner/scanner.go::getNginxPrefix` 按以下顺序探测：

1. `SetPrefixOverride()` 显式 override（CLI `--nginx-prefix`，仅当前进程内存生效，不写配置）
2. `nginx -V` 解析 `--prefix=`（Linux 常见发行版走这条）
3. Windows 上 `Get-CimInstance Win32_Process` 读运行进程命令行的 `-p`
4. Windows `logs/error.log` 启发式（`<nginx_dir>` vs `<nginx_dir>\conf`）
5. 全失败 → 普通相对路径保持原值，不影响已经准确解析的证书和私钥路径

#### Apache 探测链（`internal/apache/scanner/prefix.go::(*Scanner).getApachePrefix`）

1. `SetPrefixOverride()` 显式 override（CLI `--apache-prefix`）
2. 主配置 `ServerRoot` 指令或 `apachectl -S` 输出的最终有效值
3. `getServerRootFromProcessCmdline()`—运行进程命令行的 `-d` 参数（Linux 读 `/proc/<pid>/cmdline`，Windows 读 `Get-CimInstance`）
4. `Scanner.serverRoot`（`DetectApache` 已从 `httpd -V` 读到的编译期 `HTTPD_ROOT`）
5. `getServerRootFromVersion()`—再跑一次 `httpd -V` 解析 `HTTPD_ROOT`
6. Windows `logs/error.log`（以及 `error_log` 无扩展名变体）启发式
7. 全失败 → 返回 `*sslerrors.PrefixUnknownError{ServerKind: Apache}`

#### 共用约束

- nginx 证书相对路径由主配置目录确定，不依赖普通 prefix；Apache 证书相对路径在 `ServerRoot` 无法确定时触发阻断，绝对路径站点继续正常处理
- Apache 的 `PrefixUnknownError` 必须穿透 scanner adapter 与 `certops.ScanSites`（用 `errors.As` 检查），避免被另一个服务器类型的扫描结果掩盖
- CLI 层捕获 `PrefixUnknownError` 后调用 `err.RenderHint()` 打印修复指引并退出非零码
- `--nginx-prefix` 只覆盖 nginx 普通路径的 prefix，不改变证书、私钥和 include 的 configuration prefix；`--apache-prefix` 临时覆盖 Apache ServerRoot，均不持久化到 config.json
- Nginx 的 `nginx -T` 与文件扫描路径末尾都经过 `resolveSitePaths`，使用同一主配置目录语义
- Apache `ScanAll` 两条路径（`apachectl -S` 和文件扫描）末尾都经过 `resolveSitePaths`
- Apache Docker 扫描先按最终 `ServerRoot` 把证书、私钥、证书链和 `DocumentRoot` 转成容器内绝对路径，再匹配挂载并转换成宿主机路径

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/sslctl/internal/executor"

// 白名单中的命令
executor.Run("nginx -t")
executor.Run("nginx -s reload")
executor.Run("systemctl reload nginx")
```

支持的 Nginx 命令：
- `nginx -t`, `nginx -s reload`
- `systemctl reload/restart nginx`
- `service nginx reload/restart`
- `rc-service nginx reload/restart`

Windows 多套 Nginx 共存时，扫描结果必须携带本次实际使用的 `nginx.exe` 路径，setup、scan-result deploy、配置测试和重载均复用该路径，不得重新从 PATH 或“第一个同名进程”选择实例。非服务模式 reload 失败回退按精确 `ExecutablePath` 查询 PID 并逐 PID 停止，保留原命令的 `-p` 参数拉起同一实例；禁止使用 `taskkill /IM nginx.exe` 终止全部同名实例。进程路径查询失败或存在路径不可读的同名进程时安全失败，不做宽泛终止。

---

## Apache

### 配置文件位置

| 发行版 | 主配置 | 站点配置 |
|-------|-------|---------|
| Ubuntu/Debian | `/etc/apache2/apache2.conf` | `/etc/apache2/sites-enabled/` |
| CentOS/RHEL | `/etc/httpd/conf/httpd.conf` | `/etc/httpd/conf.d/` |
| 宝塔面板 | `/www/server/apache/conf/httpd.conf` | `/www/server/panel/vhost/apache/` |

### 证书配置

```apache
<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    SSLCertificateChainFile /path/to/chain.pem

    # 推荐配置
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
</VirtualHost>
```

> **ServerName 端口/scheme 剥离**：Apache `ServerName` 语法为 `[scheme://]fqdn[:port]`，`httpd-ssl.conf` 默认模板常写成 `ServerName www.example.com:443`。扫描器（`parseConfigFile`/`parseHTTPConfigFile`/`parseAllConfigFile`、`apachectl -S` 富化路径 `enrichSiteFromConfig`、Docker 扫描器）与安装器（`installer`）在解析 `ServerName`/`ServerAlias`、去引号后统一调用 `matcher.StripPort()` 剥离 scheme 与端口，得到纯域名再做匹配与证书目录命名。否则带端口的 `ServerName` 会导致域名匹配失败（"未找到可绑定的站点"），且 `:` 在 Windows 上是非法路径字符，会污染 `certs/{server_name}/` 目录创建。Nginx 的 `server_name` 与 `listen` 端口分开，无此问题。

### 重载服务

所有重载命令通过 `internal/executor` 包执行，使用白名单机制：

```go
import "github.com/zhuxbo/sslctl/internal/executor"

executor.Run("apachectl -t")
executor.Run("apachectl graceful")
executor.Run("systemctl reload apache2")
```

支持的 Apache 命令：
- `apachectl -t/graceful/restart`
- `apache2ctl -t/graceful/restart`
- `httpd -t`
- `systemctl reload/restart apache2/httpd`
- `service apache2/httpd reload/restart`
- `rc-service apache2/httpd reload/restart`

Linux 容器中通过 SIGUSR1 触发 Apache graceful reload 时，发送信号后必须等待 master 创建新一代 worker 才能返回；多绑定部署不得在上一轮仍读取配置时继续改写下一组证书/私钥，避免 Apache 读到瞬时错配后退出。

---

## 证书文件

### 文件类型

| 文件 | 内容 | 用途 |
|-----|------|------|
| `cert.pem` | 服务器证书 | 主证书 |
| `privkey.pem` | 私钥 | 解密 |
| `chain.pem` | 中间证书链 | 验证链 |
| `fullchain.pem` | 证书 + 中间链 | Nginx 推荐 |

### 默认存储路径

```
/opt/sslctl/certs/{domain}/
├── cert.pem
├── privkey.pem
├── chain.pem
└── fullchain.pem
```

### 权限设置

```bash
chmod 644 cert.pem chain.pem fullchain.pem
chmod 600 privkey.pem
chown root:root /opt/sslctl/certs/
```

---

## 部署流程

1. 从 API 获取证书（PEM 格式）
2. 保存证书文件到本地
3. 更新 Web 服务器配置（如需要）
4. 测试配置语法
5. 重载服务
6. 验证证书生效
7. 发送回调通知

### 证书写入顺序与校验

- **先写私钥后写证书**（nginx/apache deployer）：中途失败不留下"新证书 + 旧私钥"的错配状态。
- **中间证书校验**：API 部署必须包含中间证书（缺失报错、等待下一周期重试）；`deploy local` 的 `--ca` 参数仍可选。

### 回滚

部署前备份旧证书：

```bash
/opt/sslctl/backup/{domain}/{timestamp}/
├── cert.pem
├── privkey.pem
└── ...
```

所有部署入口（setup/deploy/续签）覆盖站点证书前先备份、失败自动回滚；证书、私钥和独立证书链的软链接保留不变，写入真实目标。备份前 Prepare 固定目标，自动回滚复用同一部署器；链接改向时中止，不覆盖续签新目标。

---

## SSL 配置自动安装（setup）

setup 流程为**未启用 SSL** 的站点安装 HTTPS 配置（需用户确认），备份原配置、配置测试失败自动回滚。

- 支持 `server\n{` 多行格式；SSL 指令仅插入 server 块顶层，兼容 `root` 写在 `location` 内的 SPA / 反代配置。
- **nginx**：先按 nginx 自身的名字优先级选出服务目标站点的**唯一** server 块（`selectTargetBlock`：精确名优先于通配符名），再只向该块注入。匹配必须是单向的——"块的 `server_name` 覆盖目标域名"，反向不成立；双向匹配会把目标站点的证书一并写进 `*.example.com` 块，使通配符站点被换上只覆盖单域名的证书、其余子域名 HTTPS 证书不匹配。同优先级内已配 SSL 的块优先选中，使常见的"`:80` 跳转块 + `:443 ssl` 块"同名布局判定为"已有 HTTPS"而不产生 duplicate listen 443。"已配置 SSL"检测（`hasSSLConfig`）与注入基于同一选块结果，两趟解析共用 `scanServerBlocks` 的块编号，不各自重复判定。
- **Apache**：生成 `:443` VirtualHost 时按地址 token 精确替换端口，仅端口恰为 80 才换，`*:8080` 等自定义端口不受污染。

### 安装器失败语义

- SSL 配置安装失败的绑定标记 `Enabled=false` 后跳过部署并计入失败（单证书与批量模式一致），不误报"部署成功"。
- nginx 安装器在非 80 端口 / 无可处理 HTTP server 块时返回明确错误而非静默跳过，与 Apache 一致；安装器"无可注入块"必须报错而非返回 `Modified=false`。判定只看**选中的目标块**是否已配 SSL：同域族的其他块（如通配符块）已有 SSL 不得让目标站点短路成"无需安装"，否则 setup/deploy 会误以为无需安装继续部署并报成功，而目标站点 HTTPS 实际未生效。

## Docker 站点部署（setup/deploy）

- volume 模式写入宿主机挂载路径（`HostCertPath`）；Nginx copy 模式写入容器内已有证书/私钥绝对路径，先持久备份并暂存两份新文件，再替换、测试和重载，失败恢复旧文件。Apache copy 不支持。
- test/reload 使用容器化命令：`docker exec <容器> nginx -t` / `nginx -s reload`（apache 用 `apachectl`）；executor 放行 `docker exec <容器> <固定命令>`（容器名字符白名单 + 内层命令白名单）；命令构建方（`webserver.DetectDockerCommands`）用 `executor.IsValidDockerContainerName` 前置校验容器名，非法即返回空命令，不拼出必然被执行期白名单拒绝的命令（那样错误指向白名单，掩盖真实原因）；base deployer 对 docker exec 命令跳过宿主机 SIGUSR1 / 进程重启回退。
- `config.ValidateDockerBinding` 按 volume/copy 模式校验服务器类型、容器、路径及 test/reload 命令；不完整或不支持的绑定返回明确错误并计为失败。copy 限制及旧绑定修复见根 `README.md` 的 Docker 部署与升级说明。
- Apache 容器内仅 `httpd`/`apache2ctl` 时 reload 明确报错，自动探测待后续支持。
- **挂载路径精确匹配**：Docker 挂载路径按精确匹配，防止 `/etc/nginx` 匹配到 `/etc/nginx-backup`。

## 扫描防护

Nginx / Apache / Docker 扫描器均有文件数量限制 1000 + 目录深度限制 100 + 单文件大小限制 10MB，防止异常配置树拖垮扫描。

---

## 常见问题

### 证书链不完整

症状：浏览器报证书错误，但证书本身有效

解决：确保 `fullchain.pem` 包含中间证书

**Nginx fullchain 拼接逻辑**：仅当 intermediate 非空时拼接（`cert + "\n" + intermediate`），防止空中间证书导致尾部多余换行。

**通配符匹配**：统一使用 `pkg/matcher.MatchDomain`（支持精确匹配和单级子域名通配符匹配，如 `*.example.com` 匹配 `www.example.com` 但不匹配 `a.b.example.com`）。

### 权限问题

症状：Nginx/Apache 无法读取证书

解决：检查文件权限，私钥应为 600

### 配置语法错误

症状：重载失败

解决：先执行 `nginx -t` 或 `apachectl configtest`
