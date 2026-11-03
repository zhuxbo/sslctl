# 构建、签名与发布 bundle

本资源只定义 sslctl 的平台构建、正式资产、签名和 bundle 契约。发布分支、GitHub、远程节点与恢复编排只在 `skills/remote-release.md` 维护；上位语义以 `deploy-spec.md` 第 8 节为准。

## 平台与正式资产

sslctl 使用 Go 1.26、`CGO_ENABLED=0` 和 `./cmd/` 包交叉编译。规范正式资产集合固定为：

| 目标 | 公开文件名 |
| --- | --- |
| linux/amd64 | `sslctl-linux-amd64.gz` |
| linux/arm64 | `sslctl-linux-arm64.gz` |
| windows/amd64 | `sslctl-windows-amd64.exe.gz` |

三份 gzip 是发布节点与 GitHub Release 必须字节一致的完整正式资产集合。`deploy/install.sh`、`deploy/install.ps1` 是发布服务器根入口，随服务器部署同步但不属于版本资产；本仓没有 GitHub-only 附加资产，也不发布独立 `.sha256` 文件。

## 确定性构建

```bash
bash build/build.sh <x.y.z[-prerelease]> <output-dir>
```

- 版本参数必须是不带 `v` 的有效 SemVer；脚本把该值原样注入 `main.version`，运行 `--version` 必须可见。
- `build.sh` 从 `go.mod` 的 `toolchain go1.26.x` 读取并强制使用精确工具链；`build/release.sh prepare` 先捕获稳定工作区快照，再从该只读语义快照构建。main 使用目标 commit 的提交时间设置 `SOURCE_DATE_EPOCH`；固定时间、`-trimpath`、`-buildvcs=false`、无时间戳 gzip 保证同提交、同工具链的产物可重建验证。
- 正式发布仍只允许构建一次；可重建性用于审计，tag 创建后的恢复禁止重建。
- 输出目录必须由调用者显式指定。发布流程不得依赖或混入仓库 `dist/` 的旧文件。

## SHA256 与 Ed25519

每份 gzip 先计算 `sha256:<hex>`，再使用 `build/sign-release.sh` 对 gzip 原始字节生成 `ed25519:<key-id>:<base64>`。`checksums` 与 `signatures` 都以公开文件名为 key。生成 manifest 后再写入同 key 的 detached `manifest.sig`，其签名覆盖 manifest 完整字节，从而把版本、通道、source commit、资产集合、SHA256 和资产签名绑定为一个不可重包装的 bundle。

签名密钥由 `build/release.conf` 的 `SIGN_KEY`、`SIGN_KEY_ID` 提供；正式发布和 dev 发布都必须签名，缺少密钥或签名失败即停止。签名脚本还会确认私钥派生公钥与 `pkg/upgrade/installer.go` 中同 key ID 的客户端公钥完全一致，防止产出客户端无法验证的资产。私钥必须离线保管且权限为 0600，绝不进入 bundle、日志或 Git。轮换时先发布同时信任新旧公钥的过渡版本，再切换签名密钥。

## 持久 bundle

`build/release.sh prepare <version> --bundle <absolute-path>` 生成且只生成一次：

```text
<bundle>/
├── manifest.json
├── manifest.sig
└── assets/
    ├── sslctl-linux-amd64.gz
    ├── sslctl-linux-arm64.gz
    └── sslctl-windows-amd64.exe.gz
```

manifest 固定记录：schema、product、version、channel、source_commit、dirty、created_at、build_time、Go 版本、三项资产的 size/SHA256/Ed25519 签名。main 的 `dirty` 必须为 false；dev 必须如实记录 `source_commit` 和 `dirty`。构建前、快照捕获后和构建签名后都会比较 HEAD、分支及完整工作区指纹；发生变化即丢弃未发布 bundle。

main 正式发布必须在 `build/release.conf` 配置仓库外的 `BUNDLE_ROOT`；dev 测试版不要求。main 的唯一路径固定为 `<BUNDLE_ROOT>/main/v<version>-<source_commit>`。main prepare 与 abort 全程先取得全部发布节点的同一组排他锁；每个节点的 `<SERVER_DIR>/.release-state/main/` 以 version + commit 为键，原子记录 `preparing` / `prepared` / `aborted`、尝试次数和完整 bundle 摘要，作为跨 clone、跨工作区的权威 reservation。本地忽略的 `.release-state/main/` 只是镜像审计，丢失不解除远端门禁。`prepared` 永不允许再次 prepare；改变 `BUNDLE_ROOT`、清理工作树或移走 bundle 也不能绕过。tag 前未完成尝试只能经 `abort-main` 在同一组锁内显式转为 `aborted` 后重试，审计状态不会删除；tag 创建后严禁 abort、移除或重建。`stage-main`、`promote-main`、`verify-main`、`resume-main` 只接受远端 state 摘要一致的现有 bundle，均先重新校验 manifest、manifest 签名、精确资产集合、大小、SHA256、资产签名和产物内置版本，不调用构建。

本仓生产拓扑至少配置两个发布节点；脚本不提供单节点发布选项。节点名称、主机、端口和绝对发布目录必须通过安全字符校验。发布阶段先在所有节点取得同一发布锁；各节点基于自己的最新公开索引生成候选，以原样保留旧客户端仍读取的兼容顶层字段。推进前对候选的 main/dev 规范安全视图计算确定性摘要，版本、校验和、签名、source commit 等任一差异都停止；旧顶层字段和历史 `released_at` 展示日期不参与安全摘要。这样既避免 main/dev 并发导致整份索引丢失更新，也不会把单节点未知旧数据传播到其他节点。

## 本地检查

以下仅为构建/发布实现变化时的命令参考，适用范围与同任务证据复用统一遵循 `skills/finish-check.md`；不因加载本文重复已通过的门禁。

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/release.sh --dry-run prepare 1.2.3 --bundle /tmp/sslctl-release-1.2.3
```

`test-release.sh` 只使用临时目录、测试密钥和 mock，不联网、不改 Git 引用。真实 Windows 运行、Docker E2E、SSH 节点和公网下载仍需在正式发布窗口按 `skills/remote-release.md` 验证。
