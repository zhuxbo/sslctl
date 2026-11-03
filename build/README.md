# 构建与发布脚本

本目录只说明脚本接口。正式资产、签名和 bundle 契约见 `skills/build-release.md`；dev/main 发布编排、Git/GitHub 门禁、恢复和验收见 `skills/remote-release.md`；统一行为边界见 `deploy-spec.md` 第 8 节。

## 脚本职责

| 入口 | 单一职责 |
| --- | --- |
| `build.sh` | 从当前工作树或显式源快照确定性构建三平台二进制与 gzip |
| `sign-release.sh` | 对固定三项 gzip 和完整 manifest 生成/验证 Ed25519 签名 |
| `release_helper.py` | 校验 SemVer/bundle，维护发布索引和 main release-state |
| `release.sh` | prepare、全节点 staging/promote/verify、main resume 和 tag 前 abort |
| `check-agent-config.sh` | 检查智能体、Skill、薄入口和发布结构防漂移 |
| `test-release.sh` | 在临时目录离线测试发布不变量 |
| `plan-checks.py` | 结合 Git 变更与 Go 依赖图生成定向完成检查计划 |
| `run-changed-checks.sh` | 执行计划内的契约、测试、lint、构建和变异门禁 |
| `run-mutation.sh` | 在一次性 RAM 盘副本中运行固定版本 gomutants 变异测试 |
| `mutation-canaries.txt` | 维护少量关键测试的稳定变异哨兵 |
| `mutation-equivalents.json` | 保存逐项等价证明及依赖源码 SHA-256，源码变化后失效 |
| `test-*mutation*.sh` | 离线验证规划、路由、RAM 隔离、版本和清理边界 |
| `generate-keys.sh` | 生成 Ed25519 seed、公钥和客户端公钥代码 |

## 本地构建

输出目录必须显式指定且为空，防止旧产物混入：

```bash
output_dir="$(mktemp -d)"
bash build/build.sh 1.2.3-rc.1 "$output_dir"
```

脚本生成 Linux amd64、Linux arm64、Windows amd64 的未压缩二进制和 gzip。正式发布只取三份固定命名 gzip，不发布独立 `.sha256` 文件。

## 发布配置

```bash
cp build/release.conf.example build/release.conf
chmod 600 build/release.conf
```

配置全部发布节点、SSH、Ed25519 seed 和 key ID；`BUNDLE_ROOT` 仅在 main 正式发布时必需，dev 测试版和节点检查不要求。发布脚本按每个节点域名组合 `https://<SERVER_HOST>/sslctl` 做公网验收，不向安装脚本注入地址。main bundle 必须使用脚本给出的 `<BUNDLE_ROOT>/main/v<version>-<source_commit>` 固定路径。全部发布节点的 `<SERVER_DIR>/.release-state/main/` 是跨 clone 的权威 prepare reservation；本地忽略的 `.release-state/` 只做镜像审计。改变 `BUNDLE_ROOT`、清理工作树或移走 bundle 都不能绕过重复构建门禁。`release.conf` 与 `build/keys/` 已忽略，不得提交。

dev 测试版使用简单入口，脚本按预发布版本自动选择 dev，并在内部依次完成 bundle 构建与全节点发布；`publish-dev` 已包含 SSH 和公网验收：

```bash
bash build/release.sh 0.4.1-beta.3
```

稳定版本会自动识别为 main，但不会由服务器阶段脚本直接发布；正式版仍按 `skills/remote-release.md` 完成 PR、CI/E2E、不可变 tag 和 GitHub Release 编排。分阶段命令保留用于正式发布及 dev 失败恢复。

## 安全演练

以下命令不联网、不构建、不改 Git 引用：

```bash
bash build/check-agent-config.sh
bash build/test-release.sh
bash build/release.sh --dry-run prepare 1.2.3 --bundle /tmp/sslctl-v1.2.3
bash build/release.sh --dry-run resume-main 1.2.3 --bundle /tmp/sslctl-v1.2.3
```

不要脱离 `skills/remote-release.md` 直接运行非 dry-run 发布阶段。正式版 tag 创建后的恢复只允许传入原持久 bundle，`resume-main` 不提供构建选项。tag 前的未完成 prepare 只有在确认版本 tag 和节点正式目录都不存在后，才可显式执行 `abort-main <version> --bundle <原路径>`；该动作删除残留 bundle，但保留 aborted 状态和尝试次数。

## 分级完成检查

`make finish-check` 默认运行相关契约、定向 race 与 Linux/Windows lint。纯文档不加载 Go；仅测试修改只检查所属包。Docker 实现/测试环境变更自动触发完整 E2E，其他部署语义风险按 `skills/finish-check.md` 判断后加 `--with-e2e`。普通小改不自动跑变异。

```bash
bash build/run-changed-checks.sh --base HEAD --plan-only
bash build/run-changed-checks.sh --base HEAD --with-mutation  # 断言有效性风险
bash build/run-changed-checks.sh --base HEAD --with-e2e       # 部署集成风险
make finish-check-full                                    # 正式发布前完整检查
```

基线须覆盖本任务全部未验收提交；只有工作区任务才用 HEAD。普通检查的输入未变且已有同任务证据时可以复用，不重复跑。运行器把路由、阶段耗时、退出码保存在忽略的 `.superpowers/finish-check/run.*/`，用于定位瓶颈与改进规则，不自动缓存通过结果。

## 变异测试

变异框架固定为 `gomutants v0.6.0`。它与项目依赖分离，不写入 `go.mod`；先安装精确版本，再执行按变更规划的入口：

```bash
go install github.com/szhekpisov/gomutants@v0.6.0
make mutation
```

`make mutation` 读取提交、暂存区、工作区和未跟踪文件。生产 Go 代码只变异本次 changed lines，要求每个可执行 mutant 都被测试杀死；关键包测试发生变化时，再独立执行 `mutation-canaries.txt` 中对应的稳定哨兵。生产代码和测试同时变化时两项都跑。`go.mod`、`go.sum` 只扩大普通测试、lint 与构建范围。`--full` 还执行契约与完整 E2E，变异始终按实际变更定向，不触发全量变异。

changed-line 允许不可编译、等价和无可变异点结果；未经逐项证明等价的 `LIVED`、`NOT COVERED`、超时和基础设施错误均失败。哨兵必须精确命中一个 mutant 且状态为 `KILLED`。两类变异共享一个 20 分钟硬截止时间，默认使用 2 个 worker。

人工等价证明只允许记录在 `build/mutation-equivalents.json`：精确匹配变异 ID、原文和替换内容，并校验条目中所有证明依赖源码的 SHA-256。每项必须说明为何所有有效输入下行为相同；源码变化后需重新证明，不能只更新哈希。仅对 `LIVED` 应用，原始报告和框架缓存不改写，日志逐项列出采用的证明。框架的 100% 阈值不变；只有报告其余项全部通过、剩余存活项全部被有效证明时，运行器才接受 efficacy 的退出码 10。其他退出码、未覆盖、超时和哨兵均不可豁免。

运行器先用 `go list` 将目标展开为完整导入路径，供 v0.6.0 正确建立逐测试覆盖映射；包解析失败或结果为空时直接失败，避免静默回退为每个变异重复执行整个包。

运行器校验二进制内嵌模块版本，并把工作区副本、独立 Git 索引、`GOCACHE`、`GOTMPDIR`、`TMPDIR`、变异文件、运行时 cache 和详细报告放入临时内存盘；`GOMODCACHE` 持久复用以避免重复下载，小型 gomutants cache 在开始时复制进 RAM，结束时只原子写回一次。Linux 使用 `/dev/shm`，macOS 自动创建 3 GiB APFS RAM Disk，退出时清理。可用 `MUTATION_RAM_MB` 调整容量，用 `MUTATION_RAM_ROOT` 指定可验证的内存文件系统，用 `MUTATION_REPORT_DIR` 导出最终报告。

常用入口：

```bash
make finish-check          # 日常定向完成检查，按风险增加重门禁
make mutation             # 只执行计划内变异门禁
make mutation-test        # 快速离线契约测试
```
