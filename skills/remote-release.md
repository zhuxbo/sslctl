# sslctl 远程发布

这是本仓 dev/main 发布、Git/GitHub 编排、中断恢复和最终验收的唯一权威实现。必须同时遵守 `deploy-spec.md` 第 8 节并读取 `skills/build-release.md`；本文只记录 sslctl 平台适配，不复制统一规范正文。

## 参数与共同前置

用户参数是一个不带 `v` 的 SemVer。带预发布段仅允许 dev；稳定版本仅允许 main。任何缺失参数、格式错误、签名密钥缺失、节点不全、资产不全、哈希/签名不一致都立即停止。

本仓 required checks 是 `.github/workflows/ci.yml` 在精确 commit 上的 `Test`、`Lint`、`Build Check`。release gate 是 `.github/workflows/e2e.yml` 的 8 个 Nginx/Apache × 发行版任务和 `E2E (Docker-in-Docker)`；通过手动 dispatch 到指定 ref 验证 PR commit、合并后的 main commit和回同步后的 dev commit。检查名称或工作流拓扑变化时必须先更新本文和防漂移门禁。

## dev 测试版

dev 允许当前分支和脏工作区快照，禁止提交、推送、合并、切分支、tag、PR 或 GitHub Release。

日常发布直接执行 `bash build/release.sh <version>`。脚本根据预发布 SemVer 自动选择 dev，创建新的临时 bundle，并依次执行 `prepare`、`publish-dev`；`publish-dev` 内部完成全节点 SSH 与公网验收。任一步失败都会输出并保留 bundle 路径。以下分阶段命令用于审计和失败恢复：

1. 记录执行前分支、HEAD 和工作区状态。
2. `bash build/release.sh prepare <version> --bundle <持久路径>`；manifest 必须为 `channel=dev`，并如实记录 `source_commit`、`dirty`。
3. `bash build/release.sh publish-dev <version> --bundle <同一路径>`：把同一 bundle 暂存到所有配置节点，逐节点核对三项资产的 SHA256 后，再更新各节点 dev 目录和原子替换索引。
4. 需要在失败恢复后单独复验时，运行 `bash build/release.sh verify-dev <version> --bundle <同一路径>`：通过全部节点的 SSH 目录及各自公网域名核对版本、资产数、SHA256、签名、`source_commit`、`dirty`。
5. 再次确认分支、HEAD 和工作区状态未被发布脚本改变；全部通过才可报告成功。

同版本可重复发布并覆盖 dev 条目；简单入口每次创建新 bundle，刷新 `released_at`、checksums、signatures 和 latest。任一步失败保留 bundle，修复后重跑 `publish-dev` 与全节点验收。

## main 正式版

正式版本严格执行以下编排；`build/release.sh` 只负责 bundle 和服务器阶段，Git/GitHub 动作由本流程显式执行。

1. 在干净 `dev` 确认 `dev == origin/dev`，稳定版本高于公网 `main.latest`，远端/本地 `v<version>`、GitHub Release 和所有节点 `main/v<version>` 均不存在。
2. 创建 `dev → main` PR；等待精确 PR commit 的三个 required checks 和完整 E2E release gate 成功后合并。发布窗口开始，禁止向 dev 添加提交。
3. fast-forward 同步本地 `main`，确认 `main == origin/main`、工作区干净；等待该精确 main commit 的三个 required checks并手动 dispatch 完整 E2E 到该 ref。
4. 只构建一次：按 `build/release.conf` 的 `BUNDLE_ROOT` 计算固定路径 `<BUNDLE_ROOT>/main/v<version>-<main-commit>`，执行 `bash build/release.sh prepare <version> --bundle <固定路径>`。保存 manifest、detached manifest 签名和完整 bundle，记录其目录哈希；不得位于仓库或会被清理的位置。
5. `bash build/release.sh stage-main <version> --bundle <同一路径>`：所有节点只写 staging，验证三项资产字节和 manifest，尚不改变公开索引。
6. 创建并推送不可变 `v<version>` tag，确认指向 manifest 的 `source_commit`；创建同 tag/commit 的 draft GitHub Release，从同一 bundle 上传三项正式资产，逐项核对 SHA256。
7. `bash build/release.sh promote-main <version> --bundle <同一路径>`：脚本取得全部节点发布锁，在锁内基于最新公开索引重新生成并对齐候选，再从 staging 提升不可变版本目录和原子替换索引；随后公开 GitHub Release并执行全节点对账。
8. 验收通过后把唯一可移动的 `latest` tag 更新到 `v<version>`。将 main fast-forward 回 dev 并推送，等待该精确 dev commit 的三个 required checks和完整 E2E gate。
9. `bash build/release.sh verify-main <version> --bundle <同一路径>`，再完成下方最终验收；全部通过前不清理 bundle、不宣布完成。

禁止 `--server` 单节点正式发布、禁止正式版覆盖、禁止删除/移动版本 tag、禁止在 resume 中构建。分支无法 fast-forward 时停止，不得 force-push。

### 精确 commit 与 GitHub 操作

所有命令先把 `version`、`bundle`、`commit` 解析为明确值并由智能体核对；禁止未解析的空变量或 glob。关键证据命令：

```bash
gh pr view <pr> --json headRefOid,mergeCommit,state
gh pr checks <pr> --watch
gh workflow run e2e.yml --ref <branch-or-tag> -f distro=all -f server=all -f test=all -f dind=true
gh run view <run-id> --json headSha,status,conclusion,jobs
```

每次 CI/E2E 都将 `headSha` 与当阶段精确 commit 比较，不能只看同名分支的最新绿色记录。main bundle 暂存并验收后，版本 Git/GitHub 对象按以下语义创建：

```bash
git tag "v<version>" "<commit>"
git push origin "refs/tags/v<version>"
gh release create "v<version>" \
  <bundle>/assets/sslctl-linux-amd64.gz \
  <bundle>/assets/sslctl-linux-arm64.gz \
  <bundle>/assets/sslctl-windows-amd64.exe.gz \
  --draft --verify-tag --title "v<version>"
```

下载 draft Release 的全部资产到新临时目录并与 bundle 逐文件 `cmp`/SHA256 对账后，才执行服务器 `promote-main`。服务器推进成功后公开 Release，并确认 target、draft/prerelease/latest 状态；全节点与公网验收通过后，唯一可移动 tag 才能更新：

```bash
gh release edit "v<version>" --draft=false --prerelease=false --latest
git tag -f latest "v<version>"
git push --force origin refs/tags/latest
git switch dev
git merge --ff-only main
git push origin dev
```

版本 tag 永不使用 `-f`；只有 `latest` 可按上述时点强制更新。以上外部写入受用户真实发布授权约束；已有该版本的完整发布授权时，由智能体核对前一阶段证据后继续，不逐命令重复询问。

## 中断恢复

- tag 前失败：以全部发布节点的权威 release-state 为准；若已为 `prepared`，只能继续使用摘要一致的原 bundle。若停在 `preparing` 且确认本地/远端版本 tag 和所有节点正式目录均不存在，可执行 `bash build/release.sh abort-main <version> --bundle <原路径>`；脚本在全节点锁内把远端 state 和本地镜像转为 `aborted` 后删除残留 bundle。禁止直接删除 state、换 clone、改 `BUNDLE_ROOT` 或移走 bundle 绕过。
- tag 后失败：只运行 `bash build/release.sh resume-main <version> --bundle <原路径>`；脚本校验 tag/commit/manifest 后，从 staging、提升、索引或验收失败点幂等继续，绝不构建。
- GitHub draft/公开状态、节点索引或 dev 回同步失败时，保留 tag、Release 和 bundle；修复失败点后使用同 commit、同 bundle 继续。
- 任一节点失败不得报告成功；若出现部分节点 latest 已更新，立即修复失败节点并重跑全节点 `verify-main`，不得用同版本重建或覆盖修复。

## 正式完成验收

逐项记录证据：三个阶段的 required checks 与 E2E 均绑定精确 commit；本地/远端 main、dev、版本 tag、latest 和 GitHub target 同 commit；工作区干净；全部节点经各自公网域名读取的 `main.latest` 正确；三项资产在节点和 GitHub 字节一致且与索引/manifest 匹配；Release 公开、非 draft、非 prerelease、为 latest；三个产物的 `--version` 与 Ed25519 验证通过；至少从每个发布节点的公网域名下载一个代表资产并校验 SHA256。

真实发布涉及外部写入，必须在用户明确授权后执行。本仓日常 finish-check 只允许 `--dry-run`、临时目录或 mock。
