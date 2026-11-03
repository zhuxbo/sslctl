# sslctl 项目智能体规则

sslctl 是 Go 实现的跨平台 SSL 证书部署工具，支持 Linux/Windows、Nginx/Apache 与 Docker 场景。

## 不可违反的规则

- 始终用中文回复；只处理当前仓库。
- `deploy-spec.md` 是跨仓部署、升级、构建和发布行为的统一边界，不得在本仓静默改变其语义。
- 匹配开发、部署、发布或完成检查任务时，先读 `skills/SKILL.md`，再读其路由的叶子资源。
- 正式发布必须从干净且与远端一致的 `main` 精确提交构建一次，使用持久 bundle 恢复；不得覆盖正式 tag、GitHub Release 或正式资产。
- dev 测试版允许从脏工作区快照发布，但不得提交、推送、合并、切分支、创建 tag 或 GitHub Release。
- 未经用户明确要求不得执行真实发布、上传发布节点、创建或移动 tag、创建 GitHub Release/PR、推送分支。
- `main` / `dev` 不自动提交；用户明确要求提交时，提交信息遵循仓库历史的中文 `type: 主题` 风格，不添加 AI 署名。

## 权威入口

- 统一部署规范：`deploy-spec.md`
- Skill 路由：`skills/SKILL.md`
- Codex 薄入口：`.agents/skills/remote-release/SKILL.md`、`.agents/skills/finish-check/SKILL.md`（分别与 Claude 同名入口引用同一叶子资源）
- 构建与签名契约：`skills/build-release.md`
- 发布编排与恢复：`skills/remote-release.md`
- 完成检查：`skills/finish-check.md`
- 用户文档：`README.md`；构建脚本使用说明：`build/README.md`

## 协作与检查

- 当前用户指令优先于 skill 默认流程。在已授权范围内自行解决常规实现选择，缺失信息会实质影响正确性或授权时才提问，不逐步重复确认。
- 局部维护直接阅读相关代码、修改并定向验证；只按任务需要加载 skill 的相关章节，不自动启动计划文档、worktree、完整 TDD 或子代理流程。
- 默认采用 `skills/finish-check.md` 的按风险检查；脚本已跑过的门禁和输入未变的同任务证据不重复执行。验收满足且适用检查通过即结束，只有新修改、失败或具体风险才扩大检查。
- 审核限定本次 diff 与直接影响链；建议和历史问题不自动变成修复任务。简洁说明结果、证据与阻塞。
- 用户纠正、实测误触发/漏检和耗时证据可触发本仓规则自进化，具体边界见 `skills/finish-check.md`；无新证据不强制反思或改规则。

## 更新原则

- 只记录长期有效、项目级、会影响智能体行为的规则；临时决策、调试记录、单一模块实现细节不得写入。
- 新增内容先判断职责：跨仓公共行为写入 `deploy-spec.md`，领域知识和工作流写入对应叶子资源，本文只保留入口与项目硬约束，不复制正文。
- 只直接维护 `AGENTS.md`；`CLAUDE.md` 始终保持固定薄入口，不在其中追加项目规则。
- 新增、删除或重命名 skill 时同步更新 `skills/SKILL.md` 及受影响引用。
- 修改后删除失效或重复内容，并检查 `CLAUDE.md` 固定模板、skill 路由、引用路径和确定性防漂移门禁；未经明确需求不得新增全局约束。
