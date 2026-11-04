#!/usr/bin/env bash
# deploy-spec.md §12 的本仓确定性防漂移检查。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() { echo "防漂移检查失败: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

EXPECTED_CLAUDE_SHA256="5d904a04b7b6ecb89a5b9254f9afcd12803cbe140d3f9af7bc3a6cf15d5de1fa"
EXPECTED_FINISH_COMMAND_SHA256="121bc2a3671b23555cb7e01074d2b5ac3463eb10a6287e00153e2f166d97c6ad"
EXPECTED_RELEASE_COMMAND_SHA256="f2e26d7329c5f1c31e80f4afb2df8e3086b042a91e1978b2e6be244c2bbfc760"
EXPECTED_CODEX_FINISH_SKILL_SHA256="329a162e0bb5861ed8283d94f5df2c042edbdc8250dd92a44b608df24700bd6f"
EXPECTED_CODEX_RELEASE_SKILL_SHA256="966a13f89cfffbfb4e8bd7c5b31855b4b3d3b34c64db789077d2d31b78c55d62"

[[ "$(sha256_file CLAUDE.md)" == "$EXPECTED_CLAUDE_SHA256" ]] || fail "CLAUDE.md 不符合固定模板"
[[ "$(sha256_file .claude/commands/finish-check.md)" == "$EXPECTED_FINISH_COMMAND_SHA256" ]] || fail "finish-check 工具入口发生漂移"
[[ "$(sha256_file .claude/commands/remote-release.md)" == "$EXPECTED_RELEASE_COMMAND_SHA256" ]] || fail "remote-release 工具入口发生漂移"
[[ "$(sha256_file .agents/skills/finish-check/SKILL.md)" == "$EXPECTED_CODEX_FINISH_SKILL_SHA256" ]] || fail "Codex finish-check 薄入口发生漂移"
[[ "$(sha256_file .agents/skills/remote-release/SKILL.md)" == "$EXPECTED_CODEX_RELEASE_SKILL_SHA256" ]] || fail "Codex remote-release 薄入口发生漂移"
for native_skill in .agents/skills/finish-check/SKILL.md .agents/skills/remote-release/SKILL.md; do
    git ls-files --error-unmatch -- "$native_skill" >/dev/null 2>&1 || fail "Codex Skill 未纳入 Git 跟踪: $native_skill"
done

actual_claude_commands=()
while IFS= read -r path; do actual_claude_commands+=("$path"); done < <(find .claude/commands -maxdepth 1 -type f -name '*.md' | sort)
expected_claude_commands=(.claude/commands/finish-check.md .claude/commands/remote-release.md)
[[ "${actual_claude_commands[*]}" == "${expected_claude_commands[*]}" ]] || fail "Claude 工具入口集合发生漂移"
actual_codex_skills=()
while IFS= read -r path; do actual_codex_skills+=("$path"); done < <(find .agents/skills -mindepth 2 -maxdepth 2 -type f -name SKILL.md | sort)
expected_codex_skills=(.agents/skills/finish-check/SKILL.md .agents/skills/remote-release/SKILL.md)
[[ "${actual_codex_skills[*]}" == "${expected_codex_skills[*]}" ]] || fail "Codex Skill 入口集合发生漂移"
grep -Fq '`../../../skills/finish-check.md`' .agents/skills/finish-check/SKILL.md || fail "Codex finish-check 未引用同名叶子 Skill"
grep -Fq '`../../../skills/remote-release.md`' .agents/skills/remote-release/SKILL.md || fail "Codex remote-release 未引用同名叶子 Skill"
[[ -f .agents/skills/finish-check/../../../skills/finish-check.md ]] || fail "Codex finish-check 叶子 Skill 不存在"
[[ -f .agents/skills/remote-release/../../../skills/remote-release.md ]] || fail "Codex remote-release 叶子 Skill 不存在"

[[ -f AGENTS.md && -f skills/SKILL.md ]] || fail "缺少 AGENTS.md 或根 Skill"
for phrase in "只记录长期有效" "只直接维护 \`AGENTS.md\`" "新增、删除或重命名 skill" "删除失效或重复内容"; do
    grep -Fq "$phrase" AGENTS.md || fail "AGENTS.md 缺少更新原则: $phrase"
done

if find skills -mindepth 1 -type d -print -quit | grep -q .; then
    fail "skills/ 中存在二级目录"
fi
while IFS= read -r leaf; do
    base="$(basename "$leaf")"
    [[ "$base" == "SKILL.md" || "$base" =~ ^[a-z0-9]+(-[a-z0-9]+)*\.md$ ]] || fail "叶子文件名不符合 kebab-case: $leaf"
done < <(find skills -maxdepth 1 -type f -name '*.md' | sort)

routes=()
while IFS= read -r route; do routes+=("$route"); done < <(grep -oE '`skills/[a-z0-9-]+\.md`' skills/SKILL.md | tr -d '`' | sort -u)
for route in "${routes[@]}"; do [[ -f "$route" ]] || fail "Skill 路由不存在: $route"; done
leaves=()
while IFS= read -r leaf; do leaves+=("$leaf"); done < <(find skills -maxdepth 1 -type f -name '*.md' ! -name SKILL.md | sort)
[[ "${routes[*]}" == "${leaves[*]}" ]] || fail "skills/SKILL.md 路由与叶子资源集合不一致"

old_refs="$(mktemp "${TMPDIR:-/tmp}/sslctl-old-skill-refs.XXXXXX")"
trap 'rm -f "$old_refs"' EXIT
python3 - "$old_refs" <<'PY'
import pathlib, re, subprocess, sys
pattern = re.compile(r"skills/[a-z0-9-]+/SKILL\.md|skills/(?:go-dev|nginx-apache|deploy-ops|build-release)/")
paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split(b"\0")
with open(sys.argv[1], "w", encoding="utf-8") as output:
    for raw_path in paths:
        if not raw_path:
            continue
        path = pathlib.Path(raw_path.decode(errors="surrogateescape"))
        if path.as_posix() in {"deploy-spec.md", "build/check-agent-config.sh"} or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for native_skill in (
            ".agents/skills/finish-check/SKILL.md",
            ".agents/skills/remote-release/SKILL.md",
        ):
            text = text.replace(native_skill, "")
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                output.write(f"{path}:{number}:{line}\n")
PY
if [[ -s "$old_refs" ]]; then
    cat "$old_refs" >&2
    fail "仍引用旧二级 Skill 路径"
fi

grep -Fq 'bash build/check-agent-config.sh' .github/workflows/ci.yml || fail "CI 未执行智能体防漂移检查"
grep -Fq 'bash build/test-release.sh' .github/workflows/ci.yml || fail "CI 未执行发布行为回归检查"
[[ "$(grep -Fc "go-version: '1.26.8'" .github/workflows/ci.yml)" == 4 ]] || fail "CI Go 版本未全部固定为 1.26.8"
[[ "$(grep -Fc "go-version: '1.26.8'" .github/workflows/e2e.yml)" == 2 ]] || fail "E2E Go 版本未全部固定为 1.26.8"
grep -Fxq 'FROM golang:1.26.8-alpine AS builder' docker/test/mock-api/Dockerfile || fail "mock API Go 版本未固定为 1.26.8"
grep -Fq 'github.com/szhekpisov/gomutants@v0.6.0' .github/workflows/mutation.yml || fail "mutation CI 未固定 gomutants 版本"
grep -Fq "go-version: '1.26.8'" .github/workflows/mutation.yml || fail "mutation CI 未固定 Go 1.26.8"
grep -Fq 'MUTATION_RAM_ROOT: /dev/shm' .github/workflows/mutation.yml || fail "mutation CI 未使用 tmpfs"
grep -Fq 'build/.gomutants-cache.json' .github/workflows/mutation.yml || fail "mutation CI 未复用小型 gomutants 缓存"
grep -Fq 'make mutation-test' .github/workflows/mutation.yml || fail "mutation CI 未验证规划与 RAM 隔离契约"
grep -Fq 'FINISH_CHECK_BASE="$finish_base" make mutation' .github/workflows/mutation.yml || fail "mutation CI 未执行定向门禁"
grep -Fq 'git cat-file -e "$BEFORE_SHA:.github/workflows/mutation.yml"' .github/workflows/mutation.yml || fail "mutation CI 缺少首次启用基线保护"
grep -Fq 'if ! git cat-file -e "$BEFORE_SHA^{commit}"' .github/workflows/mutation.yml || fail "mutation CI 在 push 基线不可解析时未失败关闭"
[[ "$(grep -Fc "      - 'Makefile'" .github/workflows/mutation.yml)" == 2 ]] || fail "mutation CI 未监听 Makefile"
[[ "$(grep -Fc "      - 'build/test-check-planner.sh'" .github/workflows/mutation.yml)" == 2 ]] || fail "mutation CI 未监听规划器契约"
if grep -Fq 'cancel-in-progress: true' .github/workflows/mutation.yml; then
    fail "mutation CI 不得取消尚未完成的 push 门禁"
fi
if grep -Eq '^[[:space:]]+(schedule:|matrix:)' .github/workflows/mutation.yml; then
    fail "mutation CI 不应包含全量调度或分片矩阵"
fi
grep -Fq "MUTATION_WORKERS: '1'" .github/workflows/mutation.yml || fail "mutation CI 未限制编译竞争"
grep -Fq 'MANUAL_BASE: ${{ inputs.base }}' .github/workflows/mutation.yml || fail "mutation CI 手动重验未接收明确基线"
grep -Fq 'git rev-parse --verify --end-of-options "${MANUAL_BASE:?必须提供重验基线}^{commit}"' .github/workflows/mutation.yml || fail "mutation CI 手动重验未校验基线提交"
for mutation_file in \
    build/plan-checks.py \
    build/run-changed-checks.sh \
    build/run-mutation.sh \
    build/test-check-planner.sh \
    build/test-mutation.sh \
    build/mutation-canaries.txt; do
    [[ -f "$mutation_file" ]] || fail "缺少 mutation 文件: $mutation_file"
done
python3 - <<'PY' || fail "mutation 哨兵清单无效"
from collections import Counter
from pathlib import Path

entries = []
for number, raw in enumerate(Path("build/mutation-canaries.txt").read_text().splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    fields = line.split("\t")
    assert len(fields) == 2, f"line {number}: expected package<TAB>mutant-id"
    package, mutant_id = fields
    assert package.startswith("./"), f"line {number}: invalid package"
    assert mutant_id, f"line {number}: empty mutant id"
    entries.append((package, mutant_id))
assert 1 <= len(entries) <= 14, f"expected 1..14 mutation canaries, got {len(entries)}"
assert len({mutant_id for _, mutant_id in entries}) == len(entries)
assert max(Counter(package for package, _ in entries).values()) <= 3
PY

for name in sslctl-linux-amd64.gz sslctl-linux-arm64.gz sslctl-windows-amd64.exe.gz; do
    grep -Fq "$name" skills/build-release.md || fail "构建 Skill 缺少正式资产: $name"
    grep -Fq "$name" build/release_helper.py || fail "发布 helper 缺少正式资产: $name"
done
grep -Fq 'resume-main)' build/release.sh || fail "缺少 main 恢复入口"
grep -Fq 'require_main_tag' build/release.sh || fail "main 恢复未绑定不可变 tag"
grep -Fq 'state-verify' build/release.sh || fail "main 恢复未绑定持久 release-state"
grep -Fq 'begin_remote_release_state' build/release.sh || fail "main prepare 未建立全节点持久 reservation"
grep -Eq 'prepare\).*with_release_locks prepare_bundle' build/release.sh || fail "main prepare 未持有全节点发布锁"
grep -Fq 'abort-main)' build/release.sh || fail "缺少 tag 前显式废弃入口"
if grep -E 'resume-main\).*prepare_bundle' build/release.sh >/dev/null; then fail "main 恢复错误调用构建"; fi
grep -Fq '至少两个节点' build/release.sh || fail "发布脚本未拒绝单节点退化"
grep -Fq '候选 releases.json 不一致' build/release.sh || fail "缺少多节点候选索引一致性门禁"
grep -Fq 'main 版本已存在，不可覆盖' build/release_helper.py || fail "main 不可变门禁缺失"

echo "智能体配置与发布结构防漂移检查通过"
