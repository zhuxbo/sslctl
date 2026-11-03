#!/usr/bin/env bash
# 变更影响规划器的离线契约测试。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() { echo "变更检查规划器测试失败: $*" >&2; exit 1; }

new_fixture() {
    local name="$1"
    local fixture="$TEST_ROOT/$name"

    mkdir -p "$fixture/app" "$fixture/core" "$fixture/pkg/config" "$fixture/docker/test/mock-api"
    (
        cd "$fixture"
        git init -q
        git config user.name test
        git config user.email test@example.test
    )
    cat >"$fixture/go.mod" <<'EOF'
module example.test/project

go 1.26.0

toolchain go1.26.8
EOF
    cat >"$fixture/core/core.go" <<'EOF'
package core

func Value() int { return 1 }
EOF
    cat >"$fixture/app/app.go" <<'EOF'
package app

import "example.test/project/core"

func Value() int { return core.Value() }
EOF
    cat >"$fixture/pkg/config/config.go" <<'EOF'
package config

func Enabled() bool { return true }
EOF
    cat >"$fixture/pkg/config/config_test.go" <<'EOF'
package config

import "testing"

func TestEnabled(t *testing.T) {
	if !Enabled() { t.Fatal("expected enabled") }
}
EOF
    cat >"$fixture/docker/test/mock-api/main.go" <<'EOF'
package main

func main() {}
EOF
    printf '# fixture\n' >"$fixture/README.md"
    (
        cd "$fixture"
        git add .
        git commit -qm baseline
    )
    printf '%s\n' "$fixture"
}

plan() {
    local fixture="$1"
    local output="$2"
    shift 2
    mkdir -p "$TEST_ROOT/go-cache" "$TEST_ROOT/go-tmp"
    GOCACHE="$TEST_ROOT/go-cache" GOTMPDIR="$TEST_ROOT/go-tmp" TMPDIR="$TEST_ROOT" \
        python3 "$ROOT/build/plan-checks.py" --root "$fixture" --base HEAD "$@" >"$output"
}

assert_json() {
    local output="$1"
    local expression="$2"
    local message="$3"
    PLAN_PATH="$output" PLAN_EXPRESSION="$expression" python3 - <<'PY' || fail "$message"
import json
import os

with open(os.environ["PLAN_PATH"], encoding="utf-8") as handle:
    plan = json.load(handle)
assert eval(
    os.environ["PLAN_EXPRESSION"],
    {"__builtins__": {"len": len, "set": set, "sorted": sorted, "sum": sum}},
    {"plan": plan},
)
PY
}

fixture="$(new_fixture docs-only)"
printf '\nchanged\n' >>"$fixture/README.md"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "文档变更不应触发变异测试"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == []' "文档变更不应触发 Go 测试"
assert_json "$fixture/plan.json" 'plan["contracts"]["agent_config"] is False' "普通文档变更不应触发防漂移检查"

fixture="$(new_fixture mutation-canaries)"
mkdir -p "$fixture/build"
printf './pkg/config\tpkg/config/config.go:Enabled:RETURN_FALSE#1\n' >"$fixture/build/mutation-canaries.txt"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["contracts"]["agent_config"] is True and plan["contracts"]["mutation"] is True' "哨兵清单变更必须验证防漂移和变异契约"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == [] and plan["go"]["build_all"] is False' "清单变更不应触发业务测试或构建"

fixture="$(new_fixture direct-and-reverse)"
printf '\n// changed\n' >>"$fixture/core/core.go"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "普通生产代码变更应使用 changed-line 模式"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core"]' "未包含直接包与反向依赖包"
assert_json "$fixture/plan.json" 'plan["mutation"]["packages"] == ["./core"]' "变异目标应限制在直接变更包"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == []' "生产变更不应凭空增加测试哨兵"

fixture="$(new_fixture critical-package)"
printf '\n// changed\n' >>"$fixture/pkg/config/config.go"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "关键包生产代码变更也应限制到 changed-line"
assert_json "$fixture/plan.json" 'plan["mutation"]["packages"] == ["./pkg/config"]' "关键包目标错误"

fixture="$(new_fixture tests-only)"
printf '\n// changed\n' >>"$fixture/pkg/config/config_test.go"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "仅测试变更不应扫描生产代码"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == ["./pkg/config"]' "仅测试变更应运行关键包哨兵"

fixture="$(new_fixture nginx-tests-only)"
for package in installer scanner; do
    mkdir -p "$fixture/internal/nginx/$package"
    printf 'package %s\nfunc Value() bool { return true }\n' "$package" >"$fixture/internal/nginx/$package/value.go"
done
git -C "$fixture" add internal
git -C "$fixture" commit -qm 'nginx baseline'
for package in installer scanner; do
    printf 'package %s\nimport "testing"\nfunc TestValue(t *testing.T) { if !Value() { t.Fatal("false") } }\n' "$package" >"$fixture/internal/nginx/$package/value_test.go"
done
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none" and plan["mutation"]["canary_packages"] == ["./internal/nginx/installer", "./internal/nginx/scanner"]' "Nginx 安装和扫描测试必须路由到各自哨兵"
python3 - "$fixture/plan.json" "$ROOT/build/mutation-canaries.txt" <<'PY' || fail "规划的 Nginx 测试包缺少实际哨兵"
import json
import sys
from pathlib import Path

targets = json.loads(Path(sys.argv[1]).read_text())["mutation"]["canary_packages"]
declared = {line.split("\t")[0] for line in Path(sys.argv[2]).read_text().splitlines() if line and not line.startswith("#")}
assert set(targets) <= declared
PY

fixture="$(new_fixture prod-and-tests)"
printf '\n// changed\n' >>"$fixture/pkg/config/config.go"
printf '\n// changed\n' >>"$fixture/pkg/config/config_test.go"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines"' "生产与测试同时变更时应保留 changed-line"
assert_json "$fixture/plan.json" 'plan["mutation"]["canary_packages"] == ["./pkg/config"]' "生产与测试同时变更时不应跳过哨兵"

fixture="$(new_fixture module-change)"
printf '\n' >>"$fixture/go.mod"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "依赖图变更不应触发全量变异"
assert_json "$fixture/plan.json" 'plan["go"]["build_all"] is True' "依赖图变更应触发全平台构建"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core", "./docker/test/mock-api", "./pkg/config"]' "依赖图变更未覆盖所有 Go 测试包"
assert_json "$fixture/plan.json" '"file_shards" not in plan["mutation"]' "规划结果仍包含全量文件分片"

fixture="$(new_fixture excluded-mock)"
printf '\n// changed\n' >>"$fixture/docker/test/mock-api/main.go"
plan "$fixture" "$fixture/plan.json" --with-mutation
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none"' "测试桩不应被当作生产代码变异"

fixture="$(new_fixture forced-full)"
plan "$fixture" "$fixture/plan.json" --full
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core", "./docker/test/mock-api", "./pkg/config"]' "显式全量未覆盖所有 Go 测试包"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] != "full"' "显式全量不应升级 mutation"

fixture="$(new_fixture fast-default)"
printf '\n// changed\n' >>"$fixture/core/core.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "none" and plan["mutation"]["canary_packages"] == []' "日常小改不应启动变异"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./app", "./core"] and plan["go"]["coverage"] is False' "快速路径仍应覆盖直接包与反向依赖"
assert_json "$fixture/plan.json" 'plan["contracts"]["docker_e2e"] is False' "日常小改不应启动完整 E2E"

fixture="$(new_fixture test-only-direct)"
printf 'package core\n' >"$fixture/core/core_test.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == ["./core"]' "仅测试变更不应扩大到生产反向依赖"

fixture="$(new_fixture scanner-default)"
mkdir -p "$fixture/internal/apache/scanner"
printf 'package scanner\n' >"$fixture/internal/apache/scanner/scanner.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["contracts"]["docker_e2e"] is False' "scanner 局部修改不应自动运行完整矩阵"
plan "$fixture" "$fixture/explicit-e2e.json" --with-e2e
assert_json "$fixture/explicit-e2e.json" 'plan["contracts"]["docker_e2e"] is True' "显式 E2E 不应被省略"

fixture="$(new_fixture docker-change)"
printf 'changed\n' >"$fixture/docker/compose.yml"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["contracts"]["docker_e2e"] is True' "Docker 配置变更必须路由真实 E2E"

fixture="$(new_fixture docs-without-go)"
printf '\nchanged\n' >>"$fixture/README.md"
mkdir -p "$fixture/bin"
printf '#!/bin/sh\nexit 97\n' >"$fixture/bin/go"
chmod +x "$fixture/bin/go"
PATH="$fixture/bin:$PATH" plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["go"]["test_packages"] == []' "纯文档不应依赖 Go 工具链"

fixture="$(new_fixture platform-change)"
printf 'package core\n' >"$fixture/core/value_windows.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["go"]["build_all"] is True and plan["go"]["coverage"] is True' "平台变更必须升级普通验证"

fixture="$(new_fixture full-with-change)"
printf '\n// changed\n' >>"$fixture/core/core.go"
plan "$fixture" "$fixture/plan.json" --full
assert_json "$fixture/plan.json" 'plan["mutation"]["mode"] == "changed-lines" and plan["contracts"]["docker_e2e"] is True and plan["contracts"]["release"] is True and plan["go"]["coverage"] is True' "完整检查必须保留变异、E2E、契约与覆盖率"

fixture="$(new_fixture docker-docs)"
printf '# docs\n' >"$fixture/docker/README.md"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["contracts"]["docker_e2e"] is False' "Docker 文档不应触发 E2E"

fixture="$(new_fixture docker-unit-test)"
mkdir -p "$fixture/internal/nginx/docker"
printf 'package docker\n' >"$fixture/internal/nginx/docker/client_test.go"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'plan["contracts"]["docker_e2e"] is False and plan["go"]["test_packages"] == ["./internal/nginx/docker"]' "Docker 单元测试修改不应触发 E2E"

fixture="$(new_fixture lint-config)"
printf 'version: "2"\n' >"$fixture/.golangci.yml"
plan "$fixture" "$fixture/plan.json"
assert_json "$fixture/plan.json" 'len(plan["go"]["lint_packages"]) == 4' "lint 配置变更不能跳过 Go 静态检查"

# 用真实规划器和 Git、替身重门禁验证执行顺序、参数及失败状态；不启动 Docker/RAM 盘。
runner="$(new_fixture runner)"
mkdir -p "$runner/build" "$runner/bin" "$runner/docker/test/scripts"
cp "$ROOT/build/run-changed-checks.sh" "$ROOT/build/plan-checks.py" "$runner/build/"
printf '.superpowers/\n' >"$runner/.gitignore"
for script in build/test-check-planner.sh build/test-mutation.sh build/check-agent-config.sh build/test-release.sh build/build.sh build/run-mutation.sh docker/test/scripts/run-tests-contract-test.sh docker/test/scripts/run-tests.sh; do
    cat >"$runner/$script" <<'EOF'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >>"$CHECK_RECORD"
EOF
done
cat >"$runner/bin/go" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == list ]]; then exec "$CHECK_REAL_GO" "$@"; fi
printf 'go %s\n' "$*" >>"$CHECK_RECORD"
if [[ "$1" == test ]]; then
    for arg in "$@"; do
        if [[ "$arg" == -coverprofile=* ]]; then printf 'mode: atomic\n' >"${arg#*=}"; fi
    done
    exit "${CHECK_GO_EXIT:-0}"
fi
EOF
cat >"$runner/bin/golangci-lint" <<'EOF'
#!/usr/bin/env bash
printf 'lint %s/%s %s\n' "$GOOS" "$GOARCH" "$*" >>"$CHECK_RECORD"
EOF
chmod +x "$runner/bin/"*
# 建立干净种子，避免测试脚本本身触发治理门禁。
(cd "$runner" && git add . && git commit -qm runner)
printf '\n// changed\n' >>"$runner/core/core.go"
run_router() {
    GOCACHE="$TEST_ROOT/go-cache" GOTMPDIR="$TEST_ROOT/go-tmp" \
        CHECK_RECORD="$runner/record" CHECK_REAL_GO="$(command -v go)" \
        PATH="$runner/bin:$PATH" bash "$runner/build/run-changed-checks.sh" --base HEAD "$@" >"$runner/output" 2>&1
}
run_router || { cat "$runner/output"; fail "默认执行失败"; }
[[ "$(grep -c '^go test ' "$runner/record")" == 1 ]] || fail "定向测试重复执行"
if grep -Eq 'coverprofile|run-mutation|run-tests' "$runner/record"; then fail "日常检查触发了额外重门禁"; fi
grep -Fq 'lint linux/amd64' "$runner/record" || fail "缺少明确 Linux lint"
grep -Fq 'lint windows/amd64' "$runner/record" || fail "缺少明确 Windows lint"
report="$(sed -n 's/^finish-check: report=//p' "$runner/output")"
[[ -s "$report/plan.json" && -s "$report/timings.tsv" && "$(cat "$report/exit-code")" == 0 ]] || fail "缺少成功耗时记录"

: >"$runner/record"
run_router --full || { cat "$runner/output"; fail "完整执行失败"; }
[[ "$(grep -c '^go test ' "$runner/record")" == 1 ]] || fail "完整检查把 race/coverage 跑成两次"
grep -Eq '^go test -race -count=1 -coverprofile=' "$runner/record" || fail "完整检查未合并 race/coverage"
for stage in build.sh test-check-planner.sh test-mutation.sh check-agent-config.sh test-release.sh run-tests-contract-test.sh run-tests.sh run-mutation.sh; do
    grep -Fq "$stage " "$runner/record" || fail "完整检查未到达 $stage"
done

: >"$runner/record"
run_router --mutation-only || { cat "$runner/output"; fail "独立变异执行失败"; }
grep -Fq 'run-mutation.sh changed-lines --base HEAD ./core' "$runner/record" || fail "独立 mutation/CI 入口未开启变异"
if grep -Eq '^go test |^lint |run-tests.sh' "$runner/record"; then fail "独立 mutation 额外运行普通门禁"; fi

: >"$runner/record"
run_router --with-mutation --with-e2e || { cat "$runner/output"; fail "显式重门禁执行失败"; }
grep -Fq 'run-mutation.sh changed-lines' "$runner/record" || fail "显式变异参数未传入规划器"
grep -Fq 'run-tests.sh ' "$runner/record" || fail "显式 E2E 参数未传入规划器"

: >"$runner/record"
status=0
CHECK_GO_EXIT=23 run_router --with-e2e || status=$?
[[ "$status" == 23 ]] || fail "失败阶段退出码未传播"
if grep -Eq '^lint |run-tests.sh' "$runner/record"; then fail "Go 失败后仍执行后续门禁"; fi
report="$(sed -n 's/^finish-check: report=//p' "$runner/output")"
[[ "$(cat "$report/exit-code")" == 23 ]] || fail "失败记录错误"
grep -Eq '^go-test[[:space:]][0-9]+[[:space:]]23$' "$report/timings.tsv" || fail "失败阶段耗时未记录"

echo "变更检查规划器测试通过"
