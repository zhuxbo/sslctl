#!/usr/bin/env bash
# 先分析变更影响，再执行定向 finish-check 门禁。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-finish-check.XXXXXX")"
PLAN_FILE="$RUN_ROOT/plan.json"
FORCE_FULL=0
BASE="${FINISH_CHECK_BASE:-}"
REPORT_DIR=""
printf 'stage\tseconds\texit_code\n' >"$RUN_ROOT/timings.tsv"

cleanup() {
    local status=$?
    if [[ -n "$REPORT_DIR" ]]; then
        cp "$PLAN_FILE" "$RUN_ROOT/timings.tsv" "$REPORT_DIR/"
        printf '%s\n' "$status" >"$REPORT_DIR/exit-code"
        echo "finish-check: report=$REPORT_DIR"
    fi
    rm -rf "$RUN_ROOT"
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
用法: build/run-changed-checks.sh [--base <git-ref>] [--full] [--plan-only] [--mutation-only] [--with-mutation] [--with-e2e]

默认先根据提交、暂存区、工作区和未跟踪文件生成计划，再运行适用门禁。
默认执行定向 race 与双平台 lint；变异按需增加，Docker 文件变更自动执行 E2E。
--full 执行全量测试/覆盖率、lint、构建、契约、完整 E2E；mutation 仍按实际变更定向。
EOF
}

PLAN_ONLY=0
MUTATION_ONLY=0
WITH_MUTATION=0
WITH_E2E=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            [[ -n "${2:-}" ]] || { echo "--base 缺少 Git ref" >&2; exit 2; }
            BASE="$2"
            shift 2
            ;;
        --full)
            FORCE_FULL=1
            shift
            ;;
        --plan-only)
            PLAN_ONLY=1
            shift
            ;;
        --mutation-only)
            MUTATION_ONLY=1
            WITH_MUTATION=1
            shift
            ;;
        --with-mutation)
            WITH_MUTATION=1
            shift
            ;;
        --with-e2e)
            WITH_E2E=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            echo "未知参数: $1" >&2
            exit 2
            ;;
    esac
done

if [[ "${FINISH_CHECK_TESTING:-0}" == 1 && -n "${FINISH_CHECK_TEST_PLAN_FILE:-}" ]]; then
    cp "$FINISH_CHECK_TEST_PLAN_FILE" "$PLAN_FILE"
else
    planner=(python3 "$ROOT/build/plan-checks.py" --root "$ROOT")
    [[ -n "$BASE" ]] && planner+=(--base "$BASE")
    [[ "$FORCE_FULL" -eq 1 ]] && planner+=(--full)
    [[ "$WITH_MUTATION" -eq 1 ]] && planner+=(--with-mutation)
    [[ "$WITH_E2E" -eq 1 ]] && planner+=(--with-e2e)
    "${planner[@]}" >"$PLAN_FILE"
fi

python3 - "$PLAN_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    plan = json.load(handle)
print(f"finish-check: profile={plan.get('profile', 'targeted')} base={plan['base']} mutation={plan['mutation']['mode']}")
print("finish-check: changed=" + (", ".join(plan["changed_files"]) or "(none)"))
print("finish-check: go-targets=" + (", ".join(plan["go"]["test_packages"]) or "(none)"))
print(f"finish-check: docker-e2e={plan['contracts']['docker_e2e']}")
for reason in plan.get("reasons", []):
    print(f"finish-check: reason={reason}")
PY

[[ "$PLAN_ONLY" -eq 0 ]] || exit 0

# 仅保存路由和阶段耗时，不保存可能含敏感信息的命令输出；历史仅用于优化。
mkdir -p "$ROOT/.superpowers/finish-check"
REPORT_DIR="$(mktemp -d "$ROOT/.superpowers/finish-check/run.XXXXXX")"

run_check() {
    local stage="$1" started=$SECONDS status=0
    shift
    echo "finish-check: start=$stage"
    "$@" || status=$?
    printf '%s\t%s\t%s\n' "$stage" "$((SECONDS - started))" "$status" >>"$RUN_ROOT/timings.tsv"
    echo "finish-check: end=$stage seconds=$((SECONDS - started)) exit=$status"
    return "$status"
}

json_lines() {
    local expression="$1"
    python3 - "$PLAN_FILE" "$expression" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
for key in sys.argv[2].split("."):
    value = value[key]
if isinstance(value, list):
    for item in value:
        print(item)
else:
    print("true" if value is True else "false" if value is False else value)
PY
}

cd "$ROOT"
if [[ "$MUTATION_ONLY" -eq 0 ]]; then
    SHELL_FILES=()
    while IFS= read -r item; do [[ -n "$item" ]] && SHELL_FILES+=("$item"); done < <(json_lines contracts.shell_files)
    if [[ ${#SHELL_FILES[@]} -gt 0 ]]; then
        for shell_file in "${SHELL_FILES[@]}"; do
            run_check "syntax:$shell_file" bash -n "$shell_file"
        done
    fi

    if [[ "$(json_lines contracts.mutation)" == true ]]; then
        run_check planner-contract bash build/test-check-planner.sh
        run_check mutation-contract bash build/test-mutation.sh
    fi
    if [[ "$(json_lines contracts.agent_config)" == true ]]; then
        run_check agent-config bash build/check-agent-config.sh
    fi
    if [[ "$(json_lines contracts.release)" == true ]]; then
        run_check release-contract bash build/test-release.sh
    fi
    run_check diff-check git diff --check
    run_check staged-diff-check git diff --cached --check

    TEST_PACKAGES=()
    while IFS= read -r item; do [[ -n "$item" ]] && TEST_PACKAGES+=("$item"); done < <(json_lines go.test_packages)
    LINT_PACKAGES=()
    while IFS= read -r item; do [[ -n "$item" ]] && LINT_PACKAGES+=("$item"); done < <(json_lines go.lint_packages)
    if [[ ${#TEST_PACKAGES[@]} -gt 0 ]]; then
        COVER_ARGS=()
        if [[ "$(json_lines go.coverage)" == true ]]; then
            COVER_ARGS+=(-coverprofile="$RUN_ROOT/coverage.out")
        fi
        run_check go-test go test -race -count=1 ${COVER_ARGS[@]+"${COVER_ARGS[@]}"} "${TEST_PACKAGES[@]}"
        if [[ -f "$RUN_ROOT/coverage.out" ]]; then
            go tool cover -func="$RUN_ROOT/coverage.out" | tail -1
        fi
    fi

    if [[ ${#LINT_PACKAGES[@]} -gt 0 ]]; then
        command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint 未安装" >&2; exit 1; }
        run_check lint-linux env GOOS=linux GOARCH=amd64 golangci-lint run --timeout=5m "${LINT_PACKAGES[@]}"
        run_check lint-windows env GOOS=windows GOARCH=amd64 golangci-lint run --timeout=5m "${LINT_PACKAGES[@]}"
    fi

    if [[ "$(json_lines go.build_all)" == true ]]; then
        mkdir -p "$RUN_ROOT/build-output"
        run_check build bash build/build.sh 0.0.0-test.1 "$RUN_ROOT/build-output"
    fi
    if [[ "$(json_lines contracts.docker_e2e)" == true ]]; then
        run_check e2e-contract bash docker/test/scripts/run-tests-contract-test.sh
        run_check docker-e2e bash docker/test/scripts/run-tests.sh
    fi
fi

MUTATION_MODE="$(json_lines mutation.mode)"
MUTATION_PACKAGES=()
while IFS= read -r item; do [[ -n "$item" ]] && MUTATION_PACKAGES+=("$item"); done < <(json_lines mutation.packages)
CANARY_PACKAGES=()
while IFS= read -r item; do [[ -n "$item" ]] && CANARY_PACKAGES+=("$item"); done < <(json_lines mutation.canary_packages)
if [[ "$MUTATION_MODE" != none || ${#CANARY_PACKAGES[@]} -gt 0 ]]; then
    export MUTATION_DEADLINE_EPOCH="${MUTATION_DEADLINE_EPOCH:-$(( $(date +%s) + 1200 ))}"
fi
case "$MUTATION_MODE" in
    none)
        echo "finish-check: mutation=not-applicable"
        ;;
    changed-lines)
        run_check mutation-changed bash build/run-mutation.sh changed-lines --base "$(json_lines base)" "${MUTATION_PACKAGES[@]}"
        ;;
    *)
        echo "未知 mutation 模式: $MUTATION_MODE" >&2
        exit 1
        ;;
esac
if [[ ${#CANARY_PACKAGES[@]} -gt 0 ]]; then
    run_check mutation-canaries bash build/run-mutation.sh canaries "${CANARY_PACKAGES[@]}"
fi

echo "定向完成检查通过"
