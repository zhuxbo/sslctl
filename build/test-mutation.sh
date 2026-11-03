#!/usr/bin/env bash
# gomutants RAM 隔离运行器的离线契约测试。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'chmod -R u+w "$TEST_ROOT" 2>/dev/null || true; rm -rf "$TEST_ROOT"' EXIT

fail() { echo "mutation 脚本测试失败: $*" >&2; exit 1; }

make_fixture() {
    local name="$1"
    local fixture="$TEST_ROOT/$name"
    mkdir -p "$fixture/repo/build" "$fixture/ram" "$fixture/bin" "$fixture/reports" "$fixture/modcache"
    cp "$ROOT/build/run-mutation.sh" "$fixture/repo/build/run-mutation.sh"
    printf 'module example.test/fixture\n\ngo 1.26.0\n\ntoolchain go1.26.8\n' >"$fixture/repo/go.mod"
    printf 'package fixture\n\nfunc Value() int { return 1 }\n' >"$fixture/repo/value.go"
    printf './...\tpkg/value.go:Value:CONDITIONALS_NEGATION#1\n' >"$fixture/repo/build/mutation-canaries.txt"
    printf '{"old":true}\n' >"$fixture/repo/build/.gomutants-cache.json"
    (
        cd "$fixture/repo"
        git init -q
        git config user.name test
        git config user.email test@example.test
        git add .
        git commit -qm baseline
    )
    printf '\nfunc NewValue() int { return 2 }\n' >"$fixture/repo/new.go"

    cat >"$fixture/bin/uname" <<'EOF'
#!/usr/bin/env bash
echo Linux
EOF
    cat >"$fixture/bin/findmnt" <<'EOF'
#!/usr/bin/env bash
echo "${MUTATION_TEST_FS_TYPE:-tmpfs}"
EOF
    cat >"$fixture/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == version && "${2:-}" == -m ]]; then
    printf '%s\n' "${3:-gomutants}: go1.26.8"
    printf '\tpath\tgithub.com/szhekpisov/gomutants\n'
    printf '\tmod\tgithub.com/szhekpisov/gomutants\t%s\th1:test\n' "${MUTATION_TEST_TOOL_VERSION:-v0.6.0}"
    exit 0
fi
if [[ "${1:-}" == env && "${2:-}" == GOMODCACHE ]]; then
    printf '%s\n' "$MUTATION_TEST_GOMODCACHE"
    exit 0
fi
if [[ "${1:-}" == list && "${2:-}" == -f && "${3:-}" == '{{.ImportPath}}' ]]; then
    [[ "${MUTATION_TEST_LIST_FAIL:-0}" == 0 ]] || exit 1
    [[ "${MUTATION_TEST_LIST_EMPTY:-0}" == 0 ]] || exit 0
    printf '%s\n' example.test/fixture example.test/fixture/sub
    exit 0
fi
exit 99
EOF
cat >"$fixture/bin/gomutants" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${MUTATION_TEST_BLOCK:-0}" == 1 ]]; then
    printf '%s\n' "$$" >"$MUTATION_TEST_PID_FILE"
    while true; do sleep 1; done
fi
[[ "$PWD" != "$MUTATION_TEST_SOURCE" ]]
[[ "$GOTOOLCHAIN" == go1.26.8 ]]
for path in "$GOCACHE" "$GOTMPDIR" "$TMPDIR"; do
    [[ "$path" == "$MUTATION_RAM_ROOT"/* ]]
done
[[ "$GOMODCACHE" == "$MUTATION_TEST_GOMODCACHE" ]]
grep -Fq '"old":true' "$MUTATION_TEST_PERSISTENT_CACHE"
if [[ -n "${MUTATION_TEST_EXPECT_STAGED:-}" ]]; then
    git diff --cached --name-only | grep -Fxq "$MUTATION_TEST_EXPECT_STAGED"
fi
report=""
cache=""
args=("$@")
seen_target=0
for arg in "${args[@]}"; do
    if [[ "$seen_target" -eq 1 && "$arg" == -* ]]; then
        echo "gomutants flag 出现在 package 之后: $arg" >&2
        exit 88
    fi
    [[ "$arg" != ./* ]] || { echo "gomutants 收到相对包路径: $arg" >&2; exit 89; }
    [[ "$arg" == example.test/* ]] && seen_target=1
done
for ((i=0; i<${#args[@]}; i++)); do
    case "${args[$i]}" in
        -o|--output) report="${args[$((i + 1))]}" ;;
        --cache) cache="${args[$((i + 1))]}" ;;
    esac
done
[[ "$report" == "$MUTATION_RAM_ROOT"/* ]]
[[ "$cache" == "$MUTATION_RAM_ROOT"/* ]]
status="${MUTATION_TEST_STATUS:-KILLED}"
    suppressed="${MUTATION_TEST_SUPPRESSED:-0}"
    suppressed_by_calls="${MUTATION_TEST_SUPPRESSED_BY_CALLS:-0}"
    if [[ "$status" == EMPTY ]]; then
        printf '{"files":[],"mutants_total":0,"mutants_suppressed":%s,"mutants_suppressed_by_calls":%s}\n' \
            "$suppressed" "$suppressed_by_calls" >"$report"
    else
        printf '{"files":[{"mutations":[{"id":"value.go:Value:INVERT_LOOP_CTRL#1","original":"break","replacement":"continue","status":"%s"}]}],"mutants_suppressed":%s,"mutants_suppressed_by_calls":%s}\n' \
            "$status" "$suppressed" "$suppressed_by_calls" >"$report"
fi
printf '{"updated":true}\n' >"$cache"
printf '%s\n' "$PWD" >"$MUTATION_TEST_RECORD"
printf '%s\n' "$@" >>"$MUTATION_TEST_ARGS_RECORD"
printf '%s\n' --call-end >>"$MUTATION_TEST_ARGS_RECORD"
exit "${MUTATION_TEST_EXIT:-0}"
EOF
    chmod +x "$fixture/bin/"*
    printf '%s\n' "$fixture"
}

run_fixture() {
    local fixture="$1"
    shift
    PATH="$fixture/bin:$PATH" \
        GOMUTANTS_BIN="$fixture/bin/gomutants" \
        MUTATION_RAM_ROOT="$fixture/ram" \
        MUTATION_REPORT_DIR="$fixture/reports" \
        MUTATION_CACHE_FILE="build/.gomutants-cache.json" \
        MUTATION_CANARY_FILE="build/mutation-canaries.txt" \
        MUTATION_TEST_SOURCE="$fixture/repo" \
        MUTATION_TEST_RECORD="$fixture/record" \
        MUTATION_TEST_ARGS_RECORD="$fixture/args-record" \
        MUTATION_TEST_PERSISTENT_CACHE="$fixture/repo/build/.gomutants-cache.json" \
        MUTATION_TEST_GOMODCACHE="$fixture/modcache" \
        bash "$fixture/repo/build/run-mutation.sh" "$@"
}

fixture="$(make_fixture changed-lines)"
MUTATION_TEST_EXPECT_STAGED=new.go run_fixture "$fixture" changed-lines --base HEAD ./...
workspace="$(cat "$fixture/record")"
[[ ! -e "$workspace" ]] || fail "成功后未清理 RAM 工作区"
grep -Fq 'return 1' "$fixture/repo/value.go" || fail "真实工作区被改写"
grep -Fq '"updated":true' "$fixture/repo/build/.gomutants-cache.json" || fail "有效运行 cache 未原子写回"
[[ -f "$fixture/reports/changed-lines.json" ]] || fail "changed-line 报告未复制出 RAM"
for option in --changed-since HEAD --workers=2 --detect-equivalent --threshold-efficacy=100 --threshold-mcover=100; do
    grep -Fxq -- "$option" "$fixture/args-record" || fail "changed-line 缺少参数: $option"
done
for target in example.test/fixture example.test/fixture/sub; do
    grep -Fxq -- "$target" "$fixture/args-record" || fail "遗漏解析后的包: $target"
done

fixture="$(make_fixture list-failed)"
if MUTATION_TEST_LIST_FAIL=1 run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "包解析失败被错误接受"
fi
[[ ! -f "$fixture/args-record" ]] || fail "包解析失败后仍调用 gomutants"

fixture="$(make_fixture list-empty)"
if MUTATION_TEST_LIST_EMPTY=1 run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "空包集合被错误接受"
fi
[[ ! -f "$fixture/args-record" ]] || fail "空包集合后仍调用 gomutants"

fixture="$(make_fixture no-mutants)"
MUTATION_TEST_STATUS=EMPTY run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output"
grep -Fq 'mutation=no-mutants-on-changed-lines' "$fixture/output" || fail "无 mutant 未输出明确结论"

fixture="$(make_fixture suppressed-directive)"
if MUTATION_TEST_STATUS=EMPTY MUTATION_TEST_SUPPRESSED=1 \
    run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "源码 gomutants 抑制指令被错误接受"
fi
grep -Fq '源码抑制了 1 个 mutant' "$fixture/output" || fail "源码抑制失败原因不明确"

fixture="$(make_fixture suppressed-call)"
MUTATION_TEST_STATUS=EMPTY MUTATION_TEST_SUPPRESSED=1 MUTATION_TEST_SUPPRESSED_BY_CALLS=1 \
    run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output"

fixture="$(make_fixture canaries)"
run_fixture "$fixture" canaries ./...
grep -Fxq -- --run-mutant-id "$fixture/args-record" || fail "canary 未按 stable ID 运行"
[[ -f "$fixture/reports/canary-1.json" ]] || fail "canary 报告未复制出 RAM"

fixture="$(make_fixture missing-canary)"
if run_fixture "$fixture" canaries ./pkg/config >"$fixture/output" 2>&1; then
    fail "关键包缺少 canary 时被错误接受"
fi
grep -Fq '没有匹配的 mutation canary' "$fixture/output" || fail "缺少 canary 失败原因不明确"

fixture="$(make_fixture partially-missing-canary)"
printf './pkg/validator\tpkg/validator/value.go:Value:CONDITIONALS_NEGATION#1\n' \
    >"$fixture/repo/build/mutation-canaries.txt"
if run_fixture "$fixture" canaries ./pkg/validator ./pkg/config >"$fixture/output" 2>&1; then
    fail "多个关键包中部分缺少 canary 时被错误接受"
fi
grep -Fq './pkg/config 没有匹配的 mutation canary' "$fixture/output" || fail "部分缺少 canary 失败原因不明确"

fixture="$(make_fixture lived)"
if MUTATION_TEST_STATUS=LIVED run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "LIVED 状态被错误接受"
fi
grep -Fq '不允许状态: LIVED' "$fixture/output" || fail "LIVED 失败原因不明确"

make_equivalent() {
    python3 - "$1/repo" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
entry = {"id": "value.go:Value:INVERT_LOOP_CTRL#1", "original": "break", "replacement": "continue",
         "sources": {"value.go": hashlib.sha256((root / "value.go").read_bytes()).hexdigest()},
         "reason": "契约测试的等价证明占位，仅验证严格匹配和失效机制。"}
(root / "build/mutation-equivalents.json").write_text(json.dumps({"version": 1, "equivalents": [entry]}))
PY
}

fixture="$(make_fixture equivalent)"
make_equivalent "$fixture"
MUTATION_TEST_STATUS=LIVED MUTATION_TEST_EXIT=10 run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output"
grep -Fq 'approved-equivalent value.go:Value:INVERT_LOOP_CTRL#1' "$fixture/output" || fail "等价证明未记录"
grep -Fq '"status":"LIVED"' "$fixture/reports/changed-lines.json" || fail "原始报告被改写"

for failure in stale mismatch duplicate missing-proof uncovered timed-out infrastructure canary; do
    fixture="$(make_fixture "equivalent-$failure")"
    make_equivalent "$fixture"
    status=LIVED
    exit_code=10
    mode=changed-lines
    case "$failure" in
        stale) printf '\n// changed\n' >>"$fixture/repo/value.go" ;;
        mismatch) sed -i.bak 's/"break"/"return"/' "$fixture/repo/build/mutation-equivalents.json" ;;
        duplicate) python3 - "$fixture/repo/build/mutation-equivalents.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data["equivalents"] *= 2
open(path, "w").write(json.dumps(data))
PY
        ;;
        missing-proof) sed -i.bak 's/"sources": {[^}]*}/"sources": {}/' "$fixture/repo/build/mutation-equivalents.json" ;;
        uncovered) status='NOT COVERED' ;;
        timed-out) status='TIMED OUT' ;;
        infrastructure) exit_code=124 ;;
        canary) mode=canaries ;;
    esac
    args=("$mode")
    [[ "$mode" != changed-lines ]] || args+=(--base HEAD)
    if MUTATION_TEST_STATUS="$status" MUTATION_TEST_EXIT="$exit_code" run_fixture "$fixture" "${args[@]}" ./... >"$fixture/output" 2>&1; then
        fail "等价清单错误放行: $failure"
    fi
done

fixture="$(make_fixture non-ram)"
if MUTATION_TEST_FS_TYPE=ext4 run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "非 RAM 文件系统被错误接受"
fi
grep -Fq '不是 tmpfs/ramfs' "$fixture/output" || fail "非 RAM 拒绝原因不明确"

fixture="$(make_fixture wrong-version)"
if MUTATION_TEST_TOOL_VERSION=v0.5.0 run_fixture "$fixture" changed-lines --base HEAD ./... >"$fixture/output" 2>&1; then
    fail "错误 gomutants 版本被接受"
fi
grep -Fq 'gomutants 版本必须为 v0.6.0' "$fixture/output" || fail "版本拒绝原因不明确"

fixture="$(make_fixture interrupted)"
PATH="$fixture/bin:$PATH" \
    GOMUTANTS_BIN="$fixture/bin/gomutants" \
    MUTATION_RAM_ROOT="$fixture/ram" \
    MUTATION_CACHE_FILE="build/.gomutants-cache.json" \
    MUTATION_CANARY_FILE="build/mutation-canaries.txt" \
    MUTATION_TEST_SOURCE="$fixture/repo" \
    MUTATION_TEST_RECORD="$fixture/record" \
    MUTATION_TEST_ARGS_RECORD="$fixture/args-record" \
    MUTATION_TEST_PERSISTENT_CACHE="$fixture/repo/build/.gomutants-cache.json" \
    MUTATION_TEST_GOMODCACHE="$fixture/modcache" \
    MUTATION_TEST_BLOCK=1 \
    MUTATION_TEST_PID_FILE="$fixture/gomutants.pid" \
    python3 - "$fixture" <<'PY' || fail "中断后遗留 gomutants 子进程"
import os
import signal
import subprocess
import sys
import time

fixture = sys.argv[1]
process = subprocess.Popen(
    ["bash", f"{fixture}/repo/build/run-mutation.sh", "changed-lines", "--base", "HEAD", "./..."],
    cwd=f"{fixture}/repo",
    env=os.environ.copy(),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
pid_file = f"{fixture}/gomutants.pid"
for _ in range(100):
    if os.path.exists(pid_file):
        break
    if process.poll() is not None:
        raise SystemExit("runner exited before starting gomutants")
    time.sleep(0.05)
else:
    process.kill()
    raise SystemExit("gomutants did not start")

with open(pid_file, encoding="utf-8") as handle:
    child_pid = int(handle.read().strip())
os.killpg(process.pid, signal.SIGTERM)
try:
    process.wait(timeout=5)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGKILL)
    process.wait()

time.sleep(0.2)
try:
    os.kill(child_pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
try:
    os.killpg(child_pid, signal.SIGKILL)
except ProcessLookupError:
    pass
raise SystemExit("orphan gomutants process is still alive")
PY

router="$TEST_ROOT/router"
mkdir -p "$router/build"
cp "$ROOT/build/run-changed-checks.sh" "$router/build/run-changed-checks.sh"
cat >"$router/build/run-mutation.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\t%s\n' "$MUTATION_DEADLINE_EPOCH" "$*" >>"$MUTATION_TEST_ROUTER_RECORD"
EOF
cat >"$router/plan.json" <<'EOF'
{"base":"HEAD","changed_files":["pkg/config/config.go","pkg/config/config_test.go"],"go":{"test_packages":[],"lint_packages":[],"build_all":false},"contracts":{"shell_files":[],"mutation":false,"agent_config":false,"release":false,"docker_e2e":false},"mutation":{"mode":"changed-lines","packages":["./pkg/config"],"canary_packages":["./pkg/config"]},"reasons":[]}
EOF
MUTATION_TEST_ROUTER_RECORD="$router/record" FINISH_CHECK_TESTING=1 FINISH_CHECK_TEST_PLAN_FILE="$router/plan.json" \
    bash "$router/build/run-changed-checks.sh" --mutation-only >/dev/null
[[ "$(wc -l <"$router/record" | tr -d ' ')" == 2 ]] || fail "生产与测试同时变更时未运行两条 mutation 路径"
first_deadline="$(sed -n '1s/\t.*//p' "$router/record")"
second_deadline="$(sed -n '2s/\t.*//p' "$router/record")"
[[ "$first_deadline" == "$second_deadline" ]] || fail "changed-line 与 canary 未共享同一截止时间"
grep -Fq $'changed-lines --base HEAD ./pkg/config' "$router/record" || fail "changed-line 路由参数错误"
grep -Fq $'canaries ./pkg/config' "$router/record" || fail "canary 路由参数错误"

echo "gomutants RAM 隔离脚本测试通过"
