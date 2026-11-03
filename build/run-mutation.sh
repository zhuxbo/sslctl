#!/usr/bin/env bash
# 在一次性 RAM 盘副本中运行固定版本 gomutants。

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CALLER_DIR="$(pwd -P)"
GOMUTANTS_VERSION="v0.6.0"
GO_TOOLCHAIN="go1.26.8"
RAM_MB="${MUTATION_RAM_MB:-3072}"
TIMEOUT_SECONDS="${MUTATION_TIMEOUT_SECONDS:-1200}"
CACHE_FILE="${MUTATION_CACHE_FILE:-build/.gomutants-cache.json}"
CANARY_FILE="${MUTATION_CANARY_FILE:-build/mutation-canaries.txt}"
RAM_DEVICE=""
RAM_MOUNT=""
RUN_ROOT=""
RAM_CACHE=""
REPORT_DIR="${MUTATION_REPORT_DIR:-}"

fail() { echo "mutation 运行失败: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法:
  build/run-mutation.sh changed-lines --base <git-ref> <package...>
  build/run-mutation.sh canaries <package...>
EOF
}

valid_json() {
    [[ -f "$1" ]] && python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$1" >/dev/null 2>&1
}

persist_outputs() {
    local source temp
    if [[ -n "$REPORT_DIR" && -n "$RUN_ROOT" && -d "$RUN_ROOT/reports" ]]; then
        mkdir -p "$REPORT_DIR"
        while IFS= read -r source; do cp "$source" "$REPORT_DIR/$(basename "$source")"; done \
            < <(find "$RUN_ROOT/reports" -maxdepth 1 -type f -name '*.json' -print)
    fi
    if [[ -n "$RAM_CACHE" && -f "$RAM_CACHE" ]]; then
        valid_json "$RAM_CACHE" || return 1
        mkdir -p "$(dirname "$ROOT/$CACHE_FILE")"
        temp="$(mktemp "$ROOT/$CACHE_FILE.tmp.XXXXXX")"
        cp "$RAM_CACHE" "$temp"
        mv "$temp" "$ROOT/$CACHE_FILE"
    fi
}

cleanup() {
    local status=$?
    trap - EXIT
    cd "$ROOT" 2>/dev/null || status=1
    persist_outputs || { echo "mutation 运行失败: 报告或 cache 不是有效 JSON" >&2; status=1; }
    if [[ -n "$RUN_ROOT" && -d "$RUN_ROOT" ]]; then
        chmod -R u+w "$RUN_ROOT" 2>/dev/null || true
        rm -rf "$RUN_ROOT" || status=1
    fi
    if [[ -n "$RAM_DEVICE" ]]; then
        hdiutil detach "$RAM_DEVICE" >/dev/null 2>&1 || \
            hdiutil detach -force "$RAM_DEVICE" >/dev/null 2>&1 || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

validate_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "$2 必须为正整数"
}

validate_linux_ram_root() {
    local fs_type
    command -v findmnt >/dev/null 2>&1 || fail "Linux 缺少 findmnt，无法验证 RAM 文件系统"
    fs_type="$(findmnt -n -o FSTYPE -T "$1" 2>/dev/null || true)"
    [[ "$fs_type" == tmpfs || "$fs_type" == ramfs ]] || fail "$1 不是 tmpfs/ramfs（实际: ${fs_type:-未知}）"
}

validate_darwin_ram_root() {
    local device info
    device="$(df "$1" | awk 'END {print $1}')"
    info="$(hdiutil info 2>/dev/null || true)"
    [[ "$device" == /dev/* && "$info" == *"ram://"* && "$info" == *"$device"* ]] || \
        fail "$1 不是可验证的 macOS RAM Disk"
}

select_ram_root() {
    local os_name requested_root sectors volume_name
    os_name="$(uname -s)"
    requested_root="${MUTATION_RAM_ROOT:-}"
    if [[ -n "$requested_root" ]]; then
        [[ -d "$requested_root" ]] || fail "MUTATION_RAM_ROOT 不存在: $requested_root"
        RAM_MOUNT="$(cd "$requested_root" && pwd -P)"
        case "$os_name" in
            Linux) validate_linux_ram_root "$RAM_MOUNT" ;;
            Darwin) validate_darwin_ram_root "$RAM_MOUNT" ;;
            *) fail "不支持在 $os_name 验证 MUTATION_RAM_ROOT" ;;
        esac
        return
    fi
    case "$os_name" in
        Linux)
            [[ -d /dev/shm ]] || fail "Linux 缺少 /dev/shm"
            validate_linux_ram_root /dev/shm
            RAM_MOUNT=/dev/shm
            ;;
        Darwin)
            command -v hdiutil >/dev/null 2>&1 || fail "macOS 缺少 hdiutil"
            command -v diskutil >/dev/null 2>&1 || fail "macOS 缺少 diskutil"
            validate_positive_integer "$RAM_MB" MUTATION_RAM_MB
            sectors="$((RAM_MB * 2048))"
            volume_name="sslctl-mutation-$$"
            RAM_DEVICE="$(hdiutil attach -nomount "ram://$sectors" | awk 'NR == 1 {print $1}')"
            [[ "$RAM_DEVICE" == /dev/* ]] || fail "无法创建 macOS RAM Disk"
            diskutil erasevolume APFS "$volume_name" "$RAM_DEVICE" >/dev/null
            RAM_MOUNT="/Volumes/$volume_name"
            [[ -d "$RAM_MOUNT" ]] || fail "无法取得 macOS RAM Disk 挂载点"
            ;;
        *) fail "只支持 Linux tmpfs 或 macOS APFS RAM Disk" ;;
    esac
}

resolve_gomutants() {
    local binary metadata
    binary="${GOMUTANTS_BIN:-$(command -v gomutants || true)}"
    [[ -n "$binary" && -x "$binary" ]] || \
        fail "未找到 gomutants；请安装 github.com/szhekpisov/gomutants@$GOMUTANTS_VERSION"
    metadata="$(GOTOOLCHAIN="$GO_TOOLCHAIN" go version -m "$binary" 2>/dev/null || true)"
    grep -Eq '^[[:space:]]*path[[:space:]]+github\.com/szhekpisov/gomutants$' <<<"$metadata" || \
        fail "$binary 不是预期的 gomutants 二进制"
    grep -Eq "^[[:space:]]*mod[[:space:]]+github\.com/szhekpisov/gomutants[[:space:]]+$GOMUTANTS_VERSION([[:space:]]|$)" <<<"$metadata" || \
        fail "gomutants 版本必须为 $GOMUTANTS_VERSION"
    printf '%s\n' "$binary"
}

copy_workspace() {
    command -v rsync >/dev/null 2>&1 || fail "缺少 rsync"
    case "$RAM_MOUNT/" in "$ROOT/"*) fail "MUTATION_RAM_ROOT 不能位于项目目录内" ;; esac
    rsync -a \
        --exclude '/.superpowers/' \
        --exclude '/.release-bundles/' \
        --exclude '/.release-state/' \
        --exclude '/dist/' \
        --exclude '/coverage.out' \
        --exclude '/build/.gomutants-cache.json' \
        "$ROOT/" "$1/"
}

run_with_deadline() {
    python3 - "$DEADLINE_EPOCH" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

deadline, command = int(sys.argv[1]), sys.argv[2:]
remaining = deadline - int(time.time())
if remaining <= 0:
    print("mutation: 已用完 20 分钟共享预算", file=sys.stderr)
    raise SystemExit(124)
process = subprocess.Popen(command, start_new_session=True)

def terminate_process():
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)

for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, interrupted)

try:
    raise SystemExit(process.wait(timeout=remaining))
except subprocess.TimeoutExpired:
    print("mutation: 超过 20 分钟共享预算", file=sys.stderr)
    terminate_process()
    raise SystemExit(124)
except BaseException:
    terminate_process()
    raise
PY
}

validate_report() {
    python3 - "$1" "$2" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

path, mode = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    report = json.load(handle)
mutations = [mutation for file in report.get("files", []) for mutation in file.get("mutations", [])]
suppressed = report.get("mutants_suppressed", 0)
suppressed_by_calls = report.get("mutants_suppressed_by_calls", 0)
if not isinstance(suppressed, int) or not isinstance(suppressed_by_calls, int) or not 0 <= suppressed_by_calls <= suppressed:
    print("mutation 运行失败: 抑制计数无效", file=sys.stderr)
    raise SystemExit(1)
directive_suppressed = suppressed - suppressed_by_calls
if directive_suppressed:
    print(f"mutation 运行失败: 源码抑制了 {directive_suppressed} 个 mutant", file=sys.stderr)
    raise SystemExit(1)
if mode == "changed-lines" and not mutations:
    print("mutation=no-mutants-on-changed-lines")
    raise SystemExit(0)
if mode == "canary":
    if len(mutations) != 1 or mutations[0].get("status") != "KILLED":
        status = mutations[0].get("status", "MISSING") if mutations else "MISSING"
        print(f"mutation 运行失败: canary 必须唯一且为 KILLED（实际: {status}）", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0)
# 只认可逐项证明且依赖源码未变的等价项；原始报告和框架缓存保持原样。
manifest = Path("build/mutation-equivalents.json")
entries = {}
try:
    if manifest.exists():
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if document.get("version") != 1 or not isinstance(document.get("equivalents"), list):
            raise ValueError("等价清单格式无效")
        for entry in document["equivalents"]:
            if set(entry) != {"id", "original", "replacement", "sources", "reason"}:
                raise ValueError("等价条目字段无效")
            ident = entry["id"]
            if not isinstance(ident, str) or ident in entries or not entry["reason"].strip():
                raise ValueError("等价条目重复或缺少证明")
            if not isinstance(entry["sources"], dict) or ident.split(":", 1)[0] not in entry["sources"]:
                raise ValueError("等价条目未绑定变异源码")
            entries[ident] = entry
    approved = []
    for mutation in mutations:
        entry = entries.get(mutation.get("id"))
        if entry is None or mutation.get("status") != "LIVED":
            continue
        if any(mutation.get(field) != entry[field] for field in ("original", "replacement")):
            raise ValueError("等价条目的原文或替换内容已变化: " + entry["id"])
        for source, digest in entry["sources"].items():
            file = Path(source)
            if file.is_absolute() or ".." in file.parts or not file.resolve().is_relative_to(Path.cwd()):
                raise ValueError("等价证明的源码路径无效")
            if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                raise ValueError("等价证明的源码已变化: " + source)
        approved.append(entry["id"])
        print("mutation: approved-equivalent " + entry["id"] + " — " + entry["reason"])
except (ValueError, TypeError, KeyError, AttributeError, OSError) as err:
    print("mutation 运行失败: " + str(err), file=sys.stderr)
    raise SystemExit(1)
allowed = {"KILLED", "NOT VIABLE", "EQUIVALENT"}
invalid = sorted({m.get("status", "MISSING").replace("_", " ") for m in mutations
                  if not (m.get("status") == "LIVED" and m.get("id") in approved)} - allowed)
if invalid:
    print("mutation 运行失败: 不允许状态: " + ", ".join(invalid), file=sys.stderr)
    raise SystemExit(1)
# 20 仅表示验证通过且使用了人工等价证明，不用于错误或超时状态。
raise SystemExit(20 if approved else 0)
PY
}

run_gomutants() {
    local report="$1"
    local validation_mode="$2"
    shift 2
    local command_status validation_status=0
    set +e
    run_with_deadline "$GOMUTANTS" --cache "$RAM_CACHE" -o "$report" "$@"
    command_status=$?
    set -e
    if [[ -f "$report" ]]; then
        validate_report "$report" "$validation_mode" || validation_status=$?
    else
        echo "mutation 运行失败: gomutants 未生成 JSON 报告" >&2
        validation_status=1
    fi
    if [[ "$validation_status" -eq 20 ]]; then
        # efficacy 阈值仍为 100；只有剩余项均已证明等价才接受 exit 10。
        [[ "$command_status" -eq 0 || "$command_status" -eq 10 ]] || return "$command_status"
        return 0
    fi
    [[ "$command_status" -eq 0 ]] || return "$command_status"
    return "$validation_status"
}

[[ $# -gt 0 ]] || { usage >&2; exit 2; }
MODE="$1"
shift
TARGETS=()
BASE=""
case "$MODE" in
    changed-lines)
        [[ "${1:-}" == --base && -n "${2:-}" ]] || fail "changed-lines 必须提供 --base <git-ref>"
        BASE="$2"
        shift 2
        [[ $# -gt 0 ]] || fail "changed-lines 至少需要一个包目标"
        TARGETS=("$@")
        ;;
    canaries)
        [[ $# -gt 0 ]] || fail "canaries 至少需要一个包目标"
        TARGETS=("$@")
        ;;
    -h|--help|help) usage; exit 0 ;;
    *) usage >&2; fail "未知模式: $MODE" ;;
esac

[[ "$CACHE_FILE" != /* && "$CACHE_FILE" != *".."* ]] || fail "MUTATION_CACHE_FILE 必须是仓库内相对路径"
[[ "$CANARY_FILE" != /* && "$CANARY_FILE" != *".."* ]] || fail "MUTATION_CANARY_FILE 必须是仓库内相对路径"
validate_positive_integer "$TIMEOUT_SECONDS" MUTATION_TIMEOUT_SECONDS
if [[ -n "$REPORT_DIR" && "$REPORT_DIR" != /* ]]; then REPORT_DIR="$CALLER_DIR/$REPORT_DIR"; fi
DEADLINE_EPOCH="${MUTATION_DEADLINE_EPOCH:-$(( $(date +%s) + TIMEOUT_SECONDS ))}"
validate_positive_integer "$DEADLINE_EPOCH" MUTATION_DEADLINE_EPOCH
PERSISTENT_GOMODCACHE="${GOMODCACHE:-$(GOTOOLCHAIN="$GO_TOOLCHAIN" go env GOMODCACHE)}"

select_ram_root
GOMUTANTS="$(resolve_gomutants)"
RUN_ROOT="$(mktemp -d "$RAM_MOUNT/sslctl-mutation.XXXXXX")"
WORKSPACE="$RUN_ROOT/workspace"
RAM_CACHE="$RUN_ROOT/cache.json"
mkdir -p "$WORKSPACE" "$RUN_ROOT/gocache" "$RUN_ROOT/gotmp" "$RUN_ROOT/tmp" "$RUN_ROOT/reports"
copy_workspace "$WORKSPACE"
if valid_json "$ROOT/$CACHE_FILE"; then cp "$ROOT/$CACHE_FILE" "$RAM_CACHE"; fi

export GOTOOLCHAIN="$GO_TOOLCHAIN"
export GOCACHE="$RUN_ROOT/gocache"
export GOMODCACHE="$PERSISTENT_GOMODCACHE"
export GOTMPDIR="$RUN_ROOT/gotmp"
export TMPDIR="$RUN_ROOT/tmp"

cd "$WORKSPACE"
git add -A
echo "mutation: framework=gomutants@$GOMUTANTS_VERSION mode=$MODE budget=${TIMEOUT_SECONDS}s ram=$RAM_MOUNT"

COMMON_ARGS=(--workers="${MUTATION_WORKERS:-2}" --detect-equivalent)
# v0.6.0 的 per-test map 按完整导入路径索引；相对路径会退化为逐 mutant 跑整包。
resolve_targets() {
    local output target
    output="$(run_with_deadline go list -f '{{.ImportPath}}' "$@")" || fail "无法解析 mutation 包目标"
    RESOLVED_TARGETS=()
    while IFS= read -r target; do
        [[ -n "$target" ]] && RESOLVED_TARGETS+=("$target")
    done <<<"$output"
    [[ ${#RESOLVED_TARGETS[@]} -gt 0 ]] || fail "mutation 包目标为空"
}
if [[ "$MODE" == changed-lines ]]; then
    resolve_targets "${TARGETS[@]}"
    run_gomutants "$RUN_ROOT/reports/changed-lines.json" changed-lines \
        --changed-since "$BASE" --threshold-efficacy=100 --threshold-mcover=100 \
        "${COMMON_ARGS[@]}" "${RESOLVED_TARGETS[@]}"
else
    [[ -f "$CANARY_FILE" ]] || fail "缺少 mutation canary 清单: $CANARY_FILE"
    canary_count=0
    for target in "${TARGETS[@]}"; do
        package_count=0
        while IFS=$'\t' read -r package mutant_id extra || [[ -n "$package$mutant_id$extra" ]]; do
            [[ -z "$package" || "$package" == \#* ]] && continue
            [[ -n "$mutant_id" && -z "$extra" ]] || fail "mutation canary 清单格式错误"
            [[ "$package" == "$target" ]] || continue
            package_count=$((package_count + 1))
            canary_count=$((canary_count + 1))
            resolve_targets "$package"
            run_gomutants "$RUN_ROOT/reports/canary-$canary_count.json" canary \
                --run-mutant-id "$mutant_id" "${COMMON_ARGS[@]}" "${RESOLVED_TARGETS[@]}"
        done <"$CANARY_FILE"
        [[ "$package_count" -gt 0 ]] || fail "$target 没有匹配的 mutation canary"
    done
fi

ram_used_kib="$(du -sk "$RUN_ROOT" 2>/dev/null | awk '{print $1}')"
[[ "$ram_used_kib" =~ ^[0-9]+$ ]] && echo "mutation: ram-used-mib=$(( (ram_used_kib + 1023) / 1024 ))"
