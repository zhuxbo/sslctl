#!/usr/bin/env bash
# 发布 helper/阶段门禁的离线回归测试；不联网、不改 Git 引用。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
HELPER="$SCRIPT_DIR/release_helper.py"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sslctl-release-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

assets="$TEST_DIR/assets"
mkdir -p "$assets"
printf 'linux-amd64\n' >"$assets/sslctl-linux-amd64.gz"
printf 'linux-arm64\n' >"$assets/sslctl-linux-arm64.gz"
printf 'windows-amd64\n' >"$assets/sslctl-windows-amd64.exe.gz"

key_dir="$TEST_DIR/keys"
bash "$SCRIPT_DIR/generate-keys.sh" "$key_dir" test-key >/dev/null
key="$key_dir/release-key.pem"
[[ "$(stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key")" == "600" ]]
if bash "$SCRIPT_DIR/generate-keys.sh" "$key_dir" replacement-key >/dev/null 2>&1; then
    echo "密钥生成脚本覆盖了已有密钥" >&2
    exit 1
fi
signatures="$TEST_DIR/signatures.json"
bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --assets-dir "$assets" --output "$signatures" >/dev/null
bash "$SCRIPT_DIR/sign-release.sh" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --assets-dir "$assets" --verify-signatures "$signatures" >/dev/null
if bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id test-key --assets-dir "$assets" --output "$TEST_DIR/untrusted.json" >/dev/null 2>&1; then
    echo "客户端未信任的签名 key ID 未被拒绝" >&2
    exit 1
fi
if bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id key-1 --assets-dir "$assets" --output "$TEST_DIR/mismatched.json" >/dev/null 2>&1; then
    echo "与客户端内置公钥不匹配的私钥未被拒绝" >&2
    exit 1
fi

commit="$(git -C "$ROOT" rev-parse HEAD)"
dev_bundle="$TEST_DIR/dev-bundle"
mkdir -p "$dev_bundle"
cp -R "$assets" "$dev_bundle/assets"
python3 "$HELPER" create-manifest --version 1.2.3-rc.1 --assets-dir "$dev_bundle/assets" \
    --signatures "$signatures" --output "$dev_bundle/manifest.json" --source-commit "$commit" --dirty true \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test
python3 "$HELPER" verify-manifest --bundle "$dev_bundle" --version 1.2.3-rc.1 >/dev/null
python3 "$HELPER" update-index --index "$TEST_DIR/missing.json" --bundle "$dev_bundle" --version 1.2.3-rc.1 --output "$TEST_DIR/dev-index.json"
python3 "$HELPER" verify-index --index "$TEST_DIR/dev-index.json" --bundle "$dev_bundle" --version 1.2.3-rc.1
python3 "$HELPER" update-index --index "$TEST_DIR/dev-index.json" --bundle "$dev_bundle" --version 1.2.3-rc.1 --output "$TEST_DIR/dev-index-2.json"

main_bundle="$TEST_DIR/main-bundle"
mkdir -p "$main_bundle"
cp -R "$assets" "$main_bundle/assets"
python3 "$HELPER" create-manifest --version 1.2.3 --assets-dir "$main_bundle/assets" \
    --signatures "$signatures" --output "$main_bundle/manifest.json" --source-commit "$commit" --dirty false \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test
bash "$SCRIPT_DIR/sign-release.sh" --key "$key" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --manifest "$main_bundle/manifest.json" --output "$main_bundle/manifest.sig" >/dev/null
bash "$SCRIPT_DIR/sign-release.sh" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --manifest "$main_bundle/manifest.json" --verify-manifest-signature "$main_bundle/manifest.sig" >/dev/null
tampered_manifest="$TEST_DIR/tampered-manifest.json"
python3 - "$main_bundle/manifest.json" "$tampered_manifest" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["version"] = "9.9.9"
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), sort_keys=True)
PY
if bash "$SCRIPT_DIR/sign-release.sh" --key-id test-key --trusted-public-key "$key_dir/release-key.pub" \
    --manifest "$tampered_manifest" --verify-manifest-signature "$main_bundle/manifest.sig" >/dev/null 2>&1; then
    echo "manifest 签名未绑定版本和 commit 元数据" >&2
    exit 1
fi
python3 "$HELPER" update-index --index "$TEST_DIR/dev-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/main-index.json"
python3 "$HELPER" verify-index --index "$TEST_DIR/main-index.json" --bundle "$main_bundle" --version 1.2.3
if python3 "$HELPER" check-new-main --index "$TEST_DIR/main-index.json" --version 1.2.3 >/dev/null 2>&1; then
    echo "main preflight 未拒绝已存在版本" >&2
    exit 1
fi
python3 "$HELPER" check-new-main --index "$TEST_DIR/main-index.json" --version 1.2.4
if python3 "$HELPER" update-index --index "$TEST_DIR/main-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/forbidden.json" 2>/dev/null; then
    echo "main 同版本覆盖未被拒绝" >&2
    exit 1
fi

python3 - "$TEST_DIR/main-index.json" "$TEST_DIR/reconcile-cn.json" "$TEST_DIR/reconcile-us.json" <<'PY'
import copy, json, sys
source = json.load(open(sys.argv[1], encoding="utf-8"))
json.dump(source, open(sys.argv[2], "w", encoding="utf-8"), indent=2, sort_keys=True)
other = copy.deepcopy(source)
other["latest_main"] = "v0.3.1"
other["versions"] = {"v0.3.1": {"legacy": True}}
other["main"]["versions"][0]["released_at"] = "2026-07-18"
json.dump(other, open(sys.argv[3], "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
cn_safety_digest="$(python3 "$HELPER" index-safety-digest --index "$TEST_DIR/reconcile-cn.json")"
us_safety_digest="$(python3 "$HELPER" index-safety-digest --index "$TEST_DIR/reconcile-us.json")"
[[ "$cn_safety_digest" == "$us_safety_digest" ]]
python3 - "$TEST_DIR/reconcile-us.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["main"]["versions"][0]["checksums"]["sslctl-linux-amd64.gz"] = "sha256:" + "0" * 64
json.dump(value, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)
PY
tampered_safety_digest="$(python3 "$HELPER" index-safety-digest --index "$TEST_DIR/reconcile-us.json")"
if [[ "$cn_safety_digest" == "$tampered_safety_digest" ]]; then
    echo "索引安全摘要未识别安全字段漂移" >&2
    exit 1
fi

cp "$TEST_DIR/main-index.json" "$TEST_DIR/resume-index.json"
python3 "$HELPER" update-index --allow-existing-main --index "$TEST_DIR/resume-index.json" --bundle "$main_bundle" --version 1.2.3 --output "$TEST_DIR/resumed.json"
cmp "$TEST_DIR/resume-index.json" "$TEST_DIR/resumed.json"

if python3 "$HELPER" channel 01.2.3 >/dev/null 2>&1; then
    echo "非法 SemVer 未被拒绝" >&2
    exit 1
fi
if python3 "$HELPER" create-manifest --version 2.0.0 --assets-dir "$assets" \
    --signatures "$signatures" --output "$TEST_DIR/dirty-main.json" --source-commit "$commit" --dirty true \
    --created-at 2026-07-19T00:00:00Z --build-time 2026-07-19T00:00:00Z --go-version test 2>/dev/null; then
    echo "main dirty bundle 未被拒绝" >&2
    exit 1
fi

state_file="$TEST_DIR/release-state.json"
python3 "$HELPER" state-begin --state "$state_file" --version 1.2.3 --source-commit "$commit" --bundle /persistent/a
if python3 "$HELPER" state-begin --state "$state_file" --version 1.2.3 --source-commit "$commit" --bundle /persistent/b >/dev/null 2>&1; then
    echo "重复 main prepare 未被 release-state 拒绝" >&2
    exit 1
fi
python3 "$HELPER" state-complete --state "$state_file" --version 1.2.3 --source-commit "$commit" --bundle /persistent/a --bundle-digest sha256:test
python3 "$HELPER" state-verify --state "$state_file" --version 1.2.3 --source-commit "$commit" --bundle /persistent/a --bundle-digest sha256:test
if python3 "$HELPER" state-begin --state "$state_file" --version 1.2.3 --source-commit "$commit" --bundle /persistent/a >/dev/null 2>&1; then
    echo "已完成 main bundle 被再次 prepare" >&2
    exit 1
fi
aborted_state="$TEST_DIR/aborted-state.json"
python3 "$HELPER" state-begin --state "$aborted_state" --version 2.0.0 --source-commit "$commit" --bundle /persistent/first
python3 "$HELPER" state-abort --state "$aborted_state" --version 2.0.0 --source-commit "$commit" --bundle /persistent/first
python3 "$HELPER" state-begin --state "$aborted_state" --version 2.0.0 --source-commit "$commit" --bundle /persistent/second

concurrent_state="$TEST_DIR/concurrent-state.json"
set +e
python3 "$HELPER" state-begin --state "$concurrent_state" --version 3.0.0 --source-commit "$commit" --bundle /persistent/concurrent-a >/dev/null 2>&1 &
first_pid=$!
python3 "$HELPER" state-begin --state "$concurrent_state" --version 3.0.0 --source-commit "$commit" --bundle /persistent/concurrent-b >/dev/null 2>&1 &
second_pid=$!
wait "$first_pid"; first_status=$?
wait "$second_pid"; second_status=$?
set -e
if (( (first_status == 0) + (second_status == 0) != 1 )); then
    echo "并发 state-begin 未保证只有一个成功" >&2
    exit 1
fi
missing_abort_state="$TEST_DIR/missing-abort-state.json"
python3 "$HELPER" state-abort --state "$missing_abort_state" --version 4.0.0 --source-commit "$commit" --bundle /persistent/missing
python3 "$HELPER" state-begin --state "$missing_abort_state" --version 4.0.0 --source-commit "$commit" --bundle /persistent/retry
extra_bundle="$TEST_DIR/extra-bundle"
cp -R "$main_bundle" "$extra_bundle"
printf 'extra\n' >"$extra_bundle/assets/unexpected.gz"
if python3 "$HELPER" verify-manifest --bundle "$extra_bundle" >/dev/null 2>&1; then
    echo "额外正式资产未被拒绝" >&2
    exit 1
fi
printf 'tamper' >>"$dev_bundle/assets/sslctl-linux-amd64.gz"
if python3 "$HELPER" verify-manifest --bundle "$dev_bundle" >/dev/null 2>&1; then
    echo "bundle 篡改未被拒绝" >&2
    exit 1
fi

dry_output="$(bash "$SCRIPT_DIR/release.sh" --dry-run resume-main 1.2.3 --bundle "$main_bundle")"
grep -Fq '只读 bundle' <<<"$dry_output"
grep -Fq '不执行任何动作' <<<"$dry_output"

simple_dev_output="$(bash "$SCRIPT_DIR/release.sh" --dry-run 1.2.3-beta.3)"
grep -Fq '自动识别通道: dev' <<<"$simple_dev_output"
grep -Fq 'prepare -> publish-dev（内含全节点验收）' <<<"$simple_dev_output"
set +e
simple_main_output="$(bash "$SCRIPT_DIR/release.sh" --dry-run 1.2.3 2>&1)"
simple_main_status=$?
set -e
[[ "$simple_main_status" -ne 0 ]]
grep -Fq '自动识别通道: main' <<<"$simple_main_output"
grep -Fq '正式发布流程' <<<"$simple_main_output"

grep -Fq 'workspace_fingerprint' "$SCRIPT_DIR/release.sh"
grep -Fq 'snapshot_worktree' "$SCRIPT_DIR/release.sh"
grep -Fq 'SSLCTL_SOURCE_DIR' "$SCRIPT_DIR/build.sh"
grep -Fq 'canonical_main_bundle' "$SCRIPT_DIR/release.sh"
grep -Fq 'acquire_release_locks' "$SCRIPT_DIR/release.sh"
grep -Fq 'begin_remote_release_state' "$SCRIPT_DIR/release.sh"
grep -Fq 'verify_remote_release_state' "$SCRIPT_DIR/release.sh"
grep -Eq 'prepare\).*with_release_locks prepare_bundle' "$SCRIPT_DIR/release.sh"
grep -Eq 'promote-main\).*stage_all' "$SCRIPT_DIR/release.sh"
grep -Fq 'manifest.sig' "$SCRIPT_DIR/release.sh"
grep -Fq 'verify_bundle_versions' "$SCRIPT_DIR/release.sh"
grep -Fq 'verify_remote_asset_set' "$SCRIPT_DIR/release.sh"
grep -Fq 'GOTOOLCHAIN=' "$SCRIPT_DIR/build.sh"
grep -Fxq 'go 1.26.0' "$ROOT/go.mod"
grep -Fxq 'toolchain go1.26.8' "$ROOT/go.mod"
grep -Fq '^go1\.26\.[0-9]+$' "$SCRIPT_DIR/build.sh"

grep -Fq 'if ((${#LOCKED_SERVERS[@]})); then' "$SCRIPT_DIR/release.sh"
grep -Fq 'index-safety-digest' "$SCRIPT_DIR/release.sh"

if grep -Fq 'PUBLIC_RELEASE_URL' "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/release.conf.example"; then
    echo "发布脚本仍要求重复配置 PUBLIC_RELEASE_URL" >&2
    exit 1
fi
grep -Fq 'server_public_url' "$SCRIPT_DIR/release.sh"
grep -Fq "printf 'https://%s/sslctl\\n' \"\$SERVER_HOST\"" "$SCRIPT_DIR/release.sh"
grep -Fq 'verify_public_server "$server"' "$SCRIPT_DIR/release.sh"
grep -Fq 'load_bundle_root()' "$SCRIPT_DIR/release.sh"
grep -Fq 'prepare) if [[ "$CHANNEL" == "main" ]]; then load_config; load_bundle_root;' "$SCRIPT_DIR/release.sh"
if grep -F 'publish-dev)' "$SCRIPT_DIR/release.sh" | grep -Fq 'load_bundle_root'; then
    echo "测试版发布仍被正式版 BUNDLE_ROOT 配置阻塞" >&2
    exit 1
fi
grep -Fq 'rsync_file "$PROJECT_ROOT/deploy/install.sh"' "$SCRIPT_DIR/release.sh"
grep -Fq 'rsync_file "$PROJECT_ROOT/deploy/install.ps1"' "$SCRIPT_DIR/release.sh"
if grep -Eq '__RELEASE_URL__|sed .*install\.(sh|ps1)' "$SCRIPT_DIR/release.sh"; then
    echo "发布脚本仍向安装脚本注入发布地址" >&2
    exit 1
fi

install_ps1="$ROOT/deploy/install.ps1"
if grep -Fq -- '-notlike "*$InstallDir*"' "$install_ps1"; then
    echo "Windows 安装脚本仍使用子串判断 PATH，可能把 sslctlw 误认为 sslctl" >&2
    exit 1
fi
grep -Fq 'function Test-PathContainsDirectory' "$install_ps1"
grep -Fq '$PathValue -split ";"' "$install_ps1"
grep -Fq '[System.StringComparison]::OrdinalIgnoreCase' "$install_ps1"
if [[ "$(grep -Fc 'Ensure-InstallDirOnPath -Directory $InstallDir' "$install_ps1")" -ne 2 ]]; then
    echo "Windows 安装脚本未同时覆盖同版本自愈和安装后 PATH 写入" >&2
    exit 1
fi

echo "发布离线回归测试通过"
