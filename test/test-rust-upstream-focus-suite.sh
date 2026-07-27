#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: Linux-only upstream focus suite runner."
    exit 0
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for cmd in meson ninja python3; do
    if ! need_cmd "$cmd"; then
        echo "SKIP: required command '$cmd' is not available."
        exit 0
    fi
done

build_dir="${SYSTEMD_RUST_FOCUS_BUILD_DIR:-build-rust-upstream-focus}"
report_path="${SYSTEMD_RUST_FOCUS_REPORT:-docs/rust-upstream-suite-report.md}"
mkdir -p "$(dirname "$report_path")"

run() {
    echo "+ $*"
    "$@"
}

declare -a focus_cases=(
    "test-unit-name"
    "test-unit-file"
    "test-calendarspec"
    "test-time-util"
    "test-parse-util"
    "test-id128"
    "test-socket-util"
    "test-transaction"
)

# pure-unit: src/test/ compiled tests
# integration: shell-driven integration tests under test/integration-tests
case_classification() {
    case "$1" in
        test-transaction)
            printf '%s\n' "pure-unit (proxy)"
            ;;
        *)
            printf '%s\n' "pure-unit"
            ;;
    esac
}

setup_args=(
    setup
    "$build_dir"
    -Dtests=true
    -Drust=enabled
    -Drust-core-pid1=enabled
    -Drust-init-milestones=enabled
)

if [[ -d "$build_dir" ]]; then
    setup_args+=(--reconfigure)
fi
run meson "${setup_args[@]}"

available_tests="$(meson test -C "$build_dir" --list)"

is_available() {
    local name="$1"
    grep -Fxq "$name" <<<"$available_tests"
}

map_case_to_test() {
    local case_name="$1"
    if is_available "$case_name"; then
        printf '%s\n' "$case_name"
        return 0
    fi

    # No dedicated upstream test-transaction binary exists in this tree.
    # test-engine exercises transaction logic in core.
    if [[ "$case_name" == "test-transaction" ]] && is_available "test-engine"; then
        printf '%s\n' "test-engine"
        return 0
    fi

    return 1
}

declare -A mapped_tests=()
declare -A notes=()
for case_name in "${focus_cases[@]}"; do
    if mapped="$(map_case_to_test "$case_name")"; then
        mapped_tests["$case_name"]="$mapped"
        if [[ "$case_name" == "test-transaction" && "$mapped" == "test-engine" ]]; then
            notes["$case_name"]="No direct test-transaction target; using test-engine as transaction proxy."
        else
            notes["$case_name"]=""
        fi
    else
        mapped_tests["$case_name"]=""
        notes["$case_name"]="No matching meson test target in this build."
    fi
done

declare -a compile_targets=()
declare -A seen_targets=()
for case_name in "${focus_cases[@]}"; do
    mapped="${mapped_tests[$case_name]}"
    if [[ -z "$mapped" ]]; then
        continue
    fi
    if [[ -z "${seen_targets[$mapped]:-}" ]]; then
        compile_targets+=("$mapped")
        seen_targets["$mapped"]=1
    fi
done

if (( ${#compile_targets[@]} > 0 )); then
    run meson compile -C "$build_dir" "${compile_targets[@]}"
fi

declare -A status=()
runnable=0
passed=0
failed=0
missing=0

for case_name in "${focus_cases[@]}"; do
    mapped="${mapped_tests[$case_name]}"
    if [[ -z "$mapped" ]]; then
        status["$case_name"]="MISSING"
        ((missing+=1))
        continue
    fi

    ((runnable+=1))
    echo "+ meson test -C $build_dir --no-rebuild --print-errorlogs $mapped"
    if meson test -C "$build_dir" --no-rebuild --print-errorlogs "$mapped"; then
        status["$case_name"]="PASS"
        ((passed+=1))
    else
        status["$case_name"]="FAIL"
        ((failed+=1))
    fi
done

total="${#focus_cases[@]}"
pass_rate_runnable="0.00"
coverage_focus="0.00"
if (( runnable > 0 )); then
    pass_rate_runnable="$(python3 - "$passed" "$runnable" <<'PY'
import sys
p = int(sys.argv[1])
r = int(sys.argv[2])
print(f"{(100.0 * p / r):.2f}")
PY
)"
fi
coverage_focus="$(python3 - "$runnable" "$total" <<'PY'
import sys
r = int(sys.argv[1])
t = int(sys.argv[2])
print(f"{(100.0 * r / t):.2f}")
PY
)"

generated_at="$(date -u +"%Y-%m-%d %H:%M:%SZ")"

{
    echo "# Rust Upstream Focus Suite Report"
    echo
    echo "- Generated: ${generated_at}"
    echo "- Build directory: \`${build_dir}\`"
    echo "- Meson configuration: \`-Dtests=true -Drust=enabled -Drust-core-pid1=enabled -Drust-init-milestones=enabled\`"
    echo
    echo "## Focus Cases"
    echo
    echo "| Focus Case | Mapped Meson Test | Classification | Status | Notes |"
    echo "|---|---|---|---|---|"
    for case_name in "${focus_cases[@]}"; do
        mapped="${mapped_tests[$case_name]}"
        [[ -n "$mapped" ]] || mapped="(none)"
        cls="$(case_classification "$case_name")"
        st="${status[$case_name]}"
        nt="${notes[$case_name]}"
        echo "| \`${case_name}\` | \`${mapped}\` | ${cls} | ${st} | ${nt} |"
    done
    echo
    echo "## Summary"
    echo
    echo "- Total focus cases: ${total}"
    echo "- Runnable in current build: ${runnable}"
    echo "- Passed: ${passed}"
    echo "- Failed: ${failed}"
    echo "- Missing target mapping: ${missing}"
    echo "- Pass rate over runnable cases: ${pass_rate_runnable}%"
    echo "- Focus-case coverage (mapped/runnable): ${coverage_focus}%"
} >"$report_path"

echo "Report written to $report_path"

if (( failed > 0 || missing > 0 || runnable != total )); then
    echo "FAIL: every required focus case must be mapped, runnable, and passing." >&2
    exit 1
fi
