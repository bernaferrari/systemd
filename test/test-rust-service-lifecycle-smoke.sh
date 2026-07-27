#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: Linux-only service lifecycle smoke check."
    exit 0
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for cmd in systemctl systemd-notify python3; do
    if ! need_cmd "$cmd"; then
        echo "SKIP: required command '$cmd' is not available."
        exit 0
    fi
done

pid1_comm="$(ps -p 1 -o comm= | tr -d '[:space:]')"
if [[ "$pid1_comm" != "systemd" ]]; then
    echo "SKIP: PID 1 is '$pid1_comm', not systemd."
    exit 0
fi

if need_cmd systemd-detect-virt && systemd-detect-virt --container --quiet; then
    echo "SKIP: containerized environments are not reliable for host lifecycle checks."
    exit 0
fi

as_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        sudo -n "$@"
    else
        return 125
    fi
}

if ! as_root true; then
    echo "SKIP: root (or passwordless sudo) is required for lifecycle smoke checks."
    exit 0
fi

if ! as_root test -d /run/systemd/system; then
    echo "SKIP: /run/systemd/system is unavailable."
    exit 0
fi

if ! as_root systemctl --system show --property Version >/dev/null 2>&1; then
    echo "SKIP: unable to communicate with the system manager."
    exit 0
fi

run() {
    echo "+ $*"
    "$@"
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

unit_prop() {
    local unit="$1"
    local prop="$2"
    as_root systemctl show --property "$prop" --value "$unit" 2>/dev/null || true
}

wait_for_state() {
    local unit="$1"
    local desired="$2"
    local i
    local state
    for i in {1..80}; do
        state="$(as_root systemctl is-active "$unit" 2>/dev/null || true)"
        if [[ "$state" == "$desired" ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "unit '$unit' did not reach state '$desired'"
}

wait_not_active() {
    local unit="$1"
    local i
    local state
    for i in {1..80}; do
        state="$(as_root systemctl is-active "$unit" 2>/dev/null || true)"
        if [[ "$state" != "active" ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "unit '$unit' remained active"
}

wait_file() {
    local path="$1"
    local i
    for i in {1..80}; do
        if as_root test -e "$path"; then
            return 0
        fi
        sleep 0.2
    done
    fail "timed out waiting for file '$path'"
}

wait_mainpid_changed() {
    local unit="$1"
    local old_pid="$2"
    local i
    local new_pid
    for i in {1..120}; do
        new_pid="$(unit_prop "$unit" MainPID | tr -d '[:space:]')"
        if [[ -n "$new_pid" && "$new_pid" != "0" && "$new_pid" != "$old_pid" ]]; then
            printf '%s\n' "$new_pid"
            return 0
        fi
        sleep 0.2
    done
    fail "unit '$unit' main PID did not change from '$old_pid'"
}

tmpdir="$(mktemp -d)"
id="rust-lifecycle-$(date +%s)-$$"
declare -a created_units=()
declare -a created_unit_files=()
declare -a runtime_files=()

register_unit() {
    created_units+=("$1")
}

install_unit() {
    local unit="$1"
    run as_root cp -f "$tmpdir/$unit" "/run/systemd/system/$unit"
    created_unit_files+=("/run/systemd/system/$unit")
    register_unit "$unit"
}

cleanup() {
    set +e
    local unit
    local path

    for unit in "${created_units[@]}"; do
        as_root systemctl stop "$unit" >/dev/null 2>&1 || true
        as_root systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    for path in "${created_unit_files[@]}"; do
        as_root rm -f "$path" >/dev/null 2>&1 || true
    done
    for path in "${runtime_files[@]}"; do
        as_root rm -f "$path" >/dev/null 2>&1 || true
    done
    as_root systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "Running service lifecycle smoke id: $id"

# 1) Type=simple: start/stop lifecycle.
simple_unit="$id-simple.service"
cat >"$tmpdir/$simple_unit" <<'EOF'
[Unit]
Description=Lifecycle simple smoke
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF
install_unit "$simple_unit"
run as_root systemctl daemon-reload
run as_root systemctl start "$simple_unit"
wait_for_state "$simple_unit" "active"
simple_pid="$(unit_prop "$simple_unit" MainPID | tr -d '[:space:]')"
[[ -n "$simple_pid" && "$simple_pid" != "0" ]] || fail "simple service did not get a running MainPID"
run as_root systemctl stop "$simple_unit"
wait_not_active "$simple_unit"

# 2) Type=oneshot: verify successful execution and exit status.
oneshot_unit="$id-oneshot.service"
oneshot_out="/run/$id-oneshot.out"
runtime_files+=("$oneshot_out")
cat >"$tmpdir/$oneshot_unit" <<EOF
[Unit]
Description=Lifecycle oneshot smoke
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo ok > "$oneshot_out"'
EOF
install_unit "$oneshot_unit"
run as_root systemctl daemon-reload
run as_root rm -f "$oneshot_out"
run as_root systemctl start "$oneshot_unit"
wait_file "$oneshot_out"
oneshot_value="$(as_root cat "$oneshot_out" | tr -d '[:space:]')"
[[ "$oneshot_value" == "ok" ]] || fail "oneshot output mismatch: '$oneshot_value'"
oneshot_result="$(unit_prop "$oneshot_unit" Result | tr -d '[:space:]')"
[[ "$oneshot_result" == "success" ]] || fail "oneshot unit result mismatch: '$oneshot_result'"

# 3) Type=notify: READY=1 transitions to active.
notify_unit="$id-notify.service"
cat >"$tmpdir/$notify_unit" <<'EOF'
[Unit]
Description=Lifecycle notify smoke
[Service]
Type=notify
NotifyAccess=all
ExecStart=/bin/sh -c 'systemd-notify --ready; sleep infinity'
EOF
install_unit "$notify_unit"
run as_root systemctl daemon-reload
run as_root systemctl start "$notify_unit"
wait_for_state "$notify_unit" "active"
run as_root systemctl stop "$notify_unit"
wait_not_active "$notify_unit"

# 4) Restart=on-failure: kill -9 triggers restart with RestartSec delay.
restart_unit="$id-restart-kill.service"
restart_log="/run/$id-restart.log"
runtime_files+=("$restart_log")
cat >"$tmpdir/$restart_unit" <<EOF
[Unit]
Description=Lifecycle restart-on-failure smoke
[Service]
Type=simple
Restart=on-failure
RestartSec=2
ExecStart=/bin/sh -c 'date +%s >> "$restart_log"; sleep infinity'
EOF
install_unit "$restart_unit"
run as_root systemctl daemon-reload
run as_root rm -f "$restart_log"
run as_root systemctl start "$restart_unit"
wait_for_state "$restart_unit" "active"
old_pid="$(unit_prop "$restart_unit" MainPID | tr -d '[:space:]')"
[[ -n "$old_pid" && "$old_pid" != "0" ]] || fail "restart test unit has invalid MainPID"
run as_root kill -9 "$old_pid"
wait_for_state "$restart_unit" "active"
new_pid="$(wait_mainpid_changed "$restart_unit" "$old_pid")"
[[ "$new_pid" != "$old_pid" ]] || fail "service did not restart after SIGKILL"

python3 - "$restart_log" <<'PY'
import pathlib
import sys

lines = [ln.strip() for ln in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if ln.strip()]
if len(lines) < 2:
    raise SystemExit("FAIL: expected at least two restart timestamps")
first = int(lines[0])
second = int(lines[1])
if second - first < 2:
    raise SystemExit(f"FAIL: RestartSec delay not respected (first={first}, second={second})")
PY
run as_root systemctl stop "$restart_unit"
wait_not_active "$restart_unit"

# 4b) StartLimitBurst eventually stops restart storms.
limit_unit="$id-startlimit.service"
cat >"$tmpdir/$limit_unit" <<'EOF'
[Unit]
Description=Lifecycle start limit smoke
StartLimitIntervalSec=10
StartLimitBurst=3
[Service]
Type=simple
Restart=on-failure
RestartSec=0
ExecStart=/bin/false
EOF
install_unit "$limit_unit"
run as_root systemctl daemon-reload
set +e
as_root systemctl start "$limit_unit"
_startlimit_rc=$?
set -e
wait_for_state "$limit_unit" "failed"
limit_result="$(unit_prop "$limit_unit" Result | tr -d '[:space:]')"
[[ "$limit_result" == "start-limit-hit" ]] || fail "expected start-limit-hit, got '$limit_result'"
restarts="$(unit_prop "$limit_unit" NRestarts | tr -d '[:space:]')"
python3 - "$restarts" <<'PY'
import sys
v = int(sys.argv[1] or "0")
if v < 3:
    raise SystemExit(f"FAIL: expected at least 3 restarts before start-limit hit, got {v}")
PY

# 5) ExecStartPre failure blocks ExecStart.
pre_unit="$id-pre-fail.service"
pre_marker="/run/$id-pre-marker"
runtime_files+=("$pre_marker")
cat >"$tmpdir/$pre_unit" <<EOF
[Unit]
Description=Lifecycle ExecStartPre failure smoke
[Service]
Type=simple
ExecStartPre=/bin/false
ExecStart=/bin/sh -c 'echo should-not-run > "$pre_marker"; sleep infinity'
EOF
install_unit "$pre_unit"
run as_root systemctl daemon-reload
run as_root rm -f "$pre_marker"
set +e
as_root systemctl start "$pre_unit"
pre_rc=$?
set -e
if (( pre_rc == 0 )); then
    fail "ExecStartPre failure unit unexpectedly started"
fi
if as_root test -e "$pre_marker"; then
    fail "ExecStart ran even though ExecStartPre failed"
fi

# 6) TimeoutStartSec for Type=notify without READY=1 results in timeout failure.
timeout_unit="$id-timeout-start.service"
cat >"$tmpdir/$timeout_unit" <<'EOF'
[Unit]
Description=Lifecycle TimeoutStartSec smoke
[Service]
Type=notify
NotifyAccess=all
TimeoutStartSec=2
ExecStart=/bin/sh -c 'sleep infinity'
EOF
install_unit "$timeout_unit"
run as_root systemctl daemon-reload
set +e
as_root systemctl start "$timeout_unit"
timeout_rc=$?
set -e
if (( timeout_rc == 0 )); then
    fail "TimeoutStartSec notify unit unexpectedly succeeded"
fi
wait_for_state "$timeout_unit" "failed"
timeout_result="$(unit_prop "$timeout_unit" Result | tr -d '[:space:]')"
[[ "$timeout_result" == "timeout" ]] || fail "expected timeout result, got '$timeout_result'"

# 7) WatchdogSec without heartbeat transitions to watchdog failure.
watchdog_unit="$id-watchdog.service"
cat >"$tmpdir/$watchdog_unit" <<'EOF'
[Unit]
Description=Lifecycle WatchdogSec smoke
[Service]
Type=notify
NotifyAccess=all
WatchdogSec=2
ExecStart=/bin/sh -c 'systemd-notify --ready; sleep infinity'
EOF
install_unit "$watchdog_unit"
run as_root systemctl daemon-reload
run as_root systemctl start "$watchdog_unit"
wait_for_state "$watchdog_unit" "active"
wait_for_state "$watchdog_unit" "failed"
watchdog_result="$(unit_prop "$watchdog_unit" Result | tr -d '[:space:]')"
[[ "$watchdog_result" == "watchdog" ]] || fail "expected watchdog result, got '$watchdog_result'"

echo "PASS: service lifecycle smoke checks completed for id=$id"
