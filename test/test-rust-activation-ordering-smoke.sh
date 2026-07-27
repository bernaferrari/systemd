#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: Linux-only activation/ordering smoke check."
    exit 0
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for cmd in systemctl systemd-run python3; do
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
    echo "SKIP: containerized environments are not reliable for host manager activation checks."
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
    echo "SKIP: root (or passwordless sudo) is required for activation/ordering smoke checks."
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

wait_file() {
    local path="$1"
    local i
    for i in {1..50}; do
        if as_root test -e "$path"; then
            return 0
        fi
        sleep 0.2
    done
    fail "timed out waiting for file '$path'"
}

wait_inactive() {
    local unit="$1"
    local state
    local i

    for i in {1..50}; do
        state="$(as_root systemctl is-active "$unit" 2>/dev/null || true)"
        if [[ "$state" == "inactive" || "$state" == "failed" || "$state" == "deactivating" ]]; then
            return 0
        fi
        sleep 0.2
    done

    fail "unit '$unit' did not transition away from active state"
}

tmpdir="$(mktemp -d)"
id="rust-activate-$(date +%s)-$$"
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

echo "Running activation/ordering smoke id: $id"

# 1) Socket activation: socket unit starts service and passes LISTEN_FDS.
sock_base="$id-echo"
sock_service="${sock_base}.service"
sock_socket="${sock_base}.socket"
sock_path="/run/${sock_base}.sock"
sock_msg="/run/${sock_base}.msg"
sock_fds="/run/${sock_base}.listen_fds"
sock_handler="/run/${sock_base}-handler.py"
runtime_files+=("$sock_path" "$sock_msg" "$sock_fds" "$sock_handler")

cat >"$tmpdir/$sock_service" <<EOF
[Unit]
Description=Rust port socket activation smoke service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $sock_handler
EOF

cat >"$tmpdir/$sock_socket" <<EOF
[Unit]
Description=Rust port socket activation smoke socket
[Socket]
ListenStream=$sock_path
SocketMode=0600
EOF

cat >"$tmpdir/sock-handler.py" <<EOF
import os
import pathlib
import socket

pathlib.Path("$sock_fds").write_text(os.environ.get("LISTEN_FDS", "0"), encoding="utf-8")
listener = socket.socket(fileno=3)
listener.settimeout(10.0)
conn, _ = listener.accept()
with conn:
    data = conn.recv(4096)
pathlib.Path("$sock_msg").write_bytes(data)
EOF

run as_root cp -f "$tmpdir/sock-handler.py" "$sock_handler"
run as_root chmod 0755 "$sock_handler"
install_unit "$sock_service"
install_unit "$sock_socket"
run as_root systemctl daemon-reload
if ! as_root systemctl show --property Triggers --value "$sock_socket" | grep -Fq "$sock_service"; then
    fail "socket '$sock_socket' is not wired to trigger '$sock_service'"
fi
if ! as_root systemctl show --property TriggeredBy --value "$sock_service" | grep -Fq "$sock_socket"; then
    fail "service '$sock_service' is not wired as triggered by '$sock_socket'"
fi
run as_root systemctl start "$sock_socket"
if as_root systemctl is-active --quiet "$sock_service"; then
    fail "service '$sock_service' is already active before a socket connection"
fi
python3 - "$sock_path" <<'PY'
import socket
import sys

path = sys.argv[1]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(10.0)
    s.connect(path)
    s.sendall(b"socket-activation-ok")
PY
wait_file "$sock_msg"
sock_payload="$(as_root cat "$sock_msg")"
[[ "$sock_payload" == "socket-activation-ok" ]] || fail "unexpected socket payload: '$sock_payload'"
sock_listen_fds="$(as_root cat "$sock_fds" | tr -d '[:space:]')"
[[ "$sock_listen_fds" == "1" ]] || fail "expected LISTEN_FDS=1, got '$sock_listen_fds'"

# 2) After=/Before= ordering: B should run before A.
order_a="$id-order-a.service"
order_b="$id-order-b.service"
order_log="/run/$id-order.log"
runtime_files+=("$order_log")

cat >"$tmpdir/$order_b" <<EOF
[Unit]
Description=Ordering smoke B
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo B >> "$order_log"'
EOF

cat >"$tmpdir/$order_a" <<EOF
[Unit]
Description=Ordering smoke A
Requires=$order_b
After=$order_b
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo A >> "$order_log"'
EOF

install_unit "$order_a"
install_unit "$order_b"
run as_root systemctl daemon-reload
run as_root rm -f "$order_log"
run as_root systemctl start "$order_a"
order_lines="$(as_root cat "$order_log" | tr -d '\r')"
[[ "$order_lines" == $'B\nA' ]] || fail "ordering mismatch, expected B then A, got: '$order_lines'"

# 3) Requires= propagation: stopping required unit stops dependent unit.
req_a="$id-req-a.service"
req_b="$id-req-b.service"

cat >"$tmpdir/$req_b" <<EOF
[Unit]
Description=Requires propagation B
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF

cat >"$tmpdir/$req_a" <<EOF
[Unit]
Description=Requires propagation A
Requires=$req_b
After=$req_b
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF

install_unit "$req_a"
install_unit "$req_b"
run as_root systemctl daemon-reload
run as_root systemctl start "$req_a"
run as_root systemctl is-active --quiet "$req_a"
run as_root systemctl is-active --quiet "$req_b"
run as_root systemctl stop "$req_b"
wait_inactive "$req_a"

# 4) BindsTo=: dependent unit stops when bound unit fails.
bind_a="$id-bind-a.service"
bind_b="$id-bind-b.service"

cat >"$tmpdir/$bind_b" <<EOF
[Unit]
Description=BindsTo provider B
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep 1; exit 1'
EOF

cat >"$tmpdir/$bind_a" <<EOF
[Unit]
Description=BindsTo dependent A
BindsTo=$bind_b
After=$bind_b
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF

install_unit "$bind_a"
install_unit "$bind_b"
run as_root systemctl daemon-reload
set +e
as_root systemctl start "$bind_a"
_bind_start_rc=$?
set -e
wait_inactive "$bind_b"
wait_inactive "$bind_a"

# 5) OnFailure=: failing unit triggers failure handler unit.
onfail_unit="$id-onfail-main.service"
onfail_handler="$id-onfail-handler.service"
onfail_flag="/run/$id-onfail.flag"
runtime_files+=("$onfail_flag")

cat >"$tmpdir/$onfail_handler" <<EOF
[Unit]
Description=OnFailure handler
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo triggered > "$onfail_flag"'
EOF

cat >"$tmpdir/$onfail_unit" <<EOF
[Unit]
Description=OnFailure source
OnFailure=$onfail_handler
[Service]
Type=oneshot
ExecStart=/bin/false
EOF

install_unit "$onfail_handler"
install_unit "$onfail_unit"
run as_root systemctl daemon-reload
run as_root rm -f "$onfail_flag"
set +e
as_root systemctl start "$onfail_unit"
onfail_rc=$?
set -e
if (( onfail_rc == 0 )); then
    fail "OnFailure source unit '$onfail_unit' unexpectedly succeeded"
fi
wait_file "$onfail_flag"

# 6) Conflicts=: starting A while B is active deactivates B.
conf_a="$id-conflict-a.service"
conf_b="$id-conflict-b.service"

cat >"$tmpdir/$conf_b" <<EOF
[Unit]
Description=Conflict target B
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF

cat >"$tmpdir/$conf_a" <<EOF
[Unit]
Description=Conflict source A
Conflicts=$conf_b
[Service]
Type=simple
ExecStart=/bin/sh -c 'sleep infinity'
EOF

install_unit "$conf_a"
install_unit "$conf_b"
run as_root systemctl daemon-reload
run as_root systemctl start "$conf_b"
run as_root systemctl is-active --quiet "$conf_b"
run as_root systemctl start "$conf_a"
run as_root systemctl is-active --quiet "$conf_a"
wait_inactive "$conf_b"

# 7) multi-user.target activation check.
run as_root systemctl start multi-user.target
run as_root systemctl is-active --quiet multi-user.target

# 8) daemon-reload applies changed unit configuration.
reload_unit="$id-reload.service"
reload_out="/run/$id-reload.out"
runtime_files+=("$reload_out")

cat >"$tmpdir/$reload_unit" <<EOF
[Unit]
Description=daemon-reload smoke
[Service]
Type=oneshot
Environment=MARK=v1
ExecStart=/bin/sh -c 'echo "\$MARK" > "$reload_out"'
EOF

install_unit "$reload_unit"
run as_root systemctl daemon-reload
run as_root systemctl start "$reload_unit"
reload_v1="$(as_root cat "$reload_out" | tr -d '[:space:]')"
[[ "$reload_v1" == "v1" ]] || fail "expected daemon-reload test value 'v1', got '$reload_v1'"

sleep 1.1
cat >"$tmpdir/$reload_unit" <<EOF
[Unit]
Description=daemon-reload smoke
[Service]
Type=oneshot
Environment=MARK=v2
ExecStart=/bin/sh -c 'echo "\$MARK" > "$reload_out"'
EOF

run as_root cp -f "$tmpdir/$reload_unit" "/run/systemd/system/$reload_unit"
run as_root systemctl daemon-reload
run as_root systemctl start "$reload_unit"
reload_v2="$(as_root cat "$reload_out" | tr -d '[:space:]')"
[[ "$reload_v2" == "v2" ]] || fail "expected daemon-reload test value 'v2', got '$reload_v2'"

echo "PASS: activation/ordering smoke checks completed for id=$id"
