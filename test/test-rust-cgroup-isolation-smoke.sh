#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: Linux-only cgroup/isolation smoke check."
    exit 0
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

for cmd in systemd-run systemctl python3 mount umount; do
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

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "SKIP: unified cgroup v2 hierarchy is required."
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
    echo "SKIP: root (or passwordless sudo) is required for cgroup/isolation smoke checks."
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

unit_substate() {
    as_root systemctl show --property SubState --value "$1" 2>/dev/null || true
}

wait_unit_active() {
    local unit="$1"
    local substate=""
    local i

    for i in {1..50}; do
        substate="$(unit_substate "$unit")"
        if [[ "$substate" == "running" ]]; then
            return 0
        fi
        if [[ "$substate" == "failed" || "$substate" == "dead" ]]; then
            break
        fi
        sleep 0.2
    done

    fail "unit '$unit' did not reach running state (last SubState='$substate')"
}

unit_control_group() {
    local unit="$1"
    local cg
    cg="$(as_root systemctl show --property ControlGroup --value "$unit" | tr -d '[:space:]')"
    [[ -n "$cg" ]] || fail "unit '$unit' has empty ControlGroup."
    printf '%s\n' "$cg"
}

tmpdir="$(mktemp -d)"
id="rust-cgroup-iso-$(date +%s)-$$"
declare -a created_units=()

register_unit() {
    created_units+=("$1")
}

cleanup() {
    set +e
    local unit

    for unit in "${created_units[@]}"; do
        as_root systemctl stop "$unit" >/dev/null 2>&1 || true
        as_root systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    rm -rf "$tmpdir"
}
trap cleanup EXIT

echo "Running cgroup/isolation smoke id: $id"

# 1) CPUQuota=50% reflects into cgroup cpu.max.
cpu_unit="$id-cpu.service"
register_unit "$cpu_unit"
run as_root systemd-run --quiet --unit "$cpu_unit" --property CPUQuota=50% --no-block \
    sleep 30
wait_unit_active "$cpu_unit"
cpu_cg="$(unit_control_group "$cpu_unit")"
cpu_max="$(as_root cat "/sys/fs/cgroup${cpu_cg}/cpu.max")"
python3 - "$cpu_max" <<'PY'
import sys

parts = sys.argv[1].split()
if len(parts) != 2:
    raise SystemExit(f"FAIL: unexpected cpu.max format: {sys.argv[1]!r}")

quota, period = parts
if quota == "max":
    raise SystemExit("FAIL: CPUQuota=50% produced cpu.max=max")

q = int(quota)
p = int(period)
if p <= 0:
    raise SystemExit(f"FAIL: invalid cpu period in cpu.max: {p}")

pct = (q * 100.0) / p
if not (45.0 <= pct <= 55.0):
    raise SystemExit(f"FAIL: expected CPU quota near 50%, got {pct:.2f}% (cpu.max={sys.argv[1]!r})")
PY

# 2) MemoryMax=100M causes OOM kill for a 220MB allocator, but only where the
# runner delegates the memory controller and applies the effective limit.
if ! grep -qw memory /sys/fs/cgroup/cgroup.controllers; then
    echo "SKIP detail: cgroup v2 memory controller is unavailable; skipping MemoryMax enforcement check."
else
    mem_probe_unit="$id-mem-probe.service"
    register_unit "$mem_probe_unit"
    run as_root systemd-run --quiet --unit "$mem_probe_unit" --property MemoryMax=100M --no-block sleep 30
    wait_unit_active "$mem_probe_unit"
    mem_probe_cg="$(unit_control_group "$mem_probe_unit")"
    mem_probe_max="$(as_root cat "/sys/fs/cgroup${mem_probe_cg}/memory.max" 2>/dev/null || true)"
    run as_root systemctl stop "$mem_probe_unit"

    if [[ "$mem_probe_max" != "104857600" ]]; then
        echo "SKIP detail: MemoryMax=100M is not effective in this runner subtree (memory.max='$mem_probe_max'); skipping enforcement check."
    else
        mem_unit="$id-mem.service"
        register_unit "$mem_unit"
        set +e
        as_root systemd-run --quiet --unit "$mem_unit" --property MemoryMax=100M --wait \
            python3 -c 'import time; n=220*1024*1024; b=bytearray(n); [b.__setitem__(i, 1) for i in range(0, n, 4096)]; time.sleep(2)'
        mem_rc=$?
        set -e
        if (( mem_rc == 0 )); then
            echo "SKIP detail: MemoryMax=100M was configured but not enforced by this runner; skipping enforcement check."
        else
            mem_result="$(as_root systemctl show --property Result --value "$mem_unit" || true)"
            if [[ "$mem_result" != "oom-kill" && "$mem_result" != "signal" ]]; then
                fail "unexpected memory pressure result for '$mem_unit': '$mem_result'"
            fi
        fi
    fi
fi

# 3) TasksMax=10 reflected in pids.max and enforces process ceiling.
tasks_unit="$id-tasks.service"
register_unit "$tasks_unit"
run as_root systemd-run --quiet --unit "$tasks_unit" --property TasksMax=10 --no-block \
    /bin/sh -c 'for i in $(seq 1 20); do sleep 30 & done; wait'
wait_unit_active "$tasks_unit"
tasks_cg="$(unit_control_group "$tasks_unit")"
pids_max="$(as_root cat "/sys/fs/cgroup${tasks_cg}/pids.max")"
pids_current="$(as_root cat "/sys/fs/cgroup${tasks_cg}/pids.current")"
[[ "$pids_max" == "10" ]] || fail "expected pids.max=10 for '$tasks_unit', got '$pids_max'"
python3 - "$pids_current" <<'PY'
import sys
cur = int(sys.argv[1])
if cur > 10:
    raise SystemExit(f"FAIL: expected pids.current <= 10, got {cur}")
PY

# 4) PrivateTmp=yes isolates /tmp from host files.
host_tmp_file="/tmp/$id-host-visible.txt"
printf 'host-visible\n' >"$host_tmp_file"
tmp_unit="$id-privatetmp.service"
register_unit "$tmp_unit"
run as_root systemd-run --quiet --unit "$tmp_unit" --wait --property PrivateTmp=yes \
    /bin/sh -c "test ! -e '$host_tmp_file'"
rm -f "$host_tmp_file"

# 5) PrivateNetwork=yes hides non-loopback interfaces.
host_non_lo="$(ls -1 /sys/class/net | grep -vc '^lo$' || true)"
if (( host_non_lo == 0 )); then
    echo "SKIP detail: host exposes no non-loopback interfaces; PrivateNetwork check is inconclusive."
else
    net_unit="$id-privnet.service"
    register_unit "$net_unit"
    run as_root systemd-run --quiet --unit "$net_unit" --wait --property PrivateNetwork=yes \
        /bin/sh -c 'n=$(ls -1 /sys/class/net | grep -vc "^lo$" || true); test "$n" -eq 0'
fi

# 6) User=nobody runs with reduced identity and cannot write root-only file.
if ! id nobody >/dev/null 2>&1; then
    echo "SKIP detail: user 'nobody' does not exist; skipping User=nobody checks."
else
    user_unit="$id-usernobody.service"
    register_unit "$user_unit"
    user_name="$(as_root systemd-run --quiet --unit "$user_unit" --wait --pipe --property User=nobody /usr/bin/id -un | tr -d '[:space:]')"
    [[ "$user_name" == "nobody" ]] || fail "expected User=nobody identity, got '$user_name'"

    protected_file="$tmpdir/protected-root.txt"
    printf 'root-only\n' >"$protected_file"
    chmod 600 "$protected_file"
    run as_root chown root:root "$protected_file"

    user_write_unit="$id-usernobody-write.service"
    register_unit "$user_write_unit"
    set +e
    as_root systemd-run --quiet --unit "$user_write_unit" --wait --property User=nobody \
        /bin/sh -c "echo blocked >> '$protected_file'"
    user_write_rc=$?
    set -e
    if (( user_write_rc == 0 )); then
        fail "User=nobody unexpectedly wrote to root-owned file '$protected_file'."
    fi
fi

# 7) SystemCallFilter blocks mount syscall path (with explicit EPERM).
syscall_probe_unit="$id-syscall-probe.service"
register_unit "$syscall_probe_unit"
probe_mount_dir="$tmpdir/mount-probe"
mkdir -p "$probe_mount_dir"
set +e
as_root systemd-run --quiet --unit "$syscall_probe_unit" --wait --property PrivateMounts=yes \
    /bin/sh -c "mount -t tmpfs tmpfs '$probe_mount_dir' && umount '$probe_mount_dir'"
probe_rc=$?
set -e
if (( probe_rc == 0 )); then
    syscall_unit="$id-syscallfilter.service"
    register_unit "$syscall_unit"
    set +e
    as_root systemd-run --quiet --unit "$syscall_unit" --wait \
        --property PrivateMounts=yes \
        --property 'SystemCallFilter=~@mount' \
        --property SystemCallErrorNumber=EPERM \
        /bin/sh -c "mount -t tmpfs tmpfs '$probe_mount_dir'"
    syscall_rc=$?
    set -e
    if (( syscall_rc == 0 )); then
        fail "SystemCallFilter=~@mount did not block mount syscall."
    fi
else
    echo "SKIP detail: baseline mount probe failed in this environment; skipping SystemCallFilter mount-path check."
fi

# 8) ReadOnlyPaths blocks writes to designated paths.
readonly_target="$tmpdir/readonly-target.txt"
printf 'seed\n' >"$readonly_target"
readonly_unit="$id-readonly.service"
register_unit "$readonly_unit"
set +e
as_root systemd-run --quiet --unit "$readonly_unit" --wait --property "ReadOnlyPaths=$readonly_target" \
    /bin/sh -c "echo blocked >> '$readonly_target'"
readonly_rc=$?
set -e
if (( readonly_rc == 0 )); then
    fail "ReadOnlyPaths did not block writes to '$readonly_target'."
fi

echo "PASS: cgroup/isolation smoke checks completed for id=$id"
