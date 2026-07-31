#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Exercise Rust PID 1's normal startup path without mutating the host's root,
# /run, UTS state, or cgroup hierarchy. This is intentionally a minimal boot
# harness, not a claim that a complete system boot or production D-Bus surface
# is ready.
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

skip_or_fail_ci() {
    local message="$1"

    if [[ -n "${CI:-}" ]]; then
        echo "FAIL: $message" >&2
        exit 1
    fi

    echo "SKIP: $message"
    exit 0
}

if [[ "$(uname -s)" != "Linux" ]]; then
    skip_or_fail_ci "Linux is required for the isolated Rust PID 1 boot harness."
fi

if ! command -v unshare >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
    skip_or_fail_ci "unshare and timeout are required for the isolated Rust PID 1 boot harness."
fi

if ! command -v sudo >/dev/null 2>&1 || ! sudo -n unshare --mount --uts --cgroup --pid --fork true >/dev/null 2>&1; then
    skip_or_fail_ci "passwordless root namespace setup is required for the isolated Rust PID 1 boot harness."
fi

run() {
    echo "+ $*"
    "$@"
}

tmpdir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

# Reuse Cargo's normal target directory unless the caller explicitly provides
# one. A separate throw-away target roughly doubles the space needed for this
# integration test, which makes an otherwise small VM validation needlessly
# fail before it reaches PID 1.
cargo_target_dir="${CARGO_TARGET_DIR:-target}"
run cargo build --locked --manifest-path src/core/rust/Cargo.toml --bin systemd
systemd_bin="$cargo_target_dir/debug/systemd"
if [[ ! -x "$systemd_bin" ]]; then
    echo "FAIL: Cargo did not produce the expected PID1 binary at $systemd_bin." >&2
    exit 1
fi

unit_dir="$tmpdir/units"
mkdir -p "$unit_dir"
cat >"$unit_dir/default.target" <<'EOF'
[Unit]
Description=Isolated Rust PID 1 boot harness target
AllowIsolate=yes
EOF

boot_log="$tmpdir/boot.log"

# The namespace setup deliberately overlays the only mutable global paths
# before execing the Rust binary:
#
# * a private mount namespace prevents every mount operation from propagating;
# * a private UTS namespace confines sethostname(2);
# * a tmpfs /run owns the test notify socket and container marker;
# * a tmpfs cgroup tree, inside a cgroup namespace, makes manager setup use
#   fixture control files rather than the guest's live hierarchy;
# * exec replaces the shell, making Rust systemd exactly PID 1.
#
# The fake init.scope control file mirrors the one the kernel creates in a real
# cgroupfs after mkdir. It lets the harness exercise the manager's bootstrap
# order without pretending a tmpfs is a real controller hierarchy.
set +e
timeout --signal=KILL 8s \
    sudo -n unshare --mount --uts --cgroup --pid --fork --mount-proc --propagation private \
    sh -ec '
        set -eu
        test "$$" -eq 1

        mount -t tmpfs -o mode=0755,size=16m tmpfs /run
        mkdir -p /run/systemd
        printf container > /run/systemd/container

        mount -t tmpfs -o mode=0755,size=1m tmpfs /sys/fs/cgroup
        : > /sys/fs/cgroup/cgroup.procs
        : > /sys/fs/cgroup/cgroup.subtree_control
        printf "cpu memory pids" > /sys/fs/cgroup/cgroup.controllers
        mkdir /sys/fs/cgroup/init.scope
        : > /sys/fs/cgroup/init.scope/cgroup.procs

        exec env SYSTEMD_UNIT_PATH="$1" "$2"
    ' rust-pid1-boot-harness "$unit_dir" "$systemd_bin" >"$boot_log" 2>&1
status=$?
set -e

cat "$boot_log"
if [[ "$status" -ne 137 ]]; then
    echo "FAIL: normal PID 1 harness exited with $status instead of timeout's SIGKILL status 137." >&2
    exit 1
fi

for marker in \
    "systemd: running as PID 1, starting early boot sequence" \
    "systemd: step 1/8: mount setup" \
    "systemd: step 2/8: cgroup setup" \
    "systemd: step 4/8: signal setup" \
    "systemd: selected boot target: default.target" \
    "systemd: step 8/8: enter event loop" \
    "systemd: entering event loop"; do
    if ! grep -Fq "$marker" "$boot_log"; then
        echo "FAIL: normal Rust PID 1 boot harness log is missing: $marker" >&2
        exit 1
    fi
done

if grep -Fq "fatal PID 1 failure" "$boot_log"; then
    echo "FAIL: normal Rust PID 1 boot harness hit the fail-closed boundary." >&2
    exit 1
fi

echo "PASS: Rust PID 1 reached the normal event loop in an isolated mount, UTS, and cgroup namespace."
