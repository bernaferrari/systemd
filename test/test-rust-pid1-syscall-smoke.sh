#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
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
    skip_or_fail_ci "Linux is required for the PID1 syscall trace smoke check."
fi

if ! command -v strace >/dev/null 2>&1; then
    skip_or_fail_ci "strace is not available for the PID1 syscall trace smoke check."
fi

if ! command -v unshare >/dev/null 2>&1; then
    skip_or_fail_ci "unshare is not available for the PID1 syscall trace smoke check."
fi

if unshare --user --map-root-user --pid --fork true >/dev/null 2>&1; then
    namespace=(unshare --user --map-root-user --pid --fork)
elif command -v sudo >/dev/null 2>&1 && sudo -n unshare --pid --fork true >/dev/null 2>&1; then
    # GitHub-hosted runners disable unprivileged user namespaces, but their
    # passwordless root execution can still create a PID namespace. Both
    # forms run the traced program as PID 1 in its own namespace.
    namespace=(sudo -n unshare --pid --fork)
else
    skip_or_fail_ci "no usable PID namespace path is available for the PID1 syscall trace smoke check."
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

trace_dir="$tmpdir/trace"
mkdir -p "$trace_dir"

cargo_target_dir="$tmpdir/cargo-target"
run env CARGO_TARGET_DIR="$cargo_target_dir" \
    cargo build --locked --manifest-path src/core/rust/Cargo.toml --bin systemd
systemd_bin="$cargo_target_dir/debug/systemd"
if [[ ! -x "$systemd_bin" ]]; then
    echo "FAIL: Cargo did not produce the expected PID1 binary at $systemd_bin." >&2
    exit 1
fi

trace_cmd=(
    "${namespace[@]}"
    strace
    -ff
    -qq
    -o
    "$trace_dir/strace"
    -e
    trace=%process,%file,%memory,%signal,%desc,%network,%ipc,mount,umount2
    "$systemd_bin"
    --test
)

echo "+ timeout --signal=KILL 10s ${trace_cmd[*]}"
set +e
timeout --signal=KILL 10s "${trace_cmd[@]}"
rc=$?
set -e

case "$rc" in
    0|124|137)
        ;;
    *)
        echo "FAIL: syscall tracing command exited with unexpected status $rc." >&2
        exit 1
        ;;
esac

python3 - "$trace_dir" <<'PY'
import pathlib
import re
import sys

trace_dir = pathlib.Path(sys.argv[1])
syscall_re = re.compile(r"^\s*(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")

forbidden = {
    "bpf",
    "delete_module",
    "finit_module",
    "init_module",
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "kexec_file_load",
    "kexec_load",
    "name_to_handle_at",
    "open_by_handle_at",
    "perf_event_open",
    "pivot_root",
    "ptrace",
    "reboot",
    "swapon",
    "swapoff",
    "userfaultfd",
}

def classify(name: str) -> str:
    if name in {"clone", "clone3", "execve", "execveat", "exit", "exit_group", "fork", "vfork", "wait4", "waitid"}:
        return "process"
    if name in {"mount", "umount2"}:
        return "mount"
    if name in {"brk", "madvise", "mmap", "mprotect", "mremap", "munmap"}:
        return "memory"
    if name.startswith("rt_sig") or name in {"sigaltstack", "signalfd4"}:
        return "signal"
    if name in {"clock_gettime", "clock_nanosleep", "gettimeofday", "nanosleep", "timerfd_create", "timerfd_settime"}:
        return "time"
    if name in {"socket", "connect", "bind", "listen", "accept", "accept4", "recvfrom", "sendto", "recvmsg", "sendmsg"}:
        return "network"
    if name.startswith(("open", "read", "write", "stat", "lstat", "fstat", "newfstat", "close", "access", "ioctl", "readlink", "getdents", "fcntl")):
        return "file"
    return "other"

syscalls = set()
for path in sorted(trace_dir.glob("strace*")):
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        match = syscall_re.match(line)
        if match:
            syscalls.add(match.group(1))

if not syscalls:
    print("FAIL: no syscalls were captured by strace.", file=sys.stderr)
    sys.exit(1)

required = {"execve", "openat", "mmap", "rt_sigprocmask"}
if not required.issubset(syscalls):
    missing = sorted(required - syscalls)
    print(f"FAIL: syscall trace is missing expected baseline calls: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

violations = sorted(syscalls & forbidden)
if violations:
    print(
        "FAIL: unexpected high-risk syscalls observed in PID1 baseline trace: "
        + ", ".join(violations),
        file=sys.stderr,
    )
    sys.exit(1)

classes = {}
for name in sorted(syscalls):
    classes.setdefault(classify(name), []).append(name)

summary = ", ".join(f"{klass}:{len(names)}" for klass, names in sorted(classes.items()))
print(f"Observed {len(syscalls)} unique syscalls across classes -> {summary}")
PY
