#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# This is intentionally a narrow Rust PID 1 `--test` signal-startup smoke.
# It is not evidence that the normal boot path or manager event loop is ready.
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
    tracer=(strace)
elif command -v sudo >/dev/null 2>&1 && sudo -n unshare --pid --fork true >/dev/null 2>&1; then
    # GitHub-hosted runners disable unprivileged user namespaces, but their
    # passwordless root execution can still create a PID namespace. Trace
    # from the elevated parent: tracing sudo itself would disable its setuid
    # elevation before it can create the namespace.
    namespace=(unshare --pid --fork)
    tracer=(sudo -n strace)
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
pid1_log="$tmpdir/pid1.log"

# Reuse Cargo's regular target directory unless a caller supplies an isolated
# one. The syscall trace is a runtime check; requiring a second complete Rust
# build makes it unusable in the small Linux VM intended to run it.
cargo_target_dir="${CARGO_TARGET_DIR:-target}"
export CARGO_TARGET_DIR="$cargo_target_dir"
run cargo build --locked --manifest-path src/core/rust/Cargo.toml --bin systemd
systemd_bin="$cargo_target_dir/debug/systemd"
if [[ ! -x "$systemd_bin" ]]; then
    echo "FAIL: Cargo did not produce the expected PID1 binary at $systemd_bin." >&2
    exit 1
fi

pid1_wrapper=(
    /bin/sh
    -ec
    'test "$$" -eq 1; exec "$1" --test'
    rust-pid1-wrapper
    "$systemd_bin"
)

trace_cmd=(
    "${tracer[@]}"
    -ff
    -qq
    -o
    "$trace_dir/strace"
    -e
    trace=%process,%file,%memory,%signal,%desc,%network,%ipc,mount,umount2
    # Keep strace outside the new PID namespace. If it ran inside, strace
    # itself would become PID 1 and the Rust binary would only be its child.
    # As the tracing parent, strace follows unshare's descendant and records
    # the actual systemd binary after it becomes PID 1.
    "${namespace[@]}"
    "${pid1_wrapper[@]}"
)

echo "+ timeout --signal=KILL 10s ${trace_cmd[*]}"
set +e
timeout --signal=KILL 10s "${trace_cmd[@]}" >"$pid1_log" 2>&1
rc=$?
set -e
cat "$pid1_log"

case "$rc" in
    0)
        ;;
    *)
        echo "FAIL: syscall tracing command exited with unexpected status $rc." >&2
        exit 1
        ;;
esac

for marker in \
    "systemd: running as PID 1, starting early boot sequence" \
    "systemd: PID 1 test mode complete; skipping manager startup and event loop"; do
    if ! grep -Fq "$marker" "$pid1_log"; then
        echo "FAIL: the Rust PID 1 test-mode log is missing: $marker" >&2
        exit 1
    fi
done

python3 - "$trace_dir" "$systemd_bin" <<'PY'
import pathlib
import re
import sys

trace_dir = pathlib.Path(sys.argv[1])
systemd_bin = sys.argv[2]
syscall_re = re.compile(r"^\s*(?:\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")
successful_call_re = {
    "rt_sigaction": re.compile(r"^\s*(?:\d+\s+)?rt_sigaction\(.*\)\s+=\s+0(?:\s|$)"),
    "rt_sigprocmask": re.compile(r"^\s*(?:\d+\s+)?rt_sigprocmask\(.*\)\s+=\s+0(?:\s|$)"),
}

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

target_traces = []
for path in sorted(trace_dir.glob("strace*")):
    text = path.read_text(encoding="utf-8", errors="replace")
    if f'execve("{systemd_bin}",' in text:
        target_traces.append((path, text))

if len(target_traces) != 1:
    paths = ", ".join(str(path) for path, _ in target_traces) or "none"
    print(
        "FAIL: unable to identify exactly one trace for the Rust systemd binary "
        f"(found: {paths}).",
        file=sys.stderr,
    )
    sys.exit(1)

target_path, target_text = target_traces[0]
syscalls = {
    match.group(1)
    for line in target_text.splitlines()
    if (match := syscall_re.match(line))
}

if not syscalls:
    print("FAIL: no syscalls were captured for the Rust systemd binary.", file=sys.stderr)
    sys.exit(1)

required = {"execve"}
if not required.issubset(syscalls):
    missing = sorted(required - syscalls)
    print(
        "FAIL: Rust PID 1 trace is missing expected test-mode startup calls: "
        f"{', '.join(missing)}",
        file=sys.stderr,
    )
    sys.exit(1)

missing_successful_calls = [
    name
    for name, pattern in successful_call_re.items()
    if not any(pattern.match(line) for line in target_text.splitlines())
]
if missing_successful_calls:
    print(
        "FAIL: Rust PID 1 test-mode signal setup lacks successful calls: "
        f"{', '.join(sorted(missing_successful_calls))}",
        file=sys.stderr,
    )
    sys.exit(1)

violations = sorted(syscalls & forbidden)
if violations:
    print(
        "FAIL: unexpected high-risk syscalls observed in the Rust PID 1 trace: "
        + ", ".join(violations),
        file=sys.stderr,
    )
    sys.exit(1)

classes = {}
for name in sorted(syscalls):
    classes.setdefault(classify(name), []).append(name)

summary = ", ".join(f"{klass}:{len(names)}" for klass, names in sorted(classes.items()))
print(
    f"Observed {len(syscalls)} unique syscalls for Rust PID 1 "
    f"({target_path.name}) across classes -> {summary}"
)
PY
