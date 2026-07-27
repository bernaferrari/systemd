#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
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

target_dir="$tmpdir/target"
shim="$target_dir/debug/journalctl"
backend="$target_dir/debug/journalctl-c"
args_file="$tmpdir/backend.args"

run cargo build --locked --manifest-path src/journal/rust/Cargo.toml --bin journalctl --target-dir "$target_dir" >/dev/null

if [[ ! -x "$shim" ]]; then
    echo "FAIL: expected built shim at $shim" >&2
    exit 1
fi

cat >"$backend" <<'EOF'
#!/usr/bin/env sh
set -eu
: "${SYSTEMD_JOURNALCTL_TEST_ARGS_FILE:?}"
printf '%s\n' "$@" > "$SYSTEMD_JOURNALCTL_TEST_ARGS_FILE"
exit 42
EOF
chmod +x "$backend"

set +e
SYSTEMD_JOURNALCTL_TEST_ARGS_FILE="$args_file" "$shim" --foo bar "--qux=a b"
status=$?
set -e
if [[ "$status" -ne 42 ]]; then
    echo "FAIL: expected shim backend exit status 42, got $status" >&2
    exit 1
fi
diff -u <(printf '%s\n' --foo bar "--qux=a b") "$args_file"

run rm -f "$backend"
set +e
SYSTEMD_JOURNALCTL_BACKEND="$shim" "$shim" --version >"$tmpdir/self.stdout" 2>"$tmpdir/self.stderr"
status=$?
set -e
if [[ "$status" -ne 127 ]]; then
    echo "FAIL: expected self-backend resolution failure exit status 127, got $status" >&2
    exit 1
fi
grep -F "could not find executable backend 'journalctl-c'" "$tmpdir/self.stderr" >/dev/null

mkdir -p "$tmpdir/path-bin"
cat >"$tmpdir/path-bin/journalctl-c" <<'EOF'
#!/usr/bin/env sh
exit 43
EOF
chmod +x "$tmpdir/path-bin/journalctl-c"

set +e
PATH="$tmpdir/path-bin:$PATH" SYSTEMD_JOURNALCTL_ALLOW_PATH=1 "$shim" --version
status=$?
set -e
if [[ "$status" -ne 43 ]]; then
    echo "FAIL: expected PATH backend exit status 43 with SYSTEMD_JOURNALCTL_ALLOW_PATH=1, got $status" >&2
    exit 1
fi

echo "PASS: rust journalctl shim smoke checks"
