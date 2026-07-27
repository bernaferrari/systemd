#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"

run() {
    echo "+ $*"
    "$@"
}

run cargo test --locked --manifest-path src/core/rust/Cargo.toml dbus_manager::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/core/rust/Cargo.toml dbus_util::tests::manage_units_authorization_ -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/udev/rust/Cargo.toml --bin systemd-udevd -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/journal/rust/Cargo.toml journald_runtime::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/journal/rust/Cargo.toml --test live_daemon_e2e -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/journal/rust/Cargo.toml --bin journalctl -- --test-threads="${RUST_TEST_THREADS}"
run ./test/test-rust-journalctl-shim-smoke.sh
run ./test/test-rust-journal-parity-smoke.sh
run ./test/test-rust-fuzz-smoke.sh
run ./test/test-rust-pid1-syscall-smoke.sh
run ./test/test-rust-cgroup-isolation-smoke.sh
run ./test/test-rust-activation-ordering-smoke.sh
run ./test/test-rust-service-lifecycle-smoke.sh
