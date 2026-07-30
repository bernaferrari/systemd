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

if ! command -v rustup >/dev/null 2>&1; then
    skip_or_fail_ci "rustup is not available for Miri smoke checks."
fi

TOOLCHAIN="${RUST_MIRI_TOOLCHAIN:-nightly}"

if ! cargo +"${TOOLCHAIN}" miri --version >/dev/null 2>&1; then
    skip_or_fail_ci "cargo-miri is unavailable for ${TOOLCHAIN}."
fi

run() {
    echo "+ $*"
    "$@"
}

run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/fundamental/rust/Cargo.toml cleanup::tests::test_array_cleanup -- --exact
run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/fundamental/rust/Cargo.toml iovec_util::tests::test_iovec_is_valid -- --exact
run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/fundamental/rust/Cargo.toml memory_util::tests::test_var_eraser -- --exact
run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/fundamental/rust/Cargo.toml unaligned::tests::test_unaligned_misaligned -- --exact
run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/libsystemd/rust/Cargo.toml sd_journal_send::tests::encodes_simple_fields -- --exact
run cargo +"${TOOLCHAIN}" miri test --locked --manifest-path src/libsystemd/rust/Cargo.toml sd_daemon_checks::tests::unix_socket_path_helper_accepts_trailing_bytes_after_nul -- --exact
