#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
    echo "Run this script from the systemd repository root." >&2
    exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "SKIP: rustup is not available, skipping Miri smoke checks."
    exit 0
fi

TOOLCHAIN="${RUST_MIRI_TOOLCHAIN:-nightly}"

echo "+ rustup toolchain install ${TOOLCHAIN} --profile minimal"
if ! rustup toolchain install "${TOOLCHAIN}" --profile minimal >/dev/null 2>&1; then
    echo "SKIP: unable to install ${TOOLCHAIN}, skipping Miri smoke checks."
    exit 0
fi

echo "+ rustup component add --toolchain ${TOOLCHAIN} miri"
if ! rustup component add --toolchain "${TOOLCHAIN}" miri >/dev/null 2>&1; then
    echo "SKIP: miri component unavailable for ${TOOLCHAIN}, skipping."
    exit 0
fi

if ! cargo +"${TOOLCHAIN}" miri --version >/dev/null 2>&1; then
    echo "SKIP: cargo-miri unavailable for ${TOOLCHAIN}, skipping."
    exit 0
fi

run() {
    echo "+ $*"
    "$@"
}

run cargo +"${TOOLCHAIN}" miri test --manifest-path src/fundamental/rust/Cargo.toml cleanup::tests::test_array_cleanup -- --exact
run cargo +"${TOOLCHAIN}" miri test --manifest-path src/fundamental/rust/Cargo.toml iovec_util::tests::test_iovec_is_valid -- --exact
run cargo +"${TOOLCHAIN}" miri test --manifest-path src/fundamental/rust/Cargo.toml memory_util::tests::test_var_eraser -- --exact
run cargo +"${TOOLCHAIN}" miri test --manifest-path src/fundamental/rust/Cargo.toml unaligned::tests::test_unaligned_misaligned -- --exact
run cargo +"${TOOLCHAIN}" miri test --manifest-path src/libsystemd/rust/Cargo.toml sd_journal_send::tests::encodes_simple_fields -- --exact
run cargo +"${TOOLCHAIN}" miri test --manifest-path src/libsystemd/rust/Cargo.toml sd_daemon_checks::tests::unix_socket_path_helper_accepts_trailing_bytes_after_nul -- --exact
