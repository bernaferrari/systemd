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

run cargo test --locked --manifest-path src/core/rust/Cargo.toml fuzz_unit_file::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/shared/rust/Cargo.toml fuzz_calendarspec::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/journal/rust/Cargo.toml fuzz_journald_native_fd::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/udev/rust/Cargo.toml fuzz_udev_rules::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/network/rust/Cargo.toml fuzz_network_parser::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/network/rust/Cargo.toml fuzz_netdev_parser::tests:: -- --test-threads="${RUST_TEST_THREADS}"
run cargo test --locked --manifest-path src/resolve/rust/Cargo.toml fuzz_dns_packet::tests:: -- --test-threads="${RUST_TEST_THREADS}"
