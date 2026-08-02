#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Paired C/Rust PID 1 evidence collector. This script is intentionally a
# release gate, not a best-effort smoke test: an unavailable required transport
# or a semantic mismatch returns nonzero and leaves the trace directory intact
# for review.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

private_bus_address='unix:path=/run/systemd/private'

usage() {
    echo "usage: $0 --run [trace-directory] | --compare <trace-directory>" >&2
    exit 2
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

require_trace_file() {
    local path="$1"
    [[ -s "$path" ]] || fail "missing or empty evidence: $path"
}

compare_metadata() {
    local trace_root="$1"
    local c_metadata="$trace_root/c/metadata.env"
    local rust_metadata="$trace_root/rust/metadata.env"
    require_trace_file "$c_metadata"
    require_trace_file "$rust_metadata"

    local c_image rust_image c_arch rust_arch
    c_image="$(awk -F= '$1 == "base_image_sha256" { print $2 }' "$c_metadata")"
    rust_image="$(awk -F= '$1 == "base_image_sha256" { print $2 }' "$rust_metadata")"
    c_arch="$(awk -F= '$1 == "architecture" { print $2 }' "$c_metadata")"
    rust_arch="$(awk -F= '$1 == "architecture" { print $2 }' "$rust_metadata")"
    [[ -n "$c_image" && "$c_image" == "$rust_image" ]] || fail "C and Rust runs did not use the same verified base image"
    [[ -n "$c_arch" && "$c_arch" == "$rust_arch" ]] || fail "C and Rust runs used different host architectures"
    awk -F= '$1 == "rust_binary_sha256" && length($2) == 64 { found = 1 } END { exit !found }' "$rust_metadata" \
        || fail "Rust sidecar hash was not recorded"
}

check_boot_identity() {
    local trace_root="$1"
    local c_identity="$trace_root/c/boot-identity.txt"
    local rust_identity="$trace_root/rust/boot-identity.txt"
    require_trace_file "$c_identity"
    require_trace_file "$rust_identity"

    grep -q '^systemd 0\.0\.1$' "$rust_identity" \
        || fail "Rust trace does not prove the sidecar was PID 1"
    if grep -q '^systemd 0\.0\.1$' "$c_identity"; then
        fail "C baseline trace selected the Rust sidecar"
    fi
}

check_private_peer_evidence() {
    local trace_root="$1"
    local c_private="$trace_root/c/private-bus.txt"
    local rust_private="$trace_root/rust/private-bus.txt"
    require_trace_file "$c_private"
    require_trace_file "$rust_private"

    # This is deliberately an exact-address contract. Do not fall back to the
    # default system bus and do not normalize D-Bus errors or signatures.
    grep -Fx "address=$private_bus_address" "$c_private" \
        || fail "C trace does not prove the direct private-peer address"
    grep -Fx "address=$private_bus_address" "$rust_private" \
        || fail "Rust trace does not prove the direct private-peer address"
    grep -q '^case=root-introspect$' "$c_private" || fail "C trace lacks root private-peer introspection"
    grep -q '^case=user-introspect$' "$c_private" || fail "C trace lacks user private-peer introspection"
    grep -q '^case=root-get-unit$' "$rust_private" || fail "Rust trace lacks root private-peer GetUnit"
    grep -q '^case=user-get-unit$' "$rust_private" || fail "Rust trace lacks user private-peer GetUnit"

    if grep -Eqi 'No such file|Failed to connect|Connection refused|Transport endpoint is not connected' "$rust_private"; then
        fail "Rust private-peer transport is unavailable; Plan 002's vtable/transport matrix must land before lifecycle parity can be claimed"
    fi

    # The connection statuses are semantic evidence. A later promoted matrix
    # supplies the exact expected error names; until then any divergence is a
    # blocker instead of a normalized pass.
    if ! cmp -s "$c_private" "$rust_private"; then
        fail "C/Rust direct private-peer traces differ; inspect $c_private and $rust_private"
    fi
}

self_test() {
    local trace_root
    trace_root="$(mktemp -d /tmp/systemd-pid1-differential-self-test.XXXXXX)"
    mkdir -p "$trace_root/c" "$trace_root/rust"

    printf '%s\n' 'base_image_sha256=fixture' 'architecture=x86_64' >"$trace_root/c/metadata.env"
    printf '%s\n' 'base_image_sha256=fixture' 'architecture=x86_64' \
        'rust_binary_sha256=0123456789012345678901234567890123456789012345678901234567890123' \
        >"$trace_root/rust/metadata.env"
    printf '%s\n' 'systemd 256' >"$trace_root/c/boot-identity.txt"
    printf '%s\n' 'systemd 0.0.1' >"$trace_root/rust/boot-identity.txt"

    write_private_trace() {
        local path="$1" address="$2" extra="${3:-}"
        printf '%s\n' "address=$address" \
            'case=root-introspect' 'status=0' \
            'case=root-get-unit' 'status=0' \
            'case=user-introspect' 'status=0' \
            'case=user-get-unit' 'status=0' \
            "$extra" >"$path"
    }

    write_private_trace "$trace_root/c/private-bus.txt" "$private_bus_address"
    write_private_trace "$trace_root/rust/private-bus.txt" "$private_bus_address"
    bash "$0" --compare "$trace_root" >/dev/null

    write_private_trace "$trace_root/rust/private-bus.txt" 'unix:path=/run/dbus/system_bus_socket'
    if bash "$0" --compare "$trace_root" >/dev/null 2>&1; then
        fail "self-test accepted a non-private D-Bus address"
    fi

    write_private_trace "$trace_root/rust/private-bus.txt" "$private_bus_address" 'Failed to connect'
    if bash "$0" --compare "$trace_root" >/dev/null 2>&1; then
        fail "self-test accepted an unavailable Rust private-peer transport"
    fi

    rm -rf "$trace_root"
    echo "PASS: direct private-peer trace prerequisite self-test."
}

case "${1:-}" in
    --run)
        trace_root="${2:-$(mktemp -d "${TMPDIR:-/tmp}/systemd-pid1-differential.XXXXXX")}"
        mkdir -p "$trace_root"
        echo "INFO: collecting paired evidence in $trace_root" >&2
        SYSTEMD_CD4_MODE=both \
            SYSTEMD_CD4_TRACE_DIR="$trace_root" \
            SYSTEMD_CD4_PRIVATE_BUS_CHECKS=1 \
            SYSTEMD_CD4_SYSTEM_BUS_CHECKS=1 \
            ./test/systemd-cd4.sh
        compare_metadata "$trace_root"
        check_boot_identity "$trace_root"
        check_private_peer_evidence "$trace_root"
        echo "PASS: paired C/Rust PID 1 differential evidence matches without semantic normalization."
        ;;
    --compare)
        trace_root="${2:-}"
        [[ -n "$trace_root" && -d "$trace_root" ]] || usage
        compare_metadata "$trace_root"
        check_boot_identity "$trace_root"
        check_private_peer_evidence "$trace_root"
        echo "PASS: paired C/Rust PID 1 differential evidence matches without semantic normalization."
        ;;
    --self-test) self_test ;;
    *) usage ;;
esac
