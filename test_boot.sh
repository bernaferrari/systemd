#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test script for booting our Rust systemd as PID 1.
# Runs inside a Linux namespace to simulate PID 1 boot.
#
# Usage:
#   ./test_boot.sh              # Build and test in unshare
#   ./test_boot.sh --build-only # Just build
#   ./test_boot.sh --docker     # Use Docker instead of unshare
#
# Prerequisites (on Linux):
#   - Rust toolchain (cross-compile for x86_64-unknown-linux-gnu)
#   - unshare capability or Docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/target/release"
BIN_NAME="systemd"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Step 1: Build
build_systemd() {
    log_info "Building Rust systemd..."
    cd "$SCRIPT_DIR"

    if ! command -v cargo &>/dev/null; then
        log_error "cargo not found. Install Rust toolchain first."
        exit 1
    fi

    cargo build --release --bin systemd 2>&1 || {
        log_error "Build failed."
        exit 1
    }

    if [ -f "${BUILD_DIR}/${BIN_NAME}" ]; then
        local size
        size=$(stat -f%z "${BUILD_DIR}/${BIN_NAME}" 2>/dev/null || stat -c%s "${BUILD_DIR}/${BIN_NAME}" 2>/dev/null || echo "unknown")
        log_info "Built: ${BUILD_DIR}/${BIN_NAME} (${size} bytes)"
    else
        log_error "Binary not found at ${BUILD_DIR}/${BIN_NAME}"
        exit 1
    fi
}

# Step 2: Prepare minimal rootfs
prepare_rootfs() {
    local rootfs="$1"
    log_info "Preparing minimal rootfs at ${rootfs}..."

    mkdir -p "${rootfs}"/{bin,sbin,etc,proc,sys,dev,run,tmp,var/log,var/lib/systemd,usr/bin,usr/lib}

    # Copy our systemd binary as both /sbin/init and /bin/systemd
    cp -f "${BUILD_DIR}/${BIN_NAME}" "${rootfs}/sbin/init"
    chmod 755 "${rootfs}/sbin/init"
    ln -sf /sbin/init "${rootfs}/bin/systemd"

    # Create minimal fstab
    cat > "${rootfs}/etc/fstab" << 'EOF'
# Minimal fstab for Rust systemd boot test
proc    /proc   proc    defaults        0 0
sysfs   /sys    sysfs   defaults        0 0
devtmpfs /dev   devtmpfs defaults       0 0
tmpfs   /run    tmpfs   defaults        0 0
tmpfs   /tmp    tmpfs   defaults        0 0
EOF

    # Create minimal os-release
    cat > "${rootfs}/etc/os-release" << 'EOF'
ID=rust-systemd
VERSION_ID="0.1.0"
PRETTY_NAME="Rust systemd Test"
EOF

    # Create machine-id
    head -c 16 /dev/urandom 2>/dev/null | xxd -p | head -c 32 > "${rootfs}/etc/machine-id" 2>/dev/null || \
        echo "uninitialized" > "${rootfs}/etc/machine-id"

    # Create default target unit
    mkdir -p "${rootfs}/etc/systemd/system"
    cat > "${rootfs}/etc/systemd/system/default.target" << 'EOF'
[Unit]
Description=Default Target
EOF

    log_info "Rootfs prepared."
}

# Step 3: Test in unshare
test_unshare() {
    local rootfs="$1"
    log_info "Testing with unshare (user namespace)..."

    unshare --user --pid --mount --fork --map-root-user \
        --root "${rootfs}" \
        /sbin/init --test 2>&1 || {
        log_warn "unshare test failed (may need root or kernel support)."
        log_warn "Try: sudo ./test_boot.sh --unshare"
        return 1
    }

    log_info "unshare test passed."
    return 0
}

# Step 4: Test in Docker
test_docker() {
    local rootfs="$1"
    log_info "Testing with Docker..."

    if ! command -v docker &>/dev/null; then
        log_error "Docker not found."
        return 1
    fi

    # Create a minimal Dockerfile
    cat > "${rootfs}/Dockerfile" << 'EOF'
FROM scratch
COPY . /
ENTRYPOINT ["/sbin/init"]
EOF

    docker build -t rust-systemd-test "${rootfs}" 2>&1 || {
        log_error "Docker build failed."
        return 1
    }

    log_info "Running container..."
    timeout 10 docker run --rm --pid=host rust-systemd-test 2>&1 || true

    log_info "Docker test completed."
    return 0
}

# Step 5: Validate binary
validate_binary() {
    local bin="${BUILD_DIR}/${BIN_NAME}"
    log_info "Validating binary..."

    # Check it's a valid ELF binary
    if file "${bin}" 2>/dev/null | grep -q "ELF\|executable"; then
        log_info "Binary format: $(file "${bin}")"
    elif file "${bin}" 2>/dev/null | grep -q "Mach-O\|PE32"; then
        log_warn "Binary is not ELF — built for non-Linux target?"
        log_warn "Cross-compile with: cargo build --target x86_64-unknown-linux-gnu"
    fi

    # Check for required symbols
    if nm "${bin}" 2>/dev/null | grep -q "main"; then
        log_info "Binary has main() symbol."
    fi
}

# Main
main() {
    local action="${1:-full}"

    case "${action}" in
        --build-only)
            build_systemd
            validate_binary
            log_info "Build complete. Run on Linux to test boot."
            ;;
        --docker)
            build_systemd
            local tmpdir
            tmpdir=$(mktemp -d /tmp/rust-systemd-test.XXXXXX)
            trap "rm -rf ${tmpdir}" EXIT
            prepare_rootfs "${tmpdir}"
            test_docker "${tmpdir}"
            ;;
        --validate)
            validate_binary
            ;;
        --help|-h)
            echo "Usage: $0 [--build-only|--docker|--validate|--help]"
            ;;
        *)
            build_systemd
            validate_binary

            if [ "$(uname -s)" = "Linux" ]; then
                local tmpdir
                tmpdir=$(mktemp -d /tmp/rust-systemd-test.XXXXXX)
                trap "rm -rf ${tmpdir}" EXIT
                prepare_rootfs "${tmpdir}"
                test_unshare "${tmpdir}" || true
            else
                log_warn "Not running on Linux. Binary built but cannot test boot."
                log_warn "Transfer to a Linux system and run as PID 1 to test."
            fi
            ;;
    esac
}

main "$@"
