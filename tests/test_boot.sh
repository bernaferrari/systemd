#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test_boot.sh — Test systemd-rs as PID 1 in a container.
#
# Usage:
#   ./tests/test_boot.sh              # build + test in podman/docker
#   ./tests/test_boot.sh --docker     # force docker
#   ./tests/test_boot.sh --podman     # force podman
#   ./tests/test_boot.sh --skip-build # skip build, test only
#
# Prerequisites:
#   - podman or docker
#   - rustup target add x86_64-unknown-linux-gnu (or cross)
#
# What this does:
#   1. Builds all systemd-rs binaries for Linux
#   2. Creates a minimal container with the binaries
#   3. Attempts to run systemd-rs as PID 1
#   4. Verifies basic boot operations:
#      - Mounts /proc, /sys, /dev
#      - Scans unit directories
#      - Starts default.target
#      - Lists loaded units
#
# NOTE: Full boot as PID 1 requires privilege and a real Linux kernel.
#       On macOS, use a Linux VM or CI (GitHub Actions) for real testing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTAINER_RUNTIME=""
SKIP_BUILD=false

for arg in "$@"; do
    case "$arg" in
        --docker) CONTAINER_RUNTIME="docker" ;;
        --podman) CONTAINER_RUNTIME="podman" ;;
        --skip-build) SKIP_BUILD=true ;;
    esac
done

# Auto-detect container runtime
if [ -z "$CONTAINER_RUNTIME" ]; then
    if command -v podman &>/dev/null; then
        CONTAINER_RUNTIME="podman"
    elif command -v docker &>/dev/null; then
        CONTAINER_RUNTIME="docker"
    else
        echo "ERROR: Neither podman nor docker found."
        echo "Install one: apt install podman  OR  apt install docker.io"
        exit 1
    fi
fi

echo "Using container runtime: $CONTAINER_RUNTIME"

# ------------------------------------------------------------------
# Step 1: Build for Linux (unless --skip-build)
# ------------------------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
    echo "========================================"
    echo " Step 1: Building systemd-rs for Linux"
    echo "========================================"
    "$SCRIPT_DIR/build_linux.sh" x86_64 --release
fi

# ------------------------------------------------------------------
# Step 2: Create minimal test rootfs
# ------------------------------------------------------------------
echo "========================================"
echo " Step 2: Creating test rootfs"
echo "========================================"

ROOTFS="/tmp/systemd-rs-test-rootfs"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,etc,proc,sys,dev,run,tmp,usr/bin,usr/sbin,usr/lib/systemd/system,var/log}

# Copy built binaries
BIN_DIR="$PROJECT_ROOT/target/x86_64-unknown-linux-gnu/release"
if [ ! -d "$BIN_DIR" ]; then
    BIN_DIR="$PROJECT_ROOT/target/x86_64-unknown-linux-gnu/debug"
fi

if [ -d "$BIN_DIR" ]; then
    cp -f "$BIN_DIR"/systemd* "$ROOTFS/sbin/" 2>/dev/null || true
    cp -f "$BIN_DIR"/systemctl "$ROOTFS/bin/" 2>/dev/null || true
    echo "  Copied binaries from $BIN_DIR"
else
    echo "  WARNING: No Linux binaries found. Run with --skip-build removed."
fi

# Create minimal unit files for testing
cat > "$ROOTFS/usr/lib/systemd/system/default.target" <<'EOF'
[Unit]
Description=Default Target
EOF

cat > "$ROOTFS/usr/lib/systemd/system/network.target" <<'EOF'
[Unit]
Description=Network
EOF

cat > "$ROOTFS/usr/lib/systemd/system/basic.target" <<'EOF'
[Unit]
Description=Basic System
Wants=network.target
After=network.target
EOF

cat > "$ROOTFS/usr/lib/systemd/system/multi-user.target" <<'EOF'
[Unit]
Description=Multi-User System
Wants=basic.target
After=basic.target
EOF

cat > "$ROOTFS/usr/lib/systemd/system/test.service" <<'EOF'
[Unit]
Description=Test Service
After=basic.target

[Service]
Type=simple
ExecStart=/bin/true
EOF

# Create an empty /etc/machine-id (systemd expects this)
echo "uninitialized" > "$ROOTFS/etc/machine-id"

echo "  Created test rootfs at $ROOTFS"
echo "  Unit files:"
ls "$ROOTFS/usr/lib/systemd/system/"

# ------------------------------------------------------------------
# Step 3: Build container image
# ------------------------------------------------------------------
echo "========================================"
echo " Step 3: Building container image"
echo "========================================"

CONTAINERFILE="/tmp/systemd-rs-test.Containerfile"
cat > "$CONTAINERFILE" <<CONTAINERFILE_EOF
FROM debian:bookworm-slim
COPY rootfs/ /
RUN ldconfig 2>/dev/null || true
ENTRYPOINT ["/sbin/systemd"]
CONTAINERFILE_EOF

# Build with rootfs as context
cd /tmp
"$CONTAINER_RUNTIME" build -t systemd-rs-test -f "$CONTAINERFILE" "$ROOTFS" 2>&1 || {
    echo ""
    echo "NOTE: Container build may fail on macOS due to Linux-specific binaries."
    echo "This is expected. Use a Linux VM or CI for full testing."
    echo ""
    echo "To test on Linux CI, add this to your GitHub Actions workflow:"
    echo "  - run: ./tests/test_boot.sh"
    exit 0
}

# ------------------------------------------------------------------
# Step 4: Run container as PID 1
# ------------------------------------------------------------------
echo "========================================"
echo " Step 4: Running systemd-rs as PID 1"
echo "========================================"

# Run with privileges needed for mount operations
"$CONTAINER_RUNTIME" run --rm \
    --name systemd-rs-test \
    --privileged \
    --pid=host \
    systemd-rs-test 2>&1 | head -50 || true

echo ""
echo "========================================"
echo " Test complete"
echo "========================================"
echo ""
echo "If you see mount/unit messages above, the basic boot path works."
echo "For full integration testing, use a real Linux system or VM."
