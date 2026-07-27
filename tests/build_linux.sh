#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# build_linux.sh — Cross-compile the systemd Rust port for a Linux target.
#
# Usage:
#   ./tests/build_linux.sh              # build for x86_64-unknown-linux-gnu
#   ./tests/build_linux.sh aarch64      # build for aarch64-unknown-linux-gnu
#   ./tests/build_linux.sh --release    # release build
#
# Prerequisites:
#   rustup target add x86_64-unknown-linux-gnu
#   # or install cross: cargo install cross
#
# On macOS this uses --target with a GNU Linux target.
# For actual Linux testing, use test_boot.sh with a container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TARGET_ARCH="${1:-x86_64}"
RELEASE_FLAG=""

for arg in "$@"; do
    case "$arg" in
        x86_64|aarch64|armv7) TARGET_ARCH="$arg" ;;
        --release) RELEASE_FLAG="--release" ;;
    esac
done

TARGET="${TARGET_ARCH}-unknown-linux-gnu"

echo "========================================"
echo " Building systemd-rs for $TARGET"
echo "========================================"

cd "$PROJECT_ROOT"

# Check if cross is available (preferred for cross-compilation)
if command -v cross &>/dev/null; then
    echo "Using 'cross' for cross-compilation..."
    cross build --workspace --target "$TARGET" $RELEASE_FLAG
elif command -v rustup &>/dev/null && rustup target list --installed | grep -q "$TARGET"; then
    echo "Using 'cargo' with target $TARGET..."
    cargo build --workspace --target "$TARGET" $RELEASE_FLAG
else
    echo "ERROR: Neither 'cross' nor rustup target '$TARGET' is available."
    echo ""
    echo "Install one of:"
    echo "  1. cargo install cross"
    echo "  2. rustup target add $TARGET"
    exit 1
fi

echo ""
echo "========================================"
echo " Build complete for $TARGET"
echo "========================================"

# Show built binaries
if [ -d "target/$TARGET/release" ]; then
    BIN_DIR="target/$TARGET/release"
else
    BIN_DIR="target/$TARGET/debug"
fi

echo "Binaries in $BIN_DIR/:"
ls -la "$BIN_DIR/systemd"* 2>/dev/null || echo "  (no systemd binaries found)"
