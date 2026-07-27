#!/usr/bin/env python3
"""Keep the unbuilt TPM2 Rust shadow ABI fail-closed.

`src/shared/rust` is explicitly IDE-only: Meson does not build a shared Rust
library from it. The three old `rs_tpm2_sym_*` declarations therefore made a
link-time promise no production or shadow-test library could honour. The C
implementation is additionally conditional on HAVE_TPM2, a configuration that
the IDE crate does not receive. Until that integration exists, this checker
requires the declaration and test surfaces to remain absent rather than letting
ordinary Rust lookup helpers become a false C ABI.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/shared/rust/tpm2_util.h"
TEST = ROOT / "tests-extra/test-tpm2-util-rust.c"
TEST_MESON = ROOT / "tests-extra/meson.build"
SHARED_MESON = ROOT / "src/shared/meson.build"
SHARED_CARGO = ROOT / "src/shared/rust/Cargo.toml"
BASELINE = ROOT / "tools/rust-port/rust-ffi-inventory-baseline.json"

SYMBOL = re.compile(r"\brs_tpm2_sym_(?:alg_to_string|mode_to_string|mode_from_string)\b")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    if HEADER.exists():
        return fail(f"unbuilt shared Rust TPM2 ABI header must remain removed: {HEADER}")
    if TEST.exists():
        return fail(f"unlinked TPM2 C shadow test must remain removed: {TEST}")

    test_meson = TEST_MESON.read_text()
    if "test-tpm2-util-rust" in test_meson:
        return fail("TPM2 C shadow test is registered without an authoritative Rust ABI library")

    shared_meson = SHARED_MESON.read_text()
    if "rust/tpm2_util.rs" in shared_meson or "systemd_shared_rs" in shared_meson:
        return fail("shared Meson unexpectedly claims to build the IDE-only TPM2 Rust core")

    cargo = SHARED_CARGO.read_text()
    if "IDE support (rust-analyzer) only" not in cargo:
        return fail("shared Rust Cargo manifest no longer records its IDE-only status")

    baseline = json.loads(BASELINE.read_text())
    if "src/shared/rust/tpm2_util.h" in baseline.get("missing_by_header", {}):
        return fail("FFI debt baseline still carries the removed TPM2 ABI header")

    lingering = []
    for path in (ROOT / "src").rglob("*.rs"):
        matches = SYMBOL.findall(path.read_text(encoding="utf-8", errors="ignore"))
        if matches:
            lingering.append(f"{path.relative_to(ROOT)}: {', '.join(sorted(set(matches)))}")
    if lingering:
        return fail("orphaned TPM2 C ABI exports remain: " + "; ".join(lingering))

    print(
        "TPM2 Rust ABI fail-closed inventory: "
        "declared=0 exported=0 signatures=0 duplicates=0 Meson-test-targets=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
