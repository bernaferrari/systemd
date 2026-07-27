#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep the Rust systemd-analyze crate behavioral and deliberately narrow."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the Rust systemd-analyze selected-verb boundary."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    return parser.parse_args()


def main() -> int:
    root = Path(parse_args().root).resolve()
    crate = root / "src/analyze/rust"
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    library = (crate / "lib.rs").read_text(encoding="utf-8")
    binary = (crate / "main.rs").read_text(encoding="utf-8")
    c_driver = (root / "src/analyze/analyze.c").read_text(encoding="utf-8")
    mapping = (root / "tools/rust-port/map.toml").read_text(encoding="utf-8")

    failures: list[str] = []
    required_manifest = (
        'name = "systemd-analyze-rust-port"',
        'name = "systemd-analyze"',
        "systemd-basic-rs",
    )
    for token in required_manifest:
        if token not in manifest:
            failures.append(f"src/analyze/rust/Cargo.toml: missing {token!r}")

    required_library = (
        "pub fn compare_versions",
        "strverscmp_improved",
        "COMPARE_ALLOW_TEXTUAL",
        "EXIT_VERSION_GREATER: i32 = 11",
        "EXIT_VERSION_LESS: i32 = 12",
        "Too few arguments.",
        "Too many arguments.",
        "Unknown operator",
    )
    for token in required_library:
        if token not in library:
            failures.append(f"src/analyze/rust/lib.rs: missing behavioral token {token!r}")

    if "const IMPLEMENTED_VERB: &str = \"compare-versions\";" not in binary:
        failures.append("src/analyze/rust/main.rs: selected verb must be compare-versions")
    if "fail_closed(unsupported)" not in binary:
        failures.append("src/analyze/rust/main.rs: unimplemented verbs must fail closed")
    for marker in ("define_analyze_module", "PortSyncModule", "all_modules", "ported modules available"):
        if marker in library or marker in binary:
            failures.append(f"src/analyze/rust: metadata-only marker remains: {marker}")

    c_verbs = set(re.findall(r'VERB(?:_SCOPE)?\([^)]*?"([^"]+)"', c_driver))
    if "compare-versions" not in c_verbs:
        failures.append("src/analyze/analyze.c: compare-versions disappeared from C verb table")
    if len(c_verbs) < 30:
        failures.append("src/analyze/analyze.c: C verb inventory unexpectedly shrank")
    mapping_entry = mapping.partition("[analyze-compare-versions]")[2].partition("\n[")[0]
    if 'status = "in-progress"' not in mapping_entry:
        failures.append("tools/rust-port/map.toml: selected Rust analyze verb must remain in-progress")

    if failures:
        print("Rust systemd-analyze selected-verb gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "Rust systemd-analyze selected-verb gate OK: compare-versions implemented; "
        f"{len(c_verbs) - 1} C verbs remain fail-closed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
