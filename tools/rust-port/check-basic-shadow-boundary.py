#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep the basic Rust static library isolated from production C ownership."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASIC_MESON = ROOT / "src/basic/meson.build"
ALLOWED_REFERENCE_FILES = {
    Path("src/basic/meson.build"),
    Path("tests-extra/meson.build"),
}
RETAINED_C_SOURCES = {
    "procfs-util.c",
    "stat-util.c",
}


def fail(message: str) -> int:
    print(f"basic Rust shadow-boundary gate: {message}", file=sys.stderr)
    return 1


def meson_files(text: str, variable: str) -> set[str]:
    match = re.search(
        rf"(?ms)^\s*{re.escape(variable)}\s*=\s*files\((.*?)^\s*\)",
        text,
    )
    if not match:
        raise ValueError(f"missing {variable} files() assignment")
    return set(re.findall(r"'([^']+\.(?:c|cc|cpp))'", match.group(1)))


def main() -> int:
    basic = BASIC_MESON.read_text(encoding="utf-8")
    try:
        c_sources = meson_files(basic, "basic_sources")
    except ValueError as error:
        return fail(str(error))

    missing_c = sorted(RETAINED_C_SOURCES - c_sources)
    if missing_c:
        return fail(f"canonical basic C sources were removed: {', '.join(missing_c)}")

    if not re.search(
        r"(?ms)libbasic_static\s*=\s*static_library\(\s*"
        r"'basic',\s*basic_sources,\s*fundamental_sources,",
        basic,
    ):
        return fail("production libbasic no longer selects basic_sources")

    rust_target = re.search(
        r"(?ms)rust_staticlib\s*=\s*custom_target\(\s*"
        r"'systemd_basic_rs',.*?"
        r"output\s*:\s*'libsystemd_basic_rs\.a',.*?"
        r"\)\s*endif",
        basic,
    )
    if not rust_target:
        return fail("Rust basic shadow static library target is missing or malformed")
    if re.search(r"\binstall\s*:\s*(?:true|'yes')", rust_target.group(0)):
        return fail("Rust basic shadow static library became installable")

    reference_files: set[Path] = set()
    for meson in ROOT.rglob("meson.build"):
        if "rust_staticlib" in meson.read_text(encoding="utf-8", errors="ignore"):
            reference_files.add(meson.relative_to(ROOT))
    unexpected = sorted(reference_files - ALLOWED_REFERENCE_FILES)
    if unexpected:
        return fail(
            "rust_staticlib escaped the shadow-test boundary: "
            + ", ".join(map(str, unexpected))
        )
    missing_reference_files = sorted(ALLOWED_REFERENCE_FILES - reference_files)
    if missing_reference_files:
        return fail(
            "expected Rust shadow ownership declarations are missing: "
            + ", ".join(map(str, missing_reference_files))
        )

    tests = (ROOT / "tests-extra/meson.build").read_text(encoding="utf-8")
    if "link_with : [libshared, rust_staticlib]" not in tests:
        return fail("registered differential tests no longer link the Rust shadow archive")

    print(
        "basic Rust shadow-boundary gate OK: "
        f"retained_c={len(RETAINED_C_SOURCES)} "
        f"reference_files={len(reference_files)} production_linkage=none"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
