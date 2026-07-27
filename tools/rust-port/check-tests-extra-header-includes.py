#!/usr/bin/env python3
"""Reject stale quoted project-header promises in registered tests-extra C tests.

This is intentionally a static source-tree check. Meson is still authoritative
for full preprocessing and generated configuration, but a registered C test
must not claim a project header that does not exist in its normal include
roots. In particular, the historical ``*-fundamental.h`` names were never
generated headers; fundamental headers use their canonical names.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MESON = ROOT / "tests-extra" / "meson.build"
TESTS_DIR = ROOT / "tests-extra"

# These mirror the common ``includes`` object supplied to tests-extra targets:
# src/shared + src/bpf, libsystemd_includes, and basic_includes. Tests can also
# include a sibling helper directly. Keep this list explicit so a same-named
# header in an unrelated subsystem does not satisfy the check accidentally.
INCLUDE_DIRS = (
    TESTS_DIR,
    ROOT / "src/shared",
    ROOT / "src/bpf",
    ROOT / "src/libsystemd",
    ROOT / "src/libsystemd/sd-bus",
    ROOT / "src/libsystemd/sd-device",
    ROOT / "src/libsystemd/sd-event",
    ROOT / "src/libsystemd/sd-future",
    ROOT / "src/libsystemd/sd-hwdb",
    ROOT / "src/libsystemd/sd-id128",
    ROOT / "src/libsystemd/sd-journal",
    ROOT / "src/libsystemd/sd-json",
    ROOT / "src/libsystemd/sd-netlink",
    ROOT / "src/libsystemd/sd-network",
    ROOT / "src/libsystemd/sd-path",
    ROOT / "src/libsystemd/sd-resolve",
    ROOT / "src/libsystemd/sd-varlink",
    ROOT / "src/basic",
    ROOT / "src/fundamental",
    ROOT / "src/systemd",
    ROOT / "src/include/uapi",
    ROOT / "src/include/override",
)

SOURCE_RE = re.compile(r"['\"](test-[^'\"]+\.c)['\"]")
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"\n]+)"', re.MULTILINE)
GENERATED_HEADER_RE = re.compile(r"\boutput\s*:\s*['\"]([^'\"/]+\.h)['\"]")


def registered_sources() -> list[Path]:
    """Return C test sources named by the tests-extra Meson target graph.

    The file contains both ``files('test-…c')`` and direct-source executable
    blocks. Restricting the extraction to test-named C sources deliberately
    excludes unregistered files such as test-sha256-rust.c.
    """

    names = sorted(set(SOURCE_RE.findall(MESON.read_text())))
    missing = [name for name in names if not (TESTS_DIR / name).is_file()]
    if missing:
        raise RuntimeError(f"Meson references missing tests-extra sources: {', '.join(missing)}")
    return [TESTS_DIR / name for name in names]


def generated_headers() -> set[str]:
    """Collect simple Meson header outputs accepted before a build directory exists."""

    outputs: set[str] = set()
    for meson in ROOT.rglob("meson.build"):
        outputs.update(GENERATED_HEADER_RE.findall(meson.read_text()))
    return outputs


def resolves(header: str, generated: set[str]) -> bool:
    if header in generated and "/" not in header:
        return True
    return any((include_dir / header).is_file() for include_dir in INCLUDE_DIRS)


def main() -> int:
    generated = generated_headers()
    errors: list[str] = []
    include_count = 0

    for source in registered_sources():
        for match in INCLUDE_RE.finditer(source.read_text()):
            header = match.group(1)
            include_count += 1
            line = source.read_text()[: match.start()].count("\n") + 1

            if header.endswith("-fundamental.h"):
                errors.append(
                    f"{source.relative_to(ROOT)}:{line}: stale nonexistent fundamental header {header!r}; "
                    "use the canonical header name"
                )
            elif not resolves(header, generated):
                errors.append(
                    f"{source.relative_to(ROOT)}:{line}: quoted project include {header!r} does not resolve "
                    "from tests-extra's tracked include roots or Meson-generated headers"
                )

    if errors:
        print("tests-extra Rust header include gate: FAILED", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(
        "tests-extra Rust header include gate: PASS "
        f"(registered-sources={len(registered_sources())} quote-includes={include_count} "
        "stale-fundamental=0)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
