#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject accidental production selection of incomplete Rust executables."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# These are the only Meson files allowed to know about the Cargo/Rust build
# graph. The basic archive is shadow-test-only; the core target is
# developer-only/non-installed; volatile-root has one fail-closed integration
# harness; tests-extra may link the basic archive.
RUST_MESON_BOUNDARY = {
    Path("src/basic/meson.build"),
    Path("src/core/meson.build"),
    Path("src/volatile-root/meson.build"),
    Path("tests-extra/meson.build"),
}

# Operational Rust counterparts for these tools are incomplete or intentionally
# fail closed. Their current C implementations must remain in Meson's selected
# production graph until an explicit, separately reviewed ownership change.
RETAINED_PRODUCTION_SOURCES = {
    Path("src/boot/meson.build"): {"random-seed.c"},
    Path("src/bootctl/meson.build"): {"bootctl.c"},
    Path("src/creds/meson.build"): {"creds.c"},
    Path("src/journal/meson.build"): {"journalctl.c"},
    Path("src/measure/meson.build"): {"measure-tool.c"},
    Path("src/random-seed/meson.build"): {"random-seed-tool.c"},
    Path("src/resolve/meson.build"): {"resolved.c"},
    Path("src/udev/meson.build"): {"udevd.c"},
    Path("src/volatile-root/meson.build"): {"volatile-root.c"},
}

RUST_BUILD_TOKEN = re.compile(
    r"(?:find_program\(\s*'cargo'|['\"][^'\"]+\.rs['\"]|"
    r"\brust_staticlib\b|\brust_pid1\b|\brust-core-pid1\b)"
)


def fail(message: str) -> int:
    print(f"Rust production-selection gate: {message}", file=sys.stderr)
    return 1


def selected_source_names(text: str) -> set[str]:
    return set(re.findall(r"['\"]([^'\"]+\.(?:c|cc|cpp))['\"]", text))


def main() -> int:
    rust_mesons: set[Path] = set()
    for meson in ROOT.rglob("meson.build"):
        relative = meson.relative_to(ROOT)
        text = meson.read_text(encoding="utf-8", errors="ignore")
        if RUST_BUILD_TOKEN.search(text):
            rust_mesons.add(relative)

    unexpected = sorted(rust_mesons - RUST_MESON_BOUNDARY)
    if unexpected:
        return fail(
            "Rust/Cargo build graph escaped reviewed Meson boundary: "
            + ", ".join(map(str, unexpected))
        )
    missing_boundary = sorted(RUST_MESON_BOUNDARY - rust_mesons)
    if missing_boundary:
        return fail(
            "reviewed Rust Meson boundary declarations disappeared: "
            + ", ".join(map(str, missing_boundary))
        )

    retained_count = 0
    for relative, required_sources in RETAINED_PRODUCTION_SOURCES.items():
        path = ROOT / relative
        if not path.is_file():
            return fail(f"production Meson file is missing: {relative}")
        present = selected_source_names(path.read_text(encoding="utf-8"))
        missing = sorted(required_sources - present)
        if missing:
            return fail(
                f"{relative} lost canonical C production sources: {', '.join(missing)}"
            )
        retained_count += len(required_sources)

    print(
        "Rust production-selection gate OK: "
        f"rust_meson_files={len(rust_mesons)} "
        f"retained_c_tools={retained_count} incomplete_rust_installed=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
