#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject accidental production selection of incomplete Rust executables."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORE_MESON = ROOT / "src/core/meson.build"
CD4_HARNESS = ROOT / "test/systemd-cd4.sh"

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

    core = CORE_MESON.read_text(encoding="utf-8")
    rust_pid1 = re.search(
        r"(?ms)rust_pid1\s*=\s*custom_target\(\s*"
        r"'systemd-rust-pid1',.*?"
        r"output\s*:\s*'systemd-rust',.*?"
        r"install\s*:\s*install_rust_pid1_sidecar,.*?"
        r"install_dir\s*:\s*libexecdir\s*\)",
        core,
    )
    if not rust_pid1:
        return fail("Rust PID1 sidecar must remain systemd-rust in libexecdir")
    if re.search(r"(?ms)rust_pid1\s*=\s*custom_target\(.*?output\s*:\s*'systemd'", core):
        return fail("Rust PID1 custom target collides with the canonical systemd output")

    cd4 = CD4_HARNESS.read_text(encoding="utf-8")
    forbidden_overwrite = re.compile(
        r"(?:cp|install)\s+[^'\n]*systemd-rust\s+/(?:usr/)?lib/systemd/systemd(?:['\s]|$)"
    )
    if forbidden_overwrite.search(cd4):
        return fail("CD4 harness overwrites the canonical C PID1 with Rust")
    required_cd4_fragments = (
        "install -m 0755 /root/systemd-rust /usr/lib/systemd/systemd-rust",
        "ln -sfnT /usr/lib/systemd/systemd-rust /sbin/init",
        "test -x /usr/lib/systemd/systemd",
        "test -x /usr/lib/systemd/systemd-rust",
        "test /proc/1/exe -ef /usr/lib/systemd/systemd-rust",
        "SYSTEMD_CD4_SYSTEM_BUS_CHECKS",
    )
    for fragment in required_cd4_fragments:
        if fragment not in cd4:
            return fail(f"CD4 harness lost required sidecar-selection contract {fragment!r}")

    print(
        "Rust production-selection gate OK: "
        f"rust_meson_files={len(rust_mesons)} "
        f"retained_c_tools={retained_count} rust_production_replacements=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
