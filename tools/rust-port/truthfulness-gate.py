#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject completed port-map claims backed by metadata or incomplete behavior."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

CLAIMED_STATUSES = {"done", "shadow", "replace", "fallback"}
DECLARED_PATH_FIELDS = ("c_file", "rust_file", "header_file", "test_file")
METADATA_MARKERS = (
    "Safe Rust metadata port",
    "Safe Rust synopsis",
    "Port-sync inventory",
    "crate::define_analyze_module!",
    "crate::define_systemctl_module!",
    "PortSyncModule",
)
INCOMPLETE_CLAIM_MARKERS = (
    "fail-closed executable boundary only",
    "full parity still needs",
    "remaining exact gaps",
    "still todo",
    "skipped",
    "subset ported",
)
PID1_RELEASE_GUARD_RE = re.compile(
    r"""^if use_rust_pid1 and get_option\('mode'\) == 'release'
\s+error\('rust-core-pid1 is experimental and cannot be enabled in release mode'\)
endif$""",
    re.MULTILINE,
)
PID1_BUILD_ONLY_WARNING_RE = re.compile(
    r"^\s*warning\('rust-core-pid1 selects an incomplete experimental Rust PID1; "
    r"build-only developer target, C remains the production-selected PID1'\)$",
    re.MULTILINE,
)
PID1_SIDECAR_WARNING_RE = re.compile(
    r"^\s*warning\('rust-core-pid1-sidecar-install installs an incomplete experimental Rust PID1 "
    r"as libexecdir/systemd-rust; developer builds only, C remains the production-selected PID1'\)$",
    re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject completed C-to-Rust mappings backed by metadata adapters or notes that document incomplete behavior."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--map",
        default="tools/rust-port/map.toml",
        help="Port mapping relative to the repository root",
    )
    return parser.parse_args()


def split_declared_paths(value: object) -> list[str] | None:
    if not isinstance(value, str):
        return None
    paths = [item.strip() for item in value.split(";")]
    if not paths or any(not item for item in paths):
        return None
    return paths


def strip_meson_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines())


def check_rust_pid1_release_guard(root: Path, failures: list[str]) -> None:
    core_meson = root / "src/core/meson.build"
    text = strip_meson_comments(core_meson.read_text(encoding="utf-8"))

    if not PID1_RELEASE_GUARD_RE.search(text):
        failures.append(
            "src/core/meson.build: missing fail-closed rust-core-pid1 release-mode guard"
        )
    if not PID1_BUILD_ONLY_WARNING_RE.search(text):
        failures.append("src/core/meson.build: missing exact Rust PID1 build-only warning")
    if not PID1_SIDECAR_WARNING_RE.search(text):
        failures.append("src/core/meson.build: missing exact Rust PID1 sidecar warning")


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    map_path = root / args.map
    manifest = tomllib.loads(map_path.read_text(encoding="utf-8"))

    failures: list[str] = []
    check_rust_pid1_release_guard(root, failures)
    checked = 0
    for module, raw in sorted(manifest.items()):
        if not isinstance(raw, dict):
            continue
        status = str(raw.get("status", "todo")).strip()
        if status not in CLAIMED_STATUSES:
            continue

        notes = str(raw.get("notes", ""))
        incomplete_markers = [
            marker for marker in INCOMPLETE_CLAIM_MARKERS if marker in notes.lower()
        ]
        if incomplete_markers:
            failures.append(
                f"{module}: status={status} contradicts incomplete notes "
                f"({', '.join(incomplete_markers)})"
            )

        for field in DECLARED_PATH_FIELDS:
            declared = raw.get(field)
            if declared is None:
                continue
            paths = split_declared_paths(declared)
            if paths is None:
                failures.append(
                    f"{module}: status={status} has invalid {field}={declared!r}"
                )
                continue
            for declared_path in paths:
                if not (root / declared_path).is_file():
                    failures.append(
                        f"{module}: status={status} points at missing "
                        f"{field} {declared_path}"
                    )

        rust_files = split_declared_paths(raw.get("rust_file"))
        if rust_files is None:
            failures.append(f"{module}: status={status} has no rust_file")
            continue

        existing_rust_files = [
            rust_file for rust_file in rust_files if (root / rust_file).is_file()
        ]
        if len(existing_rust_files) != len(rust_files):
            continue

        checked += 1
        for rust_file in existing_rust_files:
            text = (root / rust_file).read_text(encoding="utf-8", errors="ignore")
            markers = [marker for marker in METADATA_MARKERS if marker in text]
            if markers:
                failures.append(
                    f"{module}: status={status} points at metadata adapter {rust_file} "
                    f"({', '.join(markers)})"
                )

    if failures:
        print("Rust port truthfulness gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(
            "\nMetadata/source-inventory and explicitly incomplete modules must be "
            "todo/in-progress, not claimed as completed behavior.",
            file=sys.stderr,
        )
        return 1

    print(f"Rust port truthfulness gate OK: checked {checked} claimed mappings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
