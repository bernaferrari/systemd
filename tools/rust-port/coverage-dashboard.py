#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Counts:
    c_files: int = 0
    rust_files: int = 0
    rust_metadata: int = 0
    rust_test_support: int = 0

    @property
    def rust_behavior_candidates(self) -> int:
        return self.rust_files - self.rust_metadata - self.rust_test_support


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a C-vs-Rust source inventory without claiming parity."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--src",
        default="src",
        help="Source subtree to scan (default: src)",
    )
    parser.add_argument(
        "--exclude-prefix",
        action="append",
        default=["src/test"],
        help="Path prefix to exclude for the secondary total snapshot (repeatable).",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--write",
        help="Optional markdown output path. Prints to stdout if omitted.",
    )
    output.add_argument(
        "--check",
        help="Fail if the generated inventory differs from this markdown path.",
    )
    return parser.parse_args()


def is_excluded(rel: str, excluded: list[str]) -> bool:
    return any(rel == prefix or rel.startswith(prefix + "/") for prefix in excluded)


def classify_rust(path: Path) -> str:
    """Classify source inventory without claiming behavioral parity."""
    stem = path.stem
    parts = set(path.parts)
    if (
        stem.startswith(("test", "fuzz"))
        or stem.endswith(("_test", "_tests"))
        or "tests" in parts
    ):
        return "test-support"
    text = path.read_text(encoding="utf-8", errors="ignore")
    metadata_markers = (
        "Safe Rust metadata port",
        "Safe Rust synopsis",
        "Port-sync inventory",
        "crate::define_analyze_module!",
        "crate::define_systemctl_module!",
        "PortSyncModule",
    )
    if any(marker in text for marker in metadata_markers):
        return "metadata"
    return "behavior-candidate"


def add_rust(counts: Counts, category: str) -> None:
    counts.rust_files += 1
    if category == "metadata":
        counts.rust_metadata += 1
    elif category == "test-support":
        counts.rust_test_support += 1


def render_markdown(
    *,
    root: Path,
    src_root: Path,
    excluded: list[str],
    per_subsystem: dict[str, Counts],
    total: Counts,
    total_excluded: Counts,
) -> str:
    excluded_label = ", ".join(excluded) if excluded else "(none)"

    lines = [
        "# Rust Port Source Inventory",
        "",
        "Repository: repository root",
        f"Scope: `{src_root.relative_to(root).as_posix()}`",
        "",
        "> This is a source inventory, not a completion percentage. A Rust file is",
        "> counted as a behavior candidate only after excluding obvious metadata",
        "> adapters and test/fuzz support. Crate roots and FFI modules remain",
        "> candidates because their filenames do not prove they lack behavior.",
        "> Candidates are still",
        "> unverified until mapped behavior and executable tests pass.",
        "",
        "## Snapshot Totals",
        "",
        f"- All `src` C files: **{total.c_files}**",
        f"- All `src` Rust files: **{total.rust_files}**",
        f"- Rust metadata adapters: **{total.rust_metadata}**",
        f"- Rust test/fuzz support files: **{total.rust_test_support}**",
        f"- Unverified Rust behavior candidates: **{total.rust_behavior_candidates}**",
        "",
        f"Excluding `{excluded_label}`:",
        f"- C files: **{total_excluded.c_files}**",
        f"- Rust files: **{total_excluded.rust_files}**",
        f"- Rust metadata adapters: **{total_excluded.rust_metadata}**",
        f"- Rust test/fuzz support files: **{total_excluded.rust_test_support}**",
        f"- Unverified Rust behavior candidates: **{total_excluded.rust_behavior_candidates}**",
        "",
        "## Per-Subsystem Inventory",
        "",
        "| Subsystem | C | Rust | Metadata | Test/fuzz | Behavior candidates |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for subsystem in sorted(per_subsystem):
        counts = per_subsystem[subsystem]
        lines.append(
            f"| `{subsystem}` | {counts.c_files} | {counts.rust_files} | "
            f"{counts.rust_metadata} | {counts.rust_test_support} | "
            f"{counts.rust_behavior_candidates} |"
        )

    lines += [
        "",
        "## Rebuild",
        "",
        "```sh",
        "python3 tools/rust-port/coverage-dashboard.py --write docs/rust-port-coverage.md",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    src_root = root / args.src
    if not src_root.is_dir():
        raise SystemExit(f"source directory not found: {src_root}")

    per_subsystem: dict[str, Counts] = defaultdict(Counts)
    total = Counts()
    total_excluded = Counts()

    for path in src_root.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix
        if suffix not in {".c", ".rs"}:
            continue

        rel = path.relative_to(root).as_posix()
        try:
            subsystem = path.relative_to(src_root).parts[0]
        except IndexError:
            continue
        bucket = per_subsystem[subsystem]

        if suffix == ".c":
            bucket.c_files += 1
            total.c_files += 1
            if not is_excluded(rel, args.exclude_prefix):
                total_excluded.c_files += 1
        else:
            category = classify_rust(path)
            add_rust(bucket, category)
            add_rust(total, category)
            if not is_excluded(rel, args.exclude_prefix):
                add_rust(total_excluded, category)

    markdown = render_markdown(
        root=root,
        src_root=src_root,
        excluded=args.exclude_prefix,
        per_subsystem=per_subsystem,
        total=total,
        total_excluded=total_excluded,
    )

    if args.write:
        output = root / args.write
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown, encoding="utf-8")
    elif args.check:
        output = root / args.check
        if not output.is_file():
            raise SystemExit(f"inventory not found: {output}")
        if output.read_text(encoding="utf-8") != markdown:
            raise SystemExit(
                f"{output.relative_to(root)} is stale; regenerate it with "
                "tools/rust-port/coverage-dashboard.py --write "
                f"{output.relative_to(root)}"
            )
        print(f"Rust source inventory is current: {output.relative_to(root)}")
    else:
        print(markdown)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
