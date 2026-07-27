#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

UNSAFE_SITE_RE = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b|extern\b)")
UNSAFE_DECL_RE = re.compile(r"\bunsafe\s*(fn\b|impl\b|trait\b|extern\b)")
SAFETY_RATIONALE_MARKERS = ("SAFETY:", "# Safety")


@dataclass
class FileMetrics:
    unsafe_sites: int = 0
    missing_safety: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "unsafe_sites": self.unsafe_sites,
            "missing_safety": self.missing_safety,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gate missing SAFETY rationale near unsafe Rust sites with a baseline."
    )
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/unsafe-safety-baseline.json",
        help="Baseline JSON path",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=3,
        help="How many previous lines to scan for SAFETY rationale (default: 3)",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write/refresh baseline JSON from current metrics",
    )
    return parser.parse_args()


def iter_rust_sources(root: Path):
    src = root / "src"
    for path in src.rglob("*.rs"):
        parts = set(path.parts)
        if "target" in parts:
            continue
        yield path


def has_safety_rationale(
    lines: list[str], index: int, window: int, *, declaration: bool
) -> bool:
    start = max(0, index - window)
    for i in range(start, index + 1):
        if any(marker in lines[i] for marker in SAFETY_RATIONALE_MARKERS):
            return True

    if declaration:
        # Rustdoc safety sections often contain several contract lines. Scan
        # the complete contiguous doc/attribute block instead of requiring the
        # `# Safety` heading to fit inside the local unsafe-block window.
        for i in range(index - 1, -1, -1):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith(("///", "//!", "#[")):
                if any(marker in lines[i] for marker in SAFETY_RATIONALE_MARKERS):
                    return True
                continue
            break

    return False


def collect_metrics(root: Path, window: int) -> dict[str, FileMetrics]:
    out: dict[str, FileMetrics] = {}
    for path in iter_rust_sources(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        metrics = FileMetrics()
        in_type_alias = False

        for idx, line in enumerate(lines):
            stripped = line.strip()

            # Type aliases to unsafe function pointers are declarations, not
            # unsafe execution points. rustfmt may wrap the `unsafe extern`
            # portion onto continuation lines, so skip the complete alias.
            if in_type_alias:
                if ";" in line:
                    in_type_alias = False
                continue

            if not stripped or stripped.startswith("//"):
                continue

            if stripped.startswith("type "):
                in_type_alias = ";" not in line
                continue

            if UNSAFE_SITE_RE.search(line):
                metrics.unsafe_sites += 1
                if not has_safety_rationale(
                    lines,
                    idx,
                    window,
                    declaration=bool(UNSAFE_DECL_RE.search(line)),
                ):
                    metrics.missing_safety += 1

        rel = path.relative_to(root).as_posix()
        if metrics.unsafe_sites > 0:
            out[rel] = metrics

    return out


def summarize(metrics: dict[str, FileMetrics]) -> dict[str, int]:
    unsafe_sites = sum(m.unsafe_sites for m in metrics.values())
    missing_safety = sum(m.missing_safety for m in metrics.values())
    return {"unsafe_sites": unsafe_sites, "missing_safety": missing_safety}


def load_baseline(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline
    current = collect_metrics(root, args.window)
    totals = summarize(current)

    payload = {
        "window": args.window,
        "totals": totals,
        "files": {k: v.to_dict() for k, v in sorted(current.items())},
    }

    if args.write_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote baseline: {baseline_path}")
        print(f"totals unsafe_sites={totals['unsafe_sites']} missing_safety={totals['missing_safety']}")
        return 0

    baseline = load_baseline(baseline_path)
    if not baseline:
        raise SystemExit(
            f"baseline not found: {baseline_path}. Run with --write-baseline first."
        )

    base_files: dict[str, dict[str, int]] = baseline.get("files", {})  # type: ignore[assignment]
    failed = False

    print("file,unsafe_sites,missing_safety,baseline_missing_safety,status")
    for file_path, metrics in sorted(current.items()):
        base_missing = int(base_files.get(file_path, {}).get("missing_safety", 0))
        status = "OK"
        if metrics.missing_safety > base_missing:
            status = "FAIL"
            failed = True
        print(
            f"{file_path},{metrics.unsafe_sites},{metrics.missing_safety},{base_missing},{status}"
        )

    # New files with missing SAFETY comments are automatically caught above
    # because baseline value defaults to 0.
    if failed:
        print(
            "\nSAFETY gate failed: missing SAFETY rationale increased in one or more files.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nSAFETY gate OK: unsafe_sites={totals['unsafe_sites']} missing_safety={totals['missing_safety']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
