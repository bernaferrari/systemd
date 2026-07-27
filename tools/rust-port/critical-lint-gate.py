#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

WARNING_RE = re.compile(r"^warning:")
LOCATION_RE = re.compile(r"^\s*-->\s+([^:]+):\d+:\d+")
UNSAFE_RE = re.compile(r"\bunsafe\b")
TRANSMUTE_RE = re.compile(r"\btransmute\b")


@dataclass
class Metrics:
    warnings: int
    unsafe: int
    transmute: int

    def to_dict(self) -> dict[str, int]:
        return {
            "warnings": self.warnings,
            "unsafe": self.unsafe,
            "transmute": self.transmute,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gate warning/unsafe debt for critical Rust crates."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--targets",
        default="tools/rust-port/critical-lint-targets.toml",
        help="Targets config TOML path",
    )
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/critical-lint-baseline.json",
        help="Baseline JSON path",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write/refresh baseline JSON from current metrics",
    )
    return parser.parse_args()


def load_targets(path: Path) -> list[dict[str, object]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    targets = data.get("target", [])
    if not isinstance(targets, list) or not targets:
        raise SystemExit(f"no targets found in {path}")
    return targets


def run_cargo_check(root: Path, manifest: Path, cargo_args: list[str]) -> str:
    cmd = [
        "cargo",
        "check",
        "--manifest-path",
        str(manifest),
        *cargo_args,
    ]
    proc = subprocess.run(
        cmd,
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        sys.stderr.write(output)
        raise SystemExit(f"cargo check failed for {manifest}")
    return output


def count_warnings_for_source(cargo_output: str, source_dir: str) -> int:
    warnings = 0
    pending_warning = False
    source_prefix = source_dir.rstrip("/") + "/"

    for line in cargo_output.splitlines():
        if WARNING_RE.match(line):
            pending_warning = True
            continue

        if not pending_warning:
            continue

        match = LOCATION_RE.match(line)
        if not match:
            continue

        path = match.group(1)
        if path.startswith(source_prefix):
            warnings += 1
        pending_warning = False

    return warnings


def count_text_pattern(root: Path, source_dir: Path, pattern: re.Pattern[str]) -> int:
    count = 0
    for file in source_dir.rglob("*.rs"):
        text = file.read_text(encoding="utf-8", errors="ignore")
        count += len(pattern.findall(text))
    return count


def collect_metrics(root: Path, target: dict[str, object]) -> Metrics:
    name = str(target["name"])
    manifest = root / str(target["manifest"])
    source_dir = root / str(target["source_dir"])
    cargo_args = [str(arg) for arg in target.get("cargo_args", [])]

    output = run_cargo_check(root, manifest, cargo_args)
    warnings = count_warnings_for_source(output, str(target["source_dir"]))
    unsafe = count_text_pattern(root, source_dir, UNSAFE_RE)
    transmute = count_text_pattern(root, source_dir, TRANSMUTE_RE)

    return Metrics(warnings=warnings, unsafe=unsafe, transmute=transmute)


def load_baseline(path: Path) -> dict[str, dict[str, int]]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    targets_file = root / args.targets
    baseline_file = root / args.baseline

    targets = load_targets(targets_file)
    current: dict[str, Metrics] = {}

    for target in targets:
        name = str(target["name"])
        current[name] = collect_metrics(root, target)

    if args.write_baseline:
        baseline_file.parent.mkdir(parents=True, exist_ok=True)
        baseline_file.write_text(
            json.dumps({k: v.to_dict() for k, v in current.items()}, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote baseline: {baseline_file}")
        return 0

    baseline = load_baseline(baseline_file)
    if not baseline:
        raise SystemExit(
            f"baseline not found: {baseline_file}. Run with --write-baseline first."
        )

    failed = False
    print("target,warnings,unsafe,transmute,status")
    for name, metrics in current.items():
        base = baseline.get(name)
        if base is None:
            status = "FAIL(new-target-missing-baseline)"
            failed = True
        else:
            exceeds = (
                metrics.warnings > int(base.get("warnings", 0))
                or metrics.unsafe > int(base.get("unsafe", 0))
                or metrics.transmute > int(base.get("transmute", 0))
            )
            status = "FAIL" if exceeds else "OK"
            failed = failed or exceeds

        print(
            f"{name},{metrics.warnings},{metrics.unsafe},{metrics.transmute},{status}"
        )

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
