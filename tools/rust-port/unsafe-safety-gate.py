#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
from collections import Counter
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

UNSAFE_SITE_RE = re.compile(r"unsafe\s*(\{|fn\b|impl\b|trait\b|extern\b)")
UNSAFE_DECL_RE = re.compile(r"unsafe\s*(fn\b|impl\b|trait\b|extern\b)")
UNSAFE_TOKEN_RE = re.compile(r"\bunsafe\b")
TYPE_ALIAS_RE = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?type\b")
SAFETY_RATIONALE_MARKERS = ("SAFETY:", "# Safety")


@dataclass
class FileMetrics:
    unsafe_sites: int = 0
    abi_sites: int = 0
    missing_safety: int = 0
    missing_safety_sites: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "unsafe_sites": self.unsafe_sites,
            "abi_sites": self.abi_sites,
            "missing_safety": self.missing_safety,
            "missing_safety_sites": list(self.missing_safety_sites),
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


def unsafe_site_context(lines: list[str], index: int, column: int) -> str:
    """Return enough following source to recognize legal multiline unsafe syntax.

    Rust permits whitespace between `unsafe` and the construct it qualifies.
    Looking ahead a bounded number of physical lines keeps the gate conservative
    without pretending to parse the whole language.
    """

    return "\n".join([lines[index][column:], *lines[index + 1 : index + 4]])


def missing_site_key(line: str, index: int, column: int) -> str:
    """Make baseline debt location-specific and reviewable.

    A count-only baseline lets a new undocumented unsafe site replace an old
    one without failing the gate. Including the line number and source line
    makes such substitutions fail closed; intentional movement of accepted
    legacy debt requires an explicit, reviewable baseline refresh.
    """

    return f"{index + 1}:{column + 1}:{line.strip()}"


def collect_metrics(root: Path, window: int) -> dict[str, FileMetrics]:
    out: dict[str, FileMetrics] = {}
    for path in iter_rust_sources(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        metrics = FileMetrics()
        missing_safety_sites: list[str] = []
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

            if TYPE_ALIAS_RE.match(stripped):
                in_type_alias = ";" not in line
                continue

            for unsafe_token in UNSAFE_TOKEN_RE.finditer(line):
                context = unsafe_site_context(lines, idx, unsafe_token.start())
                if not UNSAFE_SITE_RE.match(context):
                    continue
                # `unsafe extern` declarations and definitions are ABI
                # contracts, not executable unsafe operations. Keep them in a
                # separate inventory so the execution-surface metric reflects
                # code that can actually perform unsafe operations while every
                # C boundary remains visible and baselined.
                if re.match(r"unsafe\s+extern\b", context):
                    metrics.abi_sites += 1
                else:
                    metrics.unsafe_sites += 1
                if not has_safety_rationale(
                    lines,
                    idx,
                    window,
                    declaration=bool(UNSAFE_DECL_RE.match(context)),
                ):
                    metrics.missing_safety += 1
                    missing_safety_sites.append(
                        missing_site_key(line, idx, unsafe_token.start())
                    )

        metrics.missing_safety_sites = tuple(missing_safety_sites)

        rel = path.relative_to(root).as_posix()
        if metrics.unsafe_sites > 0 or metrics.abi_sites > 0:
            out[rel] = metrics

    return out


def summarize(metrics: dict[str, FileMetrics]) -> dict[str, int]:
    unsafe_sites = sum(m.unsafe_sites for m in metrics.values())
    abi_sites = sum(m.abi_sites for m in metrics.values())
    missing_safety = sum(m.missing_safety for m in metrics.values())
    return {
        "unsafe_sites": unsafe_sites,
        "abi_sites": abi_sites,
        "missing_safety": missing_safety,
    }


def load_baseline(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("version") != 2:
        raise SystemExit(
            f"unsupported safety baseline version in {path}; regenerate it with --write-baseline"
        )
    files = raw.get("files")
    if not isinstance(files, dict):
        raise SystemExit(f"malformed safety baseline files table: {path}")
    for relative, metrics in files.items():
        if not isinstance(relative, str) or not isinstance(metrics, dict):
            raise SystemExit(f"malformed safety baseline file entry in {path}: {relative!r}")
        sites = metrics.get("missing_safety_sites")
        if not isinstance(sites, list) or not all(isinstance(site, str) for site in sites):
            raise SystemExit(f"malformed missing safety site ledger for {relative} in {path}")
        if len(sites) != len(set(sites)):
            raise SystemExit(f"duplicate missing safety site in {relative} in {path}")
        if metrics.get("missing_safety") != len(sites):
            raise SystemExit(
                f"missing safety count does not match site ledger for {relative} in {path}"
            )
        abi_sites = metrics.get("abi_sites", 0)
        if not isinstance(abi_sites, int) or abi_sites < 0:
            raise SystemExit(f"malformed ABI-site count for {relative} in {path}")
    return raw


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline
    current = collect_metrics(root, args.window)
    totals = summarize(current)

    payload = {
        "version": 2,
        "window": args.window,
        "totals": totals,
        "files": {k: v.to_dict() for k, v in sorted(current.items())},
    }

    if args.write_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote baseline: {baseline_path}")
        print(
            f"totals unsafe_sites={totals['unsafe_sites']} "
            f"abi_sites={totals['abi_sites']} missing_safety={totals['missing_safety']}"
        )
        return 0

    baseline = load_baseline(baseline_path)
    if not baseline:
        raise SystemExit(
            f"baseline not found: {baseline_path}. Run with --write-baseline first."
        )

    base_files: dict[str, dict[str, object]] = baseline["files"]  # type: ignore[assignment]
    failed = False

    print("file,unsafe_sites,abi_sites,missing_safety,baseline_missing_safety,status")
    for file_path, metrics in sorted(current.items()):
        base_metrics = base_files.get(file_path, {})
        base_unsafe = int(base_metrics.get("unsafe_sites", 0))
        base_abi = base_metrics.get("abi_sites")
        base_missing = int(base_metrics.get("missing_safety", 0))
        base_sites = Counter(base_metrics.get("missing_safety_sites", []))
        current_sites = Counter(metrics.missing_safety_sites)
        new_sites = sorted((current_sites - base_sites).elements())
        status = "OK"
        if metrics.unsafe_sites > base_unsafe:
            status = "FAIL"
            failed = True
            print(
                f"FAIL unsafe-site growth: {file_path}: "
                f"{base_unsafe} -> {metrics.unsafe_sites}",
                file=sys.stderr,
            )
        # Older baselines predate the split inventory. Their unsafe_sites
        # field remains a conservative upper bound; once refreshed, ABI growth
        # is checked independently here.
        if base_abi is not None and metrics.abi_sites > int(base_abi):
            status = "FAIL"
            failed = True
            print(
                f"FAIL ABI-site growth: {file_path}: "
                f"{base_abi} -> {metrics.abi_sites}",
                file=sys.stderr,
            )
        if new_sites:
            status = "FAIL"
            failed = True
            for site in new_sites:
                print(
                    f"FAIL new undocumented unsafe site: {file_path}:{site}",
                    file=sys.stderr,
                )
        print(
            f"{file_path},{metrics.unsafe_sites},{metrics.abi_sites},"
            f"{metrics.missing_safety},{base_missing},{status}"
        )

    if failed:
        print(
            "\nSAFETY gate failed: unsafe-site growth or a missing SAFETY rationale "
            "is not in the reviewed baseline ledger.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nSAFETY gate OK: unsafe_sites={totals['unsafe_sites']} "
        f"abi_sites={totals['abi_sites']} missing_safety={totals['missing_safety']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
