#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Report Rust shadow-port modules touched by git changes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Sequence, Set

try:
    import tomllib
except ModuleNotFoundError:
    print("ERROR: This script requires Python 3.11+ (tomllib).", file=sys.stderr)
    sys.exit(2)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Show mapped rust-port modules affected by git changes."
    )
    p.add_argument(
        "--map",
        default="tools/rust-port/map.toml",
        help="Path to the rust-port manifest (default: tools/rust-port/map.toml)",
    )
    p.add_argument(
        "--repo-root",
        default=".",
        help="Git repository root for diff calculations (default: current directory).",
    )
    p.add_argument(
        "--range",
        help="Git range to inspect, in A..B form. If omitted, working tree is used.",
    )
    p.add_argument(
        "--worktree",
        action="store_true",
        help=(
            "Force working-tree mode instead of range/base mode."
        ),
    )
    p.add_argument(
        "--base",
        help="Base commit to compare against --head for working snapshots.",
    )
    p.add_argument(
        "--head",
        default="HEAD",
        help="Head commit for --base comparisons (default: HEAD).",
    )
    p.add_argument(
        "--status",
        action="append",
        default=[],
        help="Only include these statuses (repeatable).",
    )
    p.add_argument(
        "--show-unmapped",
        action="store_true",
        help="Print unmapped changed files after mapped module output.",
    )
    p.add_argument(
        "--no-untracked",
        action="store_true",
        help="Do not include untracked files when using working-tree mode.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    return p.parse_args()


def git(repo_root: Path, args: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def parse_mapping(map_path: Path) -> Dict[str, Dict[str, Any]]:
    raw = tomllib.loads(map_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("manifest root must be a table")
    return {
        module_name: dict(entry)
        for module_name, entry in raw.items()
        if isinstance(entry, dict)
    }


def source_paths(
    entry: Dict[str, Any],
    module_name: str,
    *,
    plural_key: str,
    legacy_key: str,
    legacy_separator: str,
) -> List[str]:
    plural_value = entry.get(plural_key)
    legacy_value = entry.get(legacy_key)
    if plural_value is not None and legacy_value is not None:
        raise ValueError(f"{module_name} sets both {legacy_key} and {plural_key}")
    value = plural_value if plural_value is not None else legacy_value
    if value is None:
        return []

    if isinstance(value, str):
        paths = [
            item.strip() for item in value.split(legacy_separator) if item.strip()
        ]
        if not paths:
            raise ValueError(f"{module_name}.{legacy_key} is empty")
    elif isinstance(value, list):
        paths = [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
        if len(paths) != len(value):
            raise ValueError(f"{module_name}.{plural_key} contains invalid entry")
        if not paths:
            raise ValueError(f"{module_name}.{plural_key} is empty")
    else:
        raise ValueError(
            f"{module_name}.{legacy_key}/{plural_key} must be a string or array"
        )

    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise ValueError(
            f"{module_name}.{plural_key} contains duplicate paths: "
            + ", ".join(duplicates)
        )
    for path in paths:
        normalized = PurePosixPath(path)
        if (
            normalized.is_absolute()
            or ".." in normalized.parts
            or str(normalized) != path
            or "\\" in path
        ):
            raise ValueError(
                f"{module_name}.{plural_key} contains non-normalized "
                f"repository path: {path!r}"
            )
    return paths


def c_file_paths(entry: Dict[str, Any], module_name: str) -> List[str]:
    return source_paths(
        entry,
        module_name,
        plural_key="c_paths",
        legacy_key="c_file",
        legacy_separator=",",
    )


def rust_file_paths(entry: Dict[str, Any], module_name: str) -> List[str]:
    return source_paths(
        entry,
        module_name,
        plural_key="rust_paths",
        legacy_key="rust_file",
        legacy_separator=";",
    )


def get_module_touched(
    changed_files: Set[str],
    manifest: Dict[str, Dict[str, Any]],
    status_filter: List[str],
) -> Dict[str, Any]:
    touched = []
    mapped = set()
    scoped = set()

    for module_name, entry in sorted(manifest.items()):
        status = str(entry.get("status", "todo")).strip()
        if status_filter and status not in status_filter:
            continue

        c_files = c_file_paths(entry, module_name)
        rust_files = rust_file_paths(entry, module_name)
        scope_name = entry.get("scope")
        scope_roots = entry.get("rust_scope_paths", [])
        if isinstance(scope_roots, str):
            scope_roots = [scope_roots]
        if not isinstance(scope_roots, list) or not all(
            isinstance(path, str) for path in scope_roots
        ):
            raise ValueError(
                f"{module_name}.rust_scope_paths must be a string or array"
            )

        upstream_touched = sorted(set(c_files) & changed_files)
        rust_touched = sorted(set(rust_files) & changed_files)
        scoped_unowned = sorted(
            path
            for path in changed_files
            if path.endswith(".rs")
            if path not in rust_files
            and any(
                path == root if root.endswith(".rs")
                else path.startswith(root.rstrip("/") + "/")
                for root in scope_roots
            )
        )
        touched_paths = sorted(set(upstream_touched + rust_touched))
        mapped.update(touched_paths)
        scoped.update(scoped_unowned)

        if touched_paths or scoped_unowned:
            touched.append(
                {
                    "module": module_name,
                    "scope": scope_name,
                    "status": status,
                    "touched": touched_paths,
                    "upstream_touched": upstream_touched,
                    "rust_touched": rust_touched,
                    "scoped_unowned": scoped_unowned,
                    "needs_sync_review": bool(upstream_touched),
                    "rust_twin_changed": bool(rust_touched),
                    "inventory_update_required": bool(scoped_unowned),
                }
            )

    unmapped = sorted(changed_files - mapped - scoped)

    return {
        "changed_count": len(changed_files),
        "mapped_count": len(touched),
        "sync_review_count": sum(item["needs_sync_review"] for item in touched),
        "inventory_review_count": sum(
            item["inventory_update_required"] for item in touched
        ),
        "touched_modules": touched,
        "scoped_unowned": sorted(scoped),
        "unmapped": unmapped,
    }


def changed_files_range(repo_root: Path, base: str, head: str) -> Set[str]:
    out = git(repo_root, ["diff", "--name-only", f"{base}..{head}"])
    return {line.strip() for line in out.splitlines() if line.strip()}


def changed_files_worktree(repo_root: Path, include_untracked: bool) -> Set[str]:
    changed = set(line.strip() for line in git(repo_root, ["diff", "--name-only"]).splitlines() if line.strip())
    changed.update(line.strip() for line in git(repo_root, ["diff", "--cached", "--name-only"]).splitlines() if line.strip())

    if include_untracked:
        changed.update(
            line.strip() for line in git(
                repo_root,
                ["ls-files", "-o", "--exclude-standard", "--"],
            ).splitlines() if line.strip()
        )
    return changed


def format_text(report: Dict[str, Any]) -> str:
    lines = [
        f"Touched modules: {report['mapped_count']} "
        f"(sync review: {report['sync_review_count']}; "
        f"inventory review: {report['inventory_review_count']}; "
        f"of {report['changed_count']} changed files)"
    ]

    for item in report["touched_modules"]:
        scope = f" scope={item['scope']}" if item["scope"] else ""
        lines.append(f"- {item['module']} [{item['status']}]{scope}")
        if item["upstream_touched"]:
            lines.append(f"  upstream: {', '.join(item['upstream_touched'])}")
        if item["rust_touched"]:
            lines.append(f"  rust: {', '.join(item['rust_touched'])}")
        if item["scoped_unowned"]:
            lines.append(
                "  unowned-in-scope: " + ", ".join(item["scoped_unowned"])
            )
            lines.append(
                "  action: Rust scope inventory changed; update exact rust_paths"
            )
        if item["upstream_touched"] and not item["rust_touched"]:
            lines.append("  action: C authority changed; review the Rust twin")

    if not report["touched_modules"]:
        lines.append("No mapped modules touched.")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    map_path = Path(args.map)
    if not map_path.is_absolute():
        map_path = (repo_root / map_path).resolve()

    try:
        manifest = parse_mapping(map_path)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: failed to parse {map_path}: {exc}", file=sys.stderr)
        return 2

    try:
        if args.range:
            if ".." not in args.range:
                raise ValueError("--range must use A..B syntax")
            base, head = args.range.split("..", 1)
            changed = changed_files_range(repo_root, base, head)
        elif args.base and not args.worktree:
            changed = changed_files_range(repo_root, args.base, args.head)
        else:
            changed = changed_files_worktree(
                repo_root,
                include_untracked=not args.no_untracked,
            )
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: failed to compute changed files: {exc}", file=sys.stderr)
        return 2

    report = get_module_touched(changed, manifest, args.status)

    if args.show_unmapped:
        report["unmapped"] = [path for path in report["unmapped"]]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_text(report))
        if args.show_unmapped:
            if report["unmapped"]:
                print("\nUnmapped files:")
                for item in report["unmapped"]:
                    print(f"- {item}")
            else:
                print("\nUnmapped files: none")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
