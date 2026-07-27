#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Enforce truthful source ownership metadata for every mapped Rust port."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path


VALID_SYNC_STATUSES = {"needs_review", "partial", "synced", "out_of_date"}
PORT_SYNC_RE = re.compile(r"^\s*(?://|/\*)\s*PORT-SYNC:", re.MULTILINE)
PORT_GAP_RE = re.compile(r"^\s*(?://|/\*)\s*PORT-GAP:", re.MULTILINE)
SCOPED_PORT_SYNC_RE = re.compile(
    r"^\s*(?://|/\*)\s*PORT-SYNC:\s*scope=([A-Za-z0-9_.-]+)\b",
    re.MULTILINE,
)


def load_stale_check():
    script = Path(__file__).with_name("stale-check.py")
    spec = importlib.util.spec_from_file_location("rust_port_stale_check", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require mapped Rust files to declare PORT-SYNC/PORT-GAP ownership "
            "and reject unanchored sticky or falsely synced map entries."
        )
    )
    parser.add_argument("--repo-root", default=".", help="Git repository root")
    parser.add_argument(
        "--map",
        default="tools/rust-port/map.toml",
        help="Rust port map relative to the repository root",
    )
    return parser.parse_args()


def annotation_in_preamble(text: str, pattern: re.Pattern[str]) -> bool:
    """Keep ownership discoverable without accepting a marker buried in logic."""

    preamble = "\n".join(text.splitlines()[:16])
    return pattern.search(preamble) is not None


def audit_manifest(
    root: Path, manifest, stale_check
) -> tuple[list[str], int, int, int]:
    """Return failures, Rust path count, synced-anchor count, and review count."""

    failures: list[str] = []
    mapped_rust_paths: set[str] = set()
    anchored = 0
    reviewed = 0
    try:
        stale_check.validate_manifest(manifest, root)
    except (OSError, RuntimeError, ValueError) as error:
        return [f"manifest scope inventory is invalid: {error}"], 0, 0, 0

    for module, entry in sorted(manifest.items()):
        try:
            c_paths = stale_check.c_file_paths(entry, module)
            rust_paths = stale_check.rust_file_paths(entry, module)
            scope = stale_check.scope_name(entry, module)
            result = stale_check.evaluate_module(
                module,
                entry,
                root,
                strict=True,
                warn_missing=False,
                require_existing=True,
            )
        except (OSError, RuntimeError, ValueError) as error:
            failures.append(f"{module}: invalid mapping: {error}")
            continue

        if not rust_paths:
            failures.append(f"{module}: mapping has no Rust twin path")
            continue
        mapped_rust_paths.update(rust_paths)

        sync_status = entry.get("sync_status", "needs_review")
        if sync_status not in VALID_SYNC_STATUSES:
            failures.append(
                f"{module}: unsupported sync_status={sync_status!r}; "
                f"expected one of {sorted(VALID_SYNC_STATUSES)}"
            )
        if sync_status == "synced" and not result["fully_anchored"]:
            failures.append(
                f"{module}: sync_status=synced requires exact upstream and Rust blob anchors"
            )
        if result["fully_anchored"]:
            anchored += 1
        if result["fully_reviewed"] or result["fully_anchored"]:
            reviewed += 1
        if result["stale"]:
            failures.extend(f"{module}: {reason}" for reason in result["reasons"])

        if scope is not None:
            contract_file = entry.get("contract_file")
            if not isinstance(contract_file, str) or not contract_file.strip():
                failures.append(
                    f"{module}: scoped ownership requires a contract_file"
                )
            if sync_status == "partial" and not result["fully_reviewed"]:
                failures.append(
                    f"{module}: scoped sync_status=partial requires exact "
                    "last_reviewed upstream and Rust snapshots"
                )

        expected_marker = PORT_SYNC_RE if c_paths else PORT_GAP_RE
        expected_name = "PORT-SYNC" if c_paths else "PORT-GAP"
        for rust_path in rust_paths:
            source = root / rust_path
            if not source.is_file():
                # `evaluate_module(require_existing=True)` already records this,
                # but keep the annotation check from raising a second exception.
                continue
            text = source.read_text(encoding="utf-8", errors="ignore")
            if not annotation_in_preamble(text, expected_marker):
                failures.append(
                    f"{module}: {rust_path} lacks a {expected_name}: marker "
                    "in its first 16 lines"
                )
                continue
            if scope is not None and c_paths:
                marker = SCOPED_PORT_SYNC_RE.search(
                    "\n".join(text.splitlines()[:16])
                )
                if marker is None:
                    failures.append(
                        f"{module}: {rust_path} lacks a machine-checkable "
                        f"PORT-SYNC: scope={scope} marker in its first 16 lines"
                    )
                elif marker.group(1) != scope:
                    failures.append(
                        f"{module}: {rust_path} declares scope={marker.group(1)} "
                        f"but its manifest owner is scope={scope}"
                    )
    return failures, len(mapped_rust_paths), anchored, reviewed


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root).resolve()
    map_path = Path(args.map)
    if not map_path.is_absolute():
        map_path = root / map_path

    stale_check = load_stale_check()
    try:
        manifest = stale_check.load_manifest(map_path)
    except (OSError, ValueError) as error:
        print(f"sync metadata gate: cannot load map: {error}", file=sys.stderr)
        return 2

    failures, rust_path_count, anchored, reviewed = audit_manifest(
        root, manifest, stale_check
    )

    if failures:
        print("Rust port sync metadata gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "Rust port sync metadata gate OK: "
        f"modules={len(manifest)} rust_paths={rust_path_count} "
        f"synced={anchored} reviewed={reviewed} "
        f"unreviewed={len(manifest) - reviewed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
