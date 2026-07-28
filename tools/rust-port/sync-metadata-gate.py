#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Enforce truthful source ownership metadata for every mapped Rust port."""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


VALID_SYNC_STATUSES = {"needs_review", "partial", "synced", "out_of_date"}
PORT_SYNC_RE = re.compile(r"^\s*(?://|/\*)\s*PORT-SYNC:", re.MULTILINE)
PORT_GAP_RE = re.compile(r"^\s*(?://|/\*)\s*PORT-GAP:", re.MULTILINE)
SCOPED_PORT_SYNC_RE = re.compile(
    r"^\s*(?://|/\*)\s*PORT-SYNC:\s*"
    r"scope=([A-Za-z0-9][A-Za-z0-9_.-]*)\s*;\s*"
    r"authority=([^*\r\n]+?)(?:\s*\*/)?\s*$",
    re.MULTILINE,
)

# Upstream commit 74d392ed1bab578e901699ee272faa0c8b922128 renamed the
# fundamental layer to the names below.  Retaining the exact one-to-one history
# here makes a retired name an actionable metadata error, rather than merely a
# confusing missing path after the next sync.  Do not add aliases to map.toml:
# its c_paths are deliberately the current C authority.
RETIRED_FUNDAMENTAL_PATHS = {
    "src/fundamental/assert-fundamental.h": "src/fundamental/assert-util.h",
    "src/fundamental/bootspec-fundamental.c": "src/fundamental/bootspec.c",
    "src/fundamental/bootspec-fundamental.h": "src/fundamental/bootspec.h",
    "src/fundamental/chid-fundamental.c": "src/fundamental/chid.c",
    "src/fundamental/chid-fundamental.h": "src/fundamental/chid.h",
    "src/fundamental/cleanup-fundamental.h": "src/fundamental/cleanup-util.h",
    "src/fundamental/confidential-virt-fundamental.h": "src/fundamental/confidential-virt.h",
    "src/fundamental/edid-fundamental.c": "src/fundamental/edid.c",
    "src/fundamental/edid-fundamental.h": "src/fundamental/edid.h",
    "src/fundamental/efi-fundamental.h": "src/fundamental/efi.h",
    "src/fundamental/efivars-fundamental.c": "src/fundamental/efivars.c",
    "src/fundamental/efivars-fundamental.h": "src/fundamental/efivars.h",
    "src/fundamental/iovec-util-fundamental.h": "src/fundamental/iovec-util.h",
    "src/fundamental/macro-fundamental.h": "src/fundamental/macro.h",
    "src/fundamental/memory-util-fundamental.c": "src/fundamental/memory-util.c",
    "src/fundamental/memory-util-fundamental.h": "src/fundamental/memory-util.h",
    "src/fundamental/sha1-fundamental.c": "src/fundamental/sha1.c",
    "src/fundamental/sha1-fundamental.h": "src/fundamental/sha1.h",
    "src/fundamental/sha256-fundamental.c": "src/fundamental/sha256.c",
    "src/fundamental/sha256-fundamental.h": "src/fundamental/sha256.h",
    "src/fundamental/string-table-fundamental.h": "src/fundamental/string-table.h",
    "src/fundamental/string-util-fundamental.c": "src/fundamental/string-util.c",
    "src/fundamental/string-util-fundamental.h": "src/fundamental/string-util.h",
    "src/fundamental/strv-fundamental.h": "src/fundamental/strv.h",
    "src/fundamental/unaligned-fundamental.h": "src/fundamental/unaligned.h",
}


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
    parser.add_argument(
        "--upstream-ref",
        help=(
            "Require every mapped C authority path to exist at this Git ref "
            "(for example origin/main)"
        ),
    )
    return parser.parse_args()


def annotation_in_preamble(text: str, pattern: re.Pattern[str]) -> bool:
    """Keep ownership discoverable without accepting a marker buried in logic."""

    preamble = "\n".join(text.splitlines()[:16])
    return pattern.search(preamble) is not None


def audit_reviewed_rename_history(root: Path, manifest, stale_check) -> list[str]:
    """Reject fundamental authority names retired by the reviewed upstream rename.

    The manifest is authoritative for mapped Rust, while unscoped PORT-SYNC
    comments remain useful navigation for the broader fundamental crate. Audit
    both so a future edit cannot reintroduce a retired name in either layer.
    """

    failures: list[str] = []
    for module, entry in sorted(manifest.items()):
        try:
            authorities = stale_check.c_file_paths(entry, module)
        except (OSError, RuntimeError, ValueError) as error:
            # audit_manifest() reports malformed mappings with the established
            # diagnostic; do not obscure it with a second rename error.
            continue
        for authority in authorities:
            replacement = RETIRED_FUNDAMENTAL_PATHS.get(authority)
            if replacement is not None:
                failures.append(
                    f"{module}: retired C authority {authority}; use {replacement}"
                )

    source_root = root / "src"
    if not source_root.is_dir():
        return failures
    for source in sorted(source_root.rglob("*")):
        if not source.is_file() or source.suffix not in {".rs", ".h"}:
            continue
        preamble = "\n".join(
            source.read_text(encoding="utf-8", errors="ignore").splitlines()[:16]
        )
        if "PORT-SYNC:" not in preamble:
            continue
        for retired, replacement in RETIRED_FUNDAMENTAL_PATHS.items():
            if retired in preamble:
                failures.append(
                    f"{source.relative_to(root)}: retired PORT-SYNC authority "
                    f"{retired}; use {replacement}"
                )
    return failures


def audit_upstream_authority_paths(
    root: Path, manifest, stale_check, upstream_ref: str
) -> list[str]:
    """Verify C authority paths at the selected upstream tree without checkout."""

    resolved = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{upstream_ref}^{{commit}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if resolved.returncode != 0:
        detail = resolved.stderr.strip() or resolved.stdout.strip()
        return [f"cannot resolve upstream ref {upstream_ref!r}: {detail}"]

    failures: list[str] = []
    for module, entry in sorted(manifest.items()):
        try:
            authorities = stale_check.c_file_paths(entry, module)
        except (OSError, RuntimeError, ValueError):
            continue
        for authority in authorities:
            exists = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "cat-file",
                    "-e",
                    f"{upstream_ref}:{authority}",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if exists.returncode != 0:
                failures.append(
                    f"{module}: C authority {authority} does not exist at "
                    f"{upstream_ref}"
                )
    return failures


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
            provenance_edges = stale_check.scoped_c_provenance(
                entry, module, root
            )
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
                    f"{module}: sync_status=partial requires exact "
                    "last_reviewed upstream and Rust snapshots"
                )
        elif sync_status == "partial":
            failures.append(
                f"{module}: sync_status=partial requires scoped ownership "
                "and a behavior contract"
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
                direct_by_rust: dict[str, set[str]] = {
                    path: set() for path in rust_paths
                }
                assert provenance_edges is not None
                for edge in provenance_edges:
                    if edge["kind"] != "direct":
                        continue
                    for edge_rust_path in edge["rust_paths"]:
                        direct_by_rust[edge_rust_path].add(edge["path"])
                marker = SCOPED_PORT_SYNC_RE.search(
                    "\n".join(text.splitlines()[:16])
                )
                if marker is None:
                    failures.append(
                        f"{module}: {rust_path} lacks a machine-checkable "
                        f"PORT-SYNC: scope={scope}; authority=... marker "
                        "in its first 16 lines"
                    )
                elif marker.group(1) != scope:
                    failures.append(
                        f"{module}: {rust_path} declares scope={marker.group(1)} "
                        f"but its manifest owner is scope={scope}"
                    )
                else:
                    authorities = [
                        item.strip()
                        for item in marker.group(2).split(",")
                        if item.strip()
                    ]
                    if not authorities:
                        failures.append(
                            f"{module}: {rust_path} has an empty PORT-SYNC authority"
                        )
                        continue
                    duplicates = sorted(
                        {
                            path
                            for path in authorities
                            if authorities.count(path) > 1
                        }
                    )
                    if duplicates:
                        failures.append(
                            f"{module}: {rust_path} repeats PORT-SYNC authority: "
                            + ", ".join(duplicates)
                        )
                    for authority in authorities:
                        normalized = PurePosixPath(authority)
                        if (
                            normalized.is_absolute()
                            or ".." in normalized.parts
                            or str(normalized) != authority
                            or "\\" in authority
                        ):
                            failures.append(
                                f"{module}: {rust_path} has non-normalized "
                                f"PORT-SYNC authority {authority!r}"
                            )
                        elif authority not in c_paths:
                            failures.append(
                                f"{module}: {rust_path} declares unmapped "
                                f"PORT-SYNC authority {authority}"
                            )
                    expected_direct = direct_by_rust[rust_path]
                    declared_direct = set(authorities)
                    if declared_direct != expected_direct:
                        missing = sorted(expected_direct - declared_direct)
                        extra = sorted(declared_direct - expected_direct)
                        details = []
                        if missing:
                            details.append("missing " + ", ".join(missing))
                        if extra:
                            details.append("extra " + ", ".join(extra))
                        failures.append(
                            f"{module}: {rust_path} PORT-SYNC authority must "
                            "exactly match its direct provenance edges: "
                            + "; ".join(details)
                        )
    failures.extend(audit_reviewed_rename_history(root, manifest, stale_check))
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
    if args.upstream_ref:
        failures.extend(
            audit_upstream_authority_paths(
                root, manifest, stale_check, args.upstream_ref
            )
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
