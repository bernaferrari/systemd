#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Detect stale Rust shadow-port entries by comparing manifest blob IDs."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Sequence

try:
    import tomllib
except ModuleNotFoundError:
    print("ERROR: This script requires Python 3.11+ (tomllib).", file=sys.stderr)
    sys.exit(2)


VALID_STATUSES = {
    "todo",
    "in-progress",
    "done",
    "shadow",
    "replace",
    "fallback",
}

STICKY_STATES = {"done", "shadow", "replace", "fallback"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Detect stale rust-port map entries by comparing git blob hashes."
    )
    p.add_argument(
        "--map",
        default="tools/rust-port/map.toml",
        help="Path to the rust-port manifest (default: tools/rust-port/map.toml)",
    )
    p.add_argument(
        "--repo-root",
        default=".",
        help="Git repository root for git hash checks (default: current directory).",
    )
    p.add_argument(
        "--status",
        action="append",
        default=[],
        help="Filter entries by status. Repeat to match multiple statuses.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Require sync blob fields for non-todo/in-progress states "
            "instead of treating missing fields as a pass."
        ),
    )
    p.add_argument(
        "--warn-missing-files",
        action="store_true",
        help="If true, missing files are reported but do not fail the run.",
    )
    p.add_argument(
        "--require-existing-paths",
        action="store_true",
        help=(
            "Also reject nonexistent unanchored mapping paths. This is the "
            "source-authority repair diagnostic; normal mode checks paths "
            "once they carry reviewed anchors."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of plain text.",
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


def load_manifest(map_path: Path) -> Dict[str, Dict[str, Any]]:
    raw = tomllib.loads(map_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not raw:
        raise ValueError("manifest root must be a TOML table")
    invalid = sorted(
        module_name
        for module_name, entry in raw.items()
        if not isinstance(entry, dict)
    )
    if invalid:
        raise ValueError(
            "manifest entries must all be TOML tables: " + ", ".join(invalid)
        )
    return {
        module_name: dict(entry)
        for module_name, entry in raw.items()
    }


def get_blob(repo_root: Path, relpath: str) -> str:
    if not (repo_root / relpath).is_file():
        raise FileNotFoundError(f"missing path {relpath}")
    out = git(repo_root, ["hash-object", "--", relpath]).strip()
    if not out:
        raise FileNotFoundError(f"missing path {relpath}")
    return out


def source_paths(
    entry: Dict[str, Any],
    module_name: str,
    *,
    plural_key: str,
    legacy_key: str,
    legacy_separator: str,
) -> List[str]:
    """Return one normalized, duplicate-free side of a source mapping."""

    plural_value = entry.get(plural_key)
    legacy_value = entry.get(legacy_key)
    if plural_value is not None and legacy_value is not None:
        raise ValueError(
            f"{module_name} sets both {legacy_key} and {plural_key}"
        )
    value = plural_value if plural_value is not None else legacy_value
    if value is None:
        return []

    if isinstance(value, str):
        paths = [p.strip() for p in value.split(legacy_separator) if p.strip()]
        if not paths:
            raise ValueError(f"{module_name}.{legacy_key} is empty")
    elif isinstance(value, list):
        paths = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{module_name}.{plural_key} contains invalid item")
            paths.append(item.strip())
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


def optional_path_list(
    entry: Dict[str, Any], module_name: str, key: str
) -> List[str] | None:
    """Read an optional normalized repository path list.

    Scope paths deliberately use an array rather than the legacy separator
    syntax: a directory is an inventory boundary, not a source authority.
    A single string remains convenient for a one-file scope.
    """

    value = entry.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        paths = [value.strip()] if value.strip() else []
    elif isinstance(value, list):
        paths = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{module_name}.{key} contains invalid item")
            paths.append(item.strip())
    else:
        raise ValueError(f"{module_name}.{key} must be a string or array")

    if not paths:
        raise ValueError(f"{module_name}.{key} is empty")
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise ValueError(
            f"{module_name}.{key} contains duplicate paths: "
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
                f"{module_name}.{key} contains non-normalized "
                f"repository path: {path!r}"
            )
    return paths


def scope_name(entry: Dict[str, Any], module_name: str) -> str | None:
    value = entry.get("scope")
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)
    ):
        raise ValueError(
            f"{module_name}.scope must be a normalized scope identifier"
        )
    return value


def scoped_rust_inventory(
    entry: Dict[str, Any], module_name: str, repo_root: Path
) -> List[str] | None:
    """Expand a scoped Rust source inventory without making directories authority.

    ``c_paths`` remains the exact C/H authority. Rust directories merely make
    a file split visible to the manifest: every recursive ``*.rs`` leaf must
    be listed explicitly in ``rust_paths`` and can therefore carry its own
    review blob.
    """

    scope = scope_name(entry, module_name)
    scope_paths = optional_path_list(entry, module_name, "rust_scope_paths")
    interface_paths = optional_path_list(
        entry, module_name, "rust_interface_paths"
    )

    if scope is None:
        if scope_paths is not None or interface_paths is not None:
            raise ValueError(
                f"{module_name} sets rust scope paths without a scope name"
            )
        return None
    if scope_paths is None:
        raise ValueError(f"{module_name}.scope requires rust_scope_paths")

    expanded: List[str] = []
    for path in scope_paths:
        candidate = repo_root / path
        if candidate.is_file():
            if candidate.suffix != ".rs":
                raise ValueError(
                    f"{module_name}.rust_scope_paths file is not a Rust source: "
                    f"{path}"
                )
            expanded.append(path)
        elif candidate.is_dir():
            expanded.extend(
                item.relative_to(repo_root).as_posix()
                for item in sorted(candidate.rglob("*.rs"))
                if item.is_file()
            )
        else:
            raise ValueError(
                f"{module_name}.rust_scope_paths path does not exist: {path}"
            )

    duplicates = sorted({path for path in expanded if expanded.count(path) > 1})
    if duplicates:
        raise ValueError(
            f"{module_name}.rust_scope_paths overlap: " + ", ".join(duplicates)
        )

    interfaces = interface_paths or []
    overlap = sorted(set(expanded) & set(interfaces))
    if overlap:
        raise ValueError(
            f"{module_name}.rust_interface_paths overlaps Rust source inventory: "
            + ", ".join(overlap)
        )
    for path in interfaces:
        if not (repo_root / path).is_file():
            raise ValueError(
                f"{module_name}.rust_interface_paths path does not exist: {path}"
            )

    expected = sorted(expanded + interfaces)
    declared = sorted(rust_file_paths(entry, module_name))
    if declared != expected:
        missing = sorted(set(expected) - set(declared))
        extra = sorted(set(declared) - set(expected))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        raise ValueError(
            f"{module_name}.rust_paths must exactly match scoped Rust inventory: "
            + "; ".join(details)
        )
    return expected


def validate_manifest(manifest: Mapping[str, Dict[str, Any]], repo_root: Path) -> None:
    """Validate manifest-wide scoped ownership invariants.

    C files may correctly be authority for several behavioral slices. Rust
    implementation files must have one scoped owner, with shared code split
    into its own scope rather than silently co-owned.
    """

    scopes: Dict[str, str] = {}
    owners: Dict[str, List[tuple[str, bool]]] = {}
    for module_name, entry in sorted(manifest.items()):
        scope = scope_name(entry, module_name)
        inventory = scoped_rust_inventory(entry, module_name, repo_root)
        for path in rust_file_paths(entry, module_name):
            owners.setdefault(path, []).append((module_name, scope is not None))
        if scope is None:
            continue
        previous = scopes.get(scope)
        if previous is not None:
            raise ValueError(
                f"duplicate scope name {scope!r}: {previous} and {module_name}"
            )
        scopes[scope] = module_name
        assert inventory is not None
    for path, path_owners in sorted(owners.items()):
        if len(path_owners) < 2 or not any(scoped for _module, scoped in path_owners):
            continue
        raise ValueError(
            f"duplicate scoped Rust ownership for {path}: "
            + ", ".join(module for module, _scoped in path_owners)
        )


def expected_blobs(
    entry: Dict[str, Any],
    module_name: str,
    *,
    paths: Sequence[str],
    singular_key: str,
    plural_key: str,
) -> Mapping[str, str] | None:
    """Load exact per-path blob authority without inventing provenance."""

    singular = entry.get(singular_key)
    plural = entry.get(plural_key)
    if singular is not None and plural is not None:
        raise ValueError(
            f"{module_name} sets both {singular_key} and {plural_key}"
        )

    if singular is not None:
        if not isinstance(singular, str) or not singular.strip():
            raise ValueError(f"{module_name}.{singular_key} must be a blob string")
        if len(paths) != 1:
            raise ValueError(
                f"{module_name}.{singular_key} cannot anchor {len(paths)} paths; "
                f"use {plural_key}"
            )
        return {paths[0]: singular.strip()}

    if plural is None:
        return None
    if not isinstance(plural, dict):
        raise ValueError(f"{module_name}.{plural_key} must be a path-to-blob table")

    anchors: Dict[str, str] = {}
    for path, blob in plural.items():
        if not isinstance(path, str) or not path.strip():
            raise ValueError(f"{module_name}.{plural_key} contains an invalid path")
        if not isinstance(blob, str) or not blob.strip():
            raise ValueError(
                f"{module_name}.{plural_key}[{path!r}] must be a blob string"
            )
        anchors[path.strip()] = blob.strip()

    expected = set(paths)
    actual = set(anchors)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        raise ValueError(
            f"{module_name}.{plural_key} does not exactly cover mapped paths: "
            + "; ".join(details)
        )
    return anchors


def check_blobs(
    *,
    repo_root: Path,
    paths: Sequence[str],
    anchors: Mapping[str, str] | None,
    strict: bool,
    sticky: bool,
    side: str,
    warn_missing: bool,
    require_existing: bool,
    reasons: List[str],
) -> bool:
    """Compare exact path anchors and return whether this side is stale."""

    if not paths:
        if anchors:
            reasons.append(f"{side} blob anchors exist without mapped paths")
            return True
        return False
    if anchors is None:
        stale = False
        if strict and sticky:
            reasons.append(
                f"strict mode: missing per-path {side} blob anchors for sticky state"
            )
            stale = True
        if require_existing:
            for path in paths:
                try:
                    get_blob(repo_root, path)
                except FileNotFoundError as exc:
                    reasons.append(str(exc))
                    stale |= not warn_missing
        return stale

    stale = False
    for path in paths:
        try:
            current = get_blob(repo_root, path)
        except FileNotFoundError as exc:
            reasons.append(str(exc))
            stale |= not warn_missing
            continue
        expected = anchors[path]
        if current != expected:
            stale = True
            reasons.append(
                f"{side} drift in {path}: expected {expected} got {current}"
            )
    return stale


def module_status(entry: Dict[str, Any], module_name: str) -> str:
    return str(entry.get("status", "todo")).strip()


def should_check(status: str, filter_status: List[str]) -> bool:
    if not filter_status:
        return True
    return status in filter_status


def evaluate_module(
    module: str,
    entry: Dict[str, Any],
    repo_root: Path,
    strict: bool,
    warn_missing: bool,
    require_existing: bool = False,
) -> Dict[str, Any]:
    status = module_status(entry, module)
    reasons: List[str] = []
    stale = False

    if status not in VALID_STATUSES:
        reasons.append(f"unknown status '{status}'")
        stale = True

    c_paths = c_file_paths(entry, module)
    rust_paths = rust_file_paths(entry, module)
    # Validate the local scope here as well as in validate_manifest(), so
    # callers that evaluate a single fixture cannot bypass inventory checks.
    scoped_rust_inventory(entry, module, repo_root)
    upstream_blobs = expected_blobs(
        entry,
        module,
        paths=c_paths,
        singular_key="last_synced_upstream_blob",
        plural_key="last_synced_upstream_blobs",
    )
    rust_blobs = expected_blobs(
        entry,
        module,
        paths=rust_paths,
        singular_key="last_synced_rust_blob",
        plural_key="last_synced_rust_blobs",
    )
    reviewed_upstream_blobs = expected_blobs(
        entry,
        module,
        paths=c_paths,
        singular_key="last_reviewed_upstream_blob",
        plural_key="last_reviewed_upstream_blobs",
    )
    reviewed_rust_blobs = expected_blobs(
        entry,
        module,
        paths=rust_paths,
        singular_key="last_reviewed_rust_blob",
        plural_key="last_reviewed_rust_blobs",
    )
    sticky = status in STICKY_STATES
    stale |= check_blobs(
        repo_root=repo_root,
        paths=c_paths,
        anchors=upstream_blobs,
        strict=strict,
        sticky=sticky,
        side="upstream",
        warn_missing=warn_missing,
        require_existing=require_existing,
        reasons=reasons,
    )
    stale |= check_blobs(
        repo_root=repo_root,
        paths=rust_paths,
        anchors=rust_blobs,
        strict=strict,
        sticky=sticky,
        side="rust",
        warn_missing=warn_missing,
        require_existing=require_existing,
        reasons=reasons,
    )
    # A reviewed snapshot is deliberately weaker than last_synced_*: it lets
    # an incomplete scope detect upstream/Rust drift without asserting parity.
    # Missing review snapshots are not a strict-mode parity failure, but any
    # recorded snapshot must still be complete and current.
    stale |= check_blobs(
        repo_root=repo_root,
        paths=c_paths,
        anchors=reviewed_upstream_blobs,
        strict=False,
        sticky=False,
        side="reviewed upstream",
        warn_missing=warn_missing,
        # The ordinary sync-anchor pass already performs the optional
        # existence diagnostic for every mapped path. Do not duplicate its
        # messages merely because a review snapshot is absent.
        require_existing=False,
        reasons=reasons,
    )
    stale |= check_blobs(
        repo_root=repo_root,
        paths=rust_paths,
        anchors=reviewed_rust_blobs,
        strict=False,
        sticky=False,
        side="reviewed rust",
        warn_missing=warn_missing,
        require_existing=False,
        reasons=reasons,
    )

    return {
        "module": module,
        "status": status,
        "stale": stale,
        "fully_anchored": (not c_paths or upstream_blobs is not None)
        and (not rust_paths or rust_blobs is not None),
        "fully_reviewed": (not c_paths or reviewed_upstream_blobs is not None)
        and (not rust_paths or reviewed_rust_blobs is not None),
        "reasons": reasons,
        "c_file": c_paths,
        "rust_file": rust_paths or None,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    map_path = Path(args.map)
    if not map_path.is_absolute():
        map_path = (repo_root / map_path).resolve()

    try:
        manifest = load_manifest(map_path)
        validate_manifest(manifest, repo_root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: failed to parse {map_path}: {exc}", file=sys.stderr)
        return 2

    checked = []
    stale = []
    for module in sorted(manifest):
        entry = manifest[module]
        status = module_status(entry, module)
        if not should_check(status, args.status):
            continue
        try:
            result = evaluate_module(
                module,
                entry,
                repo_root,
                strict=args.strict,
                warn_missing=args.warn_missing_files,
                require_existing=args.require_existing_paths,
            )
        except (RuntimeError, OSError, ValueError) as exc:
            checked.append({
                "module": module,
                "status": status,
                "stale": True,
                "reasons": [str(exc)],
            })
            stale.append({
                "module": module,
                "status": status,
                "stale": True,
                "reasons": [str(exc)],
            })
            continue

        checked.append(result)
        if result["stale"]:
            stale.append(result)

    valid_count = len([e for e in checked if not e["stale"]])
    stale_count = len(stale)
    anchored_count = len([e for e in checked if e.get("fully_anchored")])
    unanchored_count = len(checked) - anchored_count
    reviewed_count = len(
        [
            e
            for e in checked
            if e.get("fully_reviewed") or e.get("fully_anchored")
        ]
    )
    unreviewed_count = len(checked) - reviewed_count

    if args.json:
        payload = {
            "checked": len(checked),
            "valid": valid_count,
            "stale": stale_count,
            "fully_anchored": anchored_count,
            "unanchored": unanchored_count,
            "fully_reviewed": reviewed_count,
            "unreviewed": unreviewed_count,
            "modules": checked,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1 if stale_count else 0

    if args.status:
        status_filter = ", ".join(sorted(set(args.status)))
        print(f"Filtered by status: {status_filter}")

    if stale_count:
        print(f"Stale modules: {stale_count}/{len(checked)}")
        for item in stale:
            print(f"- {item['module']} ({item['status']})")
            for reason in item["reasons"]:
                print(f"  - {reason}")
        print("Run with updates to last_synced_*_blob before merge.")
        return 1

    if unanchored_count:
        print(
            "OK: no drift in "
            f"{anchored_count} fully anchored mappings; "
            f"reviewed={reviewed_count} unreviewed={unreviewed_count} "
            f"unanchored={unanchored_count} checked={len(checked)}."
        )
    else:
        print(f"OK: all mappings anchored and current ({valid_count}/{len(checked)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
