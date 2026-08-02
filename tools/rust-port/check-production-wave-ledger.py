#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject unsupported daemon/tool promotion claims in the production-wave ledger."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = 1
STATUSES = frozenset({"shadow", "fallback", "replace"})
EVIDENCE_STATES = frozenset({"missing", "planned", "passed"})
EVIDENCE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def normalized_path(value: object, label: str, errors: list[str]) -> Path | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label} must be a non-empty relative path")
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        errors.append(f"{label} must be a normalized relative path: {value!r}")
        return None
    return path


def blob_oid(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()


def expected_blob_map(
    value: object, label: str, errors: list[str]
) -> dict[str, str] | None:
    if not isinstance(value, dict) or not value:
        errors.append(f"{label} must be a non-empty table of Git blob ids")
        return None
    result: dict[str, str] = {}
    for path, oid in value.items():
        if not isinstance(path, str) or not isinstance(oid, str) or len(oid) != 40:
            errors.append(f"{label} entries must map paths to 40-character SHA-1 blob ids")
            continue
        if any(character not in "0123456789abcdef" for character in oid):
            errors.append(f"{label} contains a non-hex blob id for {path}")
            continue
        result[path] = oid
    return result


def validate_target(root: Path, index: int, target: object) -> list[str]:
    prefix = f"target[{index}]"
    errors: list[str] = []
    if not isinstance(target, dict):
        return [f"{prefix} must be a table"]

    identifier = target.get("id")
    if not isinstance(identifier, str) or not identifier:
        errors.append(f"{prefix}.id must be a non-empty string")
    status = target.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        errors.append(f"{prefix}.status must be one of {sorted(STATUSES)}")
    owner = target.get("production_owner")
    if not isinstance(owner, str) or owner not in {"c", "rust"}:
        errors.append(f"{prefix}.production_owner must be c or rust")
    fallback_owner = target.get("fallback_owner")
    if not isinstance(fallback_owner, str) or fallback_owner != "c":
        errors.append(f"{prefix}.fallback_owner must remain c")

    required_evidence_raw = target.get("required_evidence")
    required_evidence: set[str] = set()
    if not isinstance(required_evidence_raw, list) or not required_evidence_raw:
        errors.append(f"{prefix}.required_evidence must be a non-empty array")
    else:
        for evidence_index, name in enumerate(required_evidence_raw):
            if not isinstance(name, str) or not EVIDENCE_NAME.fullmatch(name):
                errors.append(
                    f"{prefix}.required_evidence[{evidence_index}] must be a normalized category name"
                )
            elif name in required_evidence:
                errors.append(f"{prefix}: duplicate required evidence category {name}")
            else:
                required_evidence.add(name)

    c_source = normalized_path(target.get("c_source"), f"{prefix}.c_source", errors)
    meson_build = normalized_path(target.get("meson_build"), f"{prefix}.meson_build", errors)
    selected_source = target.get("c_selected_source")
    if not isinstance(selected_source, str) or not selected_source:
        errors.append(f"{prefix}.c_selected_source must be a non-empty filename")
    rust_paths_raw = target.get("rust_paths")
    rust_paths: list[Path] = []
    if not isinstance(rust_paths_raw, list) or not rust_paths_raw:
        errors.append(f"{prefix}.rust_paths must be a non-empty array")
    else:
        for rust_index, raw_path in enumerate(rust_paths_raw):
            path = normalized_path(raw_path, f"{prefix}.rust_paths[{rust_index}]", errors)
            if path is not None:
                rust_paths.append(path)

    if c_source is not None:
        source_path = root / c_source
        if not source_path.is_file():
            errors.append(f"{prefix}: C authority does not exist: {c_source}")
    if meson_build is not None:
        meson_path = root / meson_build
        if not meson_path.is_file():
            errors.append(f"{prefix}: Meson authority does not exist: {meson_build}")
        elif isinstance(selected_source, str) and selected_source not in meson_path.read_text(encoding="utf-8"):
            errors.append(f"{prefix}: Meson no longer selects the C fallback source {selected_source}")
    for rust_path in rust_paths:
        absolute = root / rust_path
        if not absolute.is_file():
            errors.append(f"{prefix}: Rust owner does not exist: {rust_path}")
        elif c_source is not None and f"PORT-SYNC: {c_source.as_posix()}" not in absolute.read_text(encoding="utf-8"):
            errors.append(f"{prefix}: Rust owner lacks direct PORT-SYNC provenance: {rust_path}")

    c_blobs = expected_blob_map(target.get("reviewed_c_blobs"), f"{prefix}.reviewed_c_blobs", errors)
    rust_blobs = expected_blob_map(target.get("reviewed_rust_blobs"), f"{prefix}.reviewed_rust_blobs", errors)
    if c_source is not None and c_blobs is not None:
        expected = c_blobs.get(c_source.as_posix())
        actual_path = root / c_source
        if expected is None:
            errors.append(f"{prefix}: C authority has no reviewed blob pin")
        elif actual_path.is_file() and blob_oid(actual_path) != expected:
            errors.append(f"{prefix}: C authority changed since its reviewed blob pin")
    if rust_blobs is not None:
        expected_paths = {path.as_posix() for path in rust_paths}
        if set(rust_blobs) != expected_paths:
            errors.append(f"{prefix}: Rust blob pins must cover exactly rust_paths")
        for path in rust_paths:
            absolute = root / path
            expected = rust_blobs.get(path.as_posix())
            if expected is not None and absolute.is_file() and blob_oid(absolute) != expected:
                errors.append(f"{prefix}: Rust owner changed since its reviewed blob pin: {path}")

    evidence = target.get("evidence")
    observed: dict[str, str] = {}
    if not isinstance(evidence, list):
        errors.append(f"{prefix}.evidence must be an array")
    else:
        for evidence_index, row in enumerate(evidence):
            row_prefix = f"{prefix}.evidence[{evidence_index}]"
            if not isinstance(row, dict):
                errors.append(f"{row_prefix} must be a table")
                continue
            name, state = row.get("name"), row.get("state")
            if not isinstance(name, str) or name not in required_evidence:
                errors.append(f"{row_prefix}.name is not a required evidence category")
                continue
            if name in observed:
                errors.append(f"{prefix}: duplicate evidence category {name}")
                continue
            if not isinstance(state, str) or state not in EVIDENCE_STATES:
                errors.append(f"{row_prefix}.state must be one of {sorted(EVIDENCE_STATES)}")
                continue
            observed[name] = state
            if not isinstance(row.get("detail"), str) or not row["detail"].strip():
                errors.append(f"{row_prefix}.detail must explain the evidence state")
    missing = required_evidence - set(observed)
    if missing:
        errors.append(f"{prefix}: missing evidence categories: {', '.join(sorted(missing))}")

    if status == "replace":
        if owner != "rust":
            errors.append(f"{prefix}: replace requires production_owner = rust")
        if any(observed.get(name) != "passed" for name in required_evidence):
            errors.append(f"{prefix}: replace requires every evidence category to pass")
    elif owner != "c":
        errors.append(f"{prefix}: non-replace target must retain C production ownership")
    return errors


def validate(root: Path, ledger: Path) -> list[str]:
    path = root / ledger
    try:
        data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{ledger}: cannot load ledger: {error}"]
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"{ledger}: schema must be {SCHEMA}")
    targets = data.get("target")
    if not isinstance(targets, list) or not targets:
        return errors + [f"{ledger}: at least one [[target]] is required"]
    identifiers: set[str] = set()
    for index, target in enumerate(targets):
        errors.extend(validate_target(root, index, target))
        if isinstance(target, dict) and isinstance(target.get("id"), str):
            if target["id"] in identifiers:
                errors.append(f"{ledger}: duplicate target id {target['id']}")
            identifiers.add(target["id"])
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--ledger", default="tools/rust-port/production-waves.toml", type=Path
    )
    args = parser.parse_args()
    errors = validate(Path(args.root).resolve(), args.ledger)
    if errors:
        print("production-wave ledger gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("production-wave ledger gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
