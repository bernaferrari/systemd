#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep every Rust-port Python, TOML, and JSON tool artifact discoverable."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


SCHEMA = 1
TOOL_SUFFIXES = {".py", ".toml", ".json"}
TAXONOMY = Path("tools/rust-port/tool-taxonomy.toml")


def tool_artifacts(root: Path) -> set[str]:
    directory = root / TAXONOMY.parent
    return {
        path.relative_to(root).as_posix()
        for path in directory.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in TOOL_SUFFIXES
        and path.relative_to(root) != TAXONOMY
    }


def validate(root: Path, taxonomy: Path = TAXONOMY) -> list[str]:
    path = root / taxonomy
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{taxonomy}: cannot load taxonomy: {error}"]

    errors: list[str] = []
    unknown_top_level = set(data) - {"schema", "category"}
    if unknown_top_level:
        errors.append(f"{taxonomy}: unknown top-level field(s): {sorted(unknown_top_level)}")
    if data.get("schema") != SCHEMA:
        errors.append(f"{taxonomy}: schema must be {SCHEMA}")
    categories = data.get("category")
    if not isinstance(categories, list) or not categories:
        return errors + [f"{taxonomy}: at least one [[category]] is required"]

    seen_ids: set[str] = set()
    classified: dict[str, str] = {}
    for index, category in enumerate(categories):
        prefix = f"{taxonomy}: category[{index}]"
        if not isinstance(category, dict):
            errors.append(f"{prefix}: must be a table")
            continue
        unknown_fields = set(category) - {"id", "purpose", "paths"}
        if unknown_fields:
            errors.append(f"{prefix}: unknown field(s): {sorted(unknown_fields)}")
        category_id = category.get("id")
        purpose = category.get("purpose")
        paths = category.get("paths")
        if not isinstance(category_id, str) or not category_id or category_id in seen_ids:
            errors.append(f"{prefix}: id must be a unique non-empty string")
            continue
        seen_ids.add(category_id)
        if not isinstance(purpose, str) or not purpose.strip():
            errors.append(f"{prefix}: purpose must be a non-empty string")
        if not isinstance(paths, list) or not paths or not all(isinstance(item, str) for item in paths):
            errors.append(f"{prefix}: paths must be a non-empty string array")
            continue
        for item in paths:
            candidate = Path(item)
            if candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != item:
                errors.append(f"{prefix}: path must be normalized and relative: {item!r}")
                continue
            if item in classified:
                errors.append(f"{prefix}: {item} is already in category {classified[item]}")
                continue
            classified[item] = category_id
            if not (root / candidate).is_file():
                errors.append(f"{prefix}: classified path does not exist: {item}")

    actual = tool_artifacts(root)
    missing = sorted(actual - set(classified))
    stale = sorted(set(classified) - actual)
    if missing:
        errors.append("unclassified Rust-port tooling: " + ", ".join(missing))
    if stale:
        errors.append("taxonomy entries are not tool artifacts: " + ", ".join(stale))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()
    errors = validate(Path(args.repo_root).resolve())
    if errors:
        print("Rust-port tool taxonomy gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Rust-port tool taxonomy gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
