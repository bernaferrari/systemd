#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep Rust-port comparison fixtures discoverable without moving them.

The catalog is intentionally a small compatibility ledger rather than a new
test tree: tests-extra remains the C-vs-Rust ABI boundary. It only freezes
the legacy numbered ``extraN`` names and requires future names to describe
the behavior they cover.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = 1
TARGET_RE = re.compile(r"test-[a-z0-9][a-z0-9-]*")
FIXTURE_RE = re.compile(r"test-[a-z0-9][a-z0-9-]*\.c")
CHRONOLOGICAL_RE = re.compile(r"^test-[a-z0-9][a-z0-9-]*(?:-extra[0-9]+(?:-rust)?|-rust[0-9]+)\.c$")
OWNER_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")


def balanced_call(text: str, opening: int) -> tuple[str, int]:
    if opening >= len(text) or text[opening] != "(":
        raise ValueError("Meson parser expected '('")
    depth, index = 1, opening + 1
    quote: str | None = None
    escaped = False
    while index < len(text) and depth:
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        index += 1
    if depth:
        raise ValueError("unterminated Meson executable() call")
    return text[opening + 1 : index - 1], index


def _executable_assignment_name(text: str, executable_start: int) -> str | None:
    """Return the identifier assigned from ``executable(`` if present."""

    prefix = text[max(0, executable_start - 120) : executable_start]
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$", prefix)
    return match.group(1) if match else None


def rust_linked_fixtures(root: Path) -> list[tuple[str, str]]:
    """Return ``(Meson target, tests-extra source)`` pairs at the Rust ABI boundary.

    A same-name ``test()`` registration is not enough: ``test()`` must invoke the
    exact ``executable()`` object produced for that target. The parser is
    deliberately literal — it tracks the last assignment of each identifier to
    an ``executable()`` target name (supporting tests-extra's reassigned
    ``rust_test_exe``) and resolves ``test('name', expr)`` only when ``expr`` is
    an identifier.
    """

    meson = root / "tests-extra/meson.build"
    text = meson.read_text(encoding="utf-8")

    events: list[tuple[int, str, re.Match[str]]] = []
    for match in re.finditer(r"\bexecutable\s*\(", text):
        events.append((match.start(), "executable", match))
    for match in re.finditer(r"\btest\s*\(", text):
        events.append((match.start(), "test", match))
    events.sort(key=lambda item: item[0])

    # Last assignment of each identifier → executable() target name.
    bindings: dict[str, str] = {}
    # Targets whose test() call resolved to that same executable object.
    proven: set[str] = set()
    records: list[tuple[str, str]] = []

    for _pos, kind, match in events:
        if kind == "executable":
            body, _ = balanced_call(text, match.end() - 1)
            # Track every assigned executable name so wrong-variable bindings fail.
            name_match = re.match(r"\s*['\"]([^'\"]+)['\"]\s*,", body)
            if name_match is None:
                continue
            target = name_match.group(1)
            assigned = _executable_assignment_name(text, match.start())
            if assigned is not None:
                bindings[assigned] = target

            # The catalog owns the Rust ABI boundary, not a particular ordering of
            # its support libraries. Requiring an exact two-item list let a Rust
            # fixture disappear from review merely by reordering or extending it.
            if not target.startswith("test-") or not re.search(
                r"\blink_with\s*:\s*(?:\[[^]]*\brust_staticlib\b[^]]*\]|\brust_staticlib\b)",
                body,
            ):
                continue
            sources = sorted(set(re.findall(r"['\"](test-[^'\"]+\.c)['\"]", body)))
            if len(sources) != 1:
                raise ValueError(
                    f"{target}: expected exactly one literal test-*.c fixture, got {sources}"
                )
            records.append((target, sources[0]))
            continue

        body, _ = balanced_call(text, match.end() - 1)
        # Supported form: test('test-foo', some_identifier[, kwargs...]).
        # balanced_call returns the interior, so the call ends at EOS or ','.
        test_match = re.match(
            r"\s*['\"](test-[^'\"]+)['\"]\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|$)",
            body,
        )
        if test_match is None:
            # Unsupported second argument (non-identifier); cannot prove a binding.
            continue
        test_name = test_match.group(1)
        resolved = bindings.get(test_match.group(2))
        if resolved == test_name:
            proven.add(test_name)

    unproven = [
        target for target, _source in records if target not in proven
    ]
    if unproven:
        # Deduplicate while preserving first-seen order (redefinition still fails later).
        seen: set[str] = set()
        messages: list[str] = []
        for target in unproven:
            if target in seen:
                continue
            seen.add(target)
            messages.append(
                f"{target}: Rust-linked fixture is not registered by test() "
                "bound to its executable"
            )
        raise ValueError("; ".join(messages))
    if not records:
        raise ValueError("no Rust-linked tests-extra fixtures found")
    return sorted(records)


def load_catalog(path: Path) -> dict[str, str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"{path}: schema must be {SCHEMA}")
    policy = data.get("policy")
    if not isinstance(policy, dict) or policy != {
        "new_fixture_pattern": "test-<semantic-subject>-<behavior>-rust.c",
        "forbid_new_numbered_extra": True,
    }:
        raise ValueError(f"{path}: policy must define the fixed semantic naming rule")
    legacy = data.get("grandfathered_chronological")
    if not isinstance(legacy, dict) or not legacy:
        raise ValueError(f"{path}: grandfathered_chronological must be a non-empty table")
    result: dict[str, str] = {}
    for fixture, owner in legacy.items():
        if not isinstance(fixture, str) or not CHRONOLOGICAL_RE.fullmatch(fixture):
            raise ValueError(f"{path}: non-chronological legacy fixture {fixture!r}")
        if not isinstance(owner, str) or not OWNER_RE.fullmatch(owner):
            raise ValueError(f"{path}: invalid owner for {fixture}: {owner!r}")
        result[fixture] = owner
    return result


def audit(root: Path, catalog_path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    try:
        legacy = load_catalog(catalog_path)
        fixtures = rust_linked_fixtures(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        return [str(exc)], []
    seen_targets: set[str] = set()
    seen_fixtures: set[str] = set()
    chronological: set[str] = set()
    records: list[dict[str, Any]] = []
    for target, fixture in fixtures:
        if target in seen_targets:
            errors.append(f"duplicate Rust fixture target {target}")
        if fixture in seen_fixtures:
            errors.append(f"fixture {fixture} is registered by more than one Rust target")
        seen_targets.add(target)
        seen_fixtures.add(fixture)
        if not TARGET_RE.fullmatch(target) or not FIXTURE_RE.fullmatch(fixture):
            errors.append(f"{target}: target and fixture must begin with test- and use lowercase kebab-case")
        if fixture != f"{target}.c":
            errors.append(f"{target}: fixture must be named {target}.c, got {fixture}")
        source = root / "tests-extra" / fixture
        if not source.is_file():
            errors.append(f"{target}: fixture source is missing: tests-extra/{fixture}")
        is_legacy = CHRONOLOGICAL_RE.fullmatch(fixture) is not None
        if is_legacy:
            chronological.add(fixture)
            if fixture not in legacy:
                errors.append(
                    f"{fixture}: new chronological fixture name is forbidden; use a semantic behavior name"
                )
        records.append({
            "fixture": f"tests-extra/{fixture}",
            "target": target,
            "grandfathered_chronological": is_legacy,
            "owner": legacy.get(fixture, "semantic-name"),
        })
    stale = sorted(set(legacy) - chronological)
    if stale:
        errors.append("catalog has stale grandfathered fixture(s): " + ", ".join(stale))
    return errors, records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--catalog", default="tools/rust-port/rust-fixture-catalog.toml")
    parser.add_argument("--json", action="store_true", help="print the queryable fixture catalog")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root).resolve()
    catalog = Path(args.catalog)
    if not catalog.is_absolute():
        catalog = root / catalog
    errors, records = audit(root, catalog)
    if args.json:
        print(json.dumps({"fixtures": records, "errors": errors}, indent=2, sort_keys=True))
    if errors:
        if not args.json:
            print("Rust fixture catalog gate failed:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
        return 1
    if not args.json:
        legacy = sum(record["grandfathered_chronological"] for record in records)
        print(f"Rust fixture catalog gate OK: fixtures={len(records)} grandfathered_chronological={legacy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
