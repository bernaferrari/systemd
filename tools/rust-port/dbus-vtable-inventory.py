#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inventory the C PID 1 sd-bus vtables without treating DocBook as ABI data.

The C sources are the authority for member names, signatures, flags, and
vtable membership.  Object bindings and behavioral status are deliberately
kept in a small reviewed JSON overlay: those facts cannot safely be inferred
from an SD_BUS_* declaration alone.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = 1
METADATA_NAME = "tools/rust-port/dbus-vtable-metadata.json"
VTABLE_RE = re.compile(r"(?:static\s+)?const\s+sd_bus_vtable\s+(\w+)\s*\[\]\s*=\s*\{")
OBJECT_RE = re.compile(r"(?:static\s+)?const\s+BusObjectImplementation\s+\w+\s*=\s*\{")
STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
MACROS = (
    "SD_BUS_METHOD_WITH_ARGS_OFFSET",
    "SD_BUS_METHOD_WITH_ARGS",
    "SD_BUS_METHOD_WITH_NAMES_OFFSET",
    "SD_BUS_METHOD_WITH_OFFSET",
    "SD_BUS_METHOD_WITH_NAMES",
    "SD_BUS_METHOD",
    "SD_BUS_WRITABLE_PROPERTY",
    "SD_BUS_PROPERTY",
    "SD_BUS_SIGNAL_WITH_ARGS",
    "SD_BUS_SIGNAL_WITH_NAMES",
    "SD_BUS_SIGNAL",
    "BUS_PROPERTY_DUAL_TIMESTAMP",
)
MACRO_RE = re.compile(r"\b(" + "|".join(MACROS) + r")\s*\(")


def balanced(text: str, opening: int, left: str = "(", right: str = ")") -> tuple[str, int]:
    """Return the balanced contents after *opening* and its closing index."""
    if text[opening] != left:
        raise ValueError("balanced delimiter did not start at the requested character")
    depth = 1
    quote = False
    escaped = False
    index = opening + 1
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
        elif char == '"':
            quote = True
        elif char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index], index
        index += 1
    raise ValueError("unbalanced C expression")


def split_arguments(expression: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    quote = False
    escaped = False
    for index, char in enumerate(expression):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(expression[start:index].strip())
            start = index + 1
    arguments.append(expression[start:].strip())
    return arguments


def c_strings(expression: str) -> list[str]:
    return [bytes(value, "utf-8").decode("unicode_escape") for value in STRING_RE.findall(expression)]


def signature(expression: str) -> str:
    expression = expression.strip()
    if expression in {"NULL", "SD_BUS_NO_ARGS", "SD_BUS_NO_RESULT"}:
        return ""
    return "".join(c_strings(expression))


def macro_calls(body: str) -> list[tuple[str, list[str]]]:
    calls: list[tuple[str, list[str]]] = []
    start = 0
    while match := MACRO_RE.search(body, start):
        opening = match.end() - 1
        expression, end = balanced(body, opening)
        calls.append((match.group(1), split_arguments(expression)))
        start = end + 1
    return calls


def member_from_macro(source: str, vtable: str, macro: str, arguments: list[str]) -> list[dict[str, str]]:
    if not arguments or not c_strings(arguments[0]):
        raise ValueError(f"{source}:{vtable}: {macro} has no literal member name")
    name = "".join(c_strings(arguments[0]))
    flags = arguments[-1].strip()
    base = {"source": source, "vtable": vtable, "member": name, "flags": flags}
    if macro == "BUS_PROPERTY_DUAL_TIMESTAMP":
        return [
            base | {"kind": "property", "input": "", "output": "t"},
            base | {"kind": "property", "member": f"{name}Monotonic", "input": "", "output": "t"},
        ]
    if "PROPERTY" in macro:
        return [base | {"kind": "property", "input": "", "output": signature(arguments[1])}]
    if "SIGNAL" in macro:
        payload = arguments[1] if "WITH_ARGS" in macro else arguments[1]
        return [base | {"kind": "signal", "input": "", "output": signature(payload)}]
    if "WITH_ARGS" in macro:
        return [
            base
            | {
                "kind": "method",
                "input": signature(arguments[1]),
                "output": signature(arguments[2]),
            }
        ]
    if "WITH_NAMES" in macro:
        return [
            base
            | {
                "kind": "method",
                "input": signature(arguments[1]),
                "output": signature(arguments[3]),
            }
        ]
    return [
        base
        | {
            "kind": "method",
            "input": signature(arguments[1]),
            "output": signature(arguments[2]),
        }
    ]


def selected_core_sources(root: Path) -> set[str]:
    meson = (root / "src/core/meson.build").read_text(encoding="utf-8")
    return set(re.findall(r"'([^']+\.c)'", meson))


def vtable_sources(root: Path) -> list[Path]:
    selected = selected_core_sources(root)
    return [
        path
        for path in sorted((root / "src/core").glob("dbus*.c"))
        if path.name in selected and VTABLE_RE.search(path.read_text(encoding="utf-8"))
    ]


def object_bindings(root: Path) -> dict[str, list[dict[str, str]]]:
    bindings: dict[str, list[dict[str, str]]] = {}
    for source in sorted((root / "src/core").glob("dbus*.c")):
        text = source.read_text(encoding="utf-8")
        for match in OBJECT_RE.finditer(text):
            body, _ = balanced(text, match.end() - 1, "{", "}")
            strings = c_strings(body)
            if len(strings) < 2:
                continue
            path, interface = strings[0], strings[1]
            vtables = re.findall(r"\{\s*(bus_\w+_vtable)\s*,", body)
            vtables.extend(re.findall(r"BUS_VTABLES\(\s*(bus_\w+_vtable)\s*\)", body))
            for vtable in vtables:
                bindings.setdefault(vtable, []).append({"path": path, "interface": interface})
    for values in bindings.values():
        values.sort(key=lambda value: (value["path"], value["interface"]))
    return bindings


def inventory(root: Path) -> list[dict[str, Any]]:
    bindings = object_bindings(root)
    members: list[dict[str, Any]] = []
    for path in vtable_sources(root):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for match in VTABLE_RE.finditer(text):
            body, _ = balanced(text, match.end() - 1, "{", "}")
            for macro, arguments in macro_calls(body):
                for member in member_from_macro(relative, match.group(1), macro, arguments):
                    member["bindings"] = bindings.get(match.group(1), [])
                    member["feature_predicate"] = "selected-by-src/core/meson.build"
                    members.append(member)
    members.sort(key=lambda value: (value["source"], value["vtable"], value["kind"], value["member"]))
    keys = [member_key(member) for member in members]
    if len(keys) != len(set(keys)):
        duplicates = sorted(key for key in set(keys) if keys.count(key) > 1)
        raise ValueError("duplicate C vtable members: " + ", ".join(duplicates))
    return members


def member_key(member: dict[str, Any]) -> str:
    return ":".join(str(member[field]) for field in ("source", "vtable", "kind", "member"))


REQUIRED_METADATA = {
    "authorization",
    "bindings",
    "input",
    "output",
    "rust_owner",
    "state_mutation",
    "status",
    "transport",
}
STATUSES = {"shadow", "unsupported", "ready-for-integration"}


def load_metadata(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or not isinstance(data.get("members"), list):
        raise ValueError(f"{path}: expected schema={SCHEMA} and a members array")
    records: dict[str, dict[str, Any]] = {}
    for record in data["members"]:
        if not isinstance(record, dict):
            raise ValueError(f"{path}: member metadata must be an object")
        missing = REQUIRED_METADATA - set(record)
        if missing:
            raise ValueError(f"{path}: metadata member misses {sorted(missing)}")
        key = member_key(record)
        if key in records:
            raise ValueError(f"{path}: duplicate metadata for {key}")
        if record["status"] not in STATUSES:
            raise ValueError(f"{path}: invalid status for {key}: {record['status']!r}")
        if record["status"] == "ready-for-integration" and not record.get("test"):
            raise ValueError(f"{path}: promoted member {key} has no test evidence")
        records[key] = record
    return records


def apply_metadata(members: list[dict[str, Any]], metadata: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    source_keys = {member_key(member) for member in members}
    extra = sorted(set(metadata) - source_keys)
    if extra:
        raise ValueError("metadata refers to missing C members: " + ", ".join(extra))
    unreviewed: list[str] = []
    for member in members:
        key = member_key(member)
        record = metadata.get(key)
        if record is None:
            member["review"] = {"status": "unreviewed"}
            unreviewed.append(key)
            continue
        for field in ("input", "output"):
            if member[field] != record[field]:
                raise ValueError(
                    f"metadata signature disagreement for {key}: C {field}={member[field]!r}, metadata={record[field]!r}"
                )
        if record["bindings"] != member["bindings"]:
            raise ValueError(f"metadata binding disagreement for {key}")
        member["review"] = {field: record[field] for field in REQUIRED_METADATA - {"input", "output", "bindings"}}
        if record.get("test"):
            member["review"]["test"] = record["test"]
    return members, unreviewed


def meson_profile(build: Path | None) -> dict[str, Any] | None:
    if build is None:
        return None
    options = build / "meson-info/intro-buildoptions.json"
    if not options.is_file():
        raise ValueError(f"{build}: missing configured Meson profile {options.name}")
    data = json.loads(options.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{options}: expected a Meson option array")
    selected = {}
    for option in data:
        if isinstance(option, dict) and option.get("name") in {"mode", "rust", "bpf-framework"}:
            selected[option["name"]] = option.get("value")
    return selected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--metadata", help="reviewed metadata JSON (default: repository metadata)")
    parser.add_argument(
        "--meson-build",
        help="configured Linux Meson build directory; its profile is recorded in the inventory",
    )
    parser.add_argument("--output", help="write deterministic JSON to this path instead of stdout")
    parser.add_argument("--require-reviewed", action="store_true", help="fail when any C member lacks reviewed metadata")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    metadata_path = Path(args.metadata).resolve() if args.metadata else root / METADATA_NAME
    try:
        profile = meson_profile(Path(args.meson_build).resolve() if args.meson_build else None)
        members = inventory(root)
        metadata = load_metadata(metadata_path)
        members, unreviewed = apply_metadata(members, metadata)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"D-Bus vtable inventory failed: {error}", file=sys.stderr)
        return 1
    payload = {
        "schema": SCHEMA,
        "authority": "C-defined sd_bus_vtable declarations plus dbus.c object bindings",
        "meson_profile": profile,
        "members": members,
        "summary": {"members": len(members), "reviewed": len(members) - len(unreviewed), "unreviewed": len(unreviewed)},
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.require_reviewed and unreviewed:
        print(f"D-Bus vtable inventory incomplete: {len(unreviewed)} unreviewed C members", file=sys.stderr)
        return 1
    print(
        "D-Bus vtable inventory OK: "
        f"members={len(members)} reviewed={len(members) - len(unreviewed)} unreviewed={len(unreviewed)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
