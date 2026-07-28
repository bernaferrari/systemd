#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Validate explicit, boundary-level C-to-Rust behavior contracts.

The source map answers *what changed together*.  A behavior contract answers
which observable C boundary is claimed equivalent and what evidence supports
that claim.  This checker deliberately validates only declarations and static
test wiring; executing a fixture is separate runtime evidence.
"""

from __future__ import annotations

import argparse
import functools
import importlib.util
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


SCHEMA = 1
SEMANTIC_COVERAGE = {"none", "partial", "complete"}
SOURCE_STRUCTURE = {"independent", "intentionally-coupled"}
DEVIATION_POLICY = {"explicit-only", "forbid"}
SURFACE_COVERAGE = {"exact", "partial", "unclaimed", "deviation"}
ABI = {"c-exact", "rust-only", "unclaimed"}
BYTES = {"borrowed-cstr-opaque", "ptr-len-opaque", "scalar", "unclaimed"}
ERRORS = {"negative-errno", "nullable", "boolean", "none", "unclaimed"}
RUNTIME = {"none", "environment", "kernel", "io", "unclaimed"}
VERIFICATION = {"static-only", "runtime-verified"}
OWNERSHIP = {
    "caller-storage", "owned-libc", "borrowed", "borrowed-interior",
    "no-ownership", "unclaimed",
}
PUBLICATION = {"write", "unchanged", "return", "n/a", "unclaimed"}
CONTRACT_ROOT = Path("tools/rust-port/contracts")
MARKER_RE = re.compile(r"RUST-CONTRACT:\s*([A-Za-z0-9][A-Za-z0-9_-]*)")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def normalized_path(value: object, field: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value:
        fail(errors, f"{field}: expected a non-empty relative path")
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        fail(errors, f"{field}: path must be normalized and relative: {value!r}")
        return None
    return value


def path_list(value: object, field: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        fail(errors, f"{field}: expected a non-empty path array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        path = normalized_path(item, f"{field}[{index}]", errors)
        if path is not None:
            result.append(path)
    if len(set(result)) != len(result):
        fail(errors, f"{field}: duplicate path")
    return result


def symbol_list(value: object, field: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item)
        for item in value
    ):
        fail(errors, f"{field}: expected a non-empty C identifier array")
        return []
    result = list(value)
    if len(set(result)) != len(result):
        fail(errors, f"{field}: duplicate symbol")
    return result


def label_list(value: object, field: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]*", item)
        for item in value
    ):
        fail(errors, f"{field}: expected a non-empty kebab-case label array")
        return []
    result = list(value)
    if len(set(result)) != len(result):
        fail(errors, f"{field}: duplicate label")
    return result


def map_paths(entry: dict[str, Any], singular: str, plural: str) -> set[str]:
    if plural in entry:
        value = entry[plural]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{plural} must be a string array")
        return set(value)
    value = entry.get(singular)
    if value is None:
        return set()
    if not isinstance(value, str):
        raise ValueError(f"{singular} must be a string")
    separator = ";" if singular == "rust_file" else ","
    return {item.strip() for item in value.split(separator) if item.strip()}


def code_only(text: str) -> str:
    """Blank comments and quoted literals while preserving token positions."""

    result = list(text)
    index = 0
    state = "code"
    quote = ""
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block-comment":
            result[index] = "\n" if char == "\n" else " "
            if char == "*" and following == "/":
                result[index + 1] = " "
                index += 1
                state = "code"
        elif state == "quoted":
            result[index] = "\n" if char == "\n" else " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        elif char == "/" and following == "/":
            result[index] = result[index + 1] = " "
            index += 1
            state = "line-comment"
        elif char == "/" and following == "*":
            result[index] = result[index + 1] = " "
            index += 1
            state = "block-comment"
        elif (
            char == "r"
            and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_"))
            and (raw_start := re.match(r'r(#+)?"', text[index:])) is not None
        ):
            hashes = raw_start.group(1) or ""
            closing = '"' + hashes
            end = text.find(closing, index + raw_start.end())
            end = len(text) if end < 0 else end + len(closing)
            for raw_index in range(index, end):
                result[raw_index] = (
                    "\n" if text[raw_index] == "\n" else " "
                )
            index = end - 1
        elif char == '"' or (
            char == "'"
            and (
                (index + 2 < len(text) and text[index + 2] == "'")
                or (
                    following == "\\"
                    and index + 3 < len(text)
                    and text[index + 3] == "'"
                )
            )
        ):
            result[index] = " "
            quote = char
            state = "quoted"
        index += 1
    return "".join(result)


def contains_symbol(paths: list[str], root: Path, symbol: str) -> bool:
    """Return whether code declares a symbol, including string-table macro APIs."""

    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    for path in paths:
        source = root / path
        if not source.is_file():
            continue
        code = code_only(source.read_text(encoding="utf-8", errors="ignore"))
        if pattern.search(code):
            return True

        # DECLARE_STRING_TABLE_LOOKUP(name, Type) expands to the two public
        # name_to_string()/name_from_string() declarations. Keep generated C
        # APIs reviewable without pretending the macro expansion is prose.
        for table in re.findall(
            r"\bDECLARE_STRING_TABLE_LOOKUP\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
            code,
        ):
            if symbol in {f"{table}_to_string", f"{table}_from_string"}:
                return True
        for table in re.findall(
            r"\bDECLARE_STRING_TABLE_LOOKUP_TO_STRING\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
            code,
        ):
            if symbol == f"{table}_to_string":
                return True
        for table in re.findall(
            r"\bDECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
            code,
        ):
            if symbol in {f"{table}_to_string_alloc", f"{table}_from_string"}:
                return True
    return False


def fixture_calls_symbol(text: str, symbol: str) -> bool:
    """Require a call-shaped symbol occurrence inside C fixture function code."""

    masked = code_only(text)
    first_body = masked.find("{")
    if first_body < 0:
        return False
    return re.search(
        rf"\b{re.escape(symbol)}\s*\(",
        masked[first_body + 1 :],
    ) is not None


def declaration_has_parameter(
    paths: list[str],
    root: Path,
    symbol: str,
    parameter: str,
) -> bool:
    """Return whether a C declaration names ``parameter`` for ``symbol``."""

    symbol_pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(")
    parameter_pattern = re.compile(rf"\b{re.escape(parameter)}\b")
    for path in paths:
        source = root / path
        if not source.is_file():
            continue
        text = code_only(source.read_text(encoding="utf-8", errors="ignore"))
        for match in symbol_pattern.finditer(text):
            try:
                arguments, _end = balanced_call(text, match.end() - 1)
            except ValueError:
                continue
            if parameter_pattern.search(arguments):
                return True
        for table in re.findall(
            r"\bDECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
            text,
        ):
            if symbol == f"{table}_to_string_alloc" and parameter == "ret":
                return True
    return False


@functools.cache
def load_fixture_catalog_gate():
    """Load the one authoritative Meson executable-identity parser."""

    script = Path(__file__).with_name("check-rust-fixture-catalog.py")
    spec = importlib.util.spec_from_file_location(
        "rust_port_fixture_catalog_for_contracts",
        script,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def registered_fixture_records(root: Path) -> tuple[tuple[str, str, bool], ...]:
    """Parse the repository's Meson fixture graph once per validation run."""

    records = load_fixture_catalog_gate().discover_rust_linked_fixtures(root)
    return tuple(records)


def meson_target_links_fixture(root: Path, target: str, fixture: str) -> bool:
    """Verify exact fixture path and executable identity with the catalog parser."""

    fixture_path = Path(fixture)
    if fixture_path != Path("tests-extra") / fixture_path.name:
        return False
    try:
        records = registered_fixture_records(root)
    except (OSError, ValueError):
        return False
    matches = [
        registered
        for record_target, source, registered in records
        if record_target == target and source == fixture_path.name
    ]
    return matches == [True]


def balanced_call(text: str, opening: int) -> tuple[str, int]:
    """Return a Meson call body and the offset immediately after its close."""

    if opening >= len(text) or text[opening] != "(":
        raise ValueError("balanced Meson parser expected '('")
    depth = 1
    quote: str | None = None
    escaped = False
    index = opening + 1
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
    return text[opening + 1:index - 1], index


def validate_fixture(
    surface: dict[str, Any], root: Path, errors: list[str], contract_name: str,
) -> None:
    fixture = surface.get("static_fixture")
    label = surface.get("id", "<unknown>")
    if not isinstance(fixture, dict):
        fail(errors, f"{contract_name}:{label}: exact/deviation surface needs [surface.static_fixture]")
        return
    allowed = {"file", "meson_target", "labels"}
    unknown = set(fixture) - allowed
    if unknown:
        fail(errors, f"{contract_name}:{label}: unknown fixture field(s): {sorted(unknown)}")
    fixture_path = normalized_path(fixture.get("file"), f"{contract_name}:{label}: fixture.file", errors)
    target = fixture.get("meson_target")
    if not isinstance(target, str) or not re.fullmatch(r"test-[A-Za-z0-9_-]+", target):
        fail(errors, f"{contract_name}:{label}: fixture.meson_target must be a test-* target")
    labels = label_list(fixture.get("labels"), f"{contract_name}:{label}: fixture.labels", errors)
    if label not in labels:
        fail(errors, f"{contract_name}:{label}: fixture.labels must include the surface id")
    if fixture_path is None:
        return
    source = root / fixture_path
    if not source.is_file():
        fail(errors, f"{contract_name}:{label}: missing fixture {fixture_path}")
        return
    text = source.read_text(encoding="utf-8", errors="ignore")
    markers = MARKER_RE.findall(text)
    for item in labels:
        if markers.count(item) != 1:
            fail(errors, f"{contract_name}:{label}: fixture marker {item!r} must occur exactly once")
    if isinstance(target, str) and not meson_target_links_fixture(root, target, fixture_path):
        fail(errors, f"{contract_name}:{label}: fixture is not a registered Rust-linked Meson target")
    for symbol in surface.get("c_symbols", []):
        if not fixture_calls_symbol(text, symbol):
            fail(
                errors,
                f"{contract_name}:{label}: fixture does not call/reference "
                f"C symbol {symbol}",
            )
    for symbol in surface.get("rust_symbols", []):
        if not fixture_calls_symbol(text, symbol):
            fail(
                errors,
                f"{contract_name}:{label}: fixture does not call/reference "
                f"Rust symbol {symbol}",
            )


def validate_contract(
    contract_path: Path, root: Path, module_entry: dict[str, Any], module_name: str,
) -> list[str]:
    errors: list[str] = []
    relative = contract_path.relative_to(root)
    if not contract_path.is_file():
        return [f"{relative}: contract file does not exist"]
    try:
        data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        return [f"{relative}: invalid TOML: {exc}"]
    if not isinstance(data, dict):
        return [f"{relative}: contract root must be a TOML table"]

    allowed_top = {
        "schema", "module", "semantic_coverage", "source_structure",
        "deviation_policy", "authority", "surface", "excluded_c_symbols",
    }
    unknown = set(data) - allowed_top
    if unknown:
        fail(errors, f"{relative}: unknown top-level field(s): {sorted(unknown)}")
    if data.get("schema") != SCHEMA:
        fail(errors, f"{relative}: schema must be {SCHEMA}")
    if data.get("module") != module_name:
        fail(errors, f"{relative}: module must equal map module {module_name!r}")
    for field, allowed in (
        ("semantic_coverage", SEMANTIC_COVERAGE),
        ("source_structure", SOURCE_STRUCTURE),
        ("deviation_policy", DEVIATION_POLICY),
    ):
        if data.get(field) not in allowed:
            fail(errors, f"{relative}: {field} must be one of {sorted(allowed)}")

    authority = data.get("authority")
    if not isinstance(authority, dict):
        fail(errors, f"{relative}: [authority] is required")
        authority = {}
    allowed_authority = {"c_headers", "c_sources", "rust_headers", "rust_sources"}
    unknown_authority = set(authority) - allowed_authority
    if unknown_authority:
        fail(errors, f"{relative}: unknown authority field(s): {sorted(unknown_authority)}")
    c_headers = path_list(authority.get("c_headers"), f"{relative}: authority.c_headers", errors)
    c_sources = path_list(authority.get("c_sources"), f"{relative}: authority.c_sources", errors)
    rust_headers = path_list(authority.get("rust_headers"), f"{relative}: authority.rust_headers", errors)
    rust_sources = path_list(authority.get("rust_sources"), f"{relative}: authority.rust_sources", errors)
    for path in c_headers + c_sources + rust_headers + rust_sources:
        if not (root / path).is_file():
            fail(errors, f"{relative}: authority path does not exist: {path}")

    try:
        mapped_c = map_paths(module_entry, "c_file", "c_paths")
        mapped_rust = map_paths(module_entry, "rust_file", "rust_paths")
        mapped_headers = map_paths(module_entry, "header_file", "header_paths")
    except ValueError as exc:
        fail(errors, f"{relative}: invalid map authority: {exc}")
        mapped_c, mapped_rust, mapped_headers = set(), set(), set()
    if not set(c_sources).issubset(mapped_c):
        fail(errors, f"{relative}: authority.c_sources escapes mapped C authority")
    if not set(rust_sources).issubset(mapped_rust):
        fail(errors, f"{relative}: authority.rust_sources escapes mapped Rust authority")
    if not set(rust_headers).issubset(mapped_rust):
        fail(errors, f"{relative}: authority.rust_headers escapes mapped Rust authority")
    if not set(c_headers).issubset(mapped_c | mapped_headers):
        fail(errors, f"{relative}: authority.c_headers escapes mapped header authority")
    for path in rust_headers:
        if not Path(path).parent.is_relative_to(Path("src")):
            fail(errors, f"{relative}: rust header must live below src/: {path}")

    surfaces = data.get("surface")
    if not isinstance(surfaces, list) or not surfaces:
        fail(errors, f"{relative}: at least one [[surface]] is required")
        return errors
    seen_ids: set[str] = set()
    seen_c: set[str] = set()
    seen_rust: set[str] = set()
    claimed = 0
    for index, surface in enumerate(surfaces):
        prefix = f"{relative}: surface[{index}]"
        if not isinstance(surface, dict):
            fail(errors, f"{prefix}: must be a table")
            continue
        allowed_surface = {
            "id", "c_symbols", "rust_symbols", "coverage", "abi", "bytes", "errors",
            "runtime", "verification", "runtime_evidence", "output",
            "static_fixture", "deviation_id", "deviation_rationale",
            "deviation_approval",
        }
        unknown_surface = set(surface) - allowed_surface
        if unknown_surface:
            fail(errors, f"{prefix}: unknown field(s): {sorted(unknown_surface)}")
        identity = surface.get("id")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", identity):
            fail(errors, f"{prefix}: id must be lowercase kebab-case")
            identity = f"invalid-{index}"
        if identity in seen_ids:
            fail(errors, f"{prefix}: duplicate surface id {identity}")
        seen_ids.add(identity)
        c_symbols = symbol_list(surface.get("c_symbols"), f"{prefix}: c_symbols", errors)
        rust_symbols = symbol_list(surface.get("rust_symbols"), f"{prefix}: rust_symbols", errors)
        if (
            surface.get("abi") == "c-exact"
            and rust_symbols != [f"rs_{symbol}" for symbol in c_symbols]
        ):
            fail(
                errors,
                f"{prefix}: c-exact symbols must pair positionally as "
                "C symbol -> rs_<C symbol>",
            )
        duplicate_c = seen_c.intersection(c_symbols)
        duplicate_rust = seen_rust.intersection(rust_symbols)
        if duplicate_c:
            fail(errors, f"{prefix}: C symbols occur in another surface: {sorted(duplicate_c)}")
        if duplicate_rust:
            fail(errors, f"{prefix}: Rust symbols occur in another surface: {sorted(duplicate_rust)}")
        seen_c.update(c_symbols)
        seen_rust.update(rust_symbols)
        for field, allowed in (("coverage", SURFACE_COVERAGE), ("abi", ABI), ("bytes", BYTES), ("errors", ERRORS), ("runtime", RUNTIME)):
            if surface.get(field) not in allowed:
                fail(errors, f"{prefix}: {field} must be one of {sorted(allowed)}")
        if surface.get("verification") not in VERIFICATION:
            fail(
                errors,
                f"{prefix}: verification must be one of {sorted(VERIFICATION)}",
            )
        runtime_evidence = surface.get("runtime_evidence")
        if surface.get("verification") == "runtime-verified":
            required_evidence = {
                "target",
                "runner",
                "source_revision",
                "result_ref",
            }
            if not isinstance(runtime_evidence, dict):
                fail(
                    errors,
                    f"{prefix}: runtime-verified surface requires "
                    "[surface.runtime_evidence]",
                )
            else:
                unknown_evidence = set(runtime_evidence) - required_evidence
                missing_evidence = required_evidence - set(runtime_evidence)
                if unknown_evidence or missing_evidence:
                    fail(
                        errors,
                        f"{prefix}: runtime_evidence must contain exactly "
                        f"{sorted(required_evidence)}; missing={sorted(missing_evidence)} "
                        f"unknown={sorted(unknown_evidence)}",
                    )
                for field in required_evidence & set(runtime_evidence):
                    value = runtime_evidence[field]
                    if not isinstance(value, str) or not value.strip():
                        fail(
                            errors,
                            f"{prefix}: runtime_evidence.{field} must be non-empty",
                        )
        elif runtime_evidence is not None:
            fail(
                errors,
                f"{prefix}: static-only surface cannot declare runtime_evidence",
            )
        outputs = surface.get("output", [])
        if not isinstance(outputs, list):
            fail(errors, f"{prefix}: output must be an array of tables")
            outputs = []
        output_args: set[tuple[str, str]] = set()
        for output_index, output in enumerate(outputs):
            output_prefix = f"{prefix}: output[{output_index}]"
            if not isinstance(output, dict):
                fail(errors, f"{output_prefix}: must be a table")
                continue
            if set(output) - {
                "symbols", "arg", "ownership", "release",
                "publication_success", "publication_error", "optional",
            }:
                fail(errors, f"{output_prefix}: unknown output field")
            output_symbols = output.get("symbols")
            if output_symbols is None:
                if len(c_symbols) > 1:
                    fail(
                        errors,
                        f"{output_prefix}: multi-symbol surface must declare "
                        "the C symbols this output applies to",
                    )
                    output_symbols = []
                else:
                    output_symbols = c_symbols
            else:
                output_symbols = symbol_list(
                    output_symbols,
                    f"{output_prefix}: symbols",
                    errors,
                )
                unknown_output_symbols = set(output_symbols) - set(c_symbols)
                if unknown_output_symbols:
                    fail(
                        errors,
                        f"{output_prefix}: symbols are not members of the surface: "
                        f"{sorted(unknown_output_symbols)}",
                    )
            arg = output.get("arg")
            if not isinstance(arg, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", arg):
                fail(errors, f"{output_prefix}: arg must be a C identifier")
            else:
                duplicates = {
                    (symbol, arg)
                    for symbol in output_symbols
                    if (symbol, arg) in output_args
                }
                if duplicates:
                    fail(
                        errors,
                        f"{output_prefix}: duplicate symbol/output pairs: "
                        f"{sorted(duplicates)}",
                    )
                output_args.update((symbol, arg) for symbol in output_symbols)
                if arg != "return":
                    for symbol in output_symbols:
                        if not declaration_has_parameter(
                            c_headers,
                            root,
                            symbol,
                            arg,
                        ):
                            fail(
                                errors,
                                f"{output_prefix}: {symbol} has no C parameter "
                                f"named {arg!r}",
                            )
            if output.get("ownership") not in OWNERSHIP:
                fail(errors, f"{output_prefix}: ownership must be one of {sorted(OWNERSHIP)}")
            for publication in ("publication_success", "publication_error"):
                if output.get(publication) not in PUBLICATION:
                    fail(errors, f"{output_prefix}: {publication} must be one of {sorted(PUBLICATION)}")
            if "optional" in output and not isinstance(output["optional"], bool):
                fail(errors, f"{output_prefix}: optional must be boolean")
            if output.get("ownership") == "owned-libc" and output.get("release") != "free":
                fail(errors, f"{output_prefix}: owned-libc output must declare release = 'free'")
        coverage = surface.get("coverage")
        if coverage in {"exact", "deviation"}:
            claimed += 1
            if any(surface.get(field) == "unclaimed" for field in ("abi", "bytes", "errors", "runtime")):
                fail(errors, f"{prefix}: claimed surface cannot leave a behavior axis unclaimed")
            validate_fixture(surface, root, errors, str(relative))
            for symbol in c_symbols:
                if not contains_symbol(c_sources + c_headers, root, symbol):
                    fail(errors, f"{prefix}: C authority does not contain {symbol}")
            for symbol in rust_symbols:
                if not contains_symbol(rust_sources, root, symbol):
                    fail(errors, f"{prefix}: Rust source does not contain {symbol}")
                if surface.get("abi") == "c-exact" and not contains_symbol(rust_headers, root, symbol):
                    fail(errors, f"{prefix}: Rust ABI header does not contain {symbol}")
        if coverage == "deviation":
            if data.get("deviation_policy") != "explicit-only":
                fail(errors, f"{prefix}: deviation requires deviation_policy = 'explicit-only'")
            for field in ("deviation_id", "deviation_rationale", "deviation_approval"):
                if not isinstance(surface.get(field), str) or not surface[field].strip():
                    fail(errors, f"{prefix}: deviation requires non-empty {field}")
        elif any(field in surface for field in ("deviation_id", "deviation_rationale", "deviation_approval")):
            fail(errors, f"{prefix}: deviation metadata is only valid for coverage = 'deviation'")
        if (
            surface.get("verification") == "runtime-verified"
            and surface.get("runtime") == "unclaimed"
        ):
            fail(
                errors,
                f"{prefix}: runtime-verified surface cannot leave runtime unclaimed",
            )

    mapped_symbol_count = module_entry.get("symbols")
    if (
        not isinstance(mapped_symbol_count, int)
        or isinstance(mapped_symbol_count, bool)
        or mapped_symbol_count < 0
    ):
        fail(errors, f"{relative}: map entry must declare a non-negative integer symbols count")
    elif mapped_symbol_count != len(seen_c):
        fail(
            errors,
            f"{relative}: map symbols={mapped_symbol_count} but contracts declare "
            f"{len(seen_c)} distinct C symbols",
        )

    excluded = data.get("excluded_c_symbols", [])
    if not isinstance(excluded, list) or not all(
        isinstance(item, str)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item)
        for item in excluded
    ):
        fail(errors, f"{relative}: excluded_c_symbols must be a C identifier array")
        excluded = []
    elif len(set(excluded)) != len(excluded):
        fail(errors, f"{relative}: excluded_c_symbols contains duplicates")
    elif set(excluded).intersection(seen_c):
        fail(errors, f"{relative}: excluded_c_symbols overlaps claimed C symbols")
    else:
        for symbol in excluded:
            if not contains_symbol(c_sources + c_headers, root, symbol):
                fail(
                    errors,
                    f"{relative}: excluded C symbol is absent from authority: {symbol}",
                )
    if data.get("semantic_coverage") == "complete" and any(
        surface.get("coverage") != "exact" for surface in surfaces if isinstance(surface, dict)
    ):
        fail(errors, f"{relative}: complete semantic coverage requires only exact surfaces")
    if data.get("semantic_coverage") == "complete" and excluded:
        fail(errors, f"{relative}: complete semantic coverage cannot exclude C symbols")
    if data.get("semantic_coverage") == "none" and claimed:
        fail(errors, f"{relative}: semantic_coverage=none cannot contain claimed surfaces")
    if data.get("semantic_coverage") == "partial":
        if not claimed:
            fail(errors, f"{relative}: partial semantic coverage requires a claimed surface")
        if not excluded:
            fail(
                errors,
                f"{relative}: partial semantic coverage must enumerate excluded_c_symbols",
            )
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--map", default="tools/rust-port/map.toml")
    parser.add_argument("--contract", help="Validate one map-indexed contract path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root).resolve()
    map_path = root / args.map
    try:
        manifest = tomllib.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"behavior contract gate: cannot load map: {exc}", file=sys.stderr)
        return 2
    selected: list[tuple[str, dict[str, Any], Path]] = []
    declared_contracts: dict[str, str] = {}
    requested: str | None = None
    if args.contract:
        requested = normalized_path(args.contract, "--contract", [])
        if requested is None:
            print("behavior contract gate: --contract must be a normalized relative path", file=sys.stderr)
            return 2
    for module, entry in manifest.items():
        if not isinstance(entry, dict):
            print(
                f"behavior contract gate: map entry {module!r} must be a table",
                file=sys.stderr,
            )
            return 1
        if "contract_file" not in entry:
            continue
        contract = entry.get("contract_file")
        path_errors: list[str] = []
        relative = normalized_path(contract, f"{module}.contract_file", path_errors)
        if path_errors:
            print("behavior contract gate: " + "; ".join(path_errors), file=sys.stderr)
            return 1
        assert relative is not None
        path = Path(relative)
        if not path.is_relative_to(CONTRACT_ROOT) or len(path.relative_to(CONTRACT_ROOT).parts) != 2:
            print(f"behavior contract gate: {module}: contract_file must be directory-local below {CONTRACT_ROOT}/", file=sys.stderr)
            return 1
        previous = declared_contracts.get(relative)
        if previous is not None:
            print(
                f"behavior contract gate: contract_file {relative!r} is declared "
                f"by both {previous} and {module}",
                file=sys.stderr,
            )
            return 1
        declared_contracts[relative] = module
        selected.append((module, entry, root / path))
    actual_contracts = {
        path.relative_to(root).as_posix()
        for path in (root / CONTRACT_ROOT).rglob("*.toml")
        if path.is_file()
    }
    orphaned = sorted(actual_contracts - set(declared_contracts))
    if orphaned:
        print(
            "behavior contract gate: contract files are not map-indexed: "
            + ", ".join(orphaned),
            file=sys.stderr,
        )
        return 1
    missing = sorted(set(declared_contracts) - actual_contracts)
    if missing:
        print(
            "behavior contract gate: map-indexed contract files are missing: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    if not declared_contracts:
        print(
            "behavior contract gate: no map-indexed behavior contracts found",
            file=sys.stderr,
        )
        return 1
    if requested is not None:
        selected = [
            item
            for item in selected
            if item[2].relative_to(root).as_posix() == requested
        ]
    if requested is not None and requested not in declared_contracts:
        print(f"behavior contract gate: no map entry declares contract_file = {requested!r}", file=sys.stderr)
        return 1
    errors: list[str] = []
    for module, entry, contract in selected:
        errors.extend(validate_contract(contract, root, entry, module))
    if errors:
        print("behavior contract gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"behavior contract gate OK: contracts={len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
