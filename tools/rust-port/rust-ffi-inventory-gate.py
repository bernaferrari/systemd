#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Ratchet advertised Rust C ABI declarations against explicit exports.

The port contains C headers beside Rust shadows. A declaration in one of those
headers is a link-time promise, not evidence that an ordinary Rust function
with similar behavior exists. This gate inventories those promises and rejects
new unbacked or duplicate symbols while the historical debt is repaired.

All current mirror headers are consumed by tests linked to
``libsystemd_basic_rs.a``.  Exports therefore count only when their source is
reachable from that artifact's Cargo library root and tracked as an input of
the exact Meson custom target.  A source-tree-global symbol union would let an
unrelated Rust binary satisfy a basic-library promise.

Specialized gates remain responsible for exact signature and behavior checks.
This repository-wide gate proves artifact-local, unconditional symbol
reachability; it does not claim link closure or behavioral parity without a
build.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path


RS_SYMBOL_RE = re.compile(r"\brs_[A-Za-z0-9_]+")
HEADER_DECL_RE = re.compile(r"\b(rs_[A-Za-z0-9_]+)(?=\s*\()")
EXPORT_NAME_RE = re.compile(
    r"#\[(?:unsafe\()?export_name\s*=\s*\"(rs_[A-Za-z0-9_]+)\"\)?\]\s*"
    r"(?:pub\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn"
)
RUST_ABI_EXPORT_NAME_RE = re.compile(
    r"#\[(?:unsafe\()?export_name\s*=\s*\"(rs_[A-Za-z0-9_]+)\"\)?\]\s*"
    r"(?:pub\s+)?(?:unsafe\s+)?fn"
)
NO_MANGLE_RE = re.compile(
    r"#\[(?:unsafe\()?no_mangle\)?\]\s*"
    r"(?:pub\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+"
    r"(rs_[A-Za-z0-9_]+)"
)
RUST_ABI_NO_MANGLE_RE = re.compile(
    r"#\[(?:unsafe\()?no_mangle\)?\]\s*"
    r"(?:pub\s+)?(?:unsafe\s+)?fn\s+(rs_[A-Za-z0-9_]+)"
)
MACRO_C_EXPORT_ATTR_RE = re.compile(
    r"#\[\s*(?:unsafe\s*\(\s*)?"
    r"(?:no_mangle|export_name\s*=\s*\$symbol)"
    r"\s*\)?\s*\]"
)
EXPORTED_TABLE_MACROS = (
    "string_table",
    "string_table_boolean",
    "string_table_fallback",
    "ffi_string_table",
    "ffi_forward",
)
CLAIMED_STATUSES = {"done", "shadow", "replace", "fallback"}
MACRO_INVOCATION_RE = re.compile(
    rf"\b({'|'.join(EXPORTED_TABLE_MACROS)})!\s*\((.*?)\)\s*;",
    flags=re.DOTALL,
)
BASIC_MANIFEST = Path("src/basic/rust/Cargo.toml")
BASIC_MESON = Path("src/basic/meson.build")
RUST_CI = Path(".github/workflows/rust-ci.yml")
SIGNATURE_GATE_SCRIPTS = (
    "rust-ffi-inventory-gate.py",
    "check-registered-test-rust-ffi.py",
    "check-basic-rust-ffi-abi.py",
    "check-string-table-abi.py",
    "check-string-util-abi.py",
    "check-gpt-basic-abi.py",
    "check-seccomp-basic-abi.py",
)


def rust_char_literal_start(text: str, index: int) -> bool:
    """Distinguish a Rust character literal from a lifetime such as ``'a``."""

    if text[index] != "'":
        return False
    if index + 2 < len(text) and text[index + 1] != "\\":
        return text[index + 2] == "'"
    if index + 3 >= len(text) or text[index + 1] != "\\":
        return False
    if text[index + 2] == "u" and index + 3 < len(text) and text[index + 3] == "{":
        closing = text.find("}", index + 4, min(len(text), index + 16))
        return closing >= 0 and closing + 1 < len(text) and text[closing + 1] == "'"
    if text[index + 2] == "x":
        return index + 5 < len(text) and text[index + 5] == "'"
    return text[index + 3] == "'"


def rust_raw_hashes_before_quote(text: str, index: int) -> int | None:
    if text[index] != '"':
        return None
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "#":
        cursor -= 1
    if cursor >= 0 and text[cursor] == "r":
        return index - cursor - 1
    if cursor >= 1 and text[cursor - 1 : cursor + 1] == "br":
        return index - cursor - 1
    return None


def strip_rust_comments(text: str) -> str:
    """Mask Rust comments while preserving strings, byte strings, and newlines."""

    result = list(text)
    state = "code"
    block_depth = 0
    quote = ""
    raw_hashes: int | None = None
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                state = "block-comment"
                block_depth = 1
                index += 2
                continue
            if char == '"' or (char == "'" and rust_char_literal_start(text, index)):
                quote = char
                raw_hashes = rust_raw_hashes_before_quote(text, index)
                state = "literal"
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block-comment":
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                block_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                result[index] = result[index + 1] = " "
                block_depth -= 1
                if block_depth == 0:
                    state = "code"
                index += 2
                continue
            if char != "\n":
                result[index] = " "
        elif state == "literal":
            if raw_hashes is not None:
                terminator = '"' + ("#" * raw_hashes)
                if text.startswith(terminator, index):
                    index += len(terminator)
                    raw_hashes = None
                    state = "code"
                    continue
            elif char == "\\" and next_char:
                index += 2
                continue
            elif char == quote:
                state = "code"
        index += 1
    if state == "block-comment":
        raise ValueError("unterminated Rust block comment")
    return "".join(result)


def strip_c_non_code(text: str) -> str:
    """Mask C comments/literals/directives without changing source line numbers."""

    result = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                state = "block-comment"
                index += 2
                continue
            if char == "/" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            if char == '"':
                result[index] = " "
                state = "string"
            elif char == "'":
                result[index] = " "
                state = "character"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                result[index] = " "
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        else:
            delimiter = '"' if state == "string" else "'"
            if char == "\\" and next_char:
                if char != "\n":
                    result[index] = " "
                if next_char != "\n":
                    result[index + 1] = " "
                index += 2
                continue
            if char == delimiter:
                result[index] = " "
                state = "code"
            elif char != "\n":
                result[index] = " "
        index += 1
    return re.sub(
        r"^[ \t]*#[^\n]*(?:\\\n[^\n]*)*$",
        "",
        "".join(result),
        flags=re.MULTILINE,
    )


def strip_meson_comments(text: str) -> str:
    cleaned: list[str] = []
    in_comment = False
    quote: str | None = None
    escaped = False
    for char in text:
        if char == "\n":
            cleaned.append(char)
            in_comment = False
            escaped = False
            continue
        if in_comment:
            cleaned.append(" ")
        elif quote is not None:
            cleaned.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
            cleaned.append(char)
        elif char == "#":
            cleaned.append(" ")
            in_comment = True
        else:
            cleaned.append(char)
    return "".join(cleaned)


def c_conditional_lines(text: str) -> set[int]:
    controlled: set[int] = set()
    depth = 0
    for number, line in enumerate(text.splitlines(), 1):
        if match := re.match(
            r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", line
        ):
            kind = match.group(1)
            if kind in {"if", "ifdef", "ifndef"}:
                depth += 1
            elif kind == "endif":
                if depth == 0:
                    raise ValueError("unmatched C preprocessor #endif")
                depth -= 1
            continue
        if depth:
            controlled.add(number)
    if depth:
        raise ValueError("unterminated C preprocessor conditional")
    return controlled


def balanced_call_body(text: str, start: int) -> tuple[str, int]:
    """Return the body/end of the parenthesized call beginning at ``start``."""

    if start >= len(text) or text[start] != "(":
        raise ValueError("balanced call parser did not start at '('")
    depth = 1
    quote: str | None = None
    escaped = False
    index = start + 1
    while index < len(text) and depth:
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == '"' or (char == "'" and rust_char_literal_start(text, index)):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        index += 1
    if depth:
        raise ValueError("unterminated parenthesized call")
    return text[start + 1 : index - 1], index


def meson_basic_rust_inputs(root: Path) -> set[Path]:
    """Parse the literal Rust inputs of the exact ``systemd_basic_rs`` target."""

    meson_path = root / BASIC_MESON
    text = strip_meson_comments(meson_path.read_text(encoding="utf-8"))
    assignment = re.search(r"\brust_sources\s*=\s*files\s*(\()", text)
    if not assignment:
        raise ValueError(f"{BASIC_MESON}: missing rust_sources = files(...)")
    body, _ = balanced_call_body(text, assignment.start(1))
    literals = re.findall(r"['\"]([^'\"]+)['\"]", body)
    rust_inputs: set[Path] = set()
    for literal in literals:
        if not literal.endswith(".rs"):
            continue
        candidate = (meson_path.parent / literal).resolve()
        if not candidate.is_file():
            raise ValueError(
                f"{BASIC_MESON}: systemd_basic_rs input is missing: "
                f"{candidate.relative_to(root)}"
            )
        if candidate in rust_inputs:
            raise ValueError(
                f"{BASIC_MESON}: duplicate systemd_basic_rs input: "
                f"{candidate.relative_to(root)}"
            )
        rust_inputs.add(candidate)
    if not rust_inputs:
        raise ValueError(f"{BASIC_MESON}: systemd_basic_rs has no Rust source inputs")
    return rust_inputs


def item_metadata_before(text: str, start: int) -> str:
    """Return contiguous outer attributes immediately before an item."""

    match = re.search(
        r"((?:\s*#\s*\[[^\]]*\]\s*)+)$",
        text[max(0, start - 4000) : start],
        flags=re.DOTALL,
    )
    return match.group(1) if match else ""


def matching_brace(text: str, opening: int) -> int:
    if opening >= len(text) or text[opening] != "{":
        raise ValueError("brace parser did not start at '{'")
    depth = 1
    quote: str | None = None
    raw_hashes: int | None = None
    escaped = False
    index = opening + 1
    while index < len(text) and depth:
        char = text[index]
        if quote is not None:
            if raw_hashes is not None:
                terminator = '"' + ("#" * raw_hashes)
                if text.startswith(terminator, index):
                    index += len(terminator)
                    quote = None
                    raw_hashes = None
                    continue
            elif escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == '"' or (char == "'" and rust_char_literal_start(text, index)):
            quote = char
            raw_hashes = rust_raw_hashes_before_quote(text, index)
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    if depth:
        raise ValueError("unterminated Rust module body")
    return index


def cfg_inline_module_ranges(text: str) -> list[tuple[int, int]]:
    """Return inline module bodies disabled by an outer cfg/cfg_attr."""

    ranges: list[tuple[int, int]] = []
    pattern = re.compile(
        r"(?P<metadata>(?:\s*#\s*\[[^\]]*\]\s*)+)"
        r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+"
        r"[A-Za-z_][A-Za-z0-9_]*\s*(?P<brace>\{)",
        flags=re.DOTALL,
    )
    for match in pattern.finditer(text):
        if not re.search(
            r"#\s*\[\s*cfg(?:_attr)?\s*\(", match.group("metadata")
        ):
            continue
        ranges.append((match.start(), matching_brace(text, match.start("brace"))))
    return ranges


def offset_in_ranges(offset: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in ranges)


def resolve_module(parent: Path, name: str, metadata: str) -> Path:
    path_match = re.search(r"#\s*\[\s*path\s*=\s*['\"]([^'\"]+)['\"]\s*\]", metadata)
    if path_match:
        return (parent.parent / path_match.group(1)).resolve()
    module_dir = (
        parent.parent
        if parent.name in {"lib.rs", "main.rs", "mod.rs"}
        else parent.parent / parent.stem
    )
    file_candidate = module_dir / f"{name}.rs"
    mod_candidate = module_dir / name / "mod.rs"
    candidates = [path for path in (file_candidate, mod_candidate) if path.is_file()]
    if len(candidates) != 1:
        raise ValueError(
            f"{parent}: module {name!r} resolves to {len(candidates)} source files"
        )
    return candidates[0].resolve()


def reachable_rust_sources(crate_root: Path) -> tuple[set[Path], list[str]]:
    """Walk unconditional out-of-line modules from a Cargo crate root."""

    reachable: set[Path] = set()
    cfg_disabled: list[str] = []
    pending = [crate_root.resolve()]
    module_re = re.compile(
        r"(?P<metadata>(?:\s*#\s*\[[^\]]*\]\s*)*)"
        r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;"
    )
    while pending:
        source_path = pending.pop()
        if source_path in reachable:
            continue
        if not source_path.is_file():
            raise ValueError(f"Cargo module source is missing: {source_path}")
        reachable.add(source_path)
        source = strip_rust_comments(source_path.read_text(encoding="utf-8"))
        for match in module_re.finditer(source):
            metadata = match.group("metadata")
            name = match.group("name")
            if re.search(r"#\s*\[\s*cfg(?:_attr)?\s*\(", metadata):
                cfg_disabled.append(
                    f"{source_path}:{source.count(chr(10), 0, match.start()) + 1}:{name}"
                )
                continue
            pending.append(resolve_module(source_path, name, metadata))
    return reachable, cfg_disabled


def basic_artifact_sources(root: Path) -> tuple[list[Path], list[str]]:
    """Return production sources compiled into the exact basic Rust artifact."""

    manifest_path = root / BASIC_MANIFEST
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    library = manifest.get("lib")
    if not isinstance(library, dict) or library.get("name") != "systemd_basic_rs":
        raise ValueError(f"{BASIC_MANIFEST}: unexpected library artifact")
    crate_relative = library.get("path")
    if not isinstance(crate_relative, str):
        raise ValueError(f"{BASIC_MANIFEST}: [lib].path must be explicit")
    crate_root = (manifest_path.parent / crate_relative).resolve()
    reachable, cfg_disabled = reachable_rust_sources(crate_root)
    meson_inputs = meson_basic_rust_inputs(root)
    missing_inputs = sorted(reachable - meson_inputs)
    if missing_inputs:
        rendered = ", ".join(path.relative_to(root).as_posix() for path in missing_inputs)
        raise ValueError(
            f"{BASIC_MESON}: Cargo-reachable production modules missing from "
            f"systemd_basic_rs inputs: {rendered}"
        )
    return sorted(reachable), cfg_disabled


def load_gate_module(root: Path, filename: str):
    path = root / "tools/rust-port" / filename
    module_name = "rust_port_" + filename.removesuffix(".py").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise ValueError(f"cannot load signature authority gate: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signature_authority_pairs(
    root: Path, declared: dict[str, list[str]]
) -> set[tuple[str, str]]:
    """Return header/symbol pairs owned by exact-signature static gates."""

    covered: set[tuple[str, str]] = set()

    def add_header(path: Path, names: set[str] | frozenset[str] | None = None) -> None:
        relative = path.resolve().relative_to(root).as_posix()
        selected = set(declared.get(relative, ())) if names is None else set(names)
        covered.update((relative, name) for name in selected)

    basic = load_gate_module(root, "check-basic-rust-ffi-abi.py")
    for header, _ in basic.SURFACES.values():
        add_header(header)
    for header, _, symbols in basic.PARTIAL_SURFACES.values():
        add_header(header, symbols)
    add_header(
        basic.SHARED_EXIT_STATUS_HEADER,
        basic.PARTIAL_SURFACES["exit_status_securebits"][2]
        | basic.PARTIAL_SURFACES["exit_status_lookup"][2],
    )
    add_header(basic.IN_ADDR_UTIL_HEADER)
    add_header(basic.ETHER_ADDR_UTIL_HEADER)

    string_tables = load_gate_module(root, "check-string-table-abi.py")
    add_header(string_tables.HEADER)
    string_util = load_gate_module(root, "check-string-util-abi.py")
    add_header(string_util.HEADER)
    gpt = load_gate_module(root, "check-gpt-basic-abi.py")
    add_header(gpt.HEADER, frozenset(gpt.EXPECTED))
    add_header(gpt.SHARED_HEADER, frozenset(gpt.SHARED_EXPECTED))
    seccomp = load_gate_module(root, "check-seccomp-basic-abi.py")
    add_header(seccomp.HEADER, frozenset(seccomp.EXPECTED))

    unit_header = (root / "src/basic/rust/unit_def.h").resolve()
    unit_unimplemented = {
        "rs_unit_dbus_interface_from_name",
        "rs_unit_dbus_interface_from_type",
        "rs_unit_dbus_path_from_name",
        "rs_unit_name_from_dbus_path",
    }
    unit_relative = unit_header.relative_to(root).as_posix()
    add_header(
        unit_header,
        frozenset(declared.get(unit_relative, ())) - unit_unimplemented,
    )
    add_header(root / "src/basic/rust/shared_facades/lookups.h")
    return covered


def signature_ci_failures(root: Path) -> list[str]:
    workflow = strip_meson_comments((root / RUST_CI).read_text(encoding="utf-8"))
    job = re.search(
        r"^  rust-port-truthfulness:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not job:
        return [f"{RUST_CI}: missing rust-port-truthfulness job"]
    failures: list[str] = []
    for script in SIGNATURE_GATE_SCRIPTS:
        command = f"python3 tools/rust-port/{script}"
        if job.group("body").count(command) != 1:
            failures.append(
                f"{RUST_CI}: signature authority command must occur exactly once "
                f"in rust-port-truthfulness: {command}"
            )
    return failures


def parser_self_check() -> None:
    sample = r'''
        // #[no_mangle] pub extern "C" fn rs_comment() {}
        const URL: &str = "https://example.invalid/* literal */";
        const RAW: &str = r#"/* raw literal */ { }"#;
        fn lifetime<'a: 'b, 'b>(value: &'a str) -> &'b str { value }
        /* outer /* nested */ comment */
        #[cfg(feature = "hidden")]
        mod hidden;
        #[path = "chosen.rs"]
        mod chosen;
        pub mod plain;
    '''
    stripped = strip_rust_comments(sample)
    if (
        "rs_comment" in stripped
        or "https://example.invalid/* literal */" not in stripped
        or "/* raw literal */ { }" not in stripped
        or "lifetime<'a: 'b, 'b>" not in stripped
    ):
        raise ValueError("Rust comment/literal parser self-check failed")
    attributes = item_metadata_before(stripped, stripped.index("mod hidden"))
    if not re.search(r"#\s*\[\s*cfg\s*\(", attributes):
        raise ValueError("Rust cfg metadata parser self-check failed")
    inline = strip_rust_comments(
        '#[cfg(test)] mod tests { #[no_mangle] pub extern "C" fn rs_hidden() {} }'
    )
    hidden = inline.index("rs_hidden")
    if not offset_in_ranges(hidden, cfg_inline_module_ranges(inline)):
        raise ValueError("Rust cfg inline-module parser self-check failed")
    meson = strip_meson_comments(
        "files('real.rs', # 'commented.rs'\n 'hash#literal.rs')"
    )
    if "commented.rs" in meson or "hash#literal.rs" not in meson:
        raise ValueError("Meson comment/literal parser self-check failed")
    c_sample = r'''
        /* int rs_comment(void); */
        const char *literal = "rs_literal(";
#define rs_macro(x) (x)
        int rs_real(const char *s);
#if ENABLED
        int rs_conditional(void);
#endif
    '''
    c_code = strip_c_non_code(c_sample)
    if set(HEADER_DECL_RE.findall(c_code)) != {"rs_real", "rs_conditional"}:
        raise ValueError("C comment/literal/macro parser self-check failed")
    conditional = c_conditional_lines(c_sample)
    conditional_line = c_code[: c_code.index("rs_conditional")].count("\n") + 1
    if conditional_line not in conditional:
        raise ValueError("C conditional parser self-check failed")
    for attribute in (
        "#[no_mangle]",
        "#[unsafe(no_mangle)]",
        "#[export_name = $symbol]",
        "#[unsafe(export_name = $symbol)]",
    ):
        if not MACRO_C_EXPORT_ATTR_RE.fullmatch(attribute):
            raise ValueError(f"macro C-export parser rejected {attribute}")
    if MACRO_C_EXPORT_ATTR_RE.fullmatch('#[unsafe(export_name = "rs_literal")]'):
        raise ValueError("macro C-export parser accepted a fixed symbol")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject growth in header-declared Rust C symbols without explicit exports."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/rust-ffi-inventory-baseline.json",
        help="Missing-symbol baseline relative to the repository root",
    )
    parser.add_argument(
        "--map",
        default="tools/rust-port/map.toml",
        help="Port mapping relative to the repository root",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Replace the baseline with the current missing-symbol inventory",
    )
    return parser.parse_args()


def rust_headers(root: Path) -> list[Path]:
    return sorted(
        path
        for path in (root / "src").rglob("*.h")
        if "rust" in path.relative_to(root / "src").parts
    )


def declarations(root: Path) -> tuple[dict[str, list[str]], list[str]]:
    inventory: dict[str, list[str]] = {}
    failures: list[str] = []
    for path in rust_headers(root):
        raw = path.read_text(encoding="utf-8", errors="ignore")
        code = strip_c_non_code(raw)
        conditional = c_conditional_lines(raw)
        names: list[str] = []
        for match in HEADER_DECL_RE.finditer(code):
            line = code.count("\n", 0, match.start()) + 1
            line_start = code.rfind("\n", 0, match.start()) + 1
            line_end = code.find("\n", match.end())
            if line_end < 0:
                line_end = len(code)
            declaration_line = code[line_start:line_end]
            prefix = code[line_start : match.start()]
            semicolon = code.find(";", match.end())
            suffix = code[match.start() : semicolon + 1] if semicolon >= 0 else ""
            if (
                not prefix.strip()
                or "(" in prefix
                or "=" in prefix
                or "{" in suffix
                or "}" in suffix
                or not re.search(
                    rf"\b{re.escape(match.group(1))}\s*\([^;{{}}]*\)\s*;",
                    suffix,
                    flags=re.DOTALL,
                )
            ):
                failures.append(
                    f"{path.relative_to(root)}:{line}: rs_* token is not a "
                    f"direct C prototype: {declaration_line.strip()}"
                )
                continue
            if line in conditional:
                failures.append(
                    f"{path.relative_to(root)}:{line}: conditional C ABI declaration "
                    f"{match.group(1)} cannot be treated as universally advertised"
                )
                continue
            names.append(match.group(1))
        if not names:
            continue
        relative = path.relative_to(root).as_posix()
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        if duplicates:
            failures.append(
                f"{relative}: duplicate declarations: {', '.join(duplicates)}"
            )
        inventory[relative] = sorted(set(names))
    return inventory, failures


def exported_macro_names(
    root: Path, source_by_path: dict[Path, str]
) -> tuple[list[str], list[str]]:
    definitions = "\n".join(source_by_path.values())
    failures: list[str] = []
    enabled: set[str] = set()
    for macro in EXPORTED_TABLE_MACROS:
        match = re.search(
            rf"macro_rules!\s+{macro}\s*\{{(.*?)^\}}",
            definitions,
            flags=re.MULTILINE | re.DOTALL,
        )
        if not match:
            continue
        body = match.group(1)
        has_c_symbol = MACRO_C_EXPORT_ATTR_RE.search(body) is not None
        if not has_c_symbol or 'extern "C"' not in body:
            failures.append(
                f"{macro}! invocations cannot count as exports: macro lacks explicit C ABI"
            )
            continue
        enabled.add(macro)

    names: list[str] = []
    for path, source in source_by_path.items():
        cfg_ranges = cfg_inline_module_ranges(source)
        for match in MACRO_INVOCATION_RE.finditer(source):
            macro, body = match.groups()
            if macro in enabled:
                if offset_in_ranges(match.start(), cfg_ranges):
                    continue
                metadata = item_metadata_before(source, match.start())
                if re.search(r"#\s*\[\s*cfg(?:_attr)?\s*\(", metadata):
                    line = source.count("\n", 0, match.start()) + 1
                    failures.append(
                        f"{path.relative_to(root)}:{line}: cfg-conditional macro export "
                        "cannot satisfy an unconditional C ABI promise"
                    )
                    continue
                # Forwarding facades name both the exported symbol and their
                # typed Rust implementation in one invocation. Count that
                # declaration once, while still preserving duplicate exports
                # across separate invocations for the global check below.
                names.extend(sorted(set(RS_SYMBOL_RE.findall(body))))
    return names, failures


def exports(
    root: Path, source_paths: list[Path] | None = None
) -> tuple[list[str], list[str]]:
    if source_paths is None:
        paths, _ = basic_artifact_sources(root)
    else:
        paths = sorted(source_paths)
    source_by_path = {
        path: strip_rust_comments(path.read_text(encoding="utf-8", errors="ignore"))
        for path in paths
    }
    names: list[str] = []
    failures: list[str] = []
    for path, source in source_by_path.items():
        cfg_ranges = cfg_inline_module_ranges(source)
        for pattern in (EXPORT_NAME_RE, NO_MANGLE_RE):
            for match in pattern.finditer(source):
                if offset_in_ranges(match.start(), cfg_ranges):
                    continue
                metadata = item_metadata_before(source, match.start())
                name = match.group(1)
                if re.search(r"#\s*\[\s*cfg(?:_attr)?\s*\(", metadata):
                    line = source.count("\n", 0, match.start()) + 1
                    failures.append(
                        f"{path.relative_to(root)}:{line}: cfg-conditional export "
                        f"{name} cannot satisfy an unconditional C ABI promise"
                    )
                    continue
                names.append(name)
        invalid = sorted(set(RUST_ABI_EXPORT_NAME_RE.findall(source)))
        invalid_no_mangle = sorted(set(RUST_ABI_NO_MANGLE_RE.findall(source)))
        if invalid or invalid_no_mangle:
            failures.append(
                f"{path.relative_to(root).as_posix()}: fixed export uses Rust ABI: "
                f"{', '.join([*invalid, *invalid_no_mangle])}"
            )
    macro_names, macro_failures = exported_macro_names(root, source_by_path)
    failures.extend(macro_failures)
    names.extend(macro_names)

    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        failures.append(f"duplicate explicit Rust exports: {', '.join(duplicates)}")
    return names, failures


def missing_inventory(
    declared: dict[str, list[str]], exported: set[str]
) -> dict[str, list[str]]:
    return {
        header: sorted(set(names) - exported)
        for header, names in declared.items()
        if set(names) - exported
    }


def write_baseline(path: Path, missing: dict[str, list[str]]) -> None:
    payload = {
        "version": 1,
        "missing_by_header": missing,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, list[str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1 or not isinstance(payload.get("missing_by_header"), dict):
        raise ValueError(f"unsupported ABI inventory baseline format: {path}")
    baseline: dict[str, list[str]] = {}
    for header, names in payload["missing_by_header"].items():
        if not isinstance(header, str) or not isinstance(names, list) or not all(
            isinstance(name, str) for name in names
        ):
            raise ValueError(f"invalid ABI inventory baseline entry: {header!r}")
        baseline[header] = names
    return baseline


def claimed_mapping_failures(
    map_path: Path, declared: dict[str, list[str]], exported: set[str]
) -> list[str]:
    manifest = tomllib.loads(map_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for module, raw in sorted(manifest.items()):
        if not isinstance(raw, dict) or raw.get("status") not in CLAIMED_STATUSES:
            continue
        header_value = raw.get("header_file")
        if not isinstance(header_value, str):
            continue
        for header in (item.strip() for item in header_value.split(";")):
            missing = sorted(set(declared.get(header, ())) - exported)
            if missing:
                failures.append(
                    f"{module}: completed status advertises unbacked symbols in "
                    f"{header}: {', '.join(missing)}"
                )
    return failures


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline

    try:
        parser_self_check()
        artifact_sources, cfg_disabled_modules = basic_artifact_sources(root)
        declared, declaration_failures = declarations(root)
        exported_names, export_failures = exports(root, artifact_sources)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    exported = set(exported_names)
    missing = missing_inventory(declared, exported)

    declared_unique = set().union(*(set(names) for names in declared.values()))
    backed = declared_unique & exported
    backed_pairs = {
        (header, symbol)
        for header, symbols in declared.items()
        for symbol in symbols
        if symbol in exported
    }
    try:
        signature_covered = signature_authority_pairs(root, declared)
    except (OSError, ValueError, AttributeError) as error:
        print(error, file=sys.stderr)
        return 1
    uncovered_signatures = sorted(backed_pairs - signature_covered)
    fully_backed_headers = sum(
        1 for names in declared.values() if set(names).issubset(exported)
    )

    if args.write_baseline:
        write_failures = [
            *declaration_failures,
            *export_failures,
            *signature_ci_failures(root),
        ]
        if uncovered_signatures:
            write_failures.append(
                "artifact-backed declarations lack an exact-signature authority gate: "
                + ", ".join(
                    f"{header}:{symbol}" for header, symbol in uncovered_signatures
                )
            )
        if write_failures:
            for failure in write_failures:
                print(failure, file=sys.stderr)
            return 1
        write_baseline(baseline_path, missing)
        print(f"wrote Rust FFI inventory baseline: {baseline_path}")
        print(
            f"headers={len(declared)} declared={len(declared_unique)} "
            f"backed={len(backed)} missing={len(declared_unique - exported)} "
            f"artifact_sources={len(artifact_sources)}"
        )
        return 0

    failures = [
        *declaration_failures,
        *export_failures,
        *claimed_mapping_failures(root / args.map, declared, exported),
        *signature_ci_failures(root),
    ]
    if uncovered_signatures:
        failures.append(
            "artifact-backed declarations lack an exact-signature authority gate: "
            + ", ".join(f"{header}:{symbol}" for header, symbol in uncovered_signatures)
        )
    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1

    for header, names in missing.items():
        regressions = sorted(set(names) - set(baseline.get(header, ())))
        if regressions:
            failures.append(
                f"{header}: newly unbacked declarations: {', '.join(regressions)}"
            )

    for header, names in baseline.items():
        resolved = sorted(set(names) - set(missing.get(header, ())))
        if resolved:
            failures.append(
                f"{header}: baseline is stale; remove now-backed/removed symbols: "
                f"{', '.join(resolved)}"
            )

    if failures:
        print("Rust FFI inventory gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "Rust FFI inventory gate OK: "
        f"headers={len(declared)} fully_backed={fully_backed_headers} "
        f"declared={len(declared_unique)} backed={len(backed)} "
        f"missing={len(declared_unique - exported)} explicit_exports={len(exported)} "
        f"artifact=systemd_basic_rs artifact_sources={len(artifact_sources)} "
        f"cfg_disabled_modules={len(cfg_disabled_modules)} "
        f"signature_authority_pairs={len(backed_pairs)} "
        "proof=artifact-local-unconditional-symbols link_parity=unclaimed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
