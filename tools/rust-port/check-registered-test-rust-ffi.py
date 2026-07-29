#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Ratchet manually declared Rust ABI promises in Meson-registered C tests.

``tests-extra`` contains C-vs-Rust shadow tests.  A test that types its own
``rs_*`` function declaration makes a link-time ABI promise which does not go
through a Rust-owned header, and is therefore outside the header inventory.
This gate inventories every literal C source in an ``executable()`` that links
``libsystemd_basic_rs.a`` and compares each top-level manual declaration to
that basic artifact's explicit Rust C-export inventory. A declaration whose
symbol is also defined unconditionally by the same C translation unit is a
local C helper, not a Rust ABI promise, and is excluded explicitly.

The checked-in baseline records the pre-existing unbacked declarations while
they are repaired.  It is deliberately debt, not an allow-list of working
tests: an entry means that the test has *not* been proven linkable.  The gate
rejects both new debt and a stale entry after a promise is exported or removed.
For declarations which are backed, this gate also compares the C prototype
with the exact export signature in ``systemd_basic_rs``.  It still does not
claim final link closure; that requires inspecting the built archive.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


RS_DECL_RE = re.compile(r"\b(rs_[A-Za-z0-9_]+)\s*\(")
RS_DEFINITION_RE = re.compile(r"\b(rs_[A-Za-z0-9_]+)\s*\([^;{}]*\)\s*$", re.DOTALL)
SOURCE_RE = re.compile(r"['\"]([^'\"]+\.c)['\"]")
CPP_DIRECTIVE_RE = re.compile(
    r"^[ \t]*\#[^\n]*(?:\\\n[^\n]*)*$", re.MULTILINE
)
Signature = tuple[tuple[str, ...], str]
UNIT_DEF_HEADER = Path("src/basic/rust/unit_def.h")
UNIT_DEF_AUTHORITIES = (
    Path("src/basic/unit-def.c"),
    Path("src/basic/cgroup-util.c"),
)
SHARED_STR_TABLES_HEADER = Path("src/basic/rust/shared_facades/lookups.h")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject growth in manually declared, unexported Rust test ABI."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/registered-test-rust-ffi-baseline.json",
        help="Debt baseline relative to the repository root",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Replace the baseline with current manually declared unbacked symbols",
    )
    return parser.parse_args()


def registered_sources(root: Path) -> list[Path]:
    """Return literal C sources linked with the basic Rust static library.

    Meson accepts sources both directly in ``executable()`` and through
    ``files()``. Balanced call parsing covers both literal forms while refusing
    to let an unrelated target or comment satisfy basic-artifact reachability.
    """

    meson = root / "tests-extra/meson.build"
    text = strip_meson_comments(meson.read_text(encoding="utf-8"))
    sources: set[Path] = set()
    executable_starts = list(re.finditer(r"\bexecutable\s*\(", text))
    for call_index, match in enumerate(executable_starts):
        body, end = balanced_meson_call(text, match.end() - 1)
        if not re.search(
            r"\blink_with\s*:\s*\[\s*libshared\s*,\s*rust_staticlib\s*\]",
            body,
        ):
            continue
        target_match = re.match(r"\s*['\"]([^'\"]+)['\"]\s*,", body)
        if not target_match:
            raise ValueError("Rust-linked executable has no literal target name")
        target = target_match.group(1)
        if not re.fullmatch(r"test-[A-Za-z0-9_-]+", target):
            raise ValueError(f"unexpected Rust-linked tests-extra target: {target}")
        if "get_option('rust').enabled()" not in meson_conditions_at(text, match.start()):
            raise ValueError(f"{target}: Rust-linked target is not guarded by -Drust=enabled")
        next_start = (
            executable_starts[call_index + 1].start()
            if call_index + 1 < len(executable_starts)
            else len(text)
        )
        registration = text[end:next_start]
        if not re.search(
            rf"\btest\s*\(\s*['\"]{re.escape(target)}['\"]\s*,\s*"
            r"rust_test_exe\s*\)",
            registration,
        ):
            raise ValueError(f"{target}: executable is not registered as the same Meson test")
        for source in SOURCE_RE.findall(body):
            candidate = root / "tests-extra" / source
            if not candidate.is_file():
                raise ValueError(
                    f"Meson-registered C source is missing: {candidate.relative_to(root)}"
                )
            sources.add(candidate)
    if not sources:
        raise ValueError("no C sources found in tests-extra/meson.build")
    return sorted(sources)


def balanced_meson_call(text: str, opening: int) -> tuple[str, int]:
    if opening >= len(text) or text[opening] != "(":
        raise ValueError("Meson call parser did not start at '('")
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
        raise ValueError("unterminated executable() call in tests-extra/meson.build")
    return text[opening + 1 : index - 1], index


def meson_conditions_at(text: str, offset: int) -> list[str]:
    """Return conservative outer Meson ``if`` conditions at an offset."""

    stack: list[str] = []
    for line in text[:offset].splitlines():
        if match := re.match(r"^\s*if\s+(.+?)\s*$", line):
            stack.append(match.group(1))
        elif re.match(r"^\s*endif\b", line):
            if not stack:
                raise ValueError("unmatched endif in tests-extra/meson.build")
            stack.pop()
        elif re.match(r"^\s*(?:elif|else)\b", line):
            if not stack:
                raise ValueError("unmatched Meson conditional branch")
            # Retain the outer conditional as a conservative marker. Targets
            # accepted here must specifically be within the positive Rust arm.
            stack[-1] = "<alternate-branch>"
    return stack


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
            continue
        if quote is not None:
            cleaned.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            cleaned.append(char)
        elif char == "#":
            cleaned.append(" ")
            in_comment = True
        else:
            cleaned.append(char)
    return "".join(cleaned)


def strip_c_non_code(text: str) -> str:
    """Remove comments, literals, and preprocessor directives without joining lines."""

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
        elif state in {"string", "character"}:
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

    return CPP_DIRECTIVE_RE.sub("", "".join(result))


def conditional_lines(text: str) -> set[int]:
    """Return source lines controlled by a C preprocessor conditional."""

    controlled: set[int] = set()
    depth = 0
    for number, line in enumerate(text.splitlines(), 1):
        directive = re.match(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", line)
        if directive:
            kind = directive.group(1)
            if kind in {"if", "ifdef", "ifndef"}:
                depth += 1
            elif kind == "endif":
                depth = max(depth - 1, 0)
            continue
        if depth:
            controlled.add(number)
    return controlled


def top_level_declarations(text: str) -> set[str]:
    """Find direct rs_* function declarations at C translation-unit scope.

    Calls inside test functions do not have the link-time declaration shape.
    Keeping only semicolon-terminated fragments at brace depth zero avoids
    mistaking calls and local initializers for forward declarations.  Function
    declarations with function-pointer return types are not present here; if
    one is added it must be expressed through a normal Rust-owned header.
    """

    depth = 0
    fragment: list[str] = []
    declared: set[str] = set()
    for char in strip_c_non_code(text):
        if char == "{":
            if depth == 0:
                # A top-level definition (or aggregate) is not a prototype.
                # Drop its prefix so it cannot hide a later declaration.
                fragment.clear()
            depth += 1
            continue
        if char == "}":
            depth = max(depth - 1, 0)
            continue
        if depth == 0:
            fragment.append(char)
        if char != ";" or depth:
            continue
        statement = "".join(fragment)
        fragment.clear()
        for name_match in RS_DECL_RE.finditer(statement):
            before = statement[: name_match.start()]
            # A direct prototype cannot already be an expression or initializer.
            if "(" not in before and "=" not in before:
                declared.add(name_match.group(1))
    return declared


def top_level_declaration_statements(text: str) -> list[tuple[str, int]]:
    """Return direct semicolon-terminated declarations at translation-unit scope."""

    depth = 0
    fragment: list[str] = []
    statements: list[tuple[str, int]] = []
    code = strip_c_non_code(text)
    fragment_start = 0
    for index, char in enumerate(code):
        if char == "{":
            if depth == 0:
                fragment.clear()
                fragment_start = index + 1
            depth += 1
            continue
        if char == "}":
            depth = max(depth - 1, 0)
            if depth == 0:
                fragment_start = index + 1
            continue
        if depth == 0:
            fragment.append(char)
        if char == ";" and depth == 0:
            statement = "".join(fragment)
            fragment.clear()
            if RS_DECL_RE.search(statement):
                statements.append(
                    (statement, code.count("\n", 0, fragment_start) + 1)
                )
            fragment_start = index + 1
    return statements


def snake_to_camel(name: str) -> str:
    return "".join(component.capitalize() for component in name.split("_"))


def canonical_c_type(raw: str, *, parameter: bool) -> str:
    """Normalize the C scalar/pointer subset used by backed manual promises."""

    value = re.sub(r"\s+", " ", raw.strip())
    value = re.sub(r"\s*\*\s*", "*", value)
    if parameter:
        value = re.sub(r"\s+[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?$", "", value)
        value = re.sub(r"\*([A-Za-z_][A-Za-z0-9_]*)$", "*", value)
    aliases = {
        "void": "()",
        "bool": "bool",
        "char": "c_char",
        "signed char": "i8",
        "unsigned char": "u8",
        "short": "i16",
        "unsigned short": "u16",
        "int": "i32",
        "unsigned": "u32",
        "unsigned int": "u32",
        "long": "isize",
        "unsigned long": "usize",
        "size_t": "usize",
        "ssize_t": "isize",
        "int8_t": "i8",
        "uint8_t": "u8",
        "int16_t": "i16",
        "uint16_t": "u16",
        "int32_t": "i32",
        "uint32_t": "u32",
        "int64_t": "i64",
        "uint64_t": "u64",
        "usec_t": "u64",
        "nsec_t": "u64",
        "dev_t": "u64",
    }
    if value in aliases:
        return aliases[value]
    pointer = re.fullmatch(r"(?P<const>const )?(?P<base>.+?)(?P<stars>\*+)", value)
    if pointer:
        base = pointer.group("base").strip()
        base = re.sub(
            r"^(?:struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)$",
            lambda match: snake_to_camel(match.group(1)),
            base,
        )
        base = "c_void" if base == "void" else aliases.get(base, base)
        stars = pointer.group("stars")
        mutability = "const" if pointer.group("const") else "mut"
        canonical = f"*{mutability}{base}"
        for _ in stars[1:]:
            canonical = f"*mut{canonical}"
        return canonical
    raise ValueError(f"unsupported backed C ABI type: {raw.strip()}")


def c_declaration_signature(statement: str, name: str) -> Signature:
    match = re.search(
        rf"(?P<result>[A-Za-z_][A-Za-z0-9_ \t]*(?:\s*\*+)?)\s*"
        rf"{re.escape(name)}\s*\((?P<parameters>[^()]*)\)\s*;",
        statement,
    )
    if not match:
        raise ValueError(f"cannot parse backed C ABI declaration for {name}")
    raw_parameters = match.group("parameters").strip()
    parameters: tuple[str, ...] = ()
    if raw_parameters and raw_parameters != "void":
        parameters = tuple(
            canonical_c_type(parameter, parameter=True)
            for parameter in raw_parameters.split(",")
        )
    return parameters, canonical_c_type(match.group("result"), parameter=False)


def declaration_signatures(text: str, only: set[str]) -> dict[str, Signature]:
    signatures: dict[str, Signature] = {}
    controlled = conditional_lines(text)
    for statement, start_line in top_level_declaration_statements(text):
        names = set(RS_DECL_RE.findall(statement)) & only
        for name in names:
            prefix = statement[: statement.index(name)]
            line = start_line + prefix.count("\n")
            if line in controlled:
                raise ValueError(
                    f"backed C ABI declaration {name} is preprocessor-conditional"
                )
            signature = c_declaration_signature(statement, name)
            if name in signatures:
                raise ValueError(f"duplicate backed C ABI declaration for {name}")
            signatures[name] = signature
    return signatures


def top_level_definitions(text: str) -> set[str]:
    """Find direct rs_* function definitions at C translation-unit scope.

    Only the declaration prefix immediately preceding a top-level opening
    brace is considered.  Clearing the prefix after every top-level semicolon
    prevents a prior prototype from being mistaken for the later definition.
    Function-like macros have already been removed with preprocessor
    directives and therefore cannot manufacture a false definition here.
    """

    depth = 0
    fragment: list[str] = []
    defined: set[str] = set()
    code = strip_c_non_code(text)
    controlled = conditional_lines(text)
    for index, char in enumerate(code):
        if char == "{":
            if depth == 0:
                match = RS_DEFINITION_RE.search("".join(fragment))
                line = code.count("\n", 0, index) + 1
                if match and line not in controlled:
                    defined.add(match.group(1))
                fragment.clear()
            depth += 1
            continue
        if char == "}":
            depth = max(depth - 1, 0)
            continue
        if depth:
            continue
        fragment.append(char)
        if char == ";":
            fragment.clear()
    return defined


def parser_self_check() -> None:
    """Guard the distinction between a Rust promise and a local C helper."""

    sample = """
        bool rs_external(unsigned value);
        unsigned rs_local(void);
        unsigned rs_local(void) {
                return 7U;
        }
        static bool rs_private(const char *s) {
                return s && *s;
        }
        static const char *url = "https://example.test/*not-a-comment*/";
        bool rs_after_literal(void);
        bool rs_conditional(void);
#define rs_macro(x) ((x) + 1)
#if 0
        bool rs_conditional(void) {
                return true;
        }
        int rs_cfg_only(const char *s);
#endif
    """
    declared = top_level_declarations(sample)
    defined = top_level_definitions(sample)
    if declared != {
        "rs_after_literal",
        "rs_cfg_only",
        "rs_conditional",
        "rs_external",
        "rs_local",
    }:
        raise ValueError(f"registered-test ABI declaration parser self-check failed: {declared}")
    if defined != {"rs_local", "rs_private"}:
        raise ValueError(f"registered-test ABI definition parser self-check failed: {defined}")
    signatures = declaration_signatures(sample, {"rs_external"})
    if signatures != {"rs_external": (("u32",), "bool")}:
        raise ValueError(
            f"registered-test ABI signature parser self-check failed: {signatures}"
        )
    try:
        declaration_signatures(sample, {"rs_cfg_only"})
    except ValueError as error:
        if "preprocessor-conditional" not in str(error):
            raise
    else:
        raise ValueError("conditional C ABI declaration parser self-check failed")

    meson_sample = """
        if get_option('rust').enabled()
                executable('test-real', files('test-real.c'),
                           link_with : [libshared, rust_staticlib]) # ignored
                marker = 'literal # is data'
        endif
    """
    meson_clean = strip_meson_comments(meson_sample)
    executable = re.search(r"\bexecutable\s*(\()", meson_clean)
    if (
        not executable
        or "literal # is data" not in meson_clean
        or "ignored" in meson_clean
        or "get_option('rust').enabled()"
        not in meson_conditions_at(meson_clean, executable.start())
    ):
        raise ValueError("Meson comment/literal/conditional parser self-check failed")
    body, _ = balanced_meson_call(meson_clean, executable.start(1))
    if "files('test-real.c')" not in body:
        raise ValueError("Meson balanced-call parser self-check failed")


def manual_declarations(
    root: Path,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    inventory: dict[str, list[str]] = {}
    c_definitions: dict[str, list[str]] = {}
    for source in registered_sources(root):
        text = source.read_text(encoding="utf-8", errors="ignore")
        declarations = top_level_declarations(text)
        definitions = top_level_definitions(text)
        same_source_helpers = declarations & definitions
        names = declarations - definitions
        if names:
            inventory[source.relative_to(root).as_posix()] = sorted(names)
        if same_source_helpers:
            c_definitions[source.relative_to(root).as_posix()] = sorted(same_source_helpers)
    return inventory, c_definitions


def explicit_exports(root: Path) -> tuple[set[str], list[str]]:
    """Use the global inventory's exact artifact/export rules."""

    module = load_inventory_gate(root)
    basic_sources, _ = module.basic_artifact_sources(root)
    names, failures = module.exports(root, basic_sources)
    return set(names), failures


def load_inventory_gate(root: Path):
    inventory_path = root / "tools/rust-port/rust-ffi-inventory-gate.py"
    spec = importlib.util.spec_from_file_location("rust_ffi_inventory_gate", inventory_path)
    if not spec or not spec.loader:
        raise ValueError(f"cannot load explicit export inventory: {inventory_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_rust_type(raw: str) -> str:
    value = re.sub(r"\s+", "", raw)
    aliases = {
        "libc::c_char": "c_char",
        "std::ffi::c_char": "c_char",
        "c_char": "c_char",
        "libc::c_int": "i32",
        "c_int": "i32",
        "libc::c_uint": "u32",
        "c_uint": "u32",
        "libc::c_void": "c_void",
        "std::ffi::c_void": "c_void",
        "c_void": "c_void",
        "libc::size_t": "usize",
        "libc::ssize_t": "isize",
        "()": "()",
    }
    for alias, canonical in aliases.items():
        value = value.replace(alias, canonical)
    return value


def rust_parameter_types(raw: str) -> tuple[str, ...]:
    parameters: list[str] = []
    for parameter in raw.split(","):
        if not parameter.strip():
            continue
        if ":" not in parameter:
            raise ValueError(f"cannot parse backed Rust ABI parameter: {parameter}")
        _, type_name = parameter.split(":", 1)
        parameters.append(canonical_rust_type(type_name))
    return tuple(parameters)


def export_signatures(root: Path) -> dict[str, Signature]:
    """Parse exact signatures for unconditional exports in systemd_basic_rs."""

    inventory = load_inventory_gate(root)
    source_paths, _ = inventory.basic_artifact_sources(root)
    signatures: dict[str, Signature] = {}
    direct_patterns = (
        re.compile(
            r"#\[(?:unsafe\()?export_name\s*=\s*\"(rs_[A-Za-z0-9_]+)\"\)?\]\s*"
            r"(?:pub\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+"
            r"[A-Za-z_][A-Za-z0-9_]*\s*\((.*?)\)\s*"
            r"(?:->\s*([^\{]+?))?\s*\{",
            re.DOTALL,
        ),
        re.compile(
            r"#\[(?:unsafe\()?no_mangle\)?\]\s*"
            r"(?:pub\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+"
            r"(rs_[A-Za-z0-9_]+)\s*\((.*?)\)\s*"
            r"(?:->\s*([^\{]+?))?\s*\{",
            re.DOTALL,
        ),
    )

    def insert(name: str, signature: Signature) -> None:
        if name in signatures:
            raise ValueError(f"duplicate parsed systemd_basic_rs signature: {name}")
        signatures[name] = signature

    for source_path in source_paths:
        source = inventory.strip_rust_comments(
            source_path.read_text(encoding="utf-8", errors="ignore")
        )
        cfg_ranges = inventory.cfg_inline_module_ranges(source)
        for pattern in direct_patterns:
            for match in pattern.finditer(source):
                if inventory.offset_in_ranges(match.start(), cfg_ranges):
                    continue
                if re.search(
                    r"#\s*\[\s*cfg(?:_attr)?\s*\(",
                    inventory.item_metadata_before(source, match.start()),
                ):
                    continue
                name, raw_parameters, raw_result = match.groups()
                insert(
                    name,
                    (
                        rust_parameter_types(raw_parameters),
                        canonical_rust_type(raw_result or "()"),
                    ),
                )

        for macro_match in inventory.MACRO_INVOCATION_RE.finditer(source):
            macro, body = macro_match.groups()
            if inventory.offset_in_ranges(macro_match.start(), cfg_ranges):
                continue
            if re.search(
                r"#\s*\[\s*cfg(?:_attr)?\s*\(",
                inventory.item_metadata_before(source, macro_match.start()),
            ):
                continue
            names = sorted(set(inventory.RS_SYMBOL_RE.findall(body)))
            if macro == "ffi_forward":
                signature = re.match(
                    r'\s*"(rs_[A-Za-z0-9_]+)"\s*,\s*'
                    r"[A-Za-z_][A-Za-z0-9_]*\s*,\s*"
                    r"\((.*?)\)\s*->\s*([^,]+)\s*,",
                    body,
                    flags=re.DOTALL,
                )
                if not signature:
                    raise ValueError("cannot parse ffi_forward! export signature")
                name, raw_parameters, raw_result = signature.groups()
                insert(
                    name,
                    (
                        rust_parameter_types(raw_parameters),
                        canonical_rust_type(raw_result),
                    ),
                )
                continue
            if len(names) != 2:
                raise ValueError(
                    f"{macro}! must declare exactly two Rust ABI names, found {names}"
                )
            for name in names:
                if name.endswith("_to_string_alloc"):
                    signature = (("i32", "*mut*mutc_char"), "i32")
                elif name.endswith("_to_string") or name.endswith("_to_name"):
                    signature = (("i32",), "*constc_char")
                elif name.endswith("_from_string") or name.endswith("_from_name"):
                    signature = (("*constc_char",), "i32")
                else:
                    raise ValueError(f"cannot curate {macro}! signature for {name}")
                insert(name, signature)
    return signatures


def backed_signature_failures(
    root: Path,
    declared: dict[str, list[str]],
    exported: set[str],
    rust_signatures: dict[str, Signature],
) -> tuple[list[str], int]:
    failures: list[str] = []
    checked = 0
    for relative, names in declared.items():
        backed = set(names) & exported
        if not backed:
            continue
        source = (root / relative).read_text(encoding="utf-8", errors="ignore")
        c_signatures = declaration_signatures(source, backed)
        missing_c = sorted(backed - c_signatures.keys())
        missing_rust = sorted(backed - rust_signatures.keys())
        if missing_c:
            failures.append(
                f"{relative}: cannot parse backed C declarations: {', '.join(missing_c)}"
            )
        if missing_rust:
            failures.append(
                f"{relative}: cannot parse backed Rust exports: {', '.join(missing_rust)}"
            )
        for name in sorted(backed & c_signatures.keys() & rust_signatures.keys()):
            checked += 1
            if c_signatures[name] != rust_signatures[name]:
                failures.append(
                    f"{relative}: signature mismatch for {name}: "
                    f"C={c_signatures[name]!r} Rust={rust_signatures[name]!r}"
                )
    return failures, checked


def unit_def_authority_failures(
    root: Path, rust_signatures: dict[str, Signature]
) -> tuple[list[str], int, int]:
    """Pin the combined unit-def/cgroup mirror to current C signatures."""

    header_text = (root / UNIT_DEF_HEADER).read_text(encoding="utf-8")
    advertised = set(RS_DECL_RE.findall(header_text))
    backed = advertised & rust_signatures.keys()
    c_signatures = declaration_signatures(header_text, backed)
    failures: list[str] = []
    for name in sorted(backed):
        if c_signatures.get(name) != rust_signatures.get(name):
            failures.append(
                f"{UNIT_DEF_HEADER}: Rust/header signature mismatch for {name}: "
                f"C={c_signatures.get(name)!r} Rust={rust_signatures.get(name)!r}"
            )

    inventory = load_inventory_gate(root)
    authority = "\n".join(
        (root / path).read_text(encoding="utf-8") for path in UNIT_DEF_AUTHORITIES
    )
    authority_code = inventory.strip_c_non_code(authority)
    parsed = 0
    curated = 0
    direct_name_helpers = {"cg_mask_to_string", "cg_mask_from_string"}
    for name in sorted(backed):
        c_name = name.removeprefix("rs_")
        if c_name not in direct_name_helpers and (
            c_name.endswith("_to_string") or c_name.endswith("_from_string")
        ):
            suffix = (
                "_to_string" if c_name.endswith("_to_string") else "_from_string"
            )
            table = c_name.removesuffix(suffix)
            if not re.search(
                rf"\bDEFINE_STRING_TABLE_LOOKUP\(\s*{re.escape(table)}\s*,"
                r"\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                authority_code,
            ):
                failures.append(
                    f"{name}: current C authority lacks exact string-table generator"
                )
                continue
            expected = (
                (("i32",), "*constc_char")
                if suffix == "_to_string"
                else (("*constc_char",), "i32")
            )
            if c_signatures[name] != expected:
                failures.append(
                    f"{name}: curated C string-table signature drift: "
                    f"{c_signatures[name]!r}"
                )
            curated += 1
            continue

        direct = re.search(
            rf"^([A-Za-z_][A-Za-z0-9_ \t*]*?(?:\s|\*))"
            rf"{re.escape(c_name)}\(([^)]*)\)\s*\{{",
            authority_code,
            flags=re.MULTILINE,
        )
        if not direct:
            failures.append(f"{name}: current C authority definition is missing")
            continue
        raw_result, raw_parameters = direct.groups()

        def authority_type(raw: str, *, parameter: bool) -> str:
            normalized = re.sub(r"\b(?:FreezerState|UnitType)\b", "int", raw)
            # `CGroupMask` is a 32-bit controller-bit enum. The Rust C ABI
            # intentionally exposes its bit representation as `u32`, matching
            # the registered C comparison prototypes and avoiding an enum
            # layout claim across compilers.
            normalized = re.sub(r"\bCGroupMask\b", "unsigned int", normalized)
            return canonical_c_type(normalized, parameter=parameter)

        try:
            parameters: tuple[str, ...] = ()
            if raw_parameters.strip() and raw_parameters.strip() != "void":
                parameters = tuple(
                    authority_type(parameter, parameter=True)
                    for parameter in raw_parameters.split(",")
                )
            current_signature = (
                parameters,
                authority_type(raw_result, parameter=False),
            )
        except ValueError as error:
            failures.append(f"{name}: cannot parse current C authority: {error}")
            continue
        if current_signature != c_signatures[name]:
            failures.append(
                f"{name}: current C authority signature mismatch: "
                f"header={c_signatures[name]!r} C={current_signature!r}"
            )
        parsed += 1

    if len(backed) != 59:
        failures.append(
            f"{UNIT_DEF_HEADER}: expected 59 artifact-backed reviewed declarations, "
            f"found {len(backed)}"
        )
    return failures, parsed, curated


def shared_str_tables_authority_failures(
    root: Path, rust_signatures: dict[str, Signature]
) -> tuple[list[str], int]:
    """Pin the newly backed shared helper batch to explicit C authorities."""

    header_text = (root / SHARED_STR_TABLES_HEADER).read_text(encoding="utf-8")
    advertised = set(RS_DECL_RE.findall(header_text))
    backed = advertised & rust_signatures.keys()
    c_signatures = declaration_signatures(header_text, backed)
    failures: list[str] = []
    for name in sorted(backed):
        if c_signatures.get(name) != rust_signatures.get(name):
            failures.append(
                f"{SHARED_STR_TABLES_HEADER}: Rust/header signature mismatch for {name}: "
                f"C={c_signatures.get(name)!r} Rust={rust_signatures.get(name)!r}"
            )

    authorities = {
        "condition": (root / "src/shared/condition.c").read_text(),
        "resolve": (root / "src/shared/resolve-util.c").read_text(),
        "netif": (root / "src/shared/netif-util.c").read_text(),
        "compress": (root / "src/basic/compress.c").read_text(),
        "socket": (root / "src/basic/socket-util.c").read_text(),
        "output": (root / "src/shared/output-mode.c").read_text(),
        "json": (root / "src/systemd/sd-json.h").read_text(),
    }
    required_authority = {
        "rs_condition_type_to_string": (
            "condition",
            r"\bconst char\*\s+condition_type_to_string\(ConditionType\s+t\)",
        ),
        "rs_condition_type_from_string": (
            "condition",
            r"\bConditionType\s+condition_type_from_string\(const char\s*\*s\)",
        ),
        "rs_assert_type_to_string": (
            "condition",
            r"\bconst char\*\s+assert_type_to_string\(ConditionType\s+t\)",
        ),
        "rs_assert_type_from_string": (
            "condition",
            r"\bConditionType\s+assert_type_from_string\(const char\s*\*s\)",
        ),
        "rs_dns_server_address_valid": (
            "resolve",
            r"\bbool\s+dns_server_address_valid\("
            r"int\s+family,\s*const union in_addr_union\s*\*sa\)",
        ),
        "rs_netif_has_carrier": (
            "netif",
            r"\bbool\s+netif_has_carrier\(uint8_t\s+operstate,\s*unsigned\s+flags\)",
        ),
        "rs_compression_lowercase_to_string": (
            "compress",
            r"\bDEFINE_STRING_TABLE_LOOKUP\(\s*compression\s*,\s*Compression\s*\)",
        ),
        "rs_compression_lowercase_from_string": (
            "compress",
            r"\bDEFINE_STRING_TABLE_LOOKUP\(\s*compression\s*,\s*Compression\s*\)",
        ),
        "rs_socket_address_type_to_string": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP\(\s*socket_address_type\s*,\s*int\s*\)",
        ),
        "rs_socket_address_type_from_string": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP\(\s*socket_address_type\s*,\s*int\s*\)",
        ),
        "rs_netlink_family_to_string_alloc": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\("
            r"\s*netlink_family\s*,\s*int\s*,\s*INT_MAX\s*\)",
        ),
        "rs_netlink_family_from_string": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\("
            r"\s*netlink_family\s*,\s*int\s*,\s*INT_MAX\s*\)",
        ),
        "rs_ip_tos_to_string_alloc": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\("
            r"\s*ip_tos\s*,\s*int\s*,\s*0xff\s*\)",
        ),
        "rs_ip_tos_from_string": (
            "socket",
            r"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\("
            r"\s*ip_tos\s*,\s*int\s*,\s*0xff\s*\)",
        ),
        "rs_output_mode_to_json_format_flags": (
            "output",
            r"\bsd_json_format_flags_t\s+output_mode_to_json_format_flags\("
            r"OutputMode\s+m\)",
        ),
    }
    expected = set(required_authority)
    if backed != expected:
        failures.append(
            f"{SHARED_STR_TABLES_HEADER}: expected exact backed authority set "
            f"missing={sorted(expected - backed)} extra={sorted(backed - expected)}"
        )
    for name, (source, pattern) in required_authority.items():
        if not re.search(pattern, authorities[source]):
            failures.append(f"{name}: current C authority marker is missing or changed")
    if not re.search(
        r"typedef enum _SD_ENUM_TYPE_S64\(sd_json_format_flags_t\)",
        authorities["json"],
    ):
        failures.append(
            "output_mode_to_json_format_flags authority is not the required signed 64-bit enum"
        )
    expected_output = (("i32",), "i64")
    if c_signatures.get("rs_output_mode_to_json_format_flags") != expected_output:
        failures.append(
            "rs_output_mode_to_json_format_flags must expose the C authority's "
            f"signed 64-bit return ABI, found "
            f"{c_signatures.get('rs_output_mode_to_json_format_flags')!r}"
        )
    return failures, len(backed)


def unbacked_inventory(
    declared: dict[str, list[str]], exported: set[str]
) -> dict[str, list[str]]:
    return {
        source: sorted(set(names) - exported)
        for source, names in declared.items()
        if set(names) - exported
    }


def load_baseline(path: Path) -> dict[str, list[str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != 1 or not isinstance(
        payload.get("unbacked_by_source"), dict
    ):
        raise ValueError(f"unsupported registered-test ABI baseline format: {path}")
    result: dict[str, list[str]] = {}
    for source, names in payload["unbacked_by_source"].items():
        if (
            not isinstance(source, str)
            or not isinstance(names, list)
            or not all(isinstance(name, str) and RS_DECL_RE.fullmatch(name + "(") for name in names)
        ):
            raise ValueError(f"invalid registered-test ABI baseline entry: {source!r}")
        if names != sorted(set(names)):
            raise ValueError(f"registered-test ABI baseline must be sorted and unique: {source}")
        result[source] = names
    return result


def write_baseline(path: Path, unbacked: dict[str, list[str]]) -> None:
    payload = {
        "version": 1,
        "unbacked_by_source": unbacked,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline
    try:
        parser_self_check()
        declared, c_definitions = manual_declarations(root)
        exported, export_failures = explicit_exports(root)
        rust_signatures = export_signatures(root)
        signature_failures, checked_signatures = backed_signature_failures(
            root, declared, exported, rust_signatures
        )
        (
            unit_def_failures,
            unit_def_authority_parsed,
            unit_def_authority_curated,
        ) = unit_def_authority_failures(root, rust_signatures)
        (
            shared_str_tables_failures,
            shared_str_tables_authority_curated,
        ) = shared_str_tables_authority_failures(root, rust_signatures)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    unbacked = unbacked_inventory(declared, exported)

    if args.write_baseline:
        if (
            export_failures
            or signature_failures
            or unit_def_failures
            or shared_str_tables_failures
        ):
            for failure in [
                *export_failures,
                *signature_failures,
                *unit_def_failures,
                *shared_str_tables_failures,
            ]:
                print(failure, file=sys.stderr)
            return 1
        write_baseline(baseline_path, unbacked)
        print(f"wrote registered-test Rust FFI baseline: {baseline_path}")
        print(
            f"registered_sources={len(registered_sources(root))} "
            f"manual_sources={len(declared)} "
            f"manual_symbols={len(set().union(*(set(v) for v in declared.values())))} "
            f"same_source_c_helpers={len(set().union(*(set(v) for v in c_definitions.values())))} "
            f"unbacked_symbols={len(set().union(*(set(v) for v in unbacked.values())))}"
        )
        return 0

    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1

    failures = [
        *export_failures,
        *signature_failures,
        *unit_def_failures,
        *shared_str_tables_failures,
    ]
    for source, names in unbacked.items():
        new_symbols = sorted(set(names) - set(baseline.get(source, ())))
        if new_symbols:
            failures.append(
                f"{source}: newly manual/unbacked Rust test ABI: {', '.join(new_symbols)}"
            )
    for source, names in baseline.items():
        stale = sorted(set(names) - set(unbacked.get(source, ())))
        if stale:
            failures.append(
                f"{source}: baseline is stale; remove exported/removed symbols: "
                f"{', '.join(stale)}"
            )

    if failures:
        print("registered-test Rust FFI gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    declared_symbols = set().union(*(set(names) for names in declared.values()))
    unbacked_symbols = set().union(*(set(names) for names in unbacked.values()))
    print(
        "registered-test Rust FFI gate OK: "
        f"registered_sources={len(registered_sources(root))} "
        f"manual_sources={len(declared)} manual_symbols={len(declared_symbols)} "
        f"same_source_c_helpers={len(set().union(*(set(v) for v in c_definitions.values())))} "
        f"unbacked_sources={len(unbacked)} unbacked_symbols={len(unbacked_symbols)} "
        f"backed_signatures={checked_signatures} artifact=systemd_basic_rs "
        f"unit-def-signatures=59 C-authority-parsed={unit_def_authority_parsed} "
        f"C-authority-curated={unit_def_authority_curated} "
        f"shared-authority-curated={shared_str_tables_authority_curated} "
        "configuration=unconditional-only link_parity=unclaimed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
