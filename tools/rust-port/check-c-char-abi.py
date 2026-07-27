#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Ratchet hard-coded ``i8`` out of Rust C ABI signatures.

Rust's ``i8`` is not a portable spelling of C ``char``.  On targets where
``libc::c_char`` is unsigned, using ``i8`` in an extern-C signature can change
ABI attributes or make otherwise-correct C-string calls fail to compile.

This gate inventories literal ``i8`` in direct extern-C function signatures,
extern-block declarations, and extern-C function-pointer types.  The baseline
is migration debt, not an allow-list: new entries and stale resolved entries
both fail so every reduction is recorded deliberately.

The gate does not guess whether a remaining ``i8`` meant C ``char`` or
``int8_t``.  A genuine signed 8-bit ABI remains visible until it is expressed
with an explicit signed C type alias and reviewed separately.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


EXTERN_FN_RE = re.compile(r'\bextern\s*"(?:C|C-unwind)"\s+fn\b')
EXTERN_BLOCK_RE = re.compile(r'\bextern\s*"(?:C|C-unwind)"\s*\{')
BLOCK_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
I8_RE = re.compile(r"\bi8\b")
C_CHAR_RE = re.compile(r"\b(?:libc::|std::ffi::)?c_char\b")
I8_POINTER_RE = re.compile(r"\*\s*(?:const|mut)\s+i8\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject growth or unrecorded shrinkage in hard-coded i8 C ABI debt."
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/c-char-abi-baseline.json",
        help="baseline path relative to the repository root",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="replace the baseline with the current inventory",
    )
    return parser.parse_args()


def mask_rust_non_code(text: str) -> str:
    """Mask comments and non-ABI literals while preserving offsets/newlines."""

    result = list(text)
    state = "code"
    quote_start = 0
    block_depth = 0
    raw_terminator = ""
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                state = "block-comment"
                block_depth = 1
                index += 2
                continue
            if char == "/" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            raw = re.match(r"(?:b|c)?r(#{0,255})\"", text[index:])
            if raw:
                raw_terminator = '"' + raw.group(1)
                for position in range(index, index + raw.end()):
                    result[position] = " "
                state = "raw-string"
                index += raw.end()
                continue
            if char == '"':
                quote_start = index
                state = "string"
            elif char == "'" and (
                next_char == "\\"
                or (index + 2 < len(text) and text[index + 2] == "'")
            ):
                result[index] = " "
                state = "character"

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
                if state == "string":
                    literal = text[quote_start : index + 1]
                    if literal not in {'"C"', '"C-unwind"'}:
                        for position in range(quote_start, index + 1):
                            if result[position] != "\n":
                                result[position] = " "
                else:
                    result[index] = " "
                state = "code"
            elif state == "character" and char != "\n":
                result[index] = " "

        elif state == "raw-string":
            if text.startswith(raw_terminator, index):
                for position in range(index, index + len(raw_terminator)):
                    result[position] = " "
                index += len(raw_terminator)
                state = "code"
                continue
            if char != "\n":
                result[index] = " "
        index += 1

    return "".join(result)


def balanced_end(text: str, start: int, terminal: str) -> int:
    """Return the index after a top-level terminal, or raise on malformed input."""

    depths = {"(": 0, "[": 0, "<": 0}
    closing = {")": "(", "]": "[", ">": "<"}
    index = start
    while index < len(text):
        char = text[index]
        if char in depths:
            depths[char] += 1
        elif char in closing and depths[closing[char]] > 0:
            depths[closing[char]] -= 1
        elif char == terminal and not any(depths.values()):
            return index + 1
        elif terminal == "{" and char == ";" and not any(depths.values()):
            return index + 1
        index += 1
    raise ValueError(f"unterminated Rust signature starting at byte {start}")


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unterminated extern block starting at byte {opening}")


def normalize_signature(signature: str) -> str:
    signature = signature.rstrip("{;").strip()
    return re.sub(r"\s+", " ", signature)


def direct_signatures(code: str) -> list[tuple[int, str]]:
    signatures: list[tuple[int, str]] = []
    for match in EXTERN_FN_RE.finditer(code):
        tail = code[match.end() :]
        named = re.match(r"\s+(?:r#)?(?:[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*)", tail)
        end = (
            balanced_end(code, match.start(), "{")
            if named
            else function_type_end(code, match.start())
        )
        signatures.append((match.start(), normalize_signature(code[match.start() : end])))
    return signatures


def function_type_end(text: str, start: int) -> int:
    """Find the end of an anonymous extern-C function-pointer type."""

    depths = {"(": 0, "[": 0, "<": 0}
    closing = {")": "(", "]": "[", ">": "<"}
    saw_parameters = False
    index = start
    while index < len(text):
        char = text[index]
        if char in depths:
            depths[char] += 1
            if char == "(":
                saw_parameters = True
        elif char in closing:
            opener = closing[char]
            if depths[opener] > 0:
                depths[opener] -= 1
            elif (
                saw_parameters
                and not any(depths.values())
                and char in {")", ">"}
                and not (char == ">" and index > 0 and text[index - 1] == "-")
            ):
                return index
        elif saw_parameters and not any(depths.values()) and char in {",", ";", "=", "{"}:
            return index
        index += 1
    raise ValueError(f"unterminated extern-C function-pointer type at byte {start}")


def extern_block_signatures(code: str) -> list[tuple[int, str]]:
    signatures: list[tuple[int, str]] = []
    for block in EXTERN_BLOCK_RE.finditer(code):
        opening = code.find("{", block.start(), block.end())
        closing = matching_brace(code, opening)
        body = code[opening + 1 : closing]
        for function in BLOCK_FN_RE.finditer(body):
            start = opening + 1 + function.start()
            end = balanced_end(code, start, ";")
            signatures.append(
                (
                    start,
                    "extern-block " + normalize_signature(code[start:end]),
                )
            )
    return signatures


def inventory(root: Path) -> tuple[dict[str, list[str]], int]:
    debt: dict[str, list[str]] = {}
    symbolic = 0
    for path in sorted((root / "src").rglob("*.rs")):
        source = path.read_text(encoding="utf-8", errors="ignore")
        code = mask_rust_non_code(source)
        signatures = [*direct_signatures(code), *extern_block_signatures(code)]
        entries: list[str] = []
        for offset, signature in signatures:
            if C_CHAR_RE.search(signature):
                symbolic += 1
            if not I8_RE.search(signature):
                continue
            line = source.count("\n", 0, offset) + 1
            entries.append(f"{line}: {signature}")
        if entries:
            debt[path.relative_to(root).as_posix()] = entries
    return debt, symbolic


def pointer_inventory(root: Path) -> dict[str, list[str]]:
    """Inventory hard-coded i8 pointer spellings outside comments/literals.

    Arrays are deliberately not included: ``[i8; N]`` is also the natural
    spelling for non-ABI signed lookup data. Arrays in an extern-C function
    signature remain covered by :func:`inventory`; reviewed repr(C) layouts
    are checked by their subsystem-specific ABI gates.
    """

    debt: dict[str, list[str]] = {}
    for path in sorted((root / "src").rglob("*.rs")):
        source = path.read_text(encoding="utf-8", errors="ignore")
        code = mask_rust_non_code(source)
        entries: list[str] = []
        for number, line in enumerate(code.splitlines(), 1):
            count = len(I8_POINTER_RE.findall(line))
            if count == 0:
                continue
            snippet = re.sub(r"\s+", " ", line.strip())
            entries.extend(f"{number}: {snippet}" for _ in range(count))
        if entries:
            debt[path.relative_to(root).as_posix()] = entries
    return debt


def stable_entries(entries: dict[str, list[str]]) -> dict[str, list[str]]:
    """Remove diagnostic line prefixes before comparing baseline identity."""

    stable: dict[str, list[str]] = {}
    for path, values in entries.items():
        signatures = [re.sub(r"^\d+:\s*", "", entry) for entry in values]
        counts = Counter(signatures)
        encoded: list[str] = []
        for signature, count in sorted(counts.items()):
            if count == 1:
                encoded.append(signature)
            else:
                encoded.extend(
                    f"{signature} [occurrence {index}/{count}]"
                    for index in range(1, count + 1)
                )
        stable[path] = encoded
    return stable


def parser_self_check() -> None:
    sample = r'''
        // extern "C" fn commented(p: *const i8);
        const TEXT: &str = "extern \"C\" fn stringed(p: *const i8);";
        const RAW: &str = r#"extern "C" fn raw_stringed(p: *const i8);"#;
        /* outer /* extern "C" fn nested(p: *const i8); */ comment */
        type Lifetime<'a> = &'a ();
        pub unsafe extern "C" fn direct(p: *const i8) -> *mut i8 { p.cast_mut() }
        type Unwind = unsafe extern "C-unwind" fn(value: i8) -> i8;
        type Callback = unsafe extern "C" fn(value: i8) -> i8;
        unsafe extern "C" {
            fn declared(name: *const i8) -> i32;
            fn portable(name: *const libc::c_char) -> i32;
        }
    '''
    found, symbolic = inventory_from_source(sample)
    if len(found) != 4 or symbolic != 1:
        raise ValueError(
            f"C-char ABI parser self-check failed: debt={found!r} symbolic={symbolic}"
        )


def inventory_from_source(source: str) -> tuple[list[str], int]:
    code = mask_rust_non_code(source)
    signatures = [*direct_signatures(code), *extern_block_signatures(code)]
    debt = [signature for _, signature in signatures if I8_RE.search(signature)]
    symbolic = sum(bool(C_CHAR_RE.search(signature)) for _, signature in signatures)
    return debt, symbolic


def load_baseline(path: Path) -> dict[str, dict[str, list[str]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        payload.get("version") != 2
        or not isinstance(payload.get("hardcoded_i8_abi"), dict)
        or not isinstance(payload.get("hardcoded_i8_pointer_types"), dict)
    ):
        raise ValueError(f"unsupported C-char ABI baseline format: {path}")
    return {
        category: validated_baseline_entries(payload[category], category)
        for category in ("hardcoded_i8_abi", "hardcoded_i8_pointer_types")
    }


def validated_baseline_entries(
    raw: dict[object, object], category: str
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for source, entries in raw.items():
        if not isinstance(source, str) or not isinstance(entries, list):
            raise ValueError(f"invalid {category} baseline entry: {source!r}")
        if not all(isinstance(entry, str) for entry in entries):
            raise ValueError(f"invalid {category} entries for {source}")
        result[source] = sorted(entries)
    return result


def write_baseline(
    path: Path,
    abi_debt: dict[str, list[str]],
    pointer_debt: dict[str, list[str]],
) -> None:
    payload = {
        "version": 2,
        "hardcoded_i8_abi": stable_entries(abi_debt),
        "hardcoded_i8_pointer_types": stable_entries(pointer_debt),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def flatten(entries: dict[str, list[str]]) -> set[tuple[str, str]]:
    return {
        (source, signature)
        for source, signatures in entries.items()
        for signature in signatures
    }


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline
    try:
        parser_self_check()
        abi_with_lines, symbolic = inventory(root)
        pointer_with_lines = pointer_inventory(root)
        abi_debt = stable_entries(abi_with_lines)
        pointer_debt = stable_entries(pointer_with_lines)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    if args.write_baseline:
        write_baseline(baseline_path, abi_with_lines, pointer_with_lines)
        print(f"wrote C-char ABI baseline: {baseline_path}")
        print(
            f"hardcoded_i8_signatures={len(flatten(abi_debt))} "
            f"abi_files={len(abi_debt)} "
            f"hardcoded_i8_pointer_types={len(flatten(pointer_debt))} "
            f"pointer_files={len(pointer_debt)} "
            f"symbolic_c_char_signatures={symbolic}"
        )
        return 0

    try:
        baseline = load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1

    current = {
        "C ABI signatures": flatten(abi_debt),
        "pointer types": flatten(pointer_debt),
    }
    recorded = {
        "C ABI signatures": flatten(baseline["hardcoded_i8_abi"]),
        "pointer types": flatten(baseline["hardcoded_i8_pointer_types"]),
    }
    failed = False
    for category in current:
        new = sorted(current[category] - recorded[category])
        stale = sorted(recorded[category] - current[category])
        if new:
            failed = True
            print(f"new hard-coded i8 {category}:", file=sys.stderr)
            for source, signature in new:
                print(f"- {source}: {signature}", file=sys.stderr)
        if stale:
            failed = True
            print(
                f"resolved/moved C-char {category} debt remains in baseline; "
                "regenerate it deliberately:",
                file=sys.stderr,
            )
            for source, signature in stale:
                print(f"- {source}: {signature}", file=sys.stderr)
    if failed:
        return 1

    print(
        "C-char ABI gate OK: "
        f"hardcoded_i8_signatures={len(current['C ABI signatures'])} "
        f"abi_files={len(abi_debt)} "
        f"hardcoded_i8_pointer_types={len(current['pointer types'])} "
        f"pointer_files={len(pointer_debt)} "
        f"symbolic_c_char_signatures={symbolic}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
