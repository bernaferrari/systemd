#!/usr/bin/env python3
"""Fail closed if the shared Rust ConditionType declarations drift from C.

This deliberately performs no build or execution: current C condition/Assert
tables are compared with the Rust enum's declared order and name tables.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
C_SOURCE = ROOT / "src/shared/condition.c"
C_HEADER = ROOT / "src/shared/condition.h"
RUST_SOURCE = ROOT / "src/shared/rust/condition.rs"
BASIC_RUST_SOURCE = ROOT / "src/basic/rust/shared_facades/policy.rs"


def block(text: str, start: int, open_: str, close: str) -> str:
    depth = 0
    for end in range(start, len(text)):
        depth += text[end] == open_
        depth -= text[end] == close
        if depth == 0:
            return text[start : end + 1]
    raise ValueError("unterminated declaration")


def named_block(text: str, pattern: str, open_: str, close: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"missing declaration matching {pattern!r}")
    return block(text, text.index(open_, match.start()), open_, close)


def c_enum_order(text: str) -> list[str]:
    contents = named_block(text, r"\btypedef\s+enum\s+ConditionType\s*\{", "{", "}")
    return [
        name
        for name in re.findall(r"^\s*(CONDITION_[A-Z_]+),", contents, re.MULTILINE)
        if not name.startswith("_CONDITION_")
    ]


def c_table(text: str, table: str, order: list[str]) -> list[str]:
    contents = named_block(text, rf"\b{re.escape(table)}\s*\[[^]]*\]\s*=\s*\{{", "{", "}")
    entries = dict(re.findall(r'\[(CONDITION_[A-Z_]+)\]\s*=\s*"([^"]+)"', contents))
    if set(entries) != set(order):
        raise ValueError(f"{table} designators differ from ConditionType enum")
    return [entries[name] for name in order]


def rust_enum(text: str) -> list[str]:
    contents = named_block(text, r"\benum\s+ConditionType\s*\{", "{", "}")
    return re.findall(r"^\s{4}([A-Z][A-Za-z0-9]+),$", contents, re.MULTILINE)


def rust_table(text: str, table: str) -> tuple[list[str], list[str]]:
    match = re.search(
        rf"\bstatic\s+{re.escape(table)}\s*:\s*&\[\(&ConditionType,\s*&str\)\]\s*=\s*&\[",
        text,
    )
    if not match:
        raise ValueError(f"missing Rust table {table}")
    contents = block(text, text.index("[", match.end() - 1), "[", "]")
    entries = re.findall(
        r"&ConditionType::([A-Z][A-Za-z0-9]+)\s*,\s*\"([^\"]+)\"",
        contents,
    )
    return [variant for variant, _ in entries], [name for _, name in entries]


def compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def main() -> int:
    c_source = C_SOURCE.read_text()
    c_header = C_HEADER.read_text()
    c_order = c_enum_order(c_header)
    rust_source = RUST_SOURCE.read_text()
    basic_rust_source = BASIC_RUST_SOURCE.read_text()
    variants = rust_enum(rust_source)
    condition_variants, condition_names = rust_table(rust_source, "CONDITION_TYPE_NAMES")
    assert_variants, assert_names = rust_table(rust_source, "ASSERT_TYPE_NAMES")
    c_condition_names = c_table(c_source, "_condition_type_table", c_order)
    c_assert_names = c_table(c_source, "_assert_type_table", c_order)

    errors = []
    if variants != condition_variants or variants != assert_variants:
        errors.append("Rust ConditionType declaration order differs from one of its name tables")
    if c_condition_names != condition_names:
        errors.append("Rust ConditionType names differ from current C _condition_type_table")
    if c_assert_names != assert_names:
        errors.append("Rust AssertType names differ from current C _assert_type_table")
    if len(variants) != 37:
        errors.append(f"Rust ConditionType count is {len(variants)}, expected current C count 37")

    c_takes_path = named_block(
        c_header,
        r"\bstatic\s+inline\s+bool\s+condition_takes_path\s*\(",
        "{",
        "}",
    )
    c_path_names = set(re.findall(r"\bCONDITION_[A-Z_]+\b", c_takes_path))
    path_start = c_order.index("CONDITION_PATH_EXISTS")
    path_end = c_order.index("CONDITION_FILE_IS_EXECUTABLE")
    expected_path_names = {
        "CONDITION_NEEDS_UPDATE",
        *c_order[path_start : path_end + 1],
    }
    if c_path_names != expected_path_names:
        errors.append("current C condition_takes_path is no longer needs-update plus the path range")

    rust_discriminants = {
        name: int(value)
        for name, value in re.findall(
            r"^const\s+(CONDITION_[A-Z_]+):\s+i32\s*=\s*(\d+);$",
            basic_rust_source,
            re.MULTILINE,
        )
    }
    expected_discriminants = {
        name: c_order.index(name)
        for name in (
            "CONDITION_NEEDS_UPDATE",
            "CONDITION_PATH_EXISTS",
            "CONDITION_FILE_IS_EXECUTABLE",
        )
    }
    if any(rust_discriminants.get(name) != value for name, value in expected_discriminants.items()):
        errors.append("basic Rust condition_takes_path discriminants differ from current C enum order")

    rust_takes_path = re.sub(
        r"\s+",
        "",
        named_block(
            basic_rust_source,
            r"\bpub\s+fn\s+condition_takes_path\s*\(",
            "{",
            "}",
        ),
    )
    if (
        "t==CONDITION_NEEDS_UPDATE" not in rust_takes_path
        or "(CONDITION_PATH_EXISTS..=CONDITION_FILE_IS_EXECUTABLE).contains(&t)"
        not in rust_takes_path
        or "pubextern\"C\"fnrs_condition_takes_path" not in re.sub(r"\s+", "", basic_rust_source)
    ):
        errors.append("basic Rust condition_takes_path/export no longer expresses the reviewed C predicate")

    c_machine_tag = compact(
        named_block(c_source, r"\bcondition_test_machine_tag\s*\(", "{", "}")
    )
    c_fraction = compact(
        named_block(c_source, r"\bcondition_test_fraction\s*\(", "{", "}")
    )
    rust_machine_tag = compact(
        named_block(rust_source, r"\bfn\s+test_machine_tag\s*\(", "{", "}")
    )
    rust_machine_info_path = compact(
        named_block(rust_source, r"\bfn\s+etc_machine_info_path\s*\(", "{", "}")
    )
    rust_machine_match = compact(
        named_block(rust_source, r"\bfn\s+machine_tag_fnmatch\s*\(", "{", "}")
    )
    rust_fraction = compact(
        named_block(rust_source, r"\bfn\s+test_fraction\s*\(", "{", "}")
    )
    rust_fraction_core = compact(
        named_block(
            rust_source,
            r"\bfn\s+condition_fraction_matches_parsed\s*\(",
            "{",
            "}",
        )
    )

    if not all(
        pin in c_machine_tag
        for pin in (
            "parse_env_file(/*f=*/NULL,etc_machine_info(),\"TAGS\",&tags)",
            "machine_tags_from_string(tags,/*graceful=*/true,&l)",
            "fnmatch(c->parameter,*i,/*flags=*/0)==0",
        )
    ):
        errors.append("current C ConditionMachineTag authority changed; review Rust semantics")
    if not all(
        pin in c_fraction
        for pin in (
            "extract_first_word(&p,&first,/*separators=*/NULL,/*flags=*/0)",
            "extract_first_word(&p,&second,/*separators=*/NULL,/*flags=*/0)",
            "parse_permyriad(percent)",
            "strjoin(\"systemd-fraction-\",strempty(tag))",
            "sd_id128_get_machine(&mid)",
            "UINT32_SCALE_FROM_PERMYRIAD(permyriad)",
        )
    ):
        errors.append("current C ConditionFraction authority changed; review Rust semantics")

    if not all(
        pin in rust_machine_tag
        for pin in (
            "fs::read(etc_machine_info_path())",
            "machine_info_tags(&contents)",
            "condition_machine_tag_matches(&self.parameter,tags.as_deref(),)",
        )
    ):
        errors.append("Rust ConditionMachineTag no longer uses the reviewed safe path/parser core")
    if not all(
        pin in rust_machine_info_path
        for pin in (
            "OnceLock<PathBuf>",
            "ifunsafe{libc::getauxval(libc::AT_SECURE)}==0",
            "std::env::var_os(\"SYSTEMD_ETC_MACHINE_INFO\")",
            "PathBuf::from(\"/etc/machine-info\")",
        )
    ):
        errors.append("Rust machine-info path no longer mirrors secure cached C override semantics")
    if "libc::fnmatch(pattern.as_ptr(),tag.as_ptr(),0)==0" not in rust_machine_match:
        errors.append("Rust ConditionMachineTag no longer uses exact libc fnmatch flags=0")
    if not all(
        pin in rust_fraction
        for pin in (
            "parse_condition_fraction(&self.parameter)",
            "fraction.permyriad==0",
            "fraction.permyriad>=10_000",
            "sd_id128_get_machine()",
        )
    ) or not all(
        pin in rust_fraction_core
        for pin in (
            "hmac_sha256(machine_id,fraction.hash_text.as_bytes())",
            "u32::from_le_bytes",
            "uint32_scale_from_permyriad(fraction.permyriad)",
        )
    ):
        errors.append("Rust ConditionFraction no longer expresses reviewed boundary/HMAC semantics")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(
        f"condition type parity: entries={len(variants)} "
        f"path_predicates={len(c_path_names)} condition/assert=current-C "
        "fraction/machine-tag=reviewed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
