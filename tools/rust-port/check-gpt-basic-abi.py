#!/usr/bin/env python3
"""Statically verify the dedicated basic Rust GPT C ABI.

The shared GPT model deliberately owns the generated partition-type table. This
small basic module instead backs the three existing C shadow tests which include
``src/basic/rust/gpt_util.h`` and link the basic Rust static library.  No build
or test execution is required for this source-level inventory check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/basic/rust/gpt_util.h"
SHARED_HEADER = ROOT / "src/shared/rust/gpt_util.h"
SOURCE = ROOT / "src/basic/rust/gpt_util.rs"
CRATE_ROOT = ROOT / "src/basic/rust/lib.rs"
BASIC_MESON = ROOT / "src/basic/meson.build"
TEST_MESON = ROOT / "tests-extra/meson.build"

EXPECTED = {
    "rs_gpt_header_has_signature": ("bool", ("*const u8",)),
    "rs_partition_designator_is_versioned": ("bool", ("c_int",)),
    "rs_partition_verity_hash_of": ("c_int", ("c_int",)),
    "rs_partition_verity_sig_of": ("c_int", ("c_int",)),
    "rs_partition_verity_hash_to_data": ("c_int", ("c_int",)),
    "rs_partition_verity_sig_to_data": ("c_int", ("c_int",)),
    "rs_partition_verity_to_data": ("c_int", ("c_int",)),
    "rs_partition_mountpoint_to_string": ("*const c_char", ("c_int",)),
    "rs_parse_vlanid": ("c_int", ("*const c_char", "*mut u16")),
    "rs_gpt_partition_label_valid": ("c_int", ("*const c_char",)),
    "rs_partition_designator_is_verity_hash": ("bool", ("c_int",)),
    "rs_partition_designator_is_verity_sig": ("bool", ("c_int",)),
    "rs_partition_designator_is_verity": ("bool", ("c_int",)),
    "rs_gpt_partition_type_knows_read_only": ("bool", ("GptPartitionType",)),
    "rs_gpt_partition_type_knows_growfs": ("bool", ("GptPartitionType",)),
    "rs_gpt_partition_type_knows_no_auto": ("bool", ("GptPartitionType",)),
    "rs_gpt_partition_type_has_filesystem": ("bool", ("GptPartitionType",)),
}
SHARED_EXPECTED = {
    name: EXPECTED[name]
    for name in (
        "rs_partition_designator_is_versioned",
        "rs_partition_verity_hash_of",
        "rs_partition_verity_sig_of",
        "rs_partition_verity_hash_to_data",
        "rs_partition_verity_sig_to_data",
        "rs_partition_verity_to_data",
        "rs_partition_mountpoint_to_string",
        "rs_parse_vlanid",
    )
}

HEADER_TYPES = {
    "bool": "bool",
    "int": "c_int",
    "const char *": "*const c_char",
    "const uint8_t *": "*const u8",
    "uint16_t *": "*mut u16",
    "unsigned short *": "*mut u16",
    "GptPartitionType": "GptPartitionType",
}

TESTS = (
    "test-gpt-util-rust.c",
    "test-misc-rust3.c",
    "test-inline-helpers-rust.c",
    "test-gpt-unit-install-rust.c",
)


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def header_inventory(text: str) -> tuple[dict[str, tuple[str, tuple[str, ...]]], list[str]]:
    def argument_type(argument: str) -> str:
        argument = argument.strip()
        for c_type in sorted(HEADER_TYPES, key=len, reverse=True):
            suffix = argument.removeprefix(c_type)
            if suffix != argument and re.fullmatch(r"\s*[A-Za-z_][A-Za-z0-9_]*", suffix):
                return HEADER_TYPES[c_type]
        raise ValueError(f"unsupported C argument declaration: {argument!r}")

    inventory: dict[str, tuple[str, tuple[str, ...]]] = {}
    names: list[str] = []
    pattern = re.compile(
        r"^(bool|int|const char \*)\s*(rs_[A-Za-z0-9_]+)\(([^)]*)\);$",
        re.MULTILINE,
    )
    for return_type, name, raw_args in pattern.findall(text):
        names.append(name)
        args = tuple(
            argument_type(argument)
            for argument in raw_args.split(",")
            if argument.strip() and argument.strip() != "void"
        )
        inventory[name] = (HEADER_TYPES[return_type], args)
    return inventory, names


def source_inventory(text: str) -> tuple[dict[str, tuple[str, tuple[str, ...]]], list[str]]:
    pattern = re.compile(
        r"#\[unsafe\(no_mangle\)\]\s+pub\s+(?:unsafe\s+)?extern \"C\" fn "
        r"(rs_[A-Za-z0-9_]+)\(([^)]*)\)\s*->\s*([^\n{]+?)\s*\{",
        re.MULTILINE,
    )
    inventory: dict[str, tuple[str, tuple[str, ...]]] = {}
    names: list[str] = []
    for name, raw_args, return_type in pattern.findall(text):
        names.append(name)
        args = tuple(argument.rsplit(":", 1)[1].strip() for argument in raw_args.split(",") if argument)
        inventory[name] = (return_type, args)
    return inventory, names


def gpt_partition_type_layout_is_exact(source: str, shared_header: str) -> bool:
    """Keep the Rust by-value adapter tied to C's complete struct ABI.

    The four property exports need only ``designator``, but C passes the whole
    ``GptPartitionType`` by value.  Checking every field here prevents a
    superficially working adapter from silently drifting to an incompatible
    calling convention.
    """

    rust_layout = re.compile(
        r"#\[repr\(C\)\]\s+(?:#\[[^\]]+\]\s+)*"
        r"pub struct GptPartitionType \{\s*"
        r"pub uuid: \[u8; 16\],\s*"
        r"pub name: \*const c_char,\s*"
        r"pub arch: c_int,\s*"
        r"pub designator: c_int,\s*"
        r"\}",
        re.DOTALL,
    )
    c_layout = re.compile(
        r"typedef struct GptPartitionType \{\s*"
        r"sd_id128_t uuid;\s*"
        r"const char \*name;\s*"
        r"Architecture arch;\s*"
        r"PartitionDesignator designator;\s*"
        r"\} GptPartitionType;",
        re.DOTALL,
    )
    return bool(rust_layout.search(source) and c_layout.search(shared_header))


def main() -> int:
    header = HEADER.read_text()
    shared_header = SHARED_HEADER.read_text()
    source = SOURCE.read_text()
    crate_root = CRATE_ROOT.read_text()
    basic_meson = BASIC_MESON.read_text()
    test_meson = TEST_MESON.read_text()

    declared, declared_names = header_inventory(header)
    duplicate_declarations = sorted({name for name in declared_names if declared_names.count(name) > 1})
    if duplicate_declarations:
        return fail(f"duplicate dedicated GPT ABI declarations: {duplicate_declarations}")
    if declared != EXPECTED:
        return fail(f"header inventory drift: expected={EXPECTED!r} actual={declared!r}")
    shared_declared, shared_declared_names = header_inventory(shared_header)
    shared_duplicates = sorted(
        {
            name
            for name in shared_declared_names
            if shared_declared_names.count(name) > 1
        }
    )
    if shared_duplicates or shared_declared != SHARED_EXPECTED:
        return fail(
            "shared GPT mirror header drift: "
            f"duplicates={shared_duplicates} expected={SHARED_EXPECTED!r} "
            f"actual={shared_declared!r}"
        )

    c_gpt_header = (ROOT / "src/shared/gpt.h").read_text()
    if not gpt_partition_type_layout_is_exact(source, c_gpt_header):
        return fail(
            "GptPartitionType by-value ABI drift: expected the exact repr(C) "
            "Rust mirror and src/shared/gpt.h field order"
        )

    exported, exported_names = source_inventory(source)
    duplicate_exports = sorted({name for name in exported_names if exported_names.count(name) > 1})
    if duplicate_exports:
        return fail(f"duplicate dedicated GPT ABI exports: {duplicate_exports}")
    if exported != EXPECTED:
        missing = sorted(set(EXPECTED) - set(exported))
        extra = sorted(set(exported) - set(EXPECTED))
        mismatched = {
            name: (EXPECTED[name], exported[name])
            for name in EXPECTED.keys() & exported.keys()
            if EXPECTED[name] != exported[name]
        }
        return fail(
            f"Rust GPT ABI drift: missing={missing} extra={extra} signature_mismatches={mismatched}"
        )

    if "pub mod gpt_util;" not in crate_root:
        return fail("basic crate does not expose gpt_util")
    if "'rust/gpt_util.rs'," not in basic_meson:
        return fail("basic Meson rust_sources does not include gpt_util.rs")

    called = set()
    for test in TESTS:
        if f"'{test}'" not in test_meson and f"files('{test}')" not in test_meson:
            return fail(f"Meson no longer registers {test}")
        test_source = ROOT / "tests-extra" / test
        called.update(re.findall(r"\b(rs_[A-Za-z0-9_]+)\s*\(", test_source.read_text()))
    unexercised = sorted(set(EXPECTED) - called)
    if unexercised:
        return fail(f"declared ABI symbols absent from the three C shadow tests: {unexercised}")

    print(
        "basic GPT ABI inventory: "
        f"declared={len(declared)} shared-declared={len(shared_declared)} "
        f"exported={len(exported)} C-shadow-tests={len(TESTS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
