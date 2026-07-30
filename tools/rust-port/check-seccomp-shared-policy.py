#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check the source-derived policy subset of shared Rust seccomp_util."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
C_SOURCE = ROOT / "src/shared/seccomp-util.c"
C_HEADER = ROOT / "src/shared/seccomp-util.h"
RUST_MODEL = ROOT / "src/shared/rust/seccomp_util/model.rs"
RUST_FILTER_SET = ROOT / "src/shared/rust/seccomp_util/filter_set.rs"
RUST_LISTS = ROOT / "src/shared/rust/seccomp_util/syscall_lists.rs"
SYSCALL_LIST = ROOT / "src/include/override/sys/syscall-list.txt"


def fail(message: str) -> None:
    print(f"seccomp shared policy parity: {message}", file=sys.stderr)
    raise SystemExit(1)


def c_filter_sets(source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    starts = list(
        re.finditer(r"\[SYSCALL_FILTER_SET_([A-Z0-9_]+)\]\s*=\s*\{", source)
    )
    for index, match in enumerate(starts):
        end = (
            starts[index + 1].start()
            if index + 1 < len(starts)
            else source.index("\n};", match.end())
        )
        block = source[match.end() : end]
        value = block[block.index(".value =") :]
        result[match.group(1)] = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)\\0"', value)
    return result


def c_filter_metadata(source: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    starts = list(
        re.finditer(r"\[SYSCALL_FILTER_SET_([A-Z0-9_]+)\]\s*=\s*\{", source)
    )
    for index, match in enumerate(starts):
        end = (
            starts[index + 1].start()
            if index + 1 < len(starts)
            else source.index("\n};", match.end())
        )
        block = source[match.end() : end]
        name = re.search(r'\.name = "([^"]+)"', block)
        help_text = re.search(r'\.help = "([^"]+)"', block)
        if name is None or help_text is None:
            fail(f"cannot parse C metadata for {match.group(1)}")
        result[match.group(1)] = (name.group(1), help_text.group(1))
    return result


def rust_filter_sets(source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for match in re.finditer(
        r"SyscallFilterSet::([A-Za-z0-9]+)\s*=>\s*&\[(.*?)\]\[\.\.\],",
        source,
        re.DOTALL,
    ):
        result[match.group(1)] = re.findall(r'"([^"]+)"', match.group(2))
    return result


def rust_filter_metadata(source: str) -> dict[str, tuple[str, str]]:
    name_body = source[
        source.index("pub const fn name") : source.index("/// Human-readable help")
    ]
    help_body = source[
        source.index("pub const fn help") : source.index("/// Syscall names")
    ]
    names = dict(re.findall(r'Self::(\w+) => "([^"]+)"', name_body))
    help_texts = dict(
        re.findall(r'Self::(\w+) =>\s*(?:\{\s*)?"([^"]+)"', help_body)
    )
    if set(names) != set(help_texts):
        fail("Rust filter-set name/help inventories differ")
    return {name: (value, help_texts[name]) for name, value in names.items()}


def rust_to_c_name(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def main() -> None:
    c_source = C_SOURCE.read_text()
    c_header = C_HEADER.read_text()
    rust_model = RUST_MODEL.read_text()
    rust_filter_set = RUST_FILTER_SET.read_text()
    rust_lists_source = RUST_LISTS.read_text()

    c_sets = c_filter_sets(c_source)
    c_metadata = c_filter_metadata(c_source)
    rust_sets = rust_filter_sets(rust_lists_source)
    rust_metadata = rust_filter_metadata(rust_filter_set)
    rust_variants_match = re.search(
        r"pub enum SyscallFilterSet\s*\{(.*?)\n\}", rust_model, re.DOTALL
    )
    if rust_variants_match is None:
        fail("cannot locate SyscallFilterSet")
    rust_variants = re.findall(
        r"^\s{4}([A-Za-z0-9]+),$",
        rust_variants_match.group(1),
        re.MULTILINE,
    )
    rust_names = {rust_to_c_name(name) for name in rust_variants}
    expected_literal_sets = set(rust_variants) - {"Known"}

    if rust_names != set(c_sets):
        fail(
            "filter-set inventory differs: "
            f"C-only={sorted(set(c_sets) - rust_names)}, "
            f"Rust-only={sorted(rust_names - set(c_sets))}"
        )
    if f"pub const MAX: usize = {len(c_sets)};" not in rust_filter_set:
        fail("SyscallFilterSet::MAX does not match the C table")
    normalized_metadata = {
        rust_to_c_name(name): metadata for name, metadata in rust_metadata.items()
    }
    if normalized_metadata != c_metadata:
        fail("filter-set names or help text differ from the C table")
    if set(rust_sets) != expected_literal_sets:
        fail(
            "literal filter-set coverage differs: "
            f"missing={sorted(expected_literal_sets - set(rust_sets))}, "
            f"extra={sorted(set(rust_sets) - expected_literal_sets)}"
        )

    for rust_name, rust_entries in rust_sets.items():
        c_name = rust_to_c_name(rust_name)
        if c_name == "KNOWN":
            continue
        if rust_entries != c_sets[c_name]:
            fail(f"{rust_name} entries or order differ from seccomp-util.c")

    expected_include = (
        'include_str!("../../../include/override/sys/syscall-list.txt")'
    )
    if expected_include not in rust_lists_source:
        fail("@known is not sourced from the same syscall-list.txt as C")
    if "SyscallFilterSet::Known => known_syscalls()," not in rust_lists_source:
        fail("@known does not use the source-derived list")
    if c_sets["KNOWN"] != ["@obsolete"]:
        fail("the C @known prefix changed")
    if not SYSCALL_LIST.read_text().splitlines():
        fail("generated syscall authority is empty")

    header_count = len(
        re.findall(r"^\s*SYSCALL_FILTER_SET_[A-Z0-9_]+,", c_header, re.MULTILINE)
    )
    if header_count != len(c_sets):
        fail("C header enum and C table have different set counts")

    print(
        "seccomp shared policy parity: "
        f"{len(c_sets)} filter sets, metadata, and source-derived @known verified"
    )


if __name__ == "__main__":
    main()
