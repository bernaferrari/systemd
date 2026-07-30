#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep the private Varlink state-table shadow aligned with current C."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the C and Rust Varlink state enum, table, and predicates."
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    return parser.parse_args()


def extract(text: str, pattern: str, description: str) -> str:
    match = re.search(pattern, text, re.DOTALL | re.MULTILINE)
    if match is None:
        raise ValueError(f"could not locate {description}")
    return match.group("body")


def c_variant_name(name: str) -> str:
    prefix = "VARLINK_"
    if not name.startswith(prefix):
        raise ValueError(f"unexpected Varlink state name {name!r}")
    return "".join(part.capitalize() for part in name.removeprefix(prefix).split("_"))


def c_state_names(header: str) -> list[str]:
    body = extract(
        header,
        r"typedef enum VarlinkState \{(?P<body>.*?)\s*_VARLINK_STATE_MAX,",
        "C VarlinkState enum",
    )
    names = re.findall(r"^\s*(VARLINK_[A-Z_]+),", body, re.MULTILINE)
    if not names:
        raise ValueError("C VarlinkState enum has no states")
    if len(names) != len(set(names)):
        raise ValueError("C VarlinkState enum has duplicate states")
    return names


def c_state_table(source: str) -> list[tuple[str, str]]:
    body = extract(
        source,
        r"static const char\* const varlink_state_table\[_VARLINK_STATE_MAX\] = \{(?P<body>.*?)\n\};",
        "C Varlink state table",
    )
    table = re.findall(
        r'^\s*\[(VARLINK_[A-Z_]+)\]\s*=\s*"([^"]+)",$', body, re.MULTILINE
    )
    if not table:
        raise ValueError("C Varlink state table has no entries")
    return table


def rust_state_variants(rust: str) -> list[tuple[str, int]]:
    body = extract(
        rust,
        r"pub enum VarlinkState \{(?P<body>.*?)\n\}",
        "Rust VarlinkState enum",
    )
    return [(name, int(value)) for name, value in re.findall(r"^\s*(\w+)\s*=\s*(-?\d+),$", body, re.MULTILINE)]


def rust_string_mapping(rust: str) -> list[tuple[str, str]]:
    body = extract(
        rust,
        r"pub fn as_str\(self\) -> &'static str \{(?P<body>.*?)\n\s*\}\n\n\s*pub fn is_alive",
        "Rust Varlink as_str()",
    )
    return re.findall(r'^\s*Self::(\w+)\s*=>\s*"([^"]+)",$', body, re.MULTILINE)


def rust_parser_mapping(rust: str) -> list[tuple[str, str]]:
    body = extract(
        rust,
        r"pub fn varlink_state_from_string\(s: &str\) -> Result<VarlinkState> \{(?P<body>.*?)\n\}",
        "Rust Varlink parser",
    )
    return re.findall(r'^\s*"([^"]+)"\s*=>\s*Ok\(VarlinkState::(\w+)\),$', body, re.MULTILINE)


def c_macro_states(header: str, macro: str) -> set[str]:
    body = extract(
        header,
        rf"#define {macro}\(state\)(?P<body>.*?)(?=\n\n)",
        f"C {macro} macro",
    )
    states = set(re.findall(r"VARLINK_[A-Z_]+", body))
    if not states:
        raise ValueError(f"C {macro} macro has no states")
    return states


def rust_predicate_states(rust: str, function: str, next_function: str) -> set[str]:
    body = extract(
        rust,
        rf"pub fn {function}\(self\) -> bool \{{(?P<body>.*?)\n\s*\}}\n\n\s*pub fn {next_function}",
        f"Rust {function}()",
    )
    return set(re.findall(r"Self::(\w+)", body))


def main() -> int:
    root = Path(parse_args().repo_root).resolve()
    try:
        header = (root / "src/libsystemd/sd-varlink/varlink-internal.h").read_text()
        source = (root / "src/libsystemd/sd-varlink/sd-varlink.c").read_text()
        rust = (root / "src/libsystemd/rust/varlink_state.rs").read_text()

        c_states = c_state_names(header)
        c_table = c_state_table(source)
        if [name for name, _ in c_table] != c_states:
            raise ValueError("C Varlink state table order differs from its enum")

        expected_variants = [(c_variant_name(name), index) for index, name in enumerate(c_states)]
        if rust_state_variants(rust) != expected_variants:
            raise ValueError(
                "Rust VarlinkState discriminants differ from C: "
                f"expected {expected_variants!r}, got {rust_state_variants(rust)!r}"
            )

        expected_strings = [(c_variant_name(name), value) for name, value in c_table]
        if rust_string_mapping(rust) != expected_strings:
            raise ValueError("Rust Varlink as_str() mapping differs from the C state table")
        expected_parser = [(value, variant) for variant, value in expected_strings]
        if rust_parser_mapping(rust) != expected_parser:
            raise ValueError("Rust Varlink parser mapping differs from the C state table")

        expected_alive = {c_variant_name(name) for name in c_macro_states(header, "VARLINK_STATE_IS_ALIVE")}
        if rust_predicate_states(rust, "is_alive", "wants_reply") != expected_alive:
            raise ValueError("Rust Varlink is_alive() predicate differs from C")

        expected_reply = {c_variant_name(name) for name in c_macro_states(header, "VARLINK_STATE_WANTS_REPLY")}
        if (
            rust_predicate_states(rust, "wants_reply", "varlink_state_from_string")
            != expected_reply
        ):
            raise ValueError("Rust Varlink wants_reply() predicate differs from C")
    except (OSError, ValueError) as exc:
        print(f"Varlink state parity check failed: {exc}", file=sys.stderr)
        return 1

    print(f"Varlink state parity check OK: states={len(c_states)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
