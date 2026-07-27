#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Generate the non-glibc Rust errno-name table from errno-list.txt."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


# Keep this mechanically identical to generate-errno-list.sh followed by
# errno-to-name.awk: the first four aliases are removed before errno-list.txt
# is consumed by C, while the latter three are excluded from its name table.
NONCANONICAL_ALIASES = frozenset(
    {
        "ECANCELLED",
        "EREFUSED",
        "EFSBADCRC",
        "EFSCORRUPTED",
        "EDEADLOCK",
        "EWOULDBLOCK",
        "ENOTSUP",
    }
)
ERRNO_NAME = re.compile(r"E[A-Z0-9]+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="target-generated errno-list.txt")
    parser.add_argument("output", type=Path, help="generated Rust source path")
    parser.add_argument(
        "compiler",
        nargs=argparse.REMAINDER,
        help="target C preprocessor command and arguments",
    )
    return parser.parse_args()


def load_names(path: Path) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if not name:
            continue
        if not ERRNO_NAME.fullmatch(name):
            raise ValueError(f"{path}: invalid errno macro name: {name!r}")
        if name not in NONCANONICAL_ALIASES and name not in seen:
            names.append(name)
            seen.add(name)

    if not names:
        raise ValueError(f"{path}: no errno names found")
    return names


def preprocessor_source(names: list[str]) -> str:
    lines = ["#include <errno.h>"]
    bit_values = tuple(1 << bit for bit in range(12))
    expression = " + ".join(f"SYSTEMD_ERRNO_BIT_{bit}" for bit in range(12))

    for name in names:
        lines.extend(
            (
                f"#if {name} < 0 || {name} > 4095",
                f'#error "{name} is outside systemd errno range"',
                "#endif",
            )
        )
        for bit, value in enumerate(bit_values):
            lines.extend(
                (
                    f"#if ({name} & {value})",
                    f"#define SYSTEMD_ERRNO_BIT_{bit} {value}",
                    "#else",
                    f"#define SYSTEMD_ERRNO_BIT_{bit} 0",
                    "#endif",
                )
            )
        lines.append(f'SYSTEMD_ERRNO_ENTRY("{name}", {expression})')
        lines.extend(f"#undef SYSTEMD_ERRNO_BIT_{bit}" for bit in range(12))

    return "\n".join(lines) + "\n"


def load_values(names: list[str], compiler: list[str]) -> list[tuple[int, str]]:
    if not compiler:
        raise ValueError("target C preprocessor command is required")
    result = subprocess.run(
        [*compiler, "-E", "-P", "-x", "c", "-"],
        input=preprocessor_source(names),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"target C preprocessor failed: {result.stderr.strip()}")

    entries = []
    for name, expression in re.findall(
        r'SYSTEMD_ERRNO_ENTRY\("([A-Z0-9]+)",\s*([0-9 +]+)\)',
        result.stdout,
    ):
        value = sum(int(part.strip()) for part in expression.split("+"))
        entries.append((value, name))

    if [name for _, name in entries] != names:
        raise ValueError("target C preprocessor did not emit every errno name in order")
    values = [value for value, _ in entries]
    if len(values) != len(set(values)):
        raise ValueError("canonical errno list contains duplicate numeric values")
    return entries


def render(entries: list[tuple[int, str]]) -> str:
    rows = "".join(f'    ({value}, c"{name}"),\n' for value, name in entries)
    return (
        "// SPDX-License-Identifier: LGPL-2.1-or-later\n"
        "//\n"
        "// Generated from the target compiler and errno-list.txt. DO NOT EDIT.\n"
        "\n"
        "static ERRNO_TO_NAME_TABLE: &[(i32, &CStr)] = &[\n"
        f"{rows}"
        "];\n"
    )


def main() -> int:
    args = parse_args()
    try:
        names = load_names(args.input)
        args.output.write_text(
            render(load_values(names, args.compiler)),
            encoding="utf-8",
        )
    except (OSError, ValueError) as error:
        parser = argparse.ArgumentParser(prog="generate-errno-rust.py")
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
