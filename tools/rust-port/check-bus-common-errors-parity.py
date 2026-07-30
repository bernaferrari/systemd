#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Check that the Rust common-error table mirrors its C authority."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


C_MAP_RE = re.compile(
    r"SD_BUS_ERROR_MAP\(\s*(BUS_ERROR_[A-Z0-9_]+),\s*([A-Z0-9_]+)\s*\)"
)
DEFINE_RE = re.compile(r"^#define\s+(BUS_ERROR_[A-Z0-9_]+)\s+(.+)$", re.MULTILINE)
DNS_PREFIX_RE = re.compile(r'^#define\s+_BUS_ERROR_DNS\s+"([^"]+)"$', re.MULTILINE)
RUST_MAP_RE = re.compile(
    r'error\(\s*"([^"]+)",\s*libc::([A-Z0-9_]+)\s*,?\s*\)\s*,'
)
STRING_RE = re.compile(r'"([^"]*)"')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="repository root")
    return parser.parse_args()


def c_error_names(header: Path) -> dict[str, str]:
    text = header.read_text(encoding="utf-8")
    dns_prefix = DNS_PREFIX_RE.search(text)
    if dns_prefix is None:
        raise RuntimeError(f"{header}: missing _BUS_ERROR_DNS definition")

    names: dict[str, str] = {}
    for symbol, value in DEFINE_RE.findall(re.sub(r"\\\n\s*", " ", text)):
        strings = STRING_RE.findall(value)
        if value.startswith("_BUS_ERROR_DNS"):
            if len(strings) != 1:
                raise RuntimeError(f"{header}: cannot resolve {symbol}")
            names[symbol] = dns_prefix.group(1) + strings[0]
        elif len(strings) == 1:
            names[symbol] = strings[0]
        else:
            raise RuntimeError(f"{header}: cannot resolve {symbol}")
    return names


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root).resolve()
    c_source = root / "src/libsystemd/sd-bus/bus-common-errors.c"
    c_header = root / "src/libsystemd/sd-bus/bus-common-errors.h"
    rust_source = root / "src/libsystemd/rust/bus_common_errors.rs"

    names = c_error_names(c_header)
    expected = []
    for symbol, errno in C_MAP_RE.findall(c_source.read_text(encoding="utf-8")):
        try:
            expected.append((names[symbol], errno))
        except KeyError as error:
            raise RuntimeError(f"{c_source}: no header value for {symbol}") from error

    actual = RUST_MAP_RE.findall(rust_source.read_text(encoding="utf-8"))
    if expected != actual:
        for index, (c_entry, rust_entry) in enumerate(zip(expected, actual, strict=False)):
            if c_entry != rust_entry:
                raise RuntimeError(
                    f"mapping {index} differs: C={c_entry!r}, Rust={rust_entry!r}"
                )
        raise RuntimeError(
            f"entry count differs: C={len(expected)}, Rust={len(actual)}"
        )

    print(f"bus common errors parity OK: {len(expected)} ordered entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
