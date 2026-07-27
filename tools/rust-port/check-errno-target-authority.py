#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Statically verify Rust errno-name generation shares C's target authority."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "src/basic/generate-errno-rust.py"
MESON = ROOT / "src/basic/meson.build"
RUST = ROOT / "src/basic/rust/errno_util.rs"
C_GENERATOR = ROOT / "src/basic/generate-errno-list.sh"
C_AWK = ROOT / "src/basic/errno-to-name.awk"
TEST = ROOT / "tests-extra/test-errno-util-rust.c"
TEST_MESON = ROOT / "tests-extra/meson.build"
RUST_CI = ROOT / ".github/workflows/rust-ci.yml"

ALIASES = {
    "ECANCELLED",
    "EREFUSED",
    "EFSBADCRC",
    "EFSCORRUPTED",
    "EDEADLOCK",
    "EWOULDBLOCK",
    "ENOTSUP",
}
CANONICAL = {"ECANCELED", "ECONNREFUSED", "EBADMSG", "EUCLEAN", "EDEADLK", "EAGAIN", "EOPNOTSUPP"}


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def generated_entries(text: str) -> list[tuple[int, str]]:
    return [
        (int(value), name)
        for value, name in re.findall(
            r'^\s*\(([0-9]+), c"([A-Z0-9]+)"\),$', text, re.MULTILINE
        )
    ]


def verify_build_wiring() -> str | None:
    meson = MESON.read_text(encoding="utf-8")
    rust = RUST.read_text(encoding="utf-8")

    required_meson = (
        "['errno',           [],                 '',        ['<errno.h>'],            ],",
        "errno_list_txt = list_txt",
        "files('generate-errno-rust.py')",
        "output : 'errno-to-name-rust.rs'",
        "'@INPUT0@', '@INPUT1@', '@OUTPUT@', cpp, system_include_args",
        "rust_sources += rust_workspace_inputs + [errno_to_name_rust]",
        'env["SYSTEMD_ERRNO_TO_NAME_RS"] = errno_to_name_rust',
        "meson.current_build_dir() / 'errno-to-name-rust.rs'",
    )
    if any(item not in meson for item in required_meson):
        return "Meson does not pass target errno-list.txt through the Rust generator"
    if 'include!(env!("SYSTEMD_ERRNO_TO_NAME_RS"));' not in rust:
        return "Rust does not include Meson-generated errno names"
    if "static ERRNO_TO_NAME_TABLE" in rust:
        return "Rust retains a hand-maintained errno-to-name table"
    generator = GENERATOR.read_text(encoding="utf-8")
    if "libc::" in generator or '"-E", "-P", "-x", "c", "-"' not in generator:
        return "Rust errno generator does not derive numeric values from the target C preprocessor"
    return None


def verify_c_alias_policy() -> str | None:
    c_generator = C_GENERATOR.read_text(encoding="utf-8")
    c_awk = C_AWK.read_text(encoding="utf-8")
    for alias in sorted(ALIASES - {"EDEADLOCK", "EWOULDBLOCK", "ENOTSUP"}):
        if alias not in c_generator:
            return f"C errno generator no longer excludes {alias}"
    for alias in ("EDEADLOCK", "EWOULDBLOCK", "ENOTSUP"):
        if alias not in c_awk:
            return f"C errno name table no longer excludes {alias}"
    return None


def verify_generated_table() -> str | None:
    target_specific = "EARCHSPEC"
    input_names = sorted(CANONICAL | ALIASES | {target_specific})

    with tempfile.TemporaryDirectory() as directory:
        input_path = Path(directory) / "errno-list.txt"
        output_path = Path(directory) / "errno-to-name-rust.rs"
        input_path.write_text("\n".join(input_names) + "\n", encoding="utf-8")
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            return f"target-authority fixture compiler is unavailable: {compiler!r}"
        result = subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                str(input_path),
                str(output_path),
                *compiler,
                "-DEARCHSPEC=4094",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return f"Rust errno generator failed: {result.stderr.strip()}"
        entries = generated_entries(output_path.read_text(encoding="utf-8"))

    names = [name for _, name in entries]
    values = [value for value, _ in entries]
    if len(set(names)) != len(names) or len(set(values)) != len(values):
        return "generated errno table has duplicate names or numeric values"
    if ALIASES & set(names):
        return "generated errno table publishes a non-canonical alias"
    if not CANONICAL <= set(names):
        return "generated errno table is missing canonical alias targets"
    if target_specific not in names:
        return "generated errno table drops a target-specific errno name"
    if dict((name, value) for value, name in entries)[target_specific] != 4094:
        return "generated errno table does not use the target preprocessor's numeric value"
    return None


def verify_exhaustive_runtime_test() -> str | None:
    test = TEST.read_text(encoding="utf-8")
    test_meson = TEST_MESON.read_text(encoding="utf-8")
    rust_ci = RUST_CI.read_text(encoding="utf-8")
    required = (
        "for (int i = 0; i <= 4095; i++)",
        "errno_name_no_fallback(i)",
        "rs_errno_name_no_fallback(i)",
        "test_errno_name_no_fallback_exhaustive();",
    )
    if any(item not in test for item in required):
        return "errno C-versus-Rust comparison is not exhaustive"
    if "files('test-errno-util-rust.c')" not in test_meson or "test('test-errno-util-rust', rust_test_exe)" not in test_meson:
        return "exhaustive errno C-versus-Rust comparison is not registered with Meson"
    if rust_ci.count("test-errno-util-rust") < 2:
        return "exhaustive errno C-versus-Rust comparison is not compiled and run in Rust CI"
    return None


def main() -> int:
    for check in (
        verify_build_wiring,
        verify_c_alias_policy,
        verify_generated_table,
        verify_exhaustive_runtime_test,
    ):
        if error := check():
            return fail(error)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
