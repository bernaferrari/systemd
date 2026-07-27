#!/usr/bin/env python3
"""Verify the five-symbol basic Rust seccomp comparison ABI statically.

This checker proves only that the existing C shadow-test surface is declared,
exported with matching signatures, included in the Rust static library, and
exercised by its registered C comparison test. It intentionally does not claim
that the shared Rust policy model implements or replaces the libseccomp runtime.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/basic/rust/seccomp_util.h"
SOURCE = ROOT / "src/basic/rust/seccomp_util.rs"
ERRNO_SOURCE = ROOT / "src/basic/rust/errno_util.rs"
CRATE_ROOT = ROOT / "src/basic/rust/lib.rs"
BASIC_MESON = ROOT / "src/basic/meson.build"
ROOT_MESON = ROOT / "meson.build"
RUST_CARGO = ROOT / "src/basic/rust/Cargo.toml"
TEST = ROOT / "tests-extra/test-seccomp-util-rust.c"
TEST_MESON = ROOT / "tests-extra/meson.build"
RUST_CI = ROOT / ".github/workflows/rust-ci.yml"
SHARED_C = ROOT / "src/shared/seccomp-util.c"
SHARED_MODEL = ROOT / "src/shared/rust/seccomp_util/model.rs"

EXPECTED = {
    "rs_seccomp_errno_or_action_is_valid": ("bool", ("c_int",)),
    "rs_seccomp_parse_errno_or_action": ("c_int", ("*const c_char",)),
    "rs_seccomp_errno_or_action_to_string": ("*const c_char", ("c_int",)),
    "rs_seccomp_arch_to_string": ("*const c_char", ("u32",)),
    "rs_seccomp_arch_from_string": ("c_int", ("*const c_char", "*mut u32")),
}

EXPECTED_ARCHITECTURES = (
    ("Native", "NATIVE", "native", 0x00000000),
    ("X86", "X86", "x86", 0x40000003),
    ("X86_64", "X86_64", "x86-64", 0xC000003E),
    ("X32", "X32", "x32", 0x4000003E),
    ("Arm", "ARM", "arm", 0x40000028),
    ("Aarch64", "AARCH64", "arm64", 0xC00000B7),
    ("Loongarch64", "LOONGARCH64", "loongarch64", 0xC0000102),
    ("Mips", "MIPS", "mips", 0x00000008),
    ("Mips64", "MIPS64", "mips64", 0x80000008),
    ("Mips64N32", "MIPS64N32", "mips64-n32", 0xA0000008),
    ("Mipsel", "MIPSEL", "mips-le", 0x40000008),
    ("Mipsel64", "MIPSEL64", "mips64-le", 0xC0000008),
    ("Mipsel64N32", "MIPSEL64N32", "mips64-le-n32", 0xE0000008),
    ("Parisc", "PARISC", "parisc", 0x0000000F),
    ("Parisc64", "PARISC64", "parisc64", 0x8000000F),
    ("Ppc", "PPC", "ppc", 0x00000014),
    ("Ppc64", "PPC64", "ppc64", 0x80000015),
    ("Ppc64Le", "PPC64LE", "ppc64-le", 0xC0000015),
    ("Riscv64", "RISCV64", "riscv64", 0xC00000F3),
    ("S390", "S390", "s390", 0x00000016),
    ("S390X", "S390X", "s390x", 0x80000016),
)

OPTIONAL_ARCHITECTURES = {
    "Loongarch64": "systemd_seccomp_arch_loongarch64",
    "Riscv64": "systemd_seccomp_arch_riscv64",
}

HEADER_TYPES = {
    "bool": "bool",
    "int": "c_int",
    "const char *": "*const c_char",
    "uint32_t": "u32",
    "uint32_t *": "*mut u32",
}


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def header_argument_type(argument: str) -> str:
    argument = " ".join(argument.split())
    for c_type in sorted(HEADER_TYPES, key=len, reverse=True):
        suffix = argument.removeprefix(c_type)
        if suffix != argument and re.fullmatch(r"\s*[A-Za-z_][A-Za-z0-9_]*", suffix):
            return HEADER_TYPES[c_type]
    raise ValueError(f"unsupported seccomp C argument declaration: {argument!r}")


def header_inventory(text: str) -> tuple[dict[str, tuple[str, tuple[str, ...]]], list[str]]:
    inventory: dict[str, tuple[str, tuple[str, ...]]] = {}
    names: list[str] = []
    pattern = re.compile(
        r"^(bool|int|const char \*)\s*(rs_seccomp_[A-Za-z0-9_]+)\(([^)]*)\);$",
        re.MULTILINE,
    )
    for return_type, name, raw_arguments in pattern.findall(text):
        names.append(name)
        arguments = tuple(
            header_argument_type(argument)
            for argument in raw_arguments.split(",")
            if argument.strip() and argument.strip() != "void"
        )
        inventory[name] = (HEADER_TYPES[return_type], arguments)
    return inventory, names


def source_inventory(text: str) -> tuple[dict[str, tuple[str, tuple[str, ...]]], list[str]]:
    pattern = re.compile(
        r"#\[unsafe\(no_mangle\)\]\s+pub (?:unsafe )?extern \"C\" fn "
        r"(rs_seccomp_[A-Za-z0-9_]+)\((.*?)\)\s*->\s*([^\n{]+?)\s*\{",
        re.DOTALL,
    )
    inventory: dict[str, tuple[str, tuple[str, ...]]] = {}
    names: list[str] = []
    for name, raw_arguments, return_type in pattern.findall(text):
        names.append(name)
        arguments = tuple(
            argument.rsplit(":", 1)[1].strip()
            for argument in raw_arguments.split(",")
            if argument.strip()
        )
        inventory[name] = (return_type.strip(), arguments)
    return inventory, names


def duplicates(names: list[str]) -> list[str]:
    return sorted({name for name in names if names.count(name) > 1})


def architecture_inventory(source: str) -> tuple[dict[str, int], dict[str, str]]:
    enum_match = re.search(
        r"pub enum SeccompArch \{(.*?)^\}",
        source,
        re.DOTALL | re.MULTILINE,
    )
    if not enum_match:
        raise ValueError("SeccompArch enum not found")
    values = {
        variant: int(raw_value.replace("_", ""), 16)
        for variant, raw_value in re.findall(
            r"^\s*([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f_]+),$",
            enum_match.group(1),
            re.MULTILINE,
        )
    }
    names = dict(
        re.findall(
            r"^\s*\(SeccompArch::([A-Za-z0-9_]+), c\"([^\"]+)\"\),$",
            source,
            re.MULTILINE,
        )
    )
    return values, names


def architecture_inventory_for_cfg(
    values: dict[str, int], names: dict[str, str], enabled_cfgs: set[str]
) -> tuple[dict[str, int], dict[str, str]]:
    """Model the two Meson-derived cfg states after validating their gates.

    This is deliberately not target-architecture driven: the C authority is
    whether the selected libseccomp header declares the token.
    """
    values = values.copy()
    names = names.copy()
    for variant, cfg in OPTIONAL_ARCHITECTURES.items():
        if cfg not in enabled_cfgs:
            values.pop(variant, None)
            names.pop(variant, None)
    return values, names


def verify_optional_architecture_gates(source: str) -> str | None:
    for variant, cfg in OPTIONAL_ARCHITECTURES.items():
        expected = next(item for item in EXPECTED_ARCHITECTURES if item[0] == variant)
        _, _, name, _ = expected
        enum_gate = (
            rf"#\[cfg\({re.escape(cfg)}\)\]\s*\n\s*"
            rf"{re.escape(variant)}\s*=\s*0x[0-9A-Fa-f_]+,"
        )
        table_gate = (
            rf"#\[cfg\({re.escape(cfg)}\)\]\s*\n\s*"
            rf"\(SeccompArch::{re.escape(variant)}, c\"{re.escape(name)}\"\),"
        )
        if not re.search(enum_gate, source):
            return f"optional {variant} enum token is not gated by {cfg}"
        if not re.search(table_gate, source):
            return f"optional {variant} name is not gated by {cfg}"
    if "target_arch" in source:
        return "basic seccomp ABI must use Meson header cfgs, not Rust target_arch"
    return None


def verify_meson_seccomp_cfgs(root_meson: str, basic_meson: str, cargo_toml: str) -> str | None:
    probes = {
        "LOONGARCH64": "have_seccomp_arch_loongarch64",
        "RISCV64": "have_seccomp_arch_riscv64",
    }
    for macro, variable in probes.items():
        if (
            f"'SCMP_ARCH_{macro}'" not in root_meson
            or "cc.has_header_symbol" not in root_meson
        ):
            return f"Meson does not probe SCMP_ARCH_{macro} in seccomp.h"
        if f"conf.set10('HAVE_SECCOMP_ARCH_{macro}', {variable})" not in root_meson:
            return f"Meson does not publish HAVE_SECCOMP_ARCH_{macro}"

    for cfg, variable in (
        ("systemd_seccomp_arch_loongarch64", "seccomp_arch_loongarch64"),
        ("systemd_seccomp_arch_riscv64", "seccomp_arch_riscv64"),
    ):
        if cfg not in basic_meson or variable not in basic_meson:
            return f"basic Rust Meson target does not propagate {cfg}"
        if not re.search(
            rf"\({re.escape(variable)},\s*\"{re.escape(cfg)}\"\)", basic_meson
        ) or '"--cfg=" + cfg' not in basic_meson:
            return f"basic Rust Meson target does not pass checked {cfg}"
        if cfg not in cargo_toml:
            return f"standalone Cargo guidance omits {cfg}"
    return None


def verify_c_optional_architecture_guards(shared_c: str) -> str | None:
    if "#elif defined(__loongarch_lp64) && defined(SCMP_ARCH_LOONGARCH64)" not in shared_c:
        return "C local LoongArch selection is not guarded by SCMP_ARCH_LOONGARCH64"
    if "#elif defined(__riscv) && __riscv_xlen == 64 && defined(SCMP_ARCH_RISCV64)" not in shared_c:
        return "C local RISC-V selection is not guarded by SCMP_ARCH_RISCV64"
    return None


def shared_architecture_inventory(source: str) -> dict[str, int]:
    inventory: dict[str, int] = {}
    for name, expression in re.findall(
        r"^pub const SCMP_ARCH_([A-Z0-9_]+): u32 = ([^;]+);$",
        source,
        re.MULTILINE,
    ):
        # Current model constants are hexadecimal literals optionally joined by
        # bitwise OR. Reject any richer expression instead of evaluating code.
        parts = [part.strip().replace("_", "") for part in expression.split("|")]
        if not all(re.fullmatch(r"0x[0-9A-Fa-f]+|0", part) for part in parts):
            raise ValueError(f"unsupported shared architecture expression: {expression!r}")
        inventory[name] = 0
        for part in parts:
            inventory[name] |= int(part, 0)
    return inventory


def verify_target_errno_tables(source: str) -> str | None:
    from_match = re.search(
        r"static ERRNO_FROM_NAME_TABLE:.*?= &\[(.*?)^\];",
        source,
        re.DOTALL | re.MULTILINE,
    )
    if not from_match:
        return "basic errno-from-name table not found"

    from_entries = re.findall(
        r'^\s*\(b"([A-Z0-9]+)", libc::([A-Z0-9]+)\),$',
        from_match.group(1),
        re.MULTILINE,
    )
    if len(from_entries) < 130:
        return f"incomplete target errno-from-name table: {len(from_entries)} entries"
    if any(name != constant for name, constant in from_entries):
        return "errno-from-name table contains a name/libc-constant mismatch"
    if re.search(r'^\s*\(b"[A-Z0-9]+",\s*\d+\),$', from_match.group(1), re.MULTILINE):
        return "errno-from-name table still hard-codes architecture-specific numbers"
    if 'include!(env!("SYSTEMD_ERRNO_TO_NAME_RS"));' not in source:
        return "errno-to-name table is not generated from the Meson target input"
    if "static ERRNO_TO_NAME_TABLE" in source:
        return "errno-to-name table is still hand-maintained in Rust"
    return None


def main() -> int:
    header = HEADER.read_text()
    source = SOURCE.read_text()
    declared, declared_names = header_inventory(header)
    exported, exported_names = source_inventory(source)

    if repeated := duplicates(declared_names):
        return fail(f"duplicate basic seccomp ABI declarations: {repeated}")
    if repeated := duplicates(exported_names):
        return fail(f"duplicate basic seccomp ABI exports: {repeated}")
    if declared != EXPECTED:
        return fail(f"basic seccomp header drift: expected={EXPECTED!r} actual={declared!r}")
    if exported != EXPECTED:
        missing = sorted(set(EXPECTED) - set(exported))
        extra = sorted(set(exported) - set(EXPECTED))
        mismatched = {
            name: (EXPECTED[name], exported[name])
            for name in EXPECTED.keys() & exported.keys()
            if EXPECTED[name] != exported[name]
        }
        return fail(
            "basic Rust seccomp ABI drift: "
            f"missing={missing} extra={extra} signature_mismatches={mismatched}"
        )

    expected_values = {variant: value for variant, _, _, value in EXPECTED_ARCHITECTURES}
    expected_names = {variant: name for variant, _, name, _ in EXPECTED_ARCHITECTURES}
    architecture_values, architecture_names = architecture_inventory(source)
    if architecture_values != expected_values or architecture_names != expected_names:
        return fail(
            "basic seccomp architecture drift: "
            f"expected_values={expected_values!r} actual_values={architecture_values!r} "
            f"expected_names={expected_names!r} actual_names={architecture_names!r}"
        )

    if gate_error := verify_optional_architecture_gates(source):
        return fail(gate_error)
    for enabled_cfgs in (set(), set(OPTIONAL_ARCHITECTURES.values())):
        expected_cfg_values, expected_cfg_names = architecture_inventory_for_cfg(
            expected_values, expected_names, enabled_cfgs
        )
        actual_cfg_values, actual_cfg_names = architecture_inventory_for_cfg(
            architecture_values, architecture_names, enabled_cfgs
        )
        if actual_cfg_values != expected_cfg_values or actual_cfg_names != expected_cfg_names:
            return fail(
                "basic seccomp architecture cfg-state drift: "
                f"enabled={sorted(enabled_cfgs)!r} "
                f"expected_values={expected_cfg_values!r} actual_values={actual_cfg_values!r} "
                f"expected_names={expected_cfg_names!r} actual_names={actual_cfg_names!r}"
            )

    if meson_error := verify_meson_seccomp_cfgs(
        ROOT_MESON.read_text(), BASIC_MESON.read_text(), RUST_CARGO.read_text()
    ):
        return fail(meson_error)

    shared_expected = {
        constant: value for _, constant, _, value in EXPECTED_ARCHITECTURES
    }
    shared_actual = shared_architecture_inventory(SHARED_MODEL.read_text())
    shared_actual = {
        name: shared_actual[name] for name in shared_expected if name in shared_actual
    }
    if shared_actual != shared_expected:
        return fail(
            "shared/basic seccomp architecture drift: "
            f"expected={shared_expected!r} shared={shared_actual!r}"
        )

    if errno_error := verify_target_errno_tables(ERRNO_SOURCE.read_text()):
        return fail(errno_error)

    if "pub mod seccomp_util;" not in CRATE_ROOT.read_text():
        return fail("basic Rust crate does not expose seccomp_util")
    if "'rust/seccomp_util.rs'," not in BASIC_MESON.read_text():
        return fail("basic Meson rust_sources does not include seccomp_util.rs")

    test_meson = TEST_MESON.read_text()
    if "files('test-seccomp-util-rust.c')" not in test_meson:
        return fail("Meson does not compile test-seccomp-util-rust.c")
    if "test('test-seccomp-util-rust', rust_test_exe)" not in test_meson:
        return fail("Meson does not register test-seccomp-util-rust")
    if "if conf.get('HAVE_SECCOMP') == 1" not in test_meson:
        return fail("the C comparison test is not guarded by HAVE_SECCOMP")
    rust_ci = RUST_CI.read_text()
    if (
        "rust-meson-reviewed-shadows:" not in rust_ci
        or "test-seccomp-util-rust" not in rust_ci
    ):
        return fail("reviewed seccomp comparison must stay in the authoritative Meson CI job")

    called = set(re.findall(r"\b(rs_seccomp_[A-Za-z0-9_]+)\s*\(", TEST.read_text()))
    if unexercised := sorted(set(EXPECTED) - called):
        return fail(f"basic seccomp ABI symbols absent from the C shadow test: {unexercised}")
    test_source = TEST.read_text()
    for macro, name in (("LOONGARCH64", "loongarch64"), ("RISCV64", "riscv64")):
        if not re.search(rf"#ifdef SCMP_ARCH_{macro}\s*\n\s*\"{name}\",", test_source):
            return fail(f"C seccomp comparison fixture does not cover optional SCMP_ARCH_{macro}")
        if not re.search(
            rf"#ifndef SCMP_ARCH_{macro}\s*\n\s*"
            rf"assert_se\(rs_seccomp_arch_from_string\(\"{name}\", &r_ret\) == -EINVAL\);",
            test_source,
        ):
            return fail(
                f"C seccomp comparison fixture does not reject {name} without SCMP_ARCH_{macro}"
            )

    shared_c = SHARED_C.read_text()
    if c_guard_error := verify_c_optional_architecture_guards(shared_c):
        return fail(c_guard_error)
    missing_authority = sorted(
        name
        for name in (
            "seccomp_errno_or_action_is_valid",
            "seccomp_parse_errno_or_action",
            "seccomp_errno_or_action_to_string",
            "seccomp_arch_to_string",
            "seccomp_arch_from_string",
        )
        if not re.search(rf"\b{re.escape(name)}\s*\(", shared_c)
    )
    if missing_authority:
        return fail(f"C semantic authority functions disappeared: {missing_authority}")

    print(
        "basic seccomp ABI inventory: "
        f"declared={len(declared)} exported={len(exported)} "
        f"architectures={len(expected_values)} cfg-states=old,new C-shadow-tests=1 meson-ci-tests=1 "
        "runtime-parity=unclaimed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
