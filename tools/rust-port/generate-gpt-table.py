#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Generate the Rust GPT partition table from systemd's canonical C sources."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GPT_C = REPO_ROOT / "src/shared/gpt.c"
SD_GPT_H = REPO_ROOT / "src/systemd/sd-gpt.h"
OUTPUT = REPO_ROOT / "src/shared/rust/gpt/table_data.rs"

ARCHITECTURES = {
    "ALPHA": "Alpha",
    "ARC": "Arc",
    "ARM": "Arm",
    "ARM64": "Arm64",
    "IA64": "Ia64",
    "LOONGARCH64": "LoongArch64",
    "MIPS": "Mips",
    "MIPS64": "Mips64",
    "MIPS_LE": "MipsLe",
    "MIPS64_LE": "Mips64Le",
    "PARISC": "Parisc",
    "PPC": "Ppc",
    "PPC64": "Ppc64",
    "PPC64_LE": "Ppc64Le",
    "RISCV32": "Riscv32",
    "RISCV64": "Riscv64",
    "S390": "S390",
    "S390X": "S390x",
    "TILEGX": "Tilegx",
    "X86": "X86",
    "X86_64": "X86_64",
}

DESIGNATORS = {
    "PARTITION_ROOT": "Root",
    "PARTITION_USR": "Usr",
    "PARTITION_HOME": "Home",
    "PARTITION_SRV": "Srv",
    "PARTITION_ESP": "Esp",
    "PARTITION_XBOOTLDR": "XBootldr",
    "PARTITION_SWAP": "Swap",
    "PARTITION_ROOT_VERITY": "RootVerity",
    "PARTITION_USR_VERITY": "UsrVerity",
    "PARTITION_ROOT_VERITY_SIG": "RootVeritySig",
    "PARTITION_USR_VERITY_SIG": "UsrVeritySig",
    "PARTITION_TMP": "Tmp",
    "PARTITION_VAR": "Var",
    "_PARTITION_DESIGNATOR_INVALID": "Invalid",
}

SEXTET = (
    ("ROOT_{arch}", "root-{name}", "Root"),
    ("ROOT_{arch}_VERITY", "root-{name}-verity", "RootVerity"),
    ("ROOT_{arch}_VERITY_SIG", "root-{name}-verity-sig", "RootVeritySig"),
    ("USR_{arch}", "usr-{name}", "Usr"),
    ("USR_{arch}_VERITY", "usr-{name}-verity", "UsrVerity"),
    ("USR_{arch}_VERITY_SIG", "usr-{name}-verity-sig", "UsrVeritySig"),
)


@dataclass(frozen=True)
class Entry:
    macro: str
    uuid: tuple[int, ...]
    name: str
    architecture: str
    designator: str


def parse_uuid_macros(header: str) -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    pattern = re.compile(
        r"^#define\s+(SD_GPT_[A-Z0-9_]+)\s+SD_ID128_MAKE\(([^)]+)\)",
        re.MULTILINE,
    )
    for name, raw_bytes in pattern.findall(header):
        uuid = tuple(int(value.strip(), 16) for value in raw_bytes.split(","))
        if len(uuid) != 16:
            raise ValueError(f"{name} has {len(uuid)} bytes, expected 16")
        result[name] = uuid
    if not result:
        raise ValueError(f"no SD_GPT_* UUID macros found in {SD_GPT_H}")
    return result


def table_initializer(source: str) -> str:
    marker = "const GptPartitionType gpt_partition_type_table[] = {"
    start = source.find(marker)
    if start < 0:
        raise ValueError(f"GPT table initializer not found in {GPT_C}")
    end = source.find("\n};", start)
    if end < 0:
        raise ValueError(f"GPT table terminator not found in {GPT_C}")
    return source[start:end]


def canonical_entries() -> list[Entry]:
    macros = parse_uuid_macros(SD_GPT_H.read_text(encoding="utf-8"))
    initializer = table_initializer(GPT_C.read_text(encoding="utf-8"))
    entries: list[Entry] = []

    for c_arch, name in re.findall(
        r"_GPT_ARCH_SEXTET\(\s*([A-Z0-9_]+)\s*,\s*\"([^\"]+)\"\s*\)",
        initializer,
    ):
        try:
            rust_arch = ARCHITECTURES[c_arch]
        except KeyError as error:
            raise ValueError(
                f"add Rust architecture mapping for {c_arch!r}"
            ) from error

        for macro_template, name_template, designator in SEXTET:
            macro = "SD_GPT_" + macro_template.format(arch=c_arch)
            try:
                uuid = macros[macro]
            except KeyError as error:
                raise ValueError(f"{macro} is referenced by gpt.c but undefined") from error
            entries.append(
                Entry(
                    macro=macro,
                    uuid=uuid,
                    name=name_template.format(name=name),
                    architecture=rust_arch,
                    designator=designator,
                )
            )

    explicit_pattern = re.compile(
        r"\{\s*(SD_GPT_[A-Z0-9_]+)\s*,\s*\"([^\"]+)\"\s*,"
        r"\s*_ARCHITECTURE_INVALID\s*,\s*\.designator\s*=\s*"
        r"(_?PARTITION_[A-Z0-9_]+)\s*\}"
    )
    for macro, name, c_designator in explicit_pattern.findall(initializer):
        try:
            uuid = macros[macro]
            designator = DESIGNATORS[c_designator]
        except KeyError as error:
            raise ValueError(f"unresolved GPT table token {error.args[0]!r}") from error
        entries.append(
            Entry(
                macro=macro,
                uuid=uuid,
                name=name,
                architecture="Invalid",
                designator=designator,
            )
        )

    if not entries:
        raise ValueError(f"no GPT table entries parsed from {GPT_C}")
    return entries


def render(entries: list[Entry]) -> str:
    lines = [
        "// SPDX-License-Identifier: LGPL-2.1-or-later",
        "//",
        "// Generated by tools/rust-port/generate-gpt-table.py.",
        "// Source UUIDs: src/systemd/sd-gpt.h",
        "// Source order/names: src/shared/gpt.c",
        "//",
        "// Target-native and secondary aliases are intentionally absent until the Rust",
        "// build supplies the same target-architecture configuration as sd-gpt.h.",
        "",
        "use super::model::{Architecture, GptPartitionType, Id128, PartitionDesignator};",
        "",
        "macro_rules! entry {",
        "    ($uuid:expr, $name:literal, $arch:ident, $designator:ident) => {",
        "        GptPartitionType {",
        "            uuid: Id128::from_bytes($uuid),",
        "            name: $name,",
        "            arch: Architecture::$arch,",
        "            designator: PartitionDesignator::$designator,",
        "        }",
        "    };",
        "}",
        "",
        "#[rustfmt::skip]",
        "pub(super) const GPT_PARTITION_TYPE_TABLE: &[GptPartitionType] = &[",
    ]
    for entry in entries:
        uuid = ", ".join(f"0x{byte:02x}" for byte in entry.uuid)
        lines.append(
            f'    entry!([{uuid}], "{entry.name}", {entry.architecture}, '
            f"{entry.designator}), // {entry.macro}"
        )
    lines.extend(["];", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "fail if the checked-in architecture-neutral Rust table differs "
            "from the canonical C sources; target-native/secondary aliases "
            "remain intentionally deferred"
        ),
    )
    args = parser.parse_args()

    try:
        entries = canonical_entries()
        generated = render(entries)
    except (OSError, ValueError) as error:
        print(f"GPT table generation failed: {error}", file=sys.stderr)
        return 2

    if args.check:
        try:
            current = OUTPUT.read_text(encoding="utf-8")
        except OSError as error:
            print(f"cannot read {OUTPUT}: {error}", file=sys.stderr)
            return 2
        if current != generated:
            print(
                "Rust GPT table is stale; run "
                "tools/rust-port/generate-gpt-table.py",
                file=sys.stderr,
            )
            return 1
        print(
            f"Rust GPT table matches {len(entries)} "
            "architecture-neutral canonical entries; target-native/secondary "
            "aliases remain intentionally deferred"
        )
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"Wrote {len(entries)} entries to {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
