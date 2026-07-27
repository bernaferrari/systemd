#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pin production C ownership for core behavior not yet ported to Rust.

The experimental Rust PID 1 is useful for incremental development, but it is
not a production replacement yet. Until each subsystem has a complete native
Rust implementation, release builds must keep using the current C owner rather
than silently selecting an incomplete Rust path.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORE_MESON = ROOT / "src/core/meson.build"
LIBSYSTEMD_MESON = ROOT / "src/libsystemd/meson.build"
OPTIONS = ROOT / "meson_options.txt"

CORE_SOURCES = {
    "bpf-restrict-fsaccess.c",
    "luo.c",
    "varlink-automount.c",
    "varlink-job.c",
    "varlink-kill.c",
    "varlink-mount.c",
    "varlink-path.c",
    "varlink-scope.c",
    "varlink-service.c",
    "varlink-socket.c",
    "varlink-swap.c",
    "varlink-timer.c",
}

FUTURE_SOURCES = {
    "sd-future/fiber-io.c",
    "sd-future/fiber.c",
    "sd-future/sd-future.c",
}

BPF_CONTRACT = {
    "bpf_restrict_fsaccess_supported",
    "bpf_restrict_fsaccess_setup",
    "bpf_restrict_fsaccess_prepare",
    "bpf_restrict_fsaccess_populate_guard",
    "bpf_restrict_fsaccess_close_initramfs_trust",
    "bpf_restrict_fsaccess_serialize",
}

LUO_CONTRACT = {
    "manager_luo_restore_fd_stores",
    "manager_luo_serialize_fd_stores",
}


def fail(message: str) -> int:
    print(f"core C-retention gate: {message}", file=sys.stderr)
    return 1


def meson_files(text: str, variable: str) -> set[str]:
    match = re.search(
        rf"(?ms)^\s*{re.escape(variable)}\s*=\s*files\((.*?)^\s*\)",
        text,
    )
    if not match:
        raise ValueError(f"missing {variable} files() assignment")
    return set(re.findall(r"'([^']+\.(?:c|cc|cpp))'", match.group(1)))


def require_symbols(path: Path, names: set[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return sorted(name for name in names if not re.search(rf"\b{re.escape(name)}\b", text))


def main() -> int:
    core = CORE_MESON.read_text(encoding="utf-8")
    libsystemd = LIBSYSTEMD_MESON.read_text(encoding="utf-8")
    options = OPTIONS.read_text(encoding="utf-8")

    try:
        core_sources = meson_files(core, "libcore_sources")
        future_sources = meson_files(libsystemd, "sd_future_sources")
    except ValueError as error:
        return fail(str(error))

    missing_core = sorted(CORE_SOURCES - core_sources)
    if missing_core:
        return fail(f"production libcore lost retained sources: {', '.join(missing_core)}")

    missing_future = sorted(FUTURE_SOURCES - future_sources)
    if missing_future:
        return fail(
            f"production libsystemd lost retained sd-future sources: {', '.join(missing_future)}"
        )

    required_core_fragments = (
        "libcore_static = static_library(\n        libcore_name,\n        libcore_sources,",
        "link_whole: libcore_static",
        "if use_rust_pid1 and get_option('mode') == 'release'",
        "error('rust-core-pid1 is experimental and cannot be enabled in release mode')",
    )
    for fragment in required_core_fragments:
        if fragment not in core:
            return fail(f"production core ownership contract lost {fragment!r}")

    installed_pid1 = re.search(
        r"(?ms)libexec_template \+ \{\s*"
        r"'name'\s*:\s*'systemd',.*?"
        r"'sources'\s*:\s*systemd_sources,.*?"
        r"'link_with'\s*:\s*\[\s*libcore,\s*libshared,\s*\].*?"
        r"'install'\s*:\s*get_option\('build-static'\) \? 'static' : 'yes',\s*\}",
        core,
    )
    if not installed_pid1:
        return fail("installed systemd no longer selects the C systemd/libcore sources")

    rust_pid1 = re.search(
        r"(?ms)rust_pid1\s*=\s*custom_target\(\s*"
        r"'systemd-rust-pid1',.*?"
        r"output\s*:\s*'systemd-rust',.*?"
        r"install\s*:\s*false\s*\)",
        core,
    )
    if not rust_pid1:
        return fail("experimental Rust PID1 is no longer a non-installed custom target")

    if "forbidden in release mode and for production installation" not in options:
        return fail("rust-core-pid1 option no longer documents its production prohibition")

    if "+ sd_future_sources +" not in libsystemd:
        return fail("sd_future_sources are no longer linked into libsystemd_sources")

    for relative in (
        "src/core/bpf-restrict-fsaccess.h",
        "src/core/bpf-restrict-fsaccess.c",
    ):
        missing_bpf = require_symbols(ROOT / relative, BPF_CONTRACT)
        if missing_bpf:
            return fail(f"{relative} lost BPF contract: {', '.join(missing_bpf)}")

    for relative in ("src/core/luo.h", "src/core/luo.c"):
        missing_luo = require_symbols(ROOT / relative, LUO_CONTRACT)
        if missing_luo:
            return fail(f"{relative} lost live-update contract: {', '.join(missing_luo)}")

    if not (ROOT / "src/systemd/sd-future.h").is_file():
        return fail("installed sd-future public header is missing")

    for source in CORE_SOURCES:
        if not (ROOT / "src/core" / source).is_file():
            return fail(f"retained core source does not exist: {source}")
    for source in FUTURE_SOURCES:
        if not (ROOT / "src/libsystemd" / source).is_file():
            return fail(f"retained sd-future source does not exist: {source}")

    print(
        "core C-retention gate OK: "
        f"core_sources={len(CORE_SOURCES)} future_sources={len(FUTURE_SOURCES)} "
        f"bpf_contract={len(BPF_CONTRACT)} luo_contract={len(LUO_CONTRACT)} "
        "rust_pid1=developer-only/non-installed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
