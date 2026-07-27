#!/usr/bin/env python3
"""Classify Basic/Shared Rust modules for Port 1 audit."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
TARGET_DIRS = (ROOT / "src" / "basic" / "rust", ROOT / "src" / "shared" / "rust")

LOGIC_TOKEN_RE = re.compile(r"\b(match|if|for|while|loop|impl|enum|struct|trait)\b")
FN_DEF_RE = re.compile(r"\bfn\s+[A-Za-z0-9_]+\s*\(")
FFI_DECL_RE = re.compile(r"\bfn\s+[A-Za-z0-9_]+\s*\([^\)]*\)\s*(?:->\s*[^;{]+)?\s*;")
PORT_STUB_RE = re.compile(r"rs_[A-Za-z0-9_]*port_stub")


@dataclass(frozen=True)
class Row:
    path: str
    category: str
    extern_blocks: int
    fn_defs: int
    ffi_decls: int
    logic_tokens: int


def iter_rs_files() -> Iterable[Path]:
    for root in TARGET_DIRS:
        for path in sorted(root.glob("*.rs")):
            if path.name == "lib.rs":
                continue
            yield path


def strip_comments_and_blanks(text: str) -> str:
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        lines.append(s)
    return "\n".join(lines)


def classify(path: Path) -> Row:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    code = strip_comments_and_blanks(raw)

    extern_blocks = raw.count('extern "C"')
    fn_defs = len(FN_DEF_RE.findall(code))
    ffi_decls = len(FFI_DECL_RE.findall(code))
    logic_tokens = len(LOGIC_TOKEN_RE.findall(code))

    if "PortSyncModule" in raw or "crate::port_sync" in raw:
        category = "metadata"
    elif PORT_STUB_RE.search(raw):
        category = "stub-wrapper"
    elif extern_blocks == 0:
        category = "genuine-rust"
    elif ffi_decls >= max(1, fn_defs) and logic_tokens <= 8 and fn_defs <= 15:
        category = "thin-ffi-wrapper"
    else:
        category = "ffi-backed-rust"

    return Row(
        path=str(path.relative_to(ROOT)),
        category=category,
        extern_blocks=extern_blocks,
        fn_defs=fn_defs,
        ffi_decls=ffi_decls,
        logic_tokens=logic_tokens,
    )


def render(rows: list[Row]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(row.category for row in rows)
    thin = [row for row in rows if row.category in {"thin-ffi-wrapper", "stub-wrapper", "metadata"}]
    ffi_backed = [row for row in rows if row.category == "ffi-backed-rust"]

    out = []
    out.append("# Port 1 Basic/Shared Audit")
    out.append("")
    out.append(f"Generated: {now}")
    out.append(f"Repository: `{ROOT}`")
    out.append("")
    out.append("## Scope")
    out.append("")
    out.append("- `src/basic/rust/*.rs` (excluding `lib.rs`)")
    out.append("- `src/shared/rust/*.rs` (excluding `lib.rs`)")
    out.append("")
    out.append("## Classification Summary")
    out.append("")
    out.append(f"- Total modules audited: **{len(rows)}**")
    for cat in ["genuine-rust", "ffi-backed-rust", "thin-ffi-wrapper", "stub-wrapper", "metadata"]:
        out.append(f"- `{cat}`: **{counts.get(cat, 0)}**")
    out.append("")
    out.append("Definitions:")
    out.append("- `genuine-rust`: no `extern \"C\"` block; implemented logic lives in Rust.")
    out.append("- `ffi-backed-rust`: Rust owns control flow/logic but calls external C symbols for selected operations.")
    out.append("- `thin-ffi-wrapper`: mostly forwarding glue with low internal logic density.")
    out.append("- `stub-wrapper`: explicit `*_port_stub` symbols.")
    out.append("- `metadata`: Port-sync inventory/spec modules rather than behavior implementations.")
    out.append("")

    out.append("## Thin-Wrapper Candidates")
    out.append("")
    if not thin:
        out.append("No thin/stub/metadata modules were detected in the audited Basic/Shared scope.")
    else:
        out.append("| Module | Category | extern C blocks | fn defs | ffi decls | logic tokens |")
        out.append("|---|---:|---:|---:|---:|---:|")
        for row in thin:
            out.append(
                f"| `{row.path}` | `{row.category}` | {row.extern_blocks} | {row.fn_defs} | {row.ffi_decls} | {row.logic_tokens} |"
            )
    out.append("")

    out.append("## FFI-Backed Rust Modules")
    out.append("")
    if not ffi_backed:
        out.append("No FFI-backed modules detected.")
    else:
        out.append("| Module | extern C blocks | fn defs | ffi decls | logic tokens |")
        out.append("|---|---:|---:|---:|---:|")
        for row in ffi_backed:
            out.append(
                f"| `{row.path}` | {row.extern_blocks} | {row.fn_defs} | {row.ffi_decls} | {row.logic_tokens} |"
            )
    out.append("")

    out.append("## Actionable Outcome")
    out.append("")
    if counts.get("thin-ffi-wrapper", 0) == 0 and counts.get("stub-wrapper", 0) == 0 and counts.get("metadata", 0) == 0:
        out.append("- No deletion candidates found in Basic/Shared by this audit; modules are either genuine Rust or FFI-backed Rust implementations.")
        out.append("- Existing crate layout (`src/basic/rust`, `src/shared/rust`) already hosts migrated Rust logic for Port 1 scope.")
    else:
        out.append("- Review the table above and convert/delete thin wrappers as follow-up work.")
    out.append("")

    out.append("## Rebuild")
    out.append("")
    out.append("```sh")
    out.append("python3 tools/rust-port/audit-port1.py --write docs/rust-port-port1-audit.md")
    out.append("```")
    out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Basic/Shared Rust modules for Port 1 classification.")
    parser.add_argument(
        "--write",
        type=Path,
        default=Path("docs/rust-port-port1-audit.md"),
        help="Output markdown path (default: docs/rust-port-port1-audit.md)",
    )
    args = parser.parse_args()

    rows = [classify(path) for path in iter_rs_files()]
    rendered = render(rows)

    output_path = args.write
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered + "\n", encoding="utf-8")

    print(f"Wrote {output_path} ({len(rows)} modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
