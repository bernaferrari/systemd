#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path


@dataclass(frozen=True)
class Waiver:
    advisory_id: str
    reason: str
    expires: date | None
    kind: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run cargo-audit against committed Cargo.lock files with waiver support."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root (default: current directory).",
    )
    parser.add_argument(
        "--waivers",
        default="tools/rust-port/cargo-audit-waivers.toml",
        help="Waiver TOML file.",
    )
    parser.add_argument(
        "--write-report",
        default="",
        help="Optional path to write a markdown report.",
    )
    return parser.parse_args()


def find_lockfiles(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "*Cargo.lock"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    lockfiles = [
        root / raw.decode("utf-8")
        for raw in result.stdout.split(b"\0")
        if raw
    ]
    missing = [path for path in lockfiles if not path.is_file()]
    if missing:
        raise SystemExit(
            "tracked lockfile is missing: " + ", ".join(str(path) for path in missing)
        )
    return sorted(lockfiles)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def group_lockfiles(lockfiles: list[Path]) -> list[tuple[Path, list[Path]]]:
    groups: dict[str, list[Path]] = {}
    for lockfile in lockfiles:
        digest = hash_file(lockfile)
        groups.setdefault(digest, []).append(lockfile)

    grouped: list[tuple[Path, list[Path]]] = []
    for _, paths in sorted(groups.items(), key=lambda item: str(item[1][0])):
        representative = paths[0]
        grouped.append((representative, paths))
    return grouped


def parse_waivers(path: Path) -> dict[str, Waiver]:
    if not path.exists():
        raise SystemExit(f"waiver file not found: {path}")

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    rows = data.get("waiver", [])
    if not isinstance(rows, list):
        raise SystemExit(f"invalid waiver format in {path}: expected [[waiver]]")

    waivers: dict[str, Waiver] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit(f"invalid waiver entry in {path}")

        advisory_id = str(row.get("id", "")).strip()
        reason = str(row.get("reason", "")).strip()
        if not advisory_id or not reason:
            raise SystemExit(f"waiver entries require id and reason: {row}")

        expires_raw = row.get("expires")
        expires_value: date | None = None
        if expires_raw is not None:
            expires_value = date.fromisoformat(str(expires_raw))

        kind_raw = row.get("kind")
        kind = str(kind_raw).strip() if kind_raw is not None else None
        waivers[advisory_id] = Waiver(
            advisory_id=advisory_id,
            reason=reason,
            expires=expires_value,
            kind=kind or None,
        )
    return waivers


def run_audit(root: Path, lockfile: Path, stale: bool) -> dict[str, object]:
    cmd = ["cargo", "audit", "--json", "--file", str(lockfile)]
    if stale:
        cmd.insert(2, "--stale")

    proc = subprocess.run(
        cmd,
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        details = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(f"cargo audit failed for {lockfile}: {details}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"failed to parse cargo audit JSON for {lockfile}: {exc}") from exc


def advisory_id(item: object) -> str:
    if not isinstance(item, dict):
        return "<unknown>"
    advisory = item.get("advisory")
    if not isinstance(advisory, dict):
        return "<unknown>"
    advisory_id_value = advisory.get("id")
    if advisory_id_value is None:
        return "<unknown>"
    advisory_id_text = str(advisory_id_value).strip()
    return advisory_id_text or "<unknown>"


def collect_findings(data: dict[str, object]) -> tuple[list[str], list[tuple[str, str]]]:
    vulnerabilities: list[str] = []
    warnings: list[tuple[str, str]] = []

    vulnerabilities_root = data.get("vulnerabilities", {})
    if isinstance(vulnerabilities_root, dict):
        vuln_list = vulnerabilities_root.get("list", [])
        if isinstance(vuln_list, list):
            for item in vuln_list:
                vulnerabilities.append(advisory_id(item))

    warnings_root = data.get("warnings", {})
    if isinstance(warnings_root, dict):
        for kind, entries in warnings_root.items():
            if not isinstance(entries, list):
                continue
            for item in entries:
                warnings.append((str(kind), advisory_id(item)))

    return vulnerabilities, warnings


def status_for_id(
    advisory_id_value: str,
    finding_kind: str,
    waivers: dict[str, Waiver],
    today: date,
) -> tuple[bool, str]:
    waiver = waivers.get(advisory_id_value)
    if waiver is None:
        return False, "unwaived"
    if waiver.expires is not None and waiver.expires < today:
        return False, f"waiver-expired({waiver.expires.isoformat()})"
    if waiver.kind is not None and waiver.kind != finding_kind:
        return False, f"waiver-kind-mismatch({waiver.kind})"
    if waiver.expires is not None:
        return True, f"waived(until {waiver.expires.isoformat()}: {waiver.reason})"
    return True, f"waived({waiver.reason})"


def write_report(
    path: Path,
    rows: list[str],
    findings: list[str],
    lockfiles: int,
    unique_lockfiles: int,
) -> None:
    content = [
        "# Rust Dependency Audit",
        "",
        f"- lockfiles scanned: `{lockfiles}`",
        f"- unique lockfile graphs: `{unique_lockfiles}`",
        "",
        "## Lockfile Summary",
        "",
        "| Lockfile | Aliases | Vulnerabilities | Warnings | Status |",
        "|---|---:|---:|---:|---|",
        *rows,
        "",
        "## Advisory Findings",
        "",
    ]
    if findings:
        content.extend(findings)
    else:
        content.append("- none")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    waiver_file = root / args.waivers
    waivers = parse_waivers(waiver_file)

    lockfiles = find_lockfiles(root)
    if not lockfiles:
        raise SystemExit("no Cargo.lock files found")

    grouped = group_lockfiles(lockfiles)
    today = date.today()

    failed = False
    summary_rows: list[str] = []
    finding_rows: list[str] = []
    seen_finding_keys: set[tuple[str, str]] = set()
    print("lockfile,aliases,vulnerabilities,warnings,status")

    for index, (representative, aliases) in enumerate(grouped):
        data = run_audit(root, representative, stale=index > 0)
        vulnerabilities, warnings = collect_findings(data)
        status = "OK"

        for advisory in vulnerabilities:
            is_waived, waiver_status = status_for_id(
                advisory, "vulnerability", waivers, today
            )
            if not is_waived:
                failed = True
                status = "FAIL"
            finding_key = ("vulnerability", advisory)
            if finding_key not in seen_finding_keys:
                seen_finding_keys.add(finding_key)
                finding_rows.append(
                    f"- vulnerability `{advisory}`: `{waiver_status}`"
                )

        for warning_kind, advisory in warnings:
            is_waived, waiver_status = status_for_id(
                advisory, warning_kind, waivers, today
            )
            if not is_waived:
                failed = True
                status = "FAIL"
            finding_key = (warning_kind, advisory)
            if finding_key not in seen_finding_keys:
                seen_finding_keys.add(finding_key)
                finding_rows.append(
                    f"- warning `{warning_kind}` / `{advisory}`: `{waiver_status}`"
                )

        rel = representative.relative_to(root)
        print(f"{rel},{len(aliases)},{len(vulnerabilities)},{len(warnings)},{status}")
        summary_rows.append(
            f"| `{rel}` | {len(aliases)} | {len(vulnerabilities)} | {len(warnings)} | {status} |"
        )

    if args.write_report:
        report_path = root / args.write_report
        write_report(
            report_path,
            summary_rows,
            finding_rows,
            lockfiles=len(lockfiles),
            unique_lockfiles=len(grouped),
        )
        print(f"wrote report: {report_path.relative_to(root)}")

    if failed:
        print("cargo audit all FAILED", file=sys.stderr)
        return 1

    print("cargo audit all OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
