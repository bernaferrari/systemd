#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

SAFETY_LINTS = frozenset(
    {
        "clippy::missing_safety_doc",
        "clippy::not_unsafe_ptr_arg_deref",
        "improper_ctypes_definitions",
    }
)
UNSAFE_OP_LINT = "unsafe_op_in_unsafe_fn"
UNSAFE_CODE_LINT = "unsafe_code"
SAFETY_LINT_RATIONALE = "SAFETY-LINT:"
CRITICAL_ROOT_DENIES = {
    "src/basic/rust/lib.rs": SAFETY_LINTS,
    "src/shared/rust/lib.rs": SAFETY_LINTS,
    "src/core/rust/lib.rs": frozenset({"clippy::missing_safety_doc"}),
    "src/libsystemd/rust/lib.rs": frozenset({"clippy::missing_safety_doc"}),
}
DIRECT_ATTRIBUTE_RE = re.compile(
    r"(?m)^[ \t]*(?P<inner>#!|#)[ \t]*\[\s*"
    r"(?P<level>allow|warn|deny|forbid)\s*"
    r"\((?P<lints>.*?)\)\s*\]",
    re.DOTALL,
)
ANY_ATTRIBUTE_RE = re.compile(
    r"(?m)^[ \t]*(?P<inner>#!|#)\s*\[(?P<body>.*?)]",
    re.DOTALL,
)
ALLOW_CALL_RE = re.compile(r"\ballow\s*\(")
WEAKEN_CALL_RE = re.compile(r"\b(?:allow|warn)\s*\(")
UNSAFE_FN_DECL_RE = re.compile(
    r"(?m)^[ \t]*"
    r"(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:const\s+)?(?:async\s+)?"
    r"unsafe\s+(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\b"
)


@dataclass(frozen=True, order=True)
class BlanketAllowance:
    path: str
    lint: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "lint": self.lint}


@dataclass(frozen=True)
class WorkspaceInventory:
    members: tuple[str, ...]
    release_targets: tuple[str, ...]
    unsafe_function_members: frozenset[str]
    statically_safe_targets: frozenset[str]
    safe_targets_missing_deny: frozenset[str]
    unsafe_op_migration: frozenset[str]
    unsafe_op_weakening_errors: tuple[str, ...]
    blanket_allowances: frozenset[BlanketAllowance]
    scoped_allowance_errors: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enforce monotonic Rust safety-lint policy across every Cargo workspace "
            "release target without requiring a build."
        )
    )
    parser.add_argument(
        "--root", default=".", help="Repository root (default: current directory)"
    )
    parser.add_argument(
        "--baseline",
        default="tools/rust-port/rust-safety-lint-policy-baseline.json",
        help="Checked legacy-debt baseline relative to the repository root",
    )
    parser.add_argument(
        "--print-baseline",
        action="store_true",
        help="Print the exact current legacy-debt baseline to stdout",
    )
    return parser.parse_args()


def normalized_lints(raw: str) -> tuple[str, ...]:
    lints: list[str] = []
    for item in raw.split(","):
        lint = item.strip()
        if not lint or "=" in lint:
            continue
        lints.append(lint)
    return tuple(lints)


def workspace_members(root: Path) -> tuple[str, ...]:
    manifest_path = root / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        raise SystemExit(f"no Cargo workspace members found in {manifest_path}")

    result: list[str] = []
    for member in members:
        if not isinstance(member, str) or not member:
            raise SystemExit(f"invalid Cargo workspace member: {member!r}")
        path = Path(member)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"workspace member must be repository-relative: {member}")
        normalized = path.as_posix()
        if not (root / normalized / "Cargo.toml").is_file():
            raise SystemExit(f"workspace member has no Cargo.toml: {normalized}")
        result.append(normalized)

    if len(result) != len(set(result)):
        raise SystemExit("Cargo workspace contains duplicate members")
    return tuple(result)


def add_target(targets: set[str], root: Path, member: str, target: str) -> None:
    target_path = Path(target)
    if target_path.is_absolute() or ".." in target_path.parts:
        raise SystemExit(f"release target must be member-relative: {member}/{target}")
    relative = (Path(member) / target_path).as_posix()
    if not (root / relative).is_file():
        raise SystemExit(f"declared Cargo release target does not exist: {relative}")
    targets.add(relative)


def release_targets(root: Path, members: tuple[str, ...]) -> tuple[str, ...]:
    targets: set[str] = set()
    for member in members:
        member_dir = root / member
        manifest = tomllib.loads(
            (member_dir / "Cargo.toml").read_text(encoding="utf-8")
        )

        library = manifest.get("lib")
        if isinstance(library, dict):
            add_target(targets, root, member, str(library.get("path", "src/lib.rs")))
        elif (member_dir / "src/lib.rs").is_file():
            add_target(targets, root, member, "src/lib.rs")

        bins = manifest.get("bin", [])
        if not isinstance(bins, list):
            raise SystemExit(f"invalid [[bin]] list in {member}/Cargo.toml")
        for binary in bins:
            if not isinstance(binary, dict) or not isinstance(binary.get("name"), str):
                raise SystemExit(f"invalid [[bin]] entry in {member}/Cargo.toml")
            default_path = f"src/bin/{binary['name']}.rs"
            add_target(targets, root, member, str(binary.get("path", default_path)))

        package = manifest.get("package", {})
        if not isinstance(package, dict):
            raise SystemExit(f"invalid [package] table in {member}/Cargo.toml")
        if package.get("autobins", True):
            if (member_dir / "src/main.rs").is_file():
                add_target(targets, root, member, "src/main.rs")
            bin_dir = member_dir / "src/bin"
            if bin_dir.is_dir():
                for candidate in sorted(bin_dir.glob("*.rs")):
                    add_target(
                        targets, root, member, candidate.relative_to(member_dir).as_posix()
                    )
                for candidate in sorted(bin_dir.glob("*/main.rs")):
                    add_target(
                        targets, root, member, candidate.relative_to(member_dir).as_posix()
                    )

        if not any(
            target == member or target.startswith(member.rstrip("/") + "/")
            for target in targets
        ):
            raise SystemExit(f"workspace member has no release target: {member}")

    return tuple(sorted(targets))


def has_unsafe_op_deny(text: str) -> bool:
    for match in DIRECT_ATTRIBUTE_RE.finditer(text):
        if match.group("inner") != "#!":
            continue
        if match.group("level") not in {"deny", "forbid"}:
            continue
        lints = normalized_lints(match.group("lints"))
        if UNSAFE_OP_LINT in lints or UNSAFE_CODE_LINT in lints:
            return True
    return False


def inner_denied_lints(text: str) -> frozenset[str]:
    denied: set[str] = set()
    for match in DIRECT_ATTRIBUTE_RE.finditer(text):
        if match.group("inner") != "#!":
            continue
        if match.group("level") not in {"deny", "forbid"}:
            continue
        denied.update(normalized_lints(match.group("lints")))
    return frozenset(denied)


def weakens_unsafe_op_policy(text: str) -> bool:
    for match in ANY_ATTRIBUTE_RE.finditer(text):
        if match.group("inner") != "#!":
            continue
        body = match.group("body")
        if UNSAFE_OP_LINT in body and WEAKEN_CALL_RE.search(body):
            return True
    return False


def has_unsafe_function_declaration(text: str) -> bool:
    return bool(UNSAFE_FN_DECL_RE.search(text))


def validate_unsafe_fn_parser() -> None:
    declarations = (
        "unsafe fn local() {}",
        "pub unsafe fn exported() {}",
        'pub(crate) unsafe extern "C" fn ffi() {}',
        "    async unsafe fn associated() {}",
    )
    non_declarations = (
        'type Callback = unsafe extern "C" fn(*mut u8);',
        'const CALLBACK: unsafe extern "C" fn() = handler;',
        '    callback: unsafe extern "C" fn(),',
        '// unsafe fn mentioned_in_a_comment()',
    )
    if not all(has_unsafe_function_declaration(case) for case in declarations):
        raise SystemExit("internal unsafe-function declaration parser self-check failed")
    if any(has_unsafe_function_declaration(case) for case in non_declarations):
        raise SystemExit(
            "internal unsafe-function type/reference parser self-check failed"
        )
    if not weakens_unsafe_op_policy("#![allow(unsafe_op_in_unsafe_fn)]"):
        raise SystemExit("internal unsafe-op weakening parser self-check failed")
    if not weakens_unsafe_op_policy(
        "#![cfg_attr(test, warn(unsafe_op_in_unsafe_fn))]"
    ):
        raise SystemExit("internal conditional unsafe-op parser self-check failed")
    if weakens_unsafe_op_policy("#![deny(unsafe_op_in_unsafe_fn)]"):
        raise SystemExit("internal unsafe-op deny parser self-check failed")


def has_scoped_rationale(text: str, offset: int) -> bool:
    line_start = text.rfind("\n", 0, offset) + 1
    prefix = text[:line_start].splitlines()
    for line in reversed(prefix[-4:]):
        stripped = line.strip()
        if SAFETY_LINT_RATIONALE in stripped:
            return True
        if stripped and not stripped.startswith(("//", "#[")):
            break
    return False


def inspect_source(
    root: Path, path: Path
) -> tuple[set[BlanketAllowance], list[str]]:
    text = path.read_text(encoding="utf-8", errors="strict")
    relative = path.relative_to(root).as_posix()
    blanket: set[BlanketAllowance] = set()
    errors: list[str] = []

    for match in ANY_ATTRIBUTE_RE.finditer(text):
        body = match.group("body")
        if not ALLOW_CALL_RE.search(body):
            continue
        for lint in SAFETY_LINTS:
            if lint not in body:
                continue
            if match.group("inner") == "#!":
                blanket.add(BlanketAllowance(relative, lint))
                continue
            if not has_scoped_rationale(text, match.start()):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{relative}:{line}: scoped allow({lint}) lacks an adjacent "
                    f"{SAFETY_LINT_RATIONALE} rationale"
                )

    return blanket, errors


def collect_inventory(root: Path) -> WorkspaceInventory:
    members = workspace_members(root)
    targets = release_targets(root, members)

    source_paths: set[Path] = set()
    member_source_paths: dict[str, list[Path]] = {}
    for member in members:
        member_sources: list[Path] = []
        for path in (root / member).rglob("*.rs"):
            if "target" not in path.relative_to(root / member).parts:
                source_paths.add(path)
                member_sources.append(path)
        member_source_paths[member] = member_sources

    unsafe_function_members = frozenset(
        member
        for member, paths in member_source_paths.items()
        if any(
            has_unsafe_function_declaration(path.read_text(encoding="utf-8"))
            for path in paths
        )
    )

    def target_member(target: str) -> str:
        owners = [
            member
            for member in members
            if target.startswith(member.rstrip("/") + "/")
        ]
        if len(owners) != 1:
            raise SystemExit(
                f"release target must belong to exactly one workspace member: {target}"
            )
        return owners[0]

    target_members = {target: target_member(target) for target in targets}
    statically_safe_targets = frozenset(
        target
        for target, member in target_members.items()
        if member not in unsafe_function_members
    )
    missing_deny = frozenset(
        target
        for target in targets
        if not has_unsafe_op_deny((root / target).read_text(encoding="utf-8"))
    )
    unsafe_op_weakening_errors = tuple(
        target
        for target in targets
        if weakens_unsafe_op_policy((root / target).read_text(encoding="utf-8"))
    )
    safe_targets_missing_deny = missing_deny & statically_safe_targets
    unsafe_op_migration = frozenset(
        target
        for target in missing_deny
        if target_members[target] in unsafe_function_members
    )

    blanket: set[BlanketAllowance] = set()
    scoped_errors: list[str] = []
    for path in sorted(source_paths):
        source_blanket, source_errors = inspect_source(root, path)
        blanket.update(source_blanket)
        scoped_errors.extend(source_errors)

    return WorkspaceInventory(
        members=members,
        release_targets=targets,
        unsafe_function_members=unsafe_function_members,
        statically_safe_targets=statically_safe_targets,
        safe_targets_missing_deny=safe_targets_missing_deny,
        unsafe_op_migration=unsafe_op_migration,
        unsafe_op_weakening_errors=unsafe_op_weakening_errors,
        blanket_allowances=frozenset(blanket),
        scoped_allowance_errors=tuple(scoped_errors),
    )


def baseline_payload(inventory: WorkspaceInventory) -> dict[str, object]:
    return {
        "version": 1,
        "unsafe_op_in_unsafe_fn_missing": sorted(inventory.unsafe_op_migration),
        "blanket_safety_lint_allowances": [
            allowance.to_dict() for allowance in sorted(inventory.blanket_allowances)
        ],
    }


def load_baseline(path: Path) -> tuple[frozenset[str], frozenset[BlanketAllowance]]:
    if not path.is_file():
        raise SystemExit(f"safety lint policy baseline not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("version") != 1:
        raise SystemExit(f"unsupported safety lint policy baseline version in {path}")

    unsafe_missing_raw = raw.get("unsafe_op_in_unsafe_fn_missing")
    blanket_raw = raw.get("blanket_safety_lint_allowances")
    if not isinstance(unsafe_missing_raw, list) or not isinstance(blanket_raw, list):
        raise SystemExit(f"malformed safety lint policy baseline: {path}")

    unsafe_missing = frozenset(str(item) for item in unsafe_missing_raw)
    blanket: set[BlanketAllowance] = set()
    for item in blanket_raw:
        if not isinstance(item, dict) or set(item) != {"path", "lint"}:
            raise SystemExit(f"malformed blanket allowance in {path}: {item!r}")
        allowance = BlanketAllowance(str(item["path"]), str(item["lint"]))
        if allowance.lint not in SAFETY_LINTS:
            raise SystemExit(
                f"baseline contains an unsupported safety lint: {allowance.lint}"
            )
        blanket.add(allowance)

    if len(unsafe_missing) != len(unsafe_missing_raw):
        raise SystemExit(f"duplicate unsafe-op target in {path}")
    if len(blanket) != len(blanket_raw):
        raise SystemExit(f"duplicate blanket allowance in {path}")
    return unsafe_missing, frozenset(blanket)


def report_set_delta(
    label: str, current: frozenset[object], baseline: frozenset[object]
) -> bool:
    failed = False
    for item in sorted(current - baseline):
        print(f"FAIL new {label}: {item}", file=sys.stderr)
        failed = True
    for item in sorted(baseline - current):
        print(
            f"FAIL stale {label} baseline entry (remove it to record the improvement): "
            f"{item}",
            file=sys.stderr,
        )
        failed = True
    return failed


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    validate_unsafe_fn_parser()
    inventory = collect_inventory(root)

    if args.print_baseline:
        print(json.dumps(baseline_payload(inventory), indent=2) + "\n", end="")
        return 0

    unsafe_baseline, blanket_baseline = load_baseline(root / args.baseline)
    failed = False

    critical_policy_errors = 0
    for relative, required in CRITICAL_ROOT_DENIES.items():
        denied = inner_denied_lints((root / relative).read_text(encoding="utf-8"))
        for lint in sorted(required - denied):
            print(
                f"FAIL critical release root must deny {lint}: {relative}",
                file=sys.stderr,
            )
            critical_policy_errors += 1
            failed = True

    for error in inventory.scoped_allowance_errors:
        print(f"FAIL {error}", file=sys.stderr)
        failed = True

    for target in sorted(inventory.safe_targets_missing_deny):
        print(
            "FAIL statically safe release target must deny "
            f"unsafe_op_in_unsafe_fn: {target}",
            file=sys.stderr,
        )
        failed = True

    for target in inventory.unsafe_op_weakening_errors:
        print(
            "FAIL release target explicitly weakens unsafe_op_in_unsafe_fn: "
            f"{target}",
            file=sys.stderr,
        )
        failed = True

    failed |= report_set_delta(
        "unsafe-function release target missing deny(unsafe_op_in_unsafe_fn)",
        inventory.unsafe_op_migration,
        unsafe_baseline,
    )
    failed |= report_set_delta(
        "blanket safety-lint allowance",
        inventory.blanket_allowances,
        blanket_baseline,
    )

    status = "FAIL" if failed else "OK"
    unsafe_op_deny = (
        len(inventory.release_targets)
        - len(inventory.safe_targets_missing_deny)
        - len(inventory.unsafe_op_migration)
    )
    print(
        "Rust safety lint policy "
        f"{status}: workspace_members={len(inventory.members)} "
        f"release_targets={len(inventory.release_targets)} "
        f"unsafe_function_members={len(inventory.unsafe_function_members)} "
        f"statically_safe_targets={len(inventory.statically_safe_targets)} "
        f"unsafe_op_deny={unsafe_op_deny} "
        f"unsafe_op_migration={len(inventory.unsafe_op_migration)} "
        f"safe_target_policy_errors={len(inventory.safe_targets_missing_deny)} "
        f"unsafe_op_weakening_errors={len(inventory.unsafe_op_weakening_errors)} "
        f"blanket_allowances={len(inventory.blanket_allowances)} "
        f"critical_policy_errors={critical_policy_errors} "
        f"scoped_allowance_errors={len(inventory.scoped_allowance_errors)}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
