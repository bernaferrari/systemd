#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Validate the single-workspace architecture used by the Rust port."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


CHRONOLOGICAL_MODULE_RE = re.compile(
    r"^(?:shared_validators|shared_str_tables|misc_validators|misc_rust)\d+\.rs$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Rust workspace membership, targets, lockfile ownership, and Meson inputs."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--large-file-policy",
        default="tools/rust-port/large-rust-files.toml",
        help="Production Rust file-size debt policy, relative to the repository root",
    )
    parser.add_argument(
        "--layer-policy",
        default="tools/rust-port/workspace-layers.toml",
        help=(
            "Rust crate layout and dependency-layer policy, relative to the "
            "repository root"
        ),
    )
    return parser.parse_args()


def dependency_name(alias: str, specification: Any) -> str:
    if isinstance(specification, dict):
        package = specification.get("package")
        if isinstance(package, str):
            return package
    return alias


def manifest_dependencies(manifest: dict[str, Any]) -> set[str]:
    dependencies: set[str] = set()
    sections = ("dependencies", "dev-dependencies", "build-dependencies")

    for section in sections:
        for alias, specification in manifest.get(section, {}).items():
            dependencies.add(dependency_name(alias, specification))

    for target in manifest.get("target", {}).values():
        if not isinstance(target, dict):
            continue
        for section in sections:
            for alias, specification in target.get(section, {}).items():
                dependencies.add(dependency_name(alias, specification))

    return dependencies


def explicit_targets(manifest: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    library = manifest.get("lib")
    if isinstance(library, dict) and isinstance(library.get("path"), str):
        targets.append(library["path"])

    binaries = manifest.get("bin", [])
    if isinstance(binaries, dict):
        binaries = [binaries]
    for binary in binaries:
        if isinstance(binary, dict) and isinstance(binary.get("path"), str):
            targets.append(binary["path"])
    return targets


def explicit_binary_names(manifest: dict[str, Any]) -> list[str]:
    binaries = manifest.get("bin", [])
    if isinstance(binaries, dict):
        binaries = [binaries]
    return [
        binary["name"]
        for binary in binaries
        if isinstance(binary, dict) and isinstance(binary.get("name"), str)
    ]


def tracked_lockfiles(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "*Cargo.lock"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(line for line in result.stdout.splitlines() if line)


def load_layer_policy(policy_path: Path) -> tuple[str, dict[str, int], dict[str, str]]:
    """Load the intentionally small, explicit workspace layering policy."""

    policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    metadata = policy.get("policy", {})
    layout = metadata.get("member_layout")
    default_layer = metadata.get("default_layer")
    layers = policy.get("layers", {})
    if layout != "src/<subsystem>/rust":
        raise ValueError("policy.member_layout must be src/<subsystem>/rust")
    if not isinstance(default_layer, str) or not default_layer:
        raise ValueError("policy.default_layer must name a layer")
    if not isinstance(layers, dict) or not layers:
        raise ValueError("layers must be a non-empty table")

    ranks: dict[str, int] = {}
    assigned: dict[str, str] = {}
    for layer_name, layer in layers.items():
        if not isinstance(layer_name, str) or not isinstance(layer, dict):
            raise ValueError("layers must contain named tables")
        rank = layer.get("rank")
        members = layer.get("members", [])
        if not isinstance(rank, int) or rank < 0:
            raise ValueError(f"layers.{layer_name}.rank must be a non-negative integer")
        if not isinstance(members, list) or not all(
            isinstance(member, str) and member for member in members
        ):
            raise ValueError(f"layers.{layer_name}.members must be a string array")
        ranks[layer_name] = rank
        for member in members:
            previous = assigned.get(member)
            if previous is not None:
                raise ValueError(
                    f"{member} is assigned to both layers {previous} and {layer_name}"
                )
            assigned[member] = layer_name
    if default_layer not in ranks:
        raise ValueError(f"policy.default_layer {default_layer!r} is not declared")
    return default_layer, ranks, assigned


def is_canonical_member_path(member: str) -> bool:
    """Return whether a member lives at src/<subsystem>/rust exactly."""

    parts = Path(member).parts
    return (
        len(parts) == 3
        and parts[0] == "src"
        and parts[1] not in {"", ".", ".."}
        and parts[2] == "rust"
    )


def validate_member_layout(
    root: Path, members: list[str], assigned_layers: dict[str, str], failures: list[str]
) -> None:
    """Keep one Cargo crate per C subsystem and no orphan Rust manifests."""

    member_set = set(members)
    for member in members:
        if not is_canonical_member_path(member):
            failures.append(
                f"{member}: workspace member must live at src/<subsystem>/rust"
            )
    for assigned in sorted(set(assigned_layers) - member_set):
        failures.append(f"layer policy assigns non-workspace member {assigned}")

    discovered: set[str] = set()
    for manifest in (root / "src").rglob("Cargo.toml"):
        relative = manifest.parent.relative_to(root).as_posix()
        if not is_canonical_member_path(relative):
            failures.append(
                f"{manifest.relative_to(root)}: Rust Cargo manifests must live at "
                "src/<subsystem>/rust/Cargo.toml"
            )
            continue
        discovered.add(relative)
    for member in sorted(discovered - member_set):
        failures.append(f"{member}: canonical Rust crate is missing from workspace members")
    for member in sorted(member_set - discovered):
        failures.append(f"{member}: workspace member has no canonical Rust Cargo.toml")


def validate_module_names(root: Path, failures: list[str]) -> None:
    """Reject batch chronology where a module should name its responsibility."""

    for path in (root / "src").rglob("*.rs"):
        if CHRONOLOGICAL_MODULE_RE.fullmatch(path.name):
            failures.append(
                f"{path.relative_to(root)}: chronological Rust module name is "
                "forbidden; use a semantic owner or a focused directory"
            )


def validate_target_path(
    member: str, manifest_path: Path, target: str, failures: list[str]
) -> None:
    """Reject target indirection outside the owning subsystem's Rust directory."""

    target_path = Path(target)
    if target_path.is_absolute() or ".." in target_path.parts:
        failures.append(f"{member}: target path escapes its Rust crate: {target}")
        return
    candidate = (manifest_path.parent / target_path).resolve()
    try:
        candidate.relative_to(manifest_path.parent.resolve())
    except ValueError:
        failures.append(f"{member}: target path escapes its Rust crate: {target}")


def validate_dependency_layers(
    manifests: dict[str, dict[str, Any]],
    member_names: dict[str, str],
    default_layer: str,
    ranks: dict[str, int],
    assigned_layers: dict[str, str],
    failures: list[str],
) -> None:
    """Allow internal dependencies only from a higher layer to a lower one."""

    for member, manifest in sorted(manifests.items()):
        layer = assigned_layers.get(member, default_layer)
        rank = ranks[layer]
        for dependency in sorted(manifest_dependencies(manifest)):
            dependency_member = member_names.get(dependency)
            if dependency_member is None:
                continue
            dependency_layer = assigned_layers.get(dependency_member, default_layer)
            dependency_rank = ranks[dependency_layer]
            if dependency_rank >= rank:
                failures.append(
                    f"{member}: layer {layer} may not depend on {dependency_member} "
                    f"in layer {dependency_layer}"
                )


def validate_language_contract(
    workspace: dict[str, Any],
    manifests: dict[str, dict[str, Any]],
    failures: list[str],
) -> None:
    """Keep every crate on the workspace's Rust 2024 language contract."""

    resolver = workspace.get("workspace", {}).get("resolver")
    if resolver != "3":
        failures.append(
            f"workspace.resolver must be '3' for the Rust 2024 workspace, got {resolver!r}"
        )

    for member, manifest in sorted(manifests.items()):
        edition = manifest.get("package", {}).get("edition")
        if edition != "2024":
            failures.append(
                f"{member}: package.edition must be '2024', got {edition!r}"
            )


def validate_large_rust_files(
    root: Path, policy_path: Path, failures: list[str]
) -> tuple[int, int]:
    policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    max_lines = policy.get("policy", {}).get("max_lines")
    allowed = policy.get("files", {})
    if not isinstance(max_lines, int) or max_lines <= 0:
        failures.append(f"{policy_path.relative_to(root)}: max_lines must be a positive integer")
        return 0, 0
    if not isinstance(allowed, dict):
        failures.append(f"{policy_path.relative_to(root)}: files must be a table")
        return max_lines, 0

    observed: dict[str, int] = {}
    for path in (root / "src").rglob("*.rs"):
        relative = path.relative_to(root)
        if "rust" not in relative.parts:
            continue
        if (
            path.name == "tests.rs"
            or path.name.endswith("_tests.rs")
            or "tests" in relative.parts
        ):
            continue

        line_count = sum(1 for _ in path.open(encoding="utf-8"))
        if line_count <= max_lines:
            continue
        relative_text = relative.as_posix()
        observed[relative_text] = line_count
        entry = allowed.get(relative_text)
        if not isinstance(entry, dict):
            failures.append(
                f"{relative_text}: {line_count} production lines exceeds {max_lines} "
                "without an architecture-debt entry"
            )
            continue
        cap = entry.get("max_lines")
        issue = entry.get("issue")
        reason = entry.get("reason")
        if not isinstance(cap, int) or cap < line_count:
            failures.append(
                f"{relative_text}: {line_count} production lines exceeds its debt cap {cap!r}"
            )
        if not isinstance(issue, str) or not issue:
            failures.append(f"{relative_text}: debt entry needs a tracking issue")
        if not isinstance(reason, str) or not reason:
            failures.append(f"{relative_text}: debt entry needs a decomposition rationale")

    for relative_text in sorted(set(allowed) - set(observed)):
        failures.append(
            f"{policy_path.relative_to(root)}: stale large-file debt entry {relative_text}"
        )

    return max_lines, len(observed)


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    workspace_path = root / "Cargo.toml"
    lock_path = root / "Cargo.lock"
    layer_policy_path = Path(args.layer_policy)
    if not layer_policy_path.is_absolute():
        layer_policy_path = root / layer_policy_path

    workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    members = workspace.get("workspace", {}).get("members", [])
    lock_packages = lock.get("package", [])

    failures: list[str] = []
    try:
        default_layer, layer_ranks, assigned_layers = load_layer_policy(
            layer_policy_path
        )
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(
            f"Rust workspace architecture gate: cannot load layer policy: {exc}",
            file=sys.stderr,
        )
        return 2
    if not isinstance(members, list) or not all(
        isinstance(member, str) for member in members
    ):
        failures.append("workspace.members must be a string array")
        members = []
    validate_member_layout(root, members, assigned_layers, failures)
    validate_module_names(root, failures)
    large_file_limit, acknowledged_large_files = validate_large_rust_files(
        root, root / args.large_file_policy, failures
    )
    meson_texts: dict[Path, str] = {
        path: path.read_text(encoding="utf-8", errors="ignore")
        for path in root.rglob("meson.build")
    }
    meson_artifact_names: set[str] = set()
    for text in meson_texts.values():
        meson_artifact_names.update(
            re.findall(r"""['"]name['"]\s*:\s*['"]([^'"]+)['"]""", text)
        )
        meson_artifact_names.update(
            re.findall(r"""install_symlink\(\s*['"]([^'"]+)['"]""", text)
        )

    tracked_locks = tracked_lockfiles(root)
    if tracked_locks != ["Cargo.lock"]:
        failures.append(
            "the repository must track exactly one workspace lockfile; found "
            + ", ".join(tracked_locks)
        )

    lock_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in lock_packages:
        identity = (str(package.get("name", "")), str(package.get("version", "")))
        lock_by_identity.setdefault(identity, []).append(package)

    member_names: dict[str, str] = {}
    binary_names: dict[str, str] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for raw_member in members:
        member = str(raw_member)
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"{member}: missing Cargo.toml")
            continue

        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        manifests[member] = manifest
        package = manifest.get("package", {})
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            failures.append(f"{member}: package name/version must be explicit strings")
            continue
        if package.get("publish") is not False:
            failures.append(
                f"{member}: incomplete internal port crates must set package.publish = false"
            )
        if name in member_names:
            failures.append(f"{member}: duplicate workspace package name {name}")
        member_names[name] = member

        entries = lock_by_identity.get((name, version), [])
        if len(entries) != 1:
            failures.append(
                f"{member}: expected one root lock entry for {name} {version}, found {len(entries)}"
            )
        else:
            locked_dependencies = {
                str(dependency).split(" ", 1)[0]
                for dependency in entries[0].get("dependencies", [])
            }
            missing = manifest_dependencies(manifest) - locked_dependencies
            if missing:
                failures.append(
                    f"{member}: root lock entry is missing direct dependencies "
                    + ", ".join(sorted(missing))
                )

        targets = explicit_targets(manifest)
        if not targets:
            failures.append(f"{member}: manifest has no explicit library or binary target")
        for target in targets:
            validate_target_path(member, manifest_path, target, failures)
            if not (manifest_path.parent / target).is_file():
                failures.append(f"{member}: declared target does not exist: {target}")

        for binary_name in explicit_binary_names(manifest):
            previous_member = binary_names.get(binary_name)
            if previous_member is not None:
                failures.append(
                    f"{member}: executable target {binary_name} duplicates "
                    f"the target declared by {previous_member}"
                )
            else:
                binary_names[binary_name] = member

            if binary_name not in meson_artifact_names:
                failures.append(
                    f"{member}: binary target {binary_name} does not match an executable "
                    "or installed symlink declared by Meson"
                )

    validate_dependency_layers(
        manifests,
        member_names,
        default_layer,
        layer_ranks,
        assigned_layers,
        failures,
    )
    validate_language_contract(workspace, manifests, failures)

    for meson_path, text in meson_texts.items():
        if "rust/Cargo.lock" in text:
            failures.append(
                f"{meson_path.relative_to(root)}: references an ignored per-crate Cargo.lock"
            )

    if failures:
        print("Rust workspace architecture gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "Rust workspace architecture gate OK: "
        f"{len(members)} members, {len(binary_names)} executable targets, "
        f"{len(lock_packages)} locked packages, one lockfile; "
        f"{acknowledged_large_files} production files above {large_file_limit} lines "
        "are capped as architecture debt"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
