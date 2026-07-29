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
DEV_ONLY_METADATA_KEY = "systemd-rust"
PATH_ATTRIBUTE_RE = re.compile(
    r"""
    \#\s*\[\s*path\s*=\s*
    (?:
        "(?P<quoted>(?:\\.|[^"\\])*)"
        | r(?P<raw_hashes>\#*)"(?P<raw>.*?)"(?P=raw_hashes)
    )
    \s*\]
    """,
    re.MULTILINE | re.DOTALL | re.VERBOSE,
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
        "--large-file-baseline",
        default="tools/rust-port/large-rust-files-baseline.toml",
        help="Immutable baseline authority for raised Rust file-size debt caps",
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


def explicit_test_targets(manifest: dict[str, Any]) -> list[str]:
    tests = manifest.get("test", [])
    if isinstance(tests, dict):
        tests = [tests]
    return [
        test["path"]
        for test in tests
        if isinstance(test, dict) and isinstance(test.get("path"), str)
    ]


def is_declared_dev_only(member: str, manifest: dict[str, Any]) -> bool:
    """Recognize the narrow, unpublished test-only crate exception."""

    package = manifest.get("package", {})
    if not isinstance(package, dict):
        return False
    metadata = package.get("metadata", {})
    if not isinstance(metadata, dict):
        return False
    systemd_metadata = metadata.get(DEV_ONLY_METADATA_KEY, {})
    if not isinstance(systemd_metadata, dict):
        return False
    if systemd_metadata.get("dev-only") is not True:
        return False
    if package.get("publish") is not False:
        raise ValueError(f"{member}: developer-only crate must set package.publish = false")
    return True


def declared_source_fixtures(member: str, manifest: dict[str, Any]) -> list[str]:
    """Return the audited out-of-crate sources used by a dev-only test crate."""

    package = manifest.get("package", {})
    metadata = package.get("metadata", {}) if isinstance(package, dict) else {}
    systemd_metadata = (
        metadata.get(DEV_ONLY_METADATA_KEY, {}) if isinstance(metadata, dict) else {}
    )
    fixtures = (
        systemd_metadata.get("source-fixtures", [])
        if isinstance(systemd_metadata, dict)
        else []
    )
    if not isinstance(fixtures, list) or not all(
        isinstance(fixture, str) and fixture for fixture in fixtures
    ):
        raise ValueError(f"{member}: source-fixtures must be a string array")
    if len(fixtures) != len(set(fixtures)):
        raise ValueError(f"{member}: source-fixtures must not contain duplicates")
    return fixtures


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


def validate_dev_only_source_fixtures(
    root: Path,
    member: str,
    manifest: dict[str, Any],
    manifest_path: Path,
    targets: list[str],
    failures: list[str],
) -> None:
    """Keep source-level fuzz fixtures explicit, canonical, and test-only.

    Fuzz smoke tests deliberately compile parser entry points from several
    subsystems without turning them into Cargo release dependencies. Those
    `#[path]` edges must therefore be declared in the manifest and may point
    only at canonical Rust source files below `src/<subsystem>/rust`.
    """

    root = root.resolve()
    try:
        declared = declared_source_fixtures(member, manifest)
    except ValueError as exc:
        failures.append(str(exc))
        return

    declared_set = set(declared)
    observed: set[str] = set()
    scanned: set[Path] = set()
    crate_root = manifest_path.parent.resolve()
    source_root = (root / "src").resolve()
    pending = [crate_root / target for target in targets]

    while pending:
        source = pending.pop()
        resolved_source = source.resolve()
        if resolved_source in scanned or not resolved_source.is_file():
            continue
        scanned.add(resolved_source)
        for match in PATH_ATTRIBUTE_RE.finditer(
            resolved_source.read_text(encoding="utf-8")
        ):
            fixture = match.group("quoted") or match.group("raw")
            if match.group("quoted") is not None and "\\" in fixture:
                failures.append(
                    f"{member}: source fixture path must not use string escapes: {fixture}"
                )
                continue
            if "\n" in fixture or "\r" in fixture:
                failures.append(
                    f"{member}: source fixture path must not contain a newline: {fixture!r}"
                )
                continue
            fixture_path = Path(fixture)
            if fixture_path.is_absolute():
                failures.append(
                    f"{member}: source fixture path must be relative: {fixture}"
                )
                continue
            candidate = (resolved_source.parent / fixture_path).resolve()
            is_external = ".." in fixture_path.parts
            if is_external:
                canonical = (
                    candidate.relative_to(root).as_posix()
                    if candidate.is_relative_to(root)
                    else None
                )
                if canonical is None:
                    failures.append(
                        f"{member}: source fixture escapes the repository: {fixture}"
                    )
                    continue
                observed.add(canonical)
                if canonical not in declared_set:
                    failures.append(
                        f"{member}: external #[path] source fixture is not declared: {canonical}"
                    )
                    continue
            try:
                relative = candidate.relative_to(source_root)
            except ValueError:
                if is_external:
                    failures.append(
                        f"{member}: source fixture escapes src/: {fixture}"
                    )
                continue
            if is_external and (
                len(relative.parts) < 3
                or relative.parts[1] != "rust"
                or candidate.suffix != ".rs"
            ):
                failures.append(
                    f"{member}: source fixture is not canonical Rust source: {fixture}"
                )
            elif is_external and not candidate.is_file():
                failures.append(f"{member}: declared source fixture does not exist: {fixture}")
            elif candidate.is_file():
                pending.append(candidate)

    for fixture in sorted(declared_set - observed):
        failures.append(
            f"{member}: declared source fixture is not used by an explicit test target: {fixture}"
        )


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


def load_large_file_baseline(baseline_path: Path) -> dict[str, int]:
    """Load the independent, stable authority for acknowledged cap growth."""

    baseline = tomllib.loads(baseline_path.read_text(encoding="utf-8"))
    files = baseline.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("files must be a table")
    result: dict[str, int] = {}
    for path, entry in files.items():
        if not isinstance(path, str) or not isinstance(entry, dict):
            raise ValueError("files must contain named tables")
        cap = entry.get("max_lines")
        if not isinstance(cap, int) or cap <= 0:
            raise ValueError(f"{path}: max_lines must be a positive integer")
        result[path] = cap
    return result


def validate_large_file_baseline_history(
    root: Path, baseline_path: Path, failures: list[str]
) -> None:
    """Reject changing the baseline once it has landed in repository history."""

    relative = baseline_path.relative_to(root).as_posix()
    previous = subprocess.run(
        ["git", "show", f"HEAD^:{relative}"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if previous.returncode != 0:
        return
    if previous.stdout != baseline_path.read_text(encoding="utf-8"):
        failures.append(
            f"{relative}: immutable large-file baseline differs from its Git parent"
        )


def validate_large_rust_files(
    root: Path,
    policy_path: Path,
    failures: list[str],
    baseline_path: Path | None = None,
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
    baseline: dict[str, int] = {}
    if baseline_path is not None:
        try:
            baseline = load_large_file_baseline(baseline_path)
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            failures.append(
                f"{baseline_path.relative_to(root)}: cannot load large-file baseline: {exc}"
            )
        else:
            validate_large_file_baseline_history(root, baseline_path, failures)

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

        with path.open(encoding="utf-8") as source:
            line_count = sum(1 for _ in source)
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
        baseline_cap = entry.get("baseline_max_lines")
        growth_reason = entry.get("growth_reason")
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
        if baseline_cap is not None:
            if not isinstance(baseline_cap, int) or baseline_cap <= 0:
                failures.append(f"{relative_text}: baseline_max_lines must be a positive integer")
            elif not isinstance(cap, int) or baseline_cap >= cap:
                failures.append(
                    f"{relative_text}: baseline_max_lines must be lower than max_lines"
                )
            elif line_count <= baseline_cap:
                failures.append(
                    f"{relative_text}: growth allowance is stale; reduce max_lines to the baseline"
                )
            if not isinstance(growth_reason, str) or not growth_reason:
                failures.append(
                    f"{relative_text}: raised debt cap needs an explicit growth_reason"
                )
            if baseline_path is not None:
                authority_cap = baseline.get(relative_text)
                if authority_cap is None:
                    failures.append(
                        f"{relative_text}: raised debt cap is missing from the immutable baseline"
                    )
                elif baseline_cap != authority_cap:
                    failures.append(
                        f"{relative_text}: baseline_max_lines differs from the immutable baseline"
                    )
        elif growth_reason is not None:
            failures.append(
                f"{relative_text}: growth_reason requires baseline_max_lines"
            )

    for relative_text in sorted(set(allowed) - set(observed)):
        failures.append(
            f"{policy_path.relative_to(root)}: stale large-file debt entry {relative_text}"
        )
    for relative_text in sorted(set(baseline) - set(allowed)):
        failures.append(
            f"{baseline_path.relative_to(root)}: baseline entry lacks a current debt entry {relative_text}"
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
    large_file_baseline_path = Path(args.large_file_baseline)
    if not large_file_baseline_path.is_absolute():
        large_file_baseline_path = root / large_file_baseline_path

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
        root, root / args.large_file_policy, failures, large_file_baseline_path
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

        try:
            dev_only = is_declared_dev_only(member, manifest)
        except ValueError as exc:
            failures.append(str(exc))
            dev_only = False

        targets = explicit_targets(manifest)
        if dev_only:
            if targets:
                failures.append(
                    f"{member}: developer-only crate must not declare a library or binary release target"
                )
            targets = explicit_test_targets(manifest)
            if not targets:
                failures.append(
                    f"{member}: developer-only crate must declare an explicit test target"
                )
        elif not targets:
            failures.append(f"{member}: manifest has no explicit library or binary target")
        for target in targets:
            validate_target_path(member, manifest_path, target, failures)
            if not (manifest_path.parent / target).is_file():
                failures.append(f"{member}: declared target does not exist: {target}")
        if dev_only:
            validate_dev_only_source_fixtures(
                root, member, manifest, manifest_path, targets, failures
            )

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
