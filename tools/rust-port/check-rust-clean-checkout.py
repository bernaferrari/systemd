#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject Rust build inputs which would disappear from a clean checkout.

The Rust port has both Cargo and Meson entry points.  This checker follows the
literal source references owned by those entry points, as well as Rust ``mod``
declarations and the Cargo manifests named by Rust CI/smoke scripts.  Its
default mode intentionally queries ``git ls-files``: a present-but-untracked
source is not evidence that a clone can build it.  ``--mode=present`` is a
developer-only pre-staging diagnostic and is never suitable as CI proof.

This is a static source graph check.  It does not invoke Cargo, Meson, rustc,
or a test binary.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MODULE_LINE = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?\s+)?)mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)
INLINE_MODULE_LINE = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?\s+)?)mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
PATH_ATTRIBUTE = re.compile(r'^\s*#\s*\[\s*path\s*=\s*"([^"\\]+)"\s*\]\s*$')
ATTRIBUTE_LINE = re.compile(r"^\s*#\s*\[[^]]+\]\s*$")
MESON_RS_LITERAL = re.compile(r"(?P<quote>['\"])(?P<path>[^'\"\n]+\.rs)(?P=quote)")
MESON_GENERATED_OUTPUT = re.compile(
    r"\boutput\s*:\s*(?P<quote>['\"])(?P<path>[^'\"\n]+\.rs)(?P=quote)"
)
CI_MANIFEST = re.compile(r"--manifest-path(?:\s+|=)(?:['\"])?([^\s'\"]*Cargo\.toml)")


@dataclass(frozen=True, order=True)
class Reference:
    path: str
    origin: str
    kind: str


def relative(root: Path, path: Path) -> str | None:
    """Return a normalized repository-relative path, rejecting escapes."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def without_rust_comments(text: str) -> str:
    """Blank comments while retaining line structure and ``#[path]`` strings."""
    result: list[str] = []
    index = 0
    block_depth = 0
    quote: str | None = None
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if block_depth:
            if char == "/" and next_char == "*":
                block_depth += 1
                result.extend((" ", " "))
                index += 2
            elif char == "*" and next_char == "/":
                block_depth -= 1
                result.extend((" ", " "))
                index += 2
            else:
                result.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if quote is not None:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            result.append(char)
            index += 1
        elif char == "/" and next_char == "/":
            while index < len(text) and text[index] != "\n":
                result.append(" ")
                index += 1
        elif char == "/" and next_char == "*":
            block_depth = 1
            result.extend((" ", " "))
            index += 2
        else:
            result.append(char)
            index += 1
    return "".join(result)


def module_references(root: Path, source: Path) -> list[Reference]:
    """Resolve external Rust module declarations from one Rust source file."""
    refs: list[Reference] = []
    pending_path: str | None = None
    # Rust 2018 locates a child of `foo.rs` below `foo/`, while children of a
    # crate root (`lib.rs`/`main.rs`) or directory module (`mod.rs`) live next
    # to that file.  Treating every source as a crate root would silently miss
    # the split facades this gate is meant to protect.
    module_directory = (
        source.parent
        if source.stem in {"lib", "main", "mod"}
        else source.parent / source.stem
    )
    inline_modules: list[tuple[str, int]] = []
    brace_depth = 0
    text = without_rust_comments(source.read_text(encoding="utf-8"))
    for line_number, line in enumerate(text.splitlines(), start=1):
        path_attribute = PATH_ATTRIBUTE.match(line)
        if path_attribute:
            pending_path = path_attribute.group(1)
            continue
        if ATTRIBUTE_LINE.match(line):
            continue
        module = MODULE_LINE.match(line)
        inline_module = INLINE_MODULE_LINE.match(line)
        if module:
            module_name = module.group(1)
            origin = f"{relative(root, source)}:{line_number}"
            candidates = (
                [source.parent / pending_path]
                if pending_path is not None
                else [
                    module_directory.joinpath(*(name for name, _ in inline_modules)) / f"{module_name}.rs",
                    module_directory.joinpath(*(name for name, _ in inline_modules)) / module_name / "mod.rs",
                ]
            )
            chosen = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
            resolved = relative(root, chosen)
            if resolved is None:
                refs.append(Reference(f"<outside repository: {chosen}>", origin, "Rust module"))
            else:
                refs.append(Reference(resolved, origin, "Rust module"))
            pending_path = None
        elif line.strip() and not line.lstrip().startswith("#"):
            pending_path = None
        brace_line = re.sub(r'r#*"(?:[^"\\]|\\.)*"#*|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', "", line)
        opened = brace_line.count("{")
        brace_depth += opened - brace_line.count("}")
        if inline_module:
            inline_modules.append((inline_module.group(1), brace_depth))
        while inline_modules and brace_depth < inline_modules[-1][1]:
            inline_modules.pop()
    return refs


def is_ignored_path(path: Path, root: Path) -> bool:
    return any(part in {".git", "target", "__pycache__"} or part.startswith("build-") for part in path.relative_to(root).parts)


def source_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.rs")
        if path.is_file() and not is_ignored_path(path, root)
    )


def manifest_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("Cargo.toml")
        if path.is_file() and not is_ignored_path(path, root)
    )


def add_reference(refs: list[Reference], root: Path, target: Path, origin: str, kind: str) -> None:
    resolved = relative(root, target)
    refs.append(Reference(resolved if resolved is not None else f"<outside repository: {target}>", origin, kind))


def cargo_target_references(root: Path, manifest: Path) -> tuple[list[Reference], list[Path]]:
    """Return literal Cargo target/dependency references and manifests to visit."""
    refs: list[Reference] = []
    discovered: list[Path] = []
    origin = relative(root, manifest) or str(manifest)
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        return [Reference(f"<invalid TOML: {error}>", origin, "Cargo manifest")], discovered

    def target_path(value: object, label: str) -> None:
        if isinstance(value, str):
            add_reference(refs, root, manifest.parent / value, origin, label)

    package = data.get("package")
    if isinstance(package, dict):
        build = package.get("build")
        if isinstance(build, str):
            target_path(build, "Cargo build script")
        elif build is True and (manifest.parent / "build.rs").is_file():
            target_path("build.rs", "Cargo build script")

    lib = data.get("lib")
    if isinstance(lib, dict):
        target_path(lib.get("path", "src/lib.rs"), "Cargo library target")
    elif (manifest.parent / "src/lib.rs").is_file():
        target_path("src/lib.rs", "Cargo implicit library target")

    for target_kind in ("bin", "example", "test", "bench"):
        entries = data.get(target_kind, [])
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                target_path(entry["path"], f"Cargo {target_kind} target")

    # Cargo discovers these directories when the respective auto-* flag is not
    # disabled.  Existing files are references even without an explicit table.
    auto_targets = {
        "autobins": manifest.parent / "src/bin",
        "autoexamples": manifest.parent / "examples",
        "autotests": manifest.parent / "tests",
        "autobenches": manifest.parent / "benches",
    }
    package_data = package if isinstance(package, dict) else {}
    for key, directory in auto_targets.items():
        if package_data.get(key, True) is not False and directory.is_dir():
            for source in sorted(directory.rglob("*.rs")):
                add_reference(refs, root, source, origin, f"Cargo implicit {key} target")
    if package_data.get("autobins", True) is not False and (manifest.parent / "src/main.rs").is_file():
        target_path("src/main.rs", "Cargo implicit binary target")

    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        for key in ("members", "default-members"):
            members = workspace.get(key, [])
            if not isinstance(members, list):
                continue
            for member in members:
                if not isinstance(member, str):
                    continue
                matches = sorted(manifest.parent.glob(member))
                if not matches:
                    add_reference(refs, root, manifest.parent / member / "Cargo.toml", origin, f"Cargo workspace {key}")
                for match in matches:
                    candidate = match if match.name == "Cargo.toml" else match / "Cargo.toml"
                    add_reference(refs, root, candidate, origin, f"Cargo workspace {key}")
                    discovered.append(candidate)

    def dependency_paths(value: object) -> Iterable[str]:
        """Read Cargo dependency tables without mistaking target ``path`` for one."""
        if not isinstance(value, dict):
            return
        for specification in value.values():
            if isinstance(specification, dict) and isinstance(specification.get("path"), str):
                yield specification["path"]

    dependency_paths_found: list[str] = []
    dependency_keys = ("dependencies", "dev-dependencies", "build-dependencies")
    for key in dependency_keys:
        dependency_paths_found.extend(dependency_paths(data.get(key)))
    if isinstance(workspace, dict):
        dependency_paths_found.extend(dependency_paths(workspace.get("dependencies")))
    target_configurations = data.get("target")
    if isinstance(target_configurations, dict):
        for configuration in target_configurations.values():
            if isinstance(configuration, dict):
                for key in dependency_keys:
                    dependency_paths_found.extend(dependency_paths(configuration.get(key)))
    for section in ("patch", "replace"):
        dependency_paths_found.extend(dependency_paths(data.get(section)))

    for dependency_path in dependency_paths_found:
        candidate = manifest.parent / dependency_path / "Cargo.toml"
        add_reference(refs, root, candidate, origin, "Cargo path dependency manifest")
        discovered.append(candidate)
    return refs, discovered


def cargo_references(root: Path) -> list[Reference]:
    refs: list[Reference] = []
    queue: deque[Path] = deque(manifest_files(root))
    visited: set[Path] = set()
    while queue:
        manifest = queue.popleft()
        normalized = manifest.resolve()
        if normalized in visited:
            continue
        visited.add(normalized)
        add_reference(refs, root, manifest, relative(root, manifest) or str(manifest), "Cargo manifest")
        if not manifest.is_file():
            continue
        current, discovered = cargo_target_references(root, manifest)
        refs.extend(current)
        queue.extend(discovered)
    return refs


def meson_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and (path.name == "meson.build" or path.suffix == ".meson")
        and not is_ignored_path(path, root)
    )


def meson_references(root: Path) -> list[Reference]:
    refs: list[Reference] = []
    for manifest in meson_files(root):
        text = manifest.read_text(encoding="utf-8")
        generated = {match.group("path") for match in MESON_GENERATED_OUTPUT.finditer(text)}
        for match in MESON_RS_LITERAL.finditer(text):
            source_name = match.group("path")
            if source_name in generated:
                continue
            line = text.count("\n", 0, match.start()) + 1
            add_reference(
                refs,
                root,
                manifest.parent / source_name,
                f"{relative(root, manifest)}:{line}",
                "Meson Rust source",
            )
    return refs


def ci_and_test_references(root: Path) -> list[Reference]:
    refs: list[Reference] = []
    manifests = [
        *sorted((root / ".github/workflows").glob("*.yml")),
        *sorted((root / ".github/workflows").glob("*.yaml")),
        *sorted((root / "test").rglob("*rust*.sh")),
    ]
    for manifest in manifests:
        if not manifest.is_file():
            continue
        text = manifest.read_text(encoding="utf-8")
        for match in CI_MANIFEST.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            add_reference(
                refs,
                root,
                root / match.group(1),
                f"{relative(root, manifest)}:{line}",
                "Rust CI/test manifest",
            )
    return refs


def collect_references(root: Path) -> list[Reference]:
    refs = cargo_references(root) + meson_references(root) + ci_and_test_references(root)
    for source in source_files(root):
        refs.extend(module_references(root, source))
    return sorted(set(refs))


def tracked_paths(root: Path) -> set[str]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return {path.decode("utf-8") for path in output.split(b"\0") if path}


def validate(root: Path, refs: Iterable[Reference], mode: str, tracked: set[str] | None = None) -> list[Reference]:
    if mode == "tracked":
        allowed = tracked if tracked is not None else tracked_paths(root)
        return [reference for reference in refs if reference.path not in allowed]
    if mode == "present":
        return [reference for reference in refs if not (root / reference.path).is_file()]
    raise ValueError(f"unsupported mode: {mode}")


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "crates/a").mkdir(parents=True)
        (root / "crates/b").mkdir(parents=True)
        (root / "src").mkdir()
        (root / ".github/workflows").mkdir(parents=True)
        (root / "test").mkdir()
        (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a"]\n', encoding="utf-8")
        (root / "crates/a/Cargo.toml").write_text(
            '[package]\nname = "a"\nversion = "0.1.0"\n[lib]\npath = "lib.rs"\n[dependencies]\nb = { path = "../b" }\n',
            encoding="utf-8",
        )
        (root / "crates/b/Cargo.toml").write_text(
            '[package]\nname = "b"\nversion = "0.1.0"\n[lib]\npath = "lib.rs"\n', encoding="utf-8"
        )
        (root / "crates/a/lib.rs").write_text(
            'pub mod namespace {\n    pub mod child;\n}\n#[path = "renamed.rs"]\nmod renamed;\n',
            encoding="utf-8",
        )
        (root / "crates/a/renamed.rs").write_text("", encoding="utf-8")
        (root / "crates/a/namespace").mkdir()
        (root / "crates/a/namespace/child.rs").write_text("", encoding="utf-8")
        (root / "crates/b/lib.rs").write_text("", encoding="utf-8")
        (root / "src/meson.rs").write_text("", encoding="utf-8")
        (root / "meson.build").write_text("input: 'src/meson.rs'\noutput: 'generated.rs'\n", encoding="utf-8")
        (root / ".github/workflows/rust.yml").write_text(
            "run: cargo check --manifest-path crates/a/Cargo.toml\n", encoding="utf-8"
        )
        refs = collect_references(root)
        paths = {reference.path for reference in refs}
        expected = {"Cargo.toml", "crates/a/Cargo.toml", "crates/a/lib.rs", "crates/a/namespace/child.rs", "crates/a/renamed.rs", "crates/b/Cargo.toml", "crates/b/lib.rs", "src/meson.rs"}
        if not expected <= paths or "generated.rs" in paths:
            raise AssertionError(f"unexpected reference collection: {sorted(paths)}")
        present_errors = validate(root, refs, "present")
        if present_errors:
            raise AssertionError(f"complete fixture did not validate in present mode: {present_errors}")
        if validate(root, refs, "tracked", tracked=paths):
            raise AssertionError("complete fixture did not validate in tracked mode")
        if not any(
            reference.path == "crates/a/renamed.rs"
            for reference in validate(root, refs, "tracked", tracked=paths - {"crates/a/renamed.rs"})
        ):
            raise AssertionError("untracked module source was not detected")
        (root / "crates/a/renamed.rs").unlink()
        if not any(reference.path == "crates/a/renamed.rs" for reference in validate(root, refs, "present")):
            raise AssertionError("missing module source was not detected")
    print("rust clean-checkout gate self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root (default: current directory)")
    parser.add_argument(
        "--mode",
        choices=("tracked", "present"),
        default="tracked",
        help="tracked proves a clean checkout; present is only a pre-staging diagnostic",
    )
    parser.add_argument("--self-test", action="store_true", help="exercise parser/resolution fixtures without build tools")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return 0

    root = args.root.resolve()
    refs = collect_references(root)
    missing = validate(root, refs, args.mode)
    if missing:
        print(f"Rust clean-checkout gate FAILED (mode={args.mode}):")
        for reference in missing:
            print(f"  {reference.path} [{reference.kind}; referenced by {reference.origin}]")
        if args.mode == "tracked":
            print("Stage authored files before accepting this gate; present-but-untracked files are not clean-checkout proof.")
        return 1
    print(f"Rust clean-checkout gate OK: references={len(refs)} mode={args.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
