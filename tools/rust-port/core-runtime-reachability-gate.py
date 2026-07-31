#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep the experimental Rust PID1 developer artifact's boundary explicit.

This is a conservative lexical reachability inventory, not a compiler or
behavior/parity/ownership claim. It starts at the Meson-selected, non-installed
PID1 Cargo binary, follows crate-level Rust paths, and records which
``src/core/rust/lib.rs`` modules can be reached. Every other declared module
remains compiled into the library but disconnected from PID1. Do not add an
otherwise unused import merely to change this inventory: reclassification is
only meaningful when the binary actually delegates the corresponding runtime
responsibility.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
import tomllib
from collections import deque
from pathlib import Path

CORE_RUST = Path("src/core/rust")
CORE_MESON = Path("src/core/meson.build")
BASELINE = Path("tools/rust-port/core-runtime-reachability-baseline.json")
CLASSIFICATIONS = {"runtime-reachable", "compiled-but-disconnected"}
BASELINE_VERSION = 2
PID1_BIN_NAME = "systemd"
TOP_LEVEL_MODULE_RE = re.compile(
    r"^\s*pub\s+mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.MULTILINE
)
CHILD_MODULE_RE = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
EXTERNAL_MODULE_ANY_RE = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;"
)
INLINE_MODULE_RE = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
)
CRATE_ALIAS_RE = re.compile(
    r"\b(?:use|extern\s+crate)\s+(?:crate|systemd_core_rs)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
PUB_USE_RE = re.compile(r"\bpub\s+use\s+([^;]+);")
CFG_TEST_MODULE_RE = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*"
    r"(?:#\s*\[\s*path\s*=\s*[^\]]+\]\s*)?"
    r"mod\s+[A-Za-z_][A-Za-z0-9_]*\s*(?P<delimiter>[;{])"
)
PATH_MODULE_ATTR_RE = re.compile(r"#\s*\[\s*path\s*=")
INCLUDE_RE = re.compile(r"\binclude\s*!\s*[\(\{\[]")
MACRO_RULES_RE = re.compile(
    r"\bmacro_rules\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*(?P<delimiter>[\(\{\[])"
)
MACRO_INVOCATION_RE = re.compile(
    r"\b(?!macro_rules\b)[A-Za-z_][A-Za-z0-9_]*\s*!\s*"
    r"(?P<delimiter>[\(\{\[])"
)
ATTRIBUTED_ITEM_RE = re.compile(
    r"(?P<attrs>(?:^\s*#\s*\[[^\]]*\]\s*)+)"
    r"(?P<item>"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*[;\{]"
    r"|(?:pub(?:\([^)]*\))?\s+)?use\s+.*?;"
    r"|extern\s+crate\s+.*?;"
    r")",
    re.MULTILINE | re.DOTALL,
)
MESON_BIN_RE = re.compile(r"""["']--bin["']\s*,\s*["']([A-Za-z0-9_-]+)["']""")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify lib.rs modules by static experimental Rust PID1 reachability."
    )
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--baseline",
        default=str(BASELINE),
        help="Reviewed classification baseline relative to the repository root",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Replace the reviewed classification baseline with the current inventory",
    )
    return parser.parse_args()


def rust_char_literal_end(source: str, quote: int) -> int | None:
    """Return the end of a Rust char/byte-char literal, but not a lifetime."""

    cursor = quote + 1
    if cursor >= len(source):
        return None

    if source[cursor] != "\\":
        cursor += 1
    else:
        cursor += 1
        if cursor >= len(source):
            return None
        escape = source[cursor]
        if escape == "x":
            cursor += 3
        elif escape == "u" and source.startswith("u{", cursor):
            close = source.find("}", cursor + 2)
            if close == -1:
                return None
            cursor = close + 1
        else:
            cursor += 1

    if cursor < len(source) and source[cursor] == "'":
        return cursor + 1
    return None


def mask_rust_non_code(source: str) -> str:
    """Mask comments and literals while preserving line positions for regexes."""

    result = list(source)
    index = 0
    block_depth = 0
    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                result[index : index + 2] = "  "
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                result[index : index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if result[index] != "\n":
                    result[index] = " "
                index += 1
            continue

        if source.startswith("//", index):
            end = source.find("\n", index)
            if end == -1:
                end = len(source)
            result[index:end] = " " * (end - index)
            index = end
            continue
        if source.startswith("/*", index):
            result[index : index + 2] = "  "
            block_depth = 1
            index += 2
            continue

        raw = re.match(r"r(#+)?\"", source[index:])
        if raw:
            hashes = raw.group(1) or ""
            terminator = '"' + hashes
            end = source.find(terminator, index + len(raw.group(0)))
            end = len(source) if end == -1 else end + len(terminator)
            for cursor in range(index, end):
                if result[cursor] != "\n":
                    result[cursor] = " "
            index = end
            continue

        if source[index] == '"':
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == '"':
                    end += 1
                    break
                end += 1
            for cursor in range(index, min(end, len(source))):
                if result[cursor] != "\n":
                    result[cursor] = " "
            index = end
            continue
        if source[index] == "'":
            end = rust_char_literal_end(source, index)
            if end is not None:
                for cursor in range(index, end):
                    if result[cursor] != "\n":
                        result[cursor] = " "
                index = end
                continue
        index += 1
    return "".join(result)


def mask_cfg_test_modules(code: str) -> str:
    """Exclude common cfg(test) module forms from shipped-runtime traversal."""

    result = list(code)
    index = 0
    while match := CFG_TEST_MODULE_RE.search(code, index):
        start = match.start()
        if match.group("delimiter") == ";":
            end = match.end()
        else:
            depth = 0
            cursor = match.end() - 1
            while cursor < len(code):
                if code[cursor] == "{":
                    depth += 1
                elif code[cursor] == "}":
                    depth -= 1
                    if depth == 0:
                        cursor += 1
                        break
                cursor += 1
            end = cursor
        for cursor in range(start, min(end, len(result))):
            if result[cursor] != "\n":
                result[cursor] = " "
        index = end
    return "".join(result)


def matching_delimiter(code: str, start: int) -> int | None:
    pairs = {"(": ")", "{": "}", "[": "]"}
    opening = code[start]
    closing = pairs[opening]
    depth = 0
    for cursor in range(start, len(code)):
        if code[cursor] == opening:
            depth += 1
        elif code[cursor] == closing:
            depth -= 1
            if depth == 0:
                return cursor + 1
    return None


def reject_unsupported_constructs(code: str, source_name: str) -> None:
    if INCLUDE_RE.search(code):
        raise ValueError(f"{source_name}: include! requires parser support")

    aliases = set(CRATE_ALIAS_RE.findall(code))
    for match in ATTRIBUTED_ITEM_RE.finditer(code):
        attrs = match.group("attrs")
        if not re.search(r"#\s*\[\s*cfg(?:_attr)?\b", attrs):
            continue
        item = match.group("item")
        if re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\b", item):
            # Inline modules are part of the containing source file. Their
            # bodies remain visible to the reference scanner, so a target
            # predicate such as `#[cfg(target_os = "linux")] mod imp { … }`
            # can be traversed conservatively for the Linux PID1 inventory.
            # External `mod name;` declarations still require resolving a
            # target-specific source tree and remain fail-closed here.
            if item.rstrip().endswith("{"):
                continue
            raise ValueError(f"{source_name}: cfg-controlled module requires parser support")
        imported_root = re.match(
            r"\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:::)?([A-Za-z_][A-Za-z0-9_]*)",
            item,
        )
        if (
            imported_root
            and (
                imported_root.group(1) in {"crate", "systemd_core_rs"}
                or imported_root.group(1) in aliases
                or item.lstrip().startswith("pub ")
            )
        ) or re.match(r"\s*extern\s+crate\s+(?:crate|systemd_core_rs)\b", item):
            raise ValueError(
                f"{source_name}: cfg-controlled crate import requires parser support"
            )

    for match in MACRO_RULES_RE.finditer(code):
        end = matching_delimiter(code, match.end("delimiter") - 1)
        if end is None:
            raise ValueError(f"{source_name}: unbalanced macro_rules! body")
        body = code[match.end("delimiter") : end - 1]
        if EXTERNAL_MODULE_ANY_RE.search(body):
            raise ValueError(
                f"{source_name}: module declaration inside macro_rules! requires parser support"
            )

    for match in MACRO_INVOCATION_RE.finditer(code):
        end = matching_delimiter(code, match.end("delimiter") - 1)
        if end is None:
            raise ValueError(f"{source_name}: unbalanced macro invocation")
        body = code[match.end("delimiter") : end - 1]
        if EXTERNAL_MODULE_ANY_RE.search(body):
            raise ValueError(
                f"{source_name}: module declaration inside a macro invocation "
                "requires parser support"
            )

    for match in INLINE_MODULE_RE.finditer(code):
        end = matching_delimiter(code, match.end() - 1)
        if end is None:
            raise ValueError(f"{source_name}: unbalanced inline module")
        body = code[match.end() : end - 1]
        if EXTERNAL_MODULE_ANY_RE.search(body):
            raise ValueError(
                f"{source_name}: external module nested in an inline module requires parser support"
            )


def runtime_code(source: str, source_name: str = "<source>") -> str:
    code = mask_cfg_test_modules(mask_rust_non_code(source))
    reject_unsupported_constructs(code, source_name)
    return code


def declared_modules(lib_source: str) -> list[str]:
    modules = TOP_LEVEL_MODULE_RE.findall(runtime_code(lib_source, "src/core/rust/lib.rs"))
    if len(modules) != len(set(modules)):
        raise ValueError("src/core/rust/lib.rs declares a top-level module more than once")
    return sorted(modules)


def split_top_level_commas(group: str) -> list[str]:
    items: list[str] = []
    start = 0
    depth = 0
    for cursor, character in enumerate(group):
        if character in "({[":
            depth += 1
        elif character in ")}]":
            depth -= 1
        elif character == "," and depth == 0:
            items.append(group[start:cursor])
            start = cursor + 1
    items.append(group[start:])
    return items


def curly_depth_at(code: str, position: int) -> int:
    depth = 0
    for character in code[:position]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
    return depth


def resolved_module(
    name: str, known_modules: set[str], root_reexports: dict[str, str]
) -> str | None:
    if name in known_modules:
        return name
    return root_reexports.get(name)


def grouped_heads(
    group: str, known_modules: set[str], root_reexports: dict[str, str]
) -> set[str]:
    heads: set[str] = set()
    for item in split_top_level_commas(group):
        item = item.strip()
        if not item or item.startswith(("self", "super")):
            continue
        head = re.split(r"\s+as\s+|::", item, maxsplit=1)[0].strip()
        module = resolved_module(head, known_modules, root_reexports)
        if module is not None:
            heads.add(module)
    return heads


def record_reexport(
    exports: dict[str, str], exported_name: str, module: str, source_name: str
) -> None:
    previous = exports.get(exported_name)
    if previous is not None and previous != module:
        raise ValueError(
            f"{source_name}: ambiguous crate-root reexport {exported_name} "
            f"from both {previous} and {module}"
        )
    exports[exported_name] = module


def crate_root_reexports(
    lib_source: str, known_modules: set[str]
) -> dict[str, str]:
    source_name = "src/core/rust/lib.rs"
    code = runtime_code(lib_source, source_name)
    exports: dict[str, str] = {}
    for match in PUB_USE_RE.finditer(code):
        if curly_depth_at(code, match.start()) != 0:
            continue
        path = match.group(1).strip()
        path = re.sub(r"^(?:crate|self)\s*::\s*", "", path)
        head_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", path)
        if not head_match or head_match.group(1) not in known_modules:
            continue
        module = head_match.group(1)
        remainder = path[head_match.end() :].strip()
        if not remainder:
            record_reexport(exports, module, module, source_name)
            continue
        if not remainder.startswith("::"):
            alias = re.fullmatch(r"as\s+([A-Za-z_][A-Za-z0-9_]*)", remainder)
            if alias:
                record_reexport(exports, alias.group(1), module, source_name)
            continue
        tail = remainder[2:].strip()
        if tail == "*":
            raise ValueError(f"{source_name}: glob reexport requires parser support")
        if tail.startswith("{") and tail.endswith("}"):
            for item in split_top_level_commas(tail[1:-1]):
                item = item.strip()
                if not item:
                    continue
                if item == "self":
                    record_reexport(exports, module, module, source_name)
                    continue
                if "{" in item or item == "*":
                    raise ValueError(
                        f"{source_name}: nested or glob reexport requires parser support"
                    )
                alias = re.fullmatch(
                    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*"
                    r"([A-Za-z_][A-Za-z0-9_]*)"
                    r"(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?",
                    item,
                )
                if not alias:
                    raise ValueError(
                        f"{source_name}: unsupported crate-root reexport item {item!r}"
                    )
                record_reexport(
                    exports, alias.group(2) or alias.group(1), module, source_name
                )
            continue
        alias = re.fullmatch(
            r"(?:[A-Za-z_][A-Za-z0-9_]*::)*"
            r"([A-Za-z_][A-Za-z0-9_]*)"
            r"(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?",
            tail,
        )
        if not alias:
            raise ValueError(f"{source_name}: unsupported crate-root reexport {path!r}")
        record_reexport(exports, alias.group(2) or alias.group(1), module, source_name)
    return exports


def references_for_root(
    code: str,
    root_name: str,
    known_modules: set[str],
    root_reexports: dict[str, str],
) -> set[str]:
    escaped = re.escape(root_name)
    prefix_re = re.compile(rf"\b{escaped}\s*::\s*")
    references: set[str] = set()
    for match in prefix_re.finditer(code):
        cursor = match.end()
        if cursor < len(code) and code[cursor] == "{":
            end = matching_delimiter(code, cursor)
            if end is None:
                raise ValueError(f"unbalanced grouped use rooted at {root_name}")
            references.update(
                grouped_heads(code[cursor + 1 : end - 1], known_modules, root_reexports)
            )
            continue
        name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", code[cursor:])
        if name:
            module = resolved_module(name.group(0), known_modules, root_reexports)
            if module is not None:
                references.add(module)
    return references


def referenced_top_modules(
    source: str,
    known_modules: set[str],
    root_reexports: dict[str, str] | None = None,
    source_name: str = "<source>",
) -> set[str]:
    code = runtime_code(source, source_name)
    reexports = root_reexports or {}
    references = references_for_root(code, "crate", known_modules, reexports)
    references.update(
        references_for_root(code, "systemd_core_rs", known_modules, reexports)
    )

    for alias in CRATE_ALIAS_RE.findall(code):
        references.update(references_for_root(code, alias, known_modules, reexports))
    return references


def module_source_path(core_root: Path, module: str) -> Path:
    candidates = (core_root / f"{module}.rs", core_root / module / "mod.rs")
    existing = [candidate for candidate in candidates if candidate.is_file()]
    if len(existing) != 1:
        raise ValueError(
            f"{module}: expected exactly one module root, found {[str(path) for path in existing]}"
        )
    return existing[0]


def child_module_path(parent: Path, child: str, *, crate_root: bool = False) -> Path | None:
    directory = (
        parent.parent
        if crate_root or parent.name == "mod.rs"
        else parent.parent / parent.stem
    )
    candidates = (directory / f"{child}.rs", directory / child / "mod.rs")
    existing = [candidate for candidate in candidates if candidate.is_file()]
    if len(existing) > 1:
        raise ValueError(f"{parent}: child module {child} is ambiguous")
    return existing[0] if existing else None


def module_source_tree(root_source: Path, *, crate_root: bool = False) -> list[Path]:
    pending = [(root_source, crate_root)]
    visited: set[Path] = set()
    while pending:
        source, source_is_crate_root = pending.pop()
        if source in visited:
            continue
        visited.add(source)
        code = runtime_code(source.read_text(encoding="utf-8"), str(source))
        if PATH_MODULE_ATTR_RE.search(code):
            raise ValueError(f"{source}: #[path] module overrides require parser support")
        for child in CHILD_MODULE_RE.findall(code):
            child_source = child_module_path(
                source, child, crate_root=source_is_crate_root
            )
            if child_source is None:
                raise ValueError(f"{source}: child module {child} could not be resolved")
            pending.append((child_source, False))
    return sorted(visited)


def authoritative_pid1_bin(root: Path) -> str:
    matches = MESON_BIN_RE.findall((root / CORE_MESON).read_text(encoding="utf-8"))
    if matches != [PID1_BIN_NAME]:
        raise ValueError(
            f"{CORE_MESON}: expected exactly one authoritative "
            f"Cargo --bin {PID1_BIN_NAME}, found {matches}"
        )
    return PID1_BIN_NAME


def binary_roots(root: Path, core_root: Path) -> list[Path]:
    manifest = tomllib.loads((core_root / "Cargo.toml").read_text(encoding="utf-8"))
    bins = manifest.get("bin", [])
    if not isinstance(bins, list) or not bins:
        raise ValueError("src/core/rust/Cargo.toml has no [[bin]] roots")
    authoritative_bin = authoritative_pid1_bin(root)
    matches: list[Path] = []
    for raw in bins:
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("name"), str)
            or not isinstance(raw.get("path"), str)
        ):
            raise ValueError(
                "every src/core/rust [[bin]] entry must declare a name and path"
            )
        if raw["name"] != authoritative_bin:
            continue
        path = core_root / raw["path"]
        if not path.is_file():
            raise ValueError(f"Cargo binary root is missing: {path}")
        matches.append(path)
    if len(matches) != 1:
        raise ValueError(
            f"Cargo.toml must declare exactly one {authoritative_bin!r} binary selected by Meson"
        )
    return matches


def inventory(root: Path) -> dict[str, object]:
    core_root = root / CORE_RUST
    lib_source = (core_root / "lib.rs").read_text(encoding="utf-8")
    modules = declared_modules(lib_source)
    known_modules = set(modules)
    root_reexports = crate_root_reexports(lib_source, known_modules)
    roots = binary_roots(root, core_root)
    edges: dict[str, set[str]] = {}
    sources: dict[str, list[str]] = {}
    for module in modules:
        tree = module_source_tree(module_source_path(core_root, module))
        sources[module] = [path.relative_to(root).as_posix() for path in tree]
        dependencies: set[str] = set()
        for path in tree:
            dependencies.update(
                referenced_top_modules(
                    path.read_text(encoding="utf-8"),
                    known_modules,
                    root_reexports,
                    path.relative_to(root).as_posix(),
                )
            )
        edges[module] = dependencies

    reachable: set[str] = set()
    pending = deque()
    binary_sources: dict[str, list[str]] = {}
    for binary in roots:
        tree = module_source_tree(binary, crate_root=True)
        relative_binary = binary.relative_to(root).as_posix()
        binary_sources[relative_binary] = [
            path.relative_to(root).as_posix() for path in tree
        ]
        for path in tree:
            pending.extend(
                referenced_top_modules(
                    path.read_text(encoding="utf-8"),
                    known_modules,
                    root_reexports,
                    path.relative_to(root).as_posix(),
                )
            )
    while pending:
        module = pending.popleft()
        if module in reachable:
            continue
        reachable.add(module)
        pending.extend(edges[module] - reachable)

    return {
        "version": BASELINE_VERSION,
        "binary_roots": [path.relative_to(root).as_posix() for path in roots],
        "binary_source_files": binary_sources,
        "modules": {
            module: {
                "classification": (
                    "runtime-reachable" if module in reachable else "compiled-but-disconnected"
                ),
                "source_files": sources[module],
            }
            for module in modules
        },
    }


def load_baseline(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != BASELINE_VERSION or not isinstance(
        payload.get("modules"), dict
    ):
        raise ValueError(f"unsupported core runtime reachability baseline: {path}")
    if not isinstance(payload.get("binary_roots"), list) or not all(
        isinstance(item, str) for item in payload["binary_roots"]
    ):
        raise ValueError(f"invalid binary_roots in {path}")
    binary_source_files = payload.get("binary_source_files")
    if not isinstance(binary_source_files, dict) or not all(
        isinstance(root, str)
        and isinstance(files, list)
        and all(isinstance(item, str) for item in files)
        for root, files in binary_source_files.items()
    ):
        raise ValueError(f"invalid binary_source_files in {path}")
    for module, entry in payload["modules"].items():
        if not isinstance(module, str) or not isinstance(entry, dict):
            raise ValueError(f"invalid module entry in {path}")
        if entry.get("classification") not in CLASSIFICATIONS:
            raise ValueError(f"invalid classification for {module} in {path}")
        source_files = entry.get("source_files")
        if not isinstance(source_files, list) or not all(
            isinstance(item, str) for item in source_files
        ):
            raise ValueError(f"invalid source_files for {module} in {path}")
    return payload


def compare_inventory(current: dict[str, object], baseline: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if current["binary_roots"] != baseline["binary_roots"]:
        failures.append(
            "authoritative Meson PID1 binary roots changed; "
            "regenerate the reviewed reachability baseline"
        )
    if current["binary_source_files"] != baseline["binary_source_files"]:
        failures.append(
            "PID1 binary source-file inventory changed; "
            "regenerate the reviewed reachability baseline"
        )

    current_modules = current["modules"]
    baseline_modules = baseline["modules"]
    assert isinstance(current_modules, dict) and isinstance(baseline_modules, dict)
    for module in sorted(current_modules.keys() - baseline_modules.keys()):
        failures.append(f"{module}: new declared module has no reviewed classification")
    for module in sorted(baseline_modules.keys() - current_modules.keys()):
        failures.append(f"{module}: baseline module was resolved or moved; regenerate deliberately")
    for module in sorted(current_modules.keys() & baseline_modules.keys()):
        if current_modules[module] != baseline_modules[module]:
            failures.append(
                f"{module}: reachability or source-file inventory changed; regenerate deliberately"
            )
    return failures


def verify_canonical_manager_vocabulary(root: Path, inventory: dict[str, object]) -> list[str]:
    """Reject parallel public manager-objective vocabularies.

    `manager.h` owns this enum in C. The reachable PID 1 modules and the
    disconnected transport/policy models must therefore share
    manager_tables::ManagerObjective rather than recreate incompatible subsets.
    """

    failures: list[str] = []
    core = root / CORE_RUST
    manager_tables = (core / "manager_tables.rs").read_text(encoding="utf-8")
    objective_definitions = sorted(
        path.relative_to(core).as_posix()
        for path in core.rglob("*.rs")
        if re.search(r"\bpub\s+enum\s+ManagerObjective\b", path.read_text(encoding="utf-8"))
    )
    if objective_definitions != ["manager_tables.rs"]:
        failures.append(
            "manager_tables must be the sole public ManagerObjective definition: "
            f"found={objective_definitions}"
        )
    if "pub const fn varlink_method_name" not in manager_tables:
        failures.append("canonical ManagerObjective lacks the varlink spelling adapter")

    for module in ("emergency_action", "varlink_manager"):
        source = (core / f"{module}.rs").read_text(encoding="utf-8")
        if "pub enum ManagerObjective" in source:
            failures.append(f"{module} defines a parallel public ManagerObjective")
        if "pub use crate::manager_tables::ManagerObjective;" not in source:
            failures.append(f"{module} does not re-export the canonical ManagerObjective")
        if "compiled-but-disconnected" not in source.lower():
            failures.append(f"{module} is not explicitly isolated from RuntimeManager")

    if "objective.varlink_method_name().is_none()" not in (core / "varlink_manager.rs").read_text(encoding="utf-8"):
        failures.append("varlink manager accepts objectives outside its canonical method subset")

    emergency = (core / "emergency_action.rs").read_text(encoding="utf-8")
    if "ManagerObjective::None" in emergency or "ManagerObjective::Ok" not in emergency:
        failures.append("emergency-action does not map its idle state to canonical ManagerObjective::Ok")

    for module in ("pid1_lifecycle", "pid1_manager_commands", "manager_serialize", "core_model"):
        source = (core / f"{module}.rs").read_text(encoding="utf-8")
        if "manager_tables" not in source or "ManagerObjective" not in source:
            failures.append(f"{module} does not use the canonical manager objective vocabulary")

    dbus_model = (core / "dbus_manager/model.rs").read_text(encoding="utf-8")
    if "use crate::runtime_manager::RuntimeManager;" not in dbus_model:
        failures.append("D-Bus manager model is no longer bound to RuntimeManager")

    for module in ("core_model", "manager", "manager_dump", "manager_serialize", "dbus"):
        source = (core / f"{module}.rs").read_text(encoding="utf-8")
        if "compiled-but-disconnected" not in source.lower():
            failures.append(f"{module} is not explicitly isolated from RuntimeManager")

    modules = inventory["modules"]
    assert isinstance(modules, dict)
    for module in (
        "manager_tables",
        "core_model",
        "manager",
        "manager_dump",
        "manager_serialize",
        "dbus",
        "emergency_action",
        "varlink_manager",
    ):
        entry = modules.get(module)
        if not isinstance(entry, dict):
            failures.append(f"manager vocabulary module {module} is missing from reachability inventory")
            continue
        expected = "runtime-reachable" if module == "manager_tables" else "compiled-but-disconnected"
        if entry.get("classification") != expected:
            failures.append(f"{module} has an unreviewed manager-vocabulary reachability classification")
    return failures


def parser_self_check() -> None:
    modules = declared_modules("pub mod alpha;\n// pub mod ignored;\npub mod beta;\n")
    if modules != ["alpha", "beta"]:
        raise ValueError(f"top-level module parser self-check failed: {modules}")

    known = {"alpha", "beta", "gamma", "delta", "epsilon", "ignored"}
    references = referenced_top_modules(
        """
        use crate::alpha as local_alpha;
        use systemd_core_rs::{beta, gamma as local_gamma};
        use systemd_core_rs as core;
        let _ = crate::delta::Thing;
        use core::{epsilon::Thing};
        let _ = "crate::ignored::Thing";
        let _ = b"crate::ignored::Thing";
        let _ = br#"crate::ignored::Thing"#;
        #[cfg(test)]
        mod test_only {
            const CLOSE: char = '}';
            let _ = crate::ignored::Thing;
        }
        #[cfg(test)]
        #[path = "test_events.rs"]
        mod path_test_only;
        """,
        known,
    )
    if references != known - {"ignored"}:
        raise ValueError(f"reference parser self-check failed: {references}")

    character_references = referenced_top_modules(
        """
        const QUOTE: u8 = b'"';
        const BRACE: char = '{';
        use crate::alpha::Thing;
        """,
        known,
    )
    if character_references != {"alpha"}:
        raise ValueError(
            f"character literal parser self-check failed: {character_references}"
        )

    reexport_source = "pub mod alpha;\npub use alpha::Thing;\n"
    reexports = crate_root_reexports(reexport_source, {"alpha"})
    reexport_references = referenced_top_modules(
        "use systemd_core_rs::Thing;\n", {"alpha"}, reexports
    )
    if reexport_references != {"alpha"}:
        raise ValueError(
            f"crate-root reexport parser self-check failed: {reexport_references}"
        )

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "parent.rs").write_text("mod child;\n", encoding="utf-8")
        (root / "parent").mkdir()
        (root / "parent/child.rs").write_text("use crate::alpha;\n", encoding="utf-8")
        paths = module_source_tree(root / "parent.rs")
        if {path.relative_to(root).as_posix() for path in paths} != {
            "parent.rs",
            "parent/child.rs",
        }:
            raise ValueError("submodule parser self-check failed")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "main.rs").write_text("mod cli;\n", encoding="utf-8")
        (root / "cli.rs").write_text(
            "use systemd_core_rs::alpha;\n", encoding="utf-8"
        )
        paths = module_source_tree(root / "main.rs", crate_root=True)
        if {path.relative_to(root).as_posix() for path in paths} != {
            "main.rs",
            "cli.rs",
        }:
            raise ValueError("binary submodule parser self-check failed")

    unsupported = {
        "include": 'include!("wiring.rs");',
        "cfg module": "#[cfg(any())]\nmod dormant;",
        "cfg import": "#[cfg(any())]\nuse crate::alpha;",
        "macro module": "macro_rules! wire {\n() => {\nmod generated;\n}\n}",
        "macro invocation module": "cfg_if! { if #[cfg(any())] { mod generated; } }",
        "nested module": "mod outer {\nmod inner;\n}",
    }
    for description, source in unsupported.items():
        try:
            runtime_code(source, f"<self-check {description}>")
        except ValueError:
            pass
        else:
            raise ValueError(f"{description} fail-closed self-check failed")

    # Inline cfg modules do not add an external source-tree edge; their
    # references remain in the containing file and are safe for the Linux
    # reachability inventory to scan conservatively.
    runtime_code(
        '#[cfg(target_os = "linux")]\nmod inline { use crate::alpha; }',
        "<self-check cfg inline module>",
    )


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    baseline_path = root / args.baseline
    try:
        parser_self_check()
        current = inventory(root)
        if args.write_baseline:
            baseline_path.write_text(
                json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(
                "wrote core runtime reachability baseline: "
                f"{baseline_path} ({len(current['modules'])} modules)"
            )
            return 0
        baseline = load_baseline(baseline_path)
        failures = compare_inventory(current, baseline)
        failures.extend(verify_canonical_manager_vocabulary(root, current))
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"core runtime reachability gate failed: {error}")
        return 1

    if failures:
        print("core runtime reachability gate failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    modules = current["modules"]
    assert isinstance(modules, dict)
    reachable = sum(
        entry["classification"] == "runtime-reachable" for entry in modules.values()
    )
    print(
        "core runtime reachability gate OK: "
        f"roots={len(current['binary_roots'])} reachable={reachable} "
        f"compiled_disconnected={len(modules) - reachable}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
