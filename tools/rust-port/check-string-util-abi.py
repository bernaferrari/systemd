#!/usr/bin/env python3
"""Statically verify the reviewed basic Rust string-util C ABI.

This intentionally does not compile or execute the port. It prevents the Rust
header, C shadow test, Meson source inventory, and explicit `extern "C"`
facade from drifting apart, including C/Rust signature mismatches.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/basic/rust/string_util.h"
FACADE = ROOT / "src/basic/rust/string_util_ffi.rs"
CRATE_ROOT = ROOT / "src/basic/rust/lib.rs"
BASIC_MESON = ROOT / "src/basic/meson.build"
TEST_MESON = ROOT / "tests-extra/meson.build"
RUST_CI = ROOT / ".github/workflows/rust-ci.yml"
TEST_SOURCE = ROOT / "tests-extra/test-string-util-rust.c"
FUNDAMENTAL_TEST_SOURCE = ROOT / "tests-extra/test-string-util-fundamental-rust.c"
PARSE_EXTRA_TEST_SOURCE = ROOT / "tests-extra/test-parse-util-extra-rust.c"
REPLACE_TEST_SOURCE = ROOT / "tests-extra/test-strreplace-rust.c"
OWNED_EXTRA_TEST_SOURCE = ROOT / "tests-extra/test-string-util-extra2-rust.c"
MAKE_CSTRING_TEST_SOURCE = ROOT / "tests-extra/test-make-cstring-rust.c"
SCAN_EXTRA_TEST_SOURCE = ROOT / "tests-extra/test-string-util-extra-rust.c"
ESCAPE_EXTRA_TEST_SOURCE = ROOT / "tests-extra/test-string-util-extra7-rust.c"
MUTATION_TEST_SOURCE = ROOT / "tests-extra/test-string-mutation-rust.c"
INLINE2_TEST_SOURCE = ROOT / "tests-extra/test-string-util-inline2-rust.c"
CORE = ROOT / "src/basic/rust/string_util.rs"
LINES_CORE = ROOT / "src/basic/rust/string_util_lines.rs"
FUNDAMENTAL_CORE = ROOT / "src/basic/rust/string_util_fundamental.rs"
OWNED_CORE = ROOT / "src/basic/rust/string_util_owned.rs"
REPLACE_CORE = ROOT / "src/basic/rust/string_util_replace.rs"
SCAN_CORE = ROOT / "src/basic/rust/string_util_scan.rs"
ESCAPE_CORE = ROOT / "src/basic/rust/string_util_escape.rs"
C_AUTHORITY_HEADER = ROOT / "src/basic/string-util.h"
C_FUNDAMENTAL_AUTHORITY_HEADER = ROOT / "src/fundamental/string-util.h"
C_AUTHORITY_SOURCE = ROOT / "src/basic/string-util.c"
C_ESCAPE_AUTHORITY_HEADER = ROOT / "src/basic/escape.h"
C_ESCAPE_AUTHORITY_SOURCE = ROOT / "src/basic/escape.c"

Signature = tuple[tuple[str, ...], str]

SAFE_VALUE_EXPORTS = {
    "rs_yes_no",
    "rs_on_off",
    "rs_comparison_operator",
    "rs_ascii_isdigit",
    "rs_ascii_ishex",
    "rs_ascii_isalpha",
    "rs_ascii_tolower",
    "rs_ascii_toupper",
    "rs_char_is_cc",
}

C_TYPES = {
    "bool": "bool",
    "char": "c_char",
    "char *": "*mutc_char",
    "char **": "*mut*mutc_char",
    "char * const *": "*const*mutc_char",
    "const char *": "*constc_char",
    "const char **": "*mut*constc_char",
    "const void *": "*constc_void",
    "void *": "*mutc_void",
    "void": "()",
    "int": "i32",
    "size_t": "usize",
    "size_t *": "*mutusize",
    "ssize_t": "isize",
}


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def duplicates(names: list[str]) -> list[str]:
    return sorted(name for name, count in Counter(names).items() if count > 1)


def compact(type_name: str) -> str:
    return re.sub(r"\s+", "", type_name.strip())


def c_type(type_name: str) -> str:
    normalized = re.sub(r"\s+", " ", type_name.strip())
    normalized = {
        "char*": "char *",
        "char**": "char **",
        "constchar*": "const char *",
        "void*": "void *",
    }.get(re.sub(r"\s+", "", normalized), normalized)
    try:
        return C_TYPES[normalized]
    except KeyError as error:
        raise ValueError(f"unsupported C type: {normalized}") from error


def c_parameter_type(parameter: str) -> str:
    parameter = re.sub(r"\s+", " ", parameter.strip())
    for type_name in sorted(C_TYPES, key=len, reverse=True):
        suffix = parameter.removeprefix(type_name)
        name_pattern = (
            r"\s*[A-Za-z_][A-Za-z0-9_]*" if "*" in type_name else r"\s+[A-Za-z_][A-Za-z0-9_]*"
        )
        if suffix != parameter and re.fullmatch(name_pattern, suffix):
            return c_type(type_name)
    raise ValueError(f"cannot parse C parameter: {parameter}")


def header_inventory(text: str) -> list[tuple[str, Signature]]:
    declarations: list[tuple[str, Signature]] = []
    prototype = re.compile(
        r"^(bool|char|char\s*\*|const\s+char\s*\*|void\s*\*|void|int|size_t|ssize_t)\s*"
        r"(rs_[A-Za-z0-9_]+)\s*\(([^)]*)\)\s*;$",
        re.MULTILINE,
    )
    for result, name, raw_parameters in prototype.findall(text):
        parameters = ()
        if raw_parameters.strip() and raw_parameters.strip() != "void":
            parameters = tuple(c_parameter_type(parameter) for parameter in raw_parameters.split(","))
        declarations.append((name, (parameters, c_type(result))))
    return declarations


def source_inventory(text: str) -> list[tuple[str, Signature, bool]]:
    exports: list[tuple[str, Signature, bool]] = []
    function = re.compile(
        r"#\[unsafe\(no_mangle\)\]\s*"
        r"pub\s+(unsafe\s+)?extern\s+\"C\"\s+fn\s+"
        r"(rs_[A-Za-z0-9_]+)\s*\((.*?)\)\s*"
        r"(?:->\s*([^\{]+?))?\s*\{",
        re.DOTALL,
    )
    for unsafe_marker, name, raw_parameters, raw_result in function.findall(text):
        parameters: list[str] = []
        if raw_parameters.strip():
            for parameter in raw_parameters.split(","):
                if not parameter.strip():
                    continue
                if ":" not in parameter:
                    raise ValueError(f"cannot parse Rust parameter for {name}: {parameter}")
                _, type_name = parameter.rsplit(":", 1)
                parameters.append(compact(type_name))
        exports.append(
            (
                name,
                (tuple(parameters), compact(raw_result or "()")),
                bool(unsafe_marker),
            )
        )
    return exports


def format_signature(signature: Signature) -> str:
    parameters, result = signature
    return f"({', '.join(parameters)}) -> {result}"


def main() -> int:
    header = HEADER.read_text()
    facade = FACADE.read_text()
    crate_root = CRATE_ROOT.read_text()
    basic_meson = BASIC_MESON.read_text()
    test_meson = TEST_MESON.read_text()
    rust_ci = RUST_CI.read_text()
    test_source = TEST_SOURCE.read_text()
    fundamental_test_source = FUNDAMENTAL_TEST_SOURCE.read_text()
    parse_extra_test_source = PARSE_EXTRA_TEST_SOURCE.read_text()
    replace_test_source = REPLACE_TEST_SOURCE.read_text()
    owned_extra_test_source = OWNED_EXTRA_TEST_SOURCE.read_text()
    make_cstring_test_source = MAKE_CSTRING_TEST_SOURCE.read_text()
    scan_extra_test_source = SCAN_EXTRA_TEST_SOURCE.read_text()
    escape_extra_test_source = ESCAPE_EXTRA_TEST_SOURCE.read_text()
    mutation_test_source = MUTATION_TEST_SOURCE.read_text()
    inline2_test_source = INLINE2_TEST_SOURCE.read_text()
    core = CORE.read_text()
    lines_core = LINES_CORE.read_text()
    fundamental_core = FUNDAMENTAL_CORE.read_text()
    owned_core = OWNED_CORE.read_text()
    replace_core = REPLACE_CORE.read_text()
    scan_core = SCAN_CORE.read_text()
    escape_core = ESCAPE_CORE.read_text()
    c_authority_header = C_AUTHORITY_HEADER.read_text()
    c_fundamental_authority_header = C_FUNDAMENTAL_AUTHORITY_HEADER.read_text()
    c_authority_source = C_AUTHORITY_SOURCE.read_text()
    c_escape_authority_header = C_ESCAPE_AUTHORITY_HEADER.read_text()
    c_escape_authority_source = C_ESCAPE_AUTHORITY_SOURCE.read_text()

    try:
        declarations = header_inventory(header)
        abi_sources = "\n".join((facade, core, lines_core))
        exports = source_inventory(abi_sources)
    except ValueError as error:
        return fail(str(error))

    declared_names = [name for name, _ in declarations]
    exported_names = [name for name, _, _ in exports]
    header_symbols = re.findall(r"\brs_[A-Za-z0-9_]+(?=\s*\()", header)
    if header_symbols != declared_names:
        return fail("unparsed or out-of-order Rust string-util header declarations")
    if duplicate := duplicates(declared_names):
        return fail(f"duplicate Rust string-util header declarations: {duplicate}")
    if duplicate := duplicates(exported_names):
        return fail(f"duplicate Rust string-util ABI exports: {duplicate}")

    declared = dict(declarations)
    exported = {name: signature for name, signature, _ in exports}
    if missing := sorted(declared.keys() - exported.keys()):
        return fail(f"header symbols without explicit Rust C export: {missing}")
    if extra := sorted(exported.keys() - declared.keys()):
        return fail(f"explicit Rust C exports missing from header: {extra}")
    mismatches = {
        name: (declared[name], exported[name])
        for name in declared.keys() & exported.keys()
        if declared[name] != exported[name]
    }
    if mismatches:
        formatted = "; ".join(
            f"{name}: C {format_signature(expected)} Rust {format_signature(actual)}"
            for name, (expected, actual) in sorted(mismatches.items())
        )
        return fail(f"Rust string-util ABI signature mismatch: {formatted}")

    export_safety = {name: is_unsafe for name, _, is_unsafe in exports}
    if wrong_safe := sorted(
        name for name in SAFE_VALUE_EXPORTS if export_safety.get(name) is not False
    ):
        return fail(f"value-only Rust string-util exports must be safe: {wrong_safe}")
    if unexpected_safe := sorted(
        name
        for name, is_unsafe in export_safety.items()
        if not is_unsafe and name not in SAFE_VALUE_EXPORTS
    ):
        return fail(
            "pointer-bearing Rust string-util exports unexpectedly became safe: "
            f"{unexpected_safe}"
        )

    for name in set(declared_names) - SAFE_VALUE_EXPORTS:
        if not re.search(
            rf"^/// # Safety.*?^pub unsafe extern \"C\" fn {name}\b",
            abi_sources,
            re.MULTILINE | re.DOTALL,
        ):
            return fail(f"Rust string-util ABI export lacks a Rustdoc safety contract: {name}")

    if "mod string_util_ffi;" not in crate_root:
        return fail("basic Rust crate does not compile the string-util ABI facade")
    if "mod string_util_fundamental;" not in crate_root:
        return fail("basic Rust crate does not compile the fundamental string-util core")
    if "'rust/string_util_ffi.rs'," not in basic_meson:
        return fail("basic Meson rust_sources omits string_util_ffi.rs")
    if "'rust/string_util_fundamental.rs'," not in basic_meson:
        return fail("basic Meson rust_sources omits the fundamental string-util core")
    if "'test-string-util-rust'" not in test_meson:
        return fail("Meson no longer registers the string-util C shadow test")
    if "'test-string-util-fundamental-rust'" not in test_meson:
        return fail("Meson no longer registers the fundamental string-util C shadow test")
    if "'test-strreplace-rust'" not in test_meson:
        return fail("Meson no longer registers the dedicated strreplace parity fixture")
    if "'test-parse-util-extra-rust'" not in test_meson:
        return fail("Meson no longer registers the strrep C comparison fixture")
    if "'test-string-util-extra2-rust'" not in test_meson:
        return fail("Meson no longer registers the free_and_strndup comparison fixture")
    if "'test-make-cstring-rust'" not in test_meson:
        return fail("Meson no longer registers the make_cstring comparison fixture")
    if "'test-string-util-extra-rust'" not in test_meson:
        return fail("Meson no longer registers the string scan comparison fixture")
    if "'test-string-util-extra7-rust'" not in test_meson:
        return fail("Meson no longer registers the string escape comparison fixture")
    if "rust-meson-reviewed-shadows:" not in rust_ci or any(
        test not in rust_ci
        for test in (
            "test-string-util-rust",
            "test-string-util-fundamental-rust",
            "test-strreplace-rust",
            "test-parse-util-extra-rust",
            "test-string-util-extra2-rust",
            "test-make-cstring-rust",
            "test-string-util-extra-rust",
            "test-string-util-extra7-rust",
        )
    ):
        return fail("reviewed string-util comparisons must stay in the authoritative Meson CI job")

    called = set(
        re.findall(
            r"\b(rs_[A-Za-z0-9_]+)\s*\(",
            test_source
            + "\n"
            + fundamental_test_source
            + "\n"
            + parse_extra_test_source
            + "\n"
            + owned_extra_test_source
            + "\n"
            + make_cstring_test_source
            + "\n"
            + scan_extra_test_source
            + "\n"
            + escape_extra_test_source
            + "\n"
            + mutation_test_source
            + "\n"
            + inline2_test_source,
        )
    )
    if untested := sorted(set(declared) - called):
        return fail(f"declared Rust string-util ABI symbols absent from C shadow test: {untested}")

    panic_prone_replacement_allocations = (
        r"\bVec::",
        r"\bString::",
        r"\bvec!\s*\[",
        r"\.collect\s*\(",
        r"\.to_vec\s*\(",
        r"\.to_owned\s*\(",
    )
    if offenders := [
        pattern
        for pattern in panic_prone_replacement_allocations
        if re.search(pattern, replace_core)
    ]:
        return fail(
            "exported strreplace core contains infallible Rust heap construction: "
            + ", ".join(offenders)
        )
    replacement_guards = (
        "output_len.checked_add(1)",
        "malloc(allocation_size)",
        "if output.is_null()",
        "written.checked_add(new.len())",
        "std::ptr::copy_nonoverlapping",
    )
    if missing_guard := [
        guard for guard in replacement_guards if guard not in replace_core
    ]:
        return fail(
            "exported strreplace core lost checked C-allocation guards: "
            + ", ".join(missing_guard)
        )
    if "bytes.len().checked_add(1)" not in owned_core:
        return fail("shared C-string allocator lost its checked trailing-NUL size")
    if re.search(r"malloc\s*\(\s*bytes\.len\(\)\s*\+\s*1\s*\)", owned_core):
        return fail("shared C-string allocator performs unchecked size arithmetic")
    reviewed_owned_authorities = (
        (
            r"\bint\s+free_and_strndup\s*\(\s*char\s*\*\*\s*p\s*,\s*"
            r"const\s+char\s*\*\s*s\s*,\s*size_t\s+l\s*\)",
            "free_and_strndup",
        ),
        (
            r"\bint\s+make_cstring\s*\(\s*const\s+void\s*\*\s*s\s*,\s*"
            r"size_t\s+n\s*,\s*MakeCStringMode\s+mode\s*,\s*char\s*\*\*\s*ret\s*\)",
            "make_cstring",
        ),
    )
    for authority_pattern, authority_name in reviewed_owned_authorities:
        if not re.search(authority_pattern, c_authority_source):
            return fail(f"current C authority drifted for {authority_name}")
    if not re.search(
        r"MAKE_CSTRING_REFUSE_TRAILING_NUL\s*,\s*"
        r"MAKE_CSTRING_ALLOW_TRAILING_NUL\s*,\s*"
        r"MAKE_CSTRING_REQUIRE_TRAILING_NUL\s*,\s*"
        r"_MAKE_CSTRING_MODE_MAX",
        c_authority_header,
        re.DOTALL,
    ):
        return fail("current MakeCStringMode discriminants drifted")
    if (
        '#include "rust/string_util.h"' not in parse_extra_test_source
        or "char* rs_strrep(" in parse_extra_test_source
        or 'strrep("ab", 3)' not in parse_extra_test_source
        or not re.search(
            r"pub unsafe fn rs_strrep\s*\(\s*s:\s*\*const\s+(?:libc::)?c_char,\s*"
            r"n:\s*usize\s*\)",
            replace_core,
        )
    ):
        return fail("strrep must use the exact size_t ABI and its registered C comparison fixture")

    scan_authorities = (
        (r"static\s+inline\s+bool\s+char_is_cc\s*\(\s*char\s+p\s*\)", c_authority_header, "char_is_cc"),
        (r"char\s*\*\s*strshorten\s*\(\s*char\s*\*\s*s\s*,\s*size_t\s+l\s*\)", c_authority_source, "strshorten"),
        (r"ssize_t\s+strlevenshtein\s*\(\s*const\s+char\s*\*\s*x\s*,\s*const\s+char\s*\*\s*y\s*\)", c_authority_source, "strlevenshtein"),
        (r"char\s*\*\s*strrstr_internal\s*\(\s*const\s+char\s*\*\s*haystack\s*,\s*const\s+char\s*\*\s*needle\s*\)", c_authority_source, "strrstr_internal"),
        (r"bool\s+version_is_valid\s*\(\s*const\s+char\s*\*\s*s\s*,\s*VersionFlags\s+flags\s*\)", c_authority_source, "version_is_valid"),
    )
    for authority_pattern, authority, authority_name in scan_authorities:
        if not re.search(authority_pattern, authority):
            return fail(f"current C authority drifted for {authority_name}")
    version_flag_values = (
        r"VERSION_ALLOW_EMPTY\s*=\s*1\s*<<\s*0",
        r"VERSION_ALLOW_UNDERSCORE\s*=\s*1\s*<<\s*1",
        r"VERSION_ALLOW_PLUS\s*=\s*1\s*<<\s*2",
    )
    if any(not re.search(value, c_authority_header) for value in version_flag_values):
        return fail("current C VersionFlags values drifted")
    if '#include "rust/string_util.h"' not in scan_extra_test_source:
        return fail("string scan fixture must consume the canonical Rust ABI header")
    if "rs_version_is_valid_versionspec" in header + abi_sources + scan_core + scan_extra_test_source:
        return fail("obsolete non-upstream version_is_valid_versionspec ABI remains exposed")
    scan_contracts = (
        "pub fn rs_char_is_cc(p: u8) -> bool",
        "pub unsafe fn rs_strshorten(s: *mut c_char, l: usize) -> *mut c_char",
        "pub unsafe fn rs_strlevenshtein(x: *const c_char, y: *const c_char) -> isize",
        "pub unsafe fn rs_strrstr_internal(haystack: *const c_char, needle: *const c_char) -> *mut c_char",
        "pub unsafe fn rs_version_is_valid(s: *const c_char, flags: i32) -> bool",
        "row.try_reserve_exact(len).map_err(|_| ())?",
        "l >= usize::MAX - 1",
        "for index in 0..=l",
        "*s.add(index)",
    )
    if missing_contract := [contract for contract in scan_contracts if contract not in scan_core]:
        return fail("string scan core lost reviewed C-parity guard: " + ", ".join(missing_contract))

    fundamental_authorities = (
        r"static\s+inline\s+int\s+strcmp_ptr\s*\(",
        r"static\s+inline\s+int\s+strncmp_ptr\s*\(",
        r"static\s+inline\s+int\s+strcasecmp_ptr\s*\(",
        r"static\s+inline\s+bool\s+streq_ptr\s*\(",
        r"static\s+inline\s+bool\s+strneq_ptr\s*\(",
        r"static\s+inline\s+bool\s+strcaseeq_ptr\s*\(",
        r"static\s+inline\s+size_t\s+strlen_ptr\s*\(",
        r"static\s+inline\s+bool\s+isempty\s*\(",
        r"static\s+inline\s+const\s+sd_char\s*\*strempty\s*\(",
        r"static\s+inline\s+const\s+sd_char\s*\*yes_no\s*\(",
        r"static\s+inline\s+const\s+sd_char\s*\*on_off\s*\(",
        r"static\s+inline\s+const\s+sd_char\s*\*\s*comparison_operator\s*\(",
        r"static\s+inline\s+void\s*\*memory_startswith\s*\(",
        r"static\s+inline\s+bool\s+ascii_isdigit\s*\(",
        r"static\s+inline\s+bool\s+ascii_ishex\s*\(",
        r"static\s+inline\s+bool\s+ascii_isalpha\s*\(",
    )
    if any(
        not re.search(authority, c_fundamental_authority_header)
        for authority in fundamental_authorities
    ):
        return fail("current fundamental string-util C authority drifted")
    if '#include "rust/string_util.h"' not in fundamental_test_source:
        return fail("fundamental string-util fixture must consume the canonical Rust ABI header")
    fundamental_contracts = (
        "pub fn nullable_order",
        "pub fn strcmp_bytes",
        "pub fn strncmp_bytes",
        "pub fn strcasecmp_bytes",
        "pub fn memory_startswith",
        "pub fn ascii_isdigit",
        "pub fn ascii_ishex",
        "pub fn ascii_isalpha",
    )
    if missing_contract := [
        contract for contract in fundamental_contracts if contract not in fundamental_core
    ]:
        return fail("fundamental string-util core lost reviewed safe contract: " + ", ".join(missing_contract))
    if any(marker in fundamental_core for marker in ("Vec", "String", "malloc", "panic!", ".unwrap(")):
        return fail("fundamental string-util core must stay allocation-free and panic-free")

    escape_authorities = (
        (r"char\s*\*\s*strextendn\s*\(\s*char\s*\*\*\s*x\s*,\s*const\s+char\s*\*\s*s\s*,\s*size_t\s+l\s*\)", c_authority_source, "strextendn"),
        (r"char\s*\*\s*cellescape\s*\(\s*char\s*\*\s*buf\s*,\s*size_t\s+len\s*,\s*const\s+char\s*\*\s*s\s*\)", c_authority_source, "cellescape"),
        (r"char\s*\*\s*string_erase\s*\(\s*char\s*\*\s*x\s*\)", c_authority_source, "string_erase"),
        (r"char\s*\*\s*escape_non_printable_full\s*\(\s*const\s+char\s*\*\s*str\s*,\s*size_t\s+console_width\s*,\s*XEscapeFlags\s+flags\s*\)", c_escape_authority_source, "escape_non_printable_full"),
    )
    for authority_pattern, authority, authority_name in escape_authorities:
        if not re.search(authority_pattern, authority):
            return fail(f"current C authority drifted for {authority_name}")
    if any(
        not re.search(value, c_escape_authority_header)
        for value in (
            r"XESCAPE_8_BIT\s*=\s*1\s*<<\s*0",
            r"XESCAPE_FORCE_ELLIPSIS\s*=\s*1\s*<<\s*1",
        )
    ):
        return fail("current C XEscapeFlags values drifted")
    if '#include "rust/string_util.h"' not in escape_extra_test_source:
        return fail("string escape fixture must consume the canonical Rust ABI header")
    escape_contracts = (
        "fn cellescape_bytes(buffer: &mut [u8], input: &[u8])",
        "fn try_xescape_without_bad",
        "fn try_utf8_escape_non_printable",
        "libc::explicit_bzero",
        "output.try_reserve_exact(capacity).map_err(|_| ())?",
        "while append_length < l",
        "*s.add(append_length)",
        "let replacement =",
        "*x = replacement;",
    )
    if missing_contract := [contract for contract in escape_contracts if contract not in escape_core]:
        return fail("string escape core lost reviewed C-parity guard: " + ", ".join(missing_contract))

    if (
        'string_has_cc("hello\\x7fworld", "\\x7f")' not in test_source
        or "if ok_bytes.contains(&c)" not in core
        or "matches!(c, 1..=0x1f | 0x7f)" not in core
    ):
        return fail("string_has_cc must apply its allowed-control set to DEL as well as C0 controls")

    replacement_fixtures = (
        'strreplace("aaa", "a", "bb")',
        'strreplace("aaabbb", "aaa", "x")',
        'strreplace("abc", "b", "")',
        'strreplace("aaa", "aa", "X")',
    )
    if missing_fixture := [
        fixture for fixture in replacement_fixtures if fixture not in replace_test_source
    ]:
        return fail(
            "dedicated strreplace parity fixture lost replacement semantics: "
            + ", ".join(missing_fixture)
        )

    print(
        "string-util ABI inventory: "
        f"declared={len(declared)} exported={len(exported)} "
        f"C-shadow-tested={len(set(declared) & called)} signatures={len(declared)} "
        "duplicates=0 meson-ci-tests=8 C-authority=11 panic-prone-allocations=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
