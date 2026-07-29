#!/usr/bin/env python3
"""Statically verify the reviewed basic Rust C ABI facades.

This intentionally does not compile or execute the port. It compares reviewed
header-declared surfaces with their explicit Rust C ABI, current C authority,
registered comparison tests, and Meson source registration.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

from basic_ffi_review_catalog import build_catalog


ROOT = Path(__file__).resolve().parents[2]
ROOT_MESON = ROOT / "meson.build"
MESON_OPTIONS = ROOT / "meson_options.txt"
MESON = ROOT / "src/basic/meson.build"
TEST_MESON = ROOT / "tests-extra/meson.build"
RUST_CI = ROOT / ".github/workflows/rust-ci.yml"
CATALOG = build_catalog(ROOT)
SURFACES = CATALOG.surfaces
SURFACE_EXTRA_SOURCES = CATALOG.surface_extra_sources
PARTIAL_SURFACES = CATALOG.partial_surfaces
PARTIAL_EXTRA_SOURCES = CATALOG.partial_extra_sources
SHADOW_TESTS = CATALOG.shadow_tests
PARTIAL_SHADOW_TESTS = CATALOG.partial_shadow_tests
C_AUTHORITIES = CATALOG.c_authorities
PARTIAL_C_AUTHORITIES = CATALOG.partial_c_authorities
IN_ADDR_UTIL_HEADER = ROOT / "src/basic/rust/in_addr_util.h"
IN_ADDR_UTIL_SOURCE = ROOT / "src/basic/rust/in_addr_util.rs"
IN_ADDR_UTIL_C_AUTHORITIES = (
    ROOT / "src/basic/in-addr-util.c",
    ROOT / "src/basic/in-addr-util.h",
)
IN_ADDR_UTIL_SHADOW_TESTS = (
    ROOT / "tests-extra/test-in-addr-util-rust.c",
    ROOT / "tests-extra/test-misc-extra-rust.c",
    ROOT / "tests-extra/test-misc-inline-rust.c",
    ROOT / "tests-extra/test-remaining-untested-rust.c",
)
ETHER_ADDR_UTIL_HEADER = ROOT / "src/basic/rust/ether_addr_util.h"
ETHER_ADDR_UTIL_SOURCE = ROOT / "src/basic/rust/ether_addr_util.rs"
ETHER_ADDR_UTIL_C_AUTHORITIES = (
    ROOT / "src/basic/ether-addr-util.c",
    ROOT / "src/basic/ether-addr-util.h",
)
ETHER_ADDR_UTIL_SHADOW_TEST = ROOT / "tests-extra/test-ether-addr-util-rust.c"
SHARED_EXIT_STATUS_HEADER = ROOT / "src/shared/rust/exit_status.h"
IOVEC_C_HEADER = ROOT / "src/basic/iovec-util.h"
IOVEC_SHADOW_TESTS = (
    ROOT / "tests-extra/test-iovec-util-rust.c",
    ROOT / "tests-extra/test-iovec-util-extra.c",
    ROOT / "tests-extra/test-iovec-util-extra2.c",
    ROOT / "tests-extra/test-iovec-util-extra4.c",
)
IOVEC_INCLUDE_TESTS = (
    ROOT / "tests-extra/test-iovec-util-rust.c",
    ROOT / "tests-extra/test-iovec-wrapper-rust.c",
    ROOT / "tests-extra/test-misc-untested2-rust.c",
)
C_TYPES = {
    "CompareOperator": "i32",
    "ColorMode": "i32",
    "ExecCommandFlags": "i32",
    "ExecCommandFlags *": "*muti32",
    "Compression": "i32",
    "CompareOperatorParseFlags": "i32",
    "ConditionType": "i32",
    "ExitStatusClass": "i32",
    "ExitClean": "i32",
    # Glyph has int ABI. The Rust facade accepts the raw integer so C callers
    # retain the header's assertion contract for out-of-range positive values.
    "Glyph": "i32",
    "NamespaceType": "i32",
    "GptPartitionType": "GptPartitionType",
    "ShellEscapeFlags": "u32",
    "SecureBootMode": "i32",
    "UnescapeFlags": "u32",
    "XEscapeFlags": "u32",
    # gunicode.c aliases its Unicode scalar type to uint32_t locally.
    "unichar": "u32",
    # These C enums have `int` ABI, but the Rust facades intentionally take
    # raw integers so invalid C discriminants remain defined/non-matching.
    "OutputMode": "i32",
    "RuntimeScope": "i32",
    "PartitionPolicyFlags": "i32",
    "PartitionDesignator": "i32",
    # These C layouts are deliberately represented by separate repr(C)
    # boundary mirrors, never by the native Rust collection/vector types.
    "const ExitStatusSet *": "*constCExitStatusSet",
    "ExitStatusSet *": "*mutCExitStatusSet",
    "const ImagePolicy *": "*constCImagePolicy",
    "ImagePolicy *": "*mutCImagePolicy",
    "ImagePolicy **": "*mut*mutCImagePolicy",
    # UIDRange is a C-owned pointer/length allocation. The native Rust Vec
    # type intentionally stays outside this ABI and is represented instead by
    # the dedicated repr(C) CUIDRange boundary mirror.
    "const UIDRange *": "*constCUIDRange",
    "UIDRange *": "*mutCUIDRange",
    "UIDRange **": "*mut*mutCUIDRange",
    # Socket ABI facades keep the platform union/aggregate representation
    # opaque in the generated C header while their Rust implementation owns
    # the private repr(C) mirrors. This is still a C-exact pointer ABI.
    "const struct sockaddr *": "*constc_void",
    "const struct sockaddr_ll *": "*constc_void",
    "const struct sockaddr_un *": "*constc_void",
    "struct sockaddr_un *": "*mutc_void",
    "const union sockaddr_union *": "*constc_void",
    "union sockaddr_union *": "*mutc_void",
    "const union in_addr_union *": "*constc_void",
    "union in_addr_union *": "*mutc_void",
    "const SocketAddress *": "*constc_void",
    "SocketAddress *": "*mutc_void",
    "IfnameValidFlags": "i32",
    "DNSLabelFlags": "u32",
    "RateLimit *": "*mutRateLimit",
    "const RateLimit *": "*constRateLimit",
    # Packed PE records stay opaque in the Rust facade. Pointer representation
    # is nevertheless C-exact, so map these C record pointers to the explicit
    # c_void boundary rather than manufacturing mirrored packed types.
    "const PeHeader *": "*constc_void",
    "const IMAGE_SECTION_HEADER *": "*constc_void",
    "const IMAGE_DATA_DIRECTORY *": "*constc_void",
    "ExtractFlags": "u32",
    "struct rs_Strbuf *": "*mutRsStrbuf",
    "struct strbuf *": "*mutRsStrbuf",
    "struct rs_Mempool *": "*mutMempool",
    "struct mempool *": "*mutMempool",
    "struct rs_sha1_ctx *": "*mutSha1Ctx",
    "struct sha1_ctx *": "*mutSha1Ctx",
    "struct rs_siphash *": "*mutsiphash",
    "const struct Bitmap *": "*constCBitmap",
    "struct Bitmap *": "*mutCBitmap",
    "struct Bitmap **": "*mut*mutCBitmap",
    "struct Iterator *": "*mutCIterator",
    "const Bitmap *": "*constCBitmap",
    "Bitmap *": "*mutCBitmap",
    "Bitmap **": "*mut*mutCBitmap",
    "Iterator *": "*mutCIterator",
    "struct rs_IoVecWrapper *": "*mutRsIoVecWrapper",
    "const struct rs_IoVecWrapper *": "*constRsIoVecWrapper",
    "struct iovec_wrapper *": "*mutRsIoVecWrapper",
    "const struct iovec_wrapper *": "*constRsIoVecWrapper",
    "struct rs_Prioq *": "*mutRsPrioq",
    "const struct rs_Prioq *": "*constRsPrioq",
    "Prioq *": "*mutRsPrioq",
    "rs_prioq_compare_fn_t": "PrioqCompareFn",
    "compare_func_t": "PrioqCompareFn",
    "comparison_fn_t": "ComparisonFn",
    "comparison_userdata_fn_t": "ComparisonUserdataFn",
    "const struct timespec *": "*constLibcTimespec",
    "struct timespec *": "*mutLibcTimespec",
    "const struct timeval *": "*constLibcTimeval",
    "struct timeval *": "*mutLibcTimeval",
    "ValidHostnameFlags": "i32",
    "SleepOperation": "i32",
    "bool": "bool",
    "bool *": "*mutbool",
    "double": "f64",
    "double *": "*mutf64",
    "char": "c_char",
    "char16_t": "u16",
    "char16_t *": "*mutu16",
    "const char16_t *": "*constu16",
    "char32_t": "u32",
    "char32_t *": "*mutu32",
    "ssize_t": "isize",
    "char *": "*mutc_char",
    "char*": "*mutc_char",
    "char * *": "*mut*mutc_char",
    "char * const *": "*const*mutc_char",
    "const char * const *": "*const*constc_char",
    "char* const*": "*const*mutc_char",
    "rs_replace_var_lookup_t": "Option<ReplaceVarLookup>",
    "char ***": "*mut*mut*mutc_char",
    "char **": "*mut*mutc_char",
    "const char *": "*constc_char",
    "const char*": "*constc_char",
    "const sd_char *": "*constc_char",
    "const char **": "*mut*constc_char",
    "const char * *": "*mut*constc_char",
    "const sd_id128_t *": "*constSdId128",
    "const void *": "*constc_void",
    "void **": "*mut*mutc_void",
    "const uint64_t *": "*constu64",
    "const uint8_t *": "*constu8",
    "const uint8_t **": "*mut*constu8",
    "const uint16_t *": "*constu16",
    "const int *": "*consti32",
    "const uint8_t": "u8",
    "const CapabilityQuintet *": "*constCapabilityQuintet",
    "const EdidHeader *": "*constEdidHeaderAbi",
    "const dev_t *": "*constu64",
    "const PidRef *": "*constPidRef",
    "const InstallChange *": "*constInstallChange",
    "const dual_timestamp *": "*constDualTimestamp",
    "dual_timestamp *": "*mutDualTimestamp",
    "struct dual_timestamp *": "*mutDualTimestamp",
    "const triple_timestamp *": "*constTripleTimestamp",
    "triple_timestamp *": "*mutTripleTimestamp",
    "clockid_t": "i32",
    "TimestampStyle": "i32",
    "const struct rs_IoVec *": "*constIoVec",
    "const struct file_handle *": "*constfile_handle",
    "const struct dirent *": "*constdirent",
    "const struct iovec *": "*constIoVec",
    "const struct rlimit *": "*constrlimit",
    "const struct stat *": "*conststat",
    "const struct statfs *": "*conststatfs",
    "const struct statx *": "*conststatx",
    "const struct statx_timestamp *": "*conststatx_timestamp",
    "const sd_bus_error *": "*constSdBusError",
    "void *": "*mutc_void",
    "EdidHeader *": "*mutEdidHeaderAbi",
    "struct stat *": "*mutstat",
    "struct statfs *": "*mutstatfs",
    "struct statx *": "*mutstatx",
    "struct siphash *": "*mutsiphash",
    "struct rs_IoVec *": "*mutIoVec",
    "struct iovec *": "*mutIoVec",
    "sd_bus_error *": "*mutSdBusError",
    "sd_id128_t *": "*mutSdId128",
    "dev_t *": "*mutu64",
    "mode_t *": "*mutu32",
    "rlim_t *": "*mutu64",
    "nsec_t *": "*mutu64",
    "loadavg_t *": "*mutc_ulong",
    "uid_t *": "*mutu32",
    "pid_t *": "*muti32",
    "uint8_t *": "*mutu8",
    "uint8_t*": "*mutu8",
    "uint16_t *": "*mutu16",
    "uint32_t *": "*mutu32",
    "uint64_t *": "*mutu64",
    "int16_t *": "*muti16",
    "int64_t *": "*muti64",
    "usec_t *": "*mutu64",
    "int32_t *": "*muti32",
    "int *": "*muti32",
    "unsigned *": "*mutu32",
    "unsigned long *": "*mutc_ulong",
    "long *": "*mutc_long",
    "long long *": "*muti64",
    "unsigned long long *": "*mutu64",
    "size_t *": "*mutusize",
    "size_t": "usize",
    "intmax_t": "i64",
    "int64_t": "i64",
    "off_t": "i64",
    "pid_t": "i32",
    "sd_id128_t": "SdId128",
    "gid_t": "u32",
    "unsigned": "u32",
    "unsigned int": "u32",
    "unsigned long": "c_ulong",
    "long": "c_long",
    "long long": "i64",
    "unsigned long long": "u64",
    "uint8_t": "u8",
    "uint16_t": "u16",
    "uint32_t": "u32",
    "uint64_t": "u64",
    "usec_t": "u64",
    "nsec_t": "u64",
    "loadavg_t": "c_ulong",
    "statfs_f_type_t": "c_long",
    "dev_t": "u64",
    "mode_t": "u32",
    "rlim_t": "u64",
    "uid_t": "u32",
    "int": "i32",
    "void": "()",
}

Signature = tuple[tuple[str, ...], str]


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def duplicates(names: list[str]) -> list[str]:
    return sorted(name for name, count in Counter(names).items() if count > 1)


def mask_c_non_code(text: str) -> str:
    """Mask C comments/literals/directives while preserving lines and identifiers."""

    result = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "*":
                result[index] = result[index + 1] = " "
                state = "block-comment"
                index += 2
                continue
            if char == "/" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            if char == '"':
                result[index] = " "
                state = "string"
            elif char == "'":
                result[index] = " "
                state = "character"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                result[index] = " "
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if char == "\\" and next_char:
                if char != "\n":
                    result[index] = " "
                if next_char != "\n":
                    result[index + 1] = " "
                index += 2
                continue
            if char == delimiter:
                result[index] = " "
                state = "code"
            elif char != "\n":
                result[index] = " "
        index += 1

    masked = "".join(result)
    return re.sub(
        r"^[ \t]*#[^\n]*(?:\\\n[^\n]*)*$",
        "",
        masked,
        flags=re.MULTILINE,
    )


def c_function_bodies(text: str) -> list[str]:
    """Return bodies of direct translation-unit function definitions."""

    code = mask_c_non_code(text)
    bodies: list[str] = []
    depth = 0
    fragment_start = 0
    body_start: int | None = None
    for index, char in enumerate(code):
        if char == "{":
            if depth == 0:
                prefix = code[fragment_start:index].strip()
                if re.search(r"\)\s*$", prefix) and "=" not in prefix:
                    body_start = index + 1
                else:
                    body_start = None
            depth += 1
        elif char == "}":
            if depth:
                depth -= 1
            if depth == 0:
                if body_start is not None:
                    bodies.append(code[body_start:index])
                body_start = None
                fragment_start = index + 1
        elif char == ";" and depth == 0:
            fragment_start = index + 1
    return bodies


def strip_meson_comments(text: str) -> str:
    """Remove Meson comments without treating a `#` inside a string as syntax."""

    cleaned: list[str] = []
    in_comment = False
    quote: str | None = None
    escaped = False
    for char in text:
        if char == "\n":
            cleaned.append(char)
            in_comment = False
            escaped = False
            continue
        if in_comment:
            cleaned.append(" ")
            continue
        if quote is not None:
            cleaned.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            cleaned.append(char)
        elif char == "#":
            cleaned.append(" ")
            in_comment = True
        else:
            cleaned.append(char)
    return "".join(cleaned)


def c_parameter_type(parameter: str) -> str:
    parameter = re.sub(r"\s+", " ", parameter.strip())
    parameter = parameter.replace("[static DEVNUM_STR_MAX]", "[]")
    parameter = parameter.replace("[static CAPABILITY_TO_STRING_MAX]", "[]")
    parameter = parameter.replace("[static SD_ID128_STRING_MAX]", "[]")
    parameter = parameter.replace("[static SD_ID128_UUID_STRING_MAX]", "[]")
    parameter = parameter.replace("[static 8]", "[]")
    parameter = re.sub(r"\[static (?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)\]", "[]", parameter)
    parameter = re.sub(r"\bUnitNameFlags\b", "int", parameter)
    parameter = re.sub(r"\bUnitType\b", "int", parameter)
    parameter = re.sub(r"\bVirtualization\b", "int", parameter)
    parameter = re.sub(r"\bValidUserFlags\b", "unsigned int", parameter)
    parameter = re.sub(r"\bInstallChangeType\b", "int", parameter)
    parameter = re.sub(r"\bXStatXFlags\b", "unsigned int", parameter)
    parameter = re.sub(r"\bExtractFlags\b", "unsigned int", parameter)
    parameter = re.sub(r"\bPathStartWithFlags\b", "unsigned int", parameter)
    parameter = re.sub(r"\bPathSimplifyFlags\b", "unsigned int", parameter)
    parameter = re.sub(r"\bsd_char\b", "char", parameter)
    for c_type in sorted(C_TYPES, key=len, reverse=True):
        suffix = parameter.removeprefix(c_type)
        if suffix == parameter:
            continue
        if re.fullmatch(r"\s*[A-Za-z_][A-Za-z0-9_]*(?:\[\])?", suffix):
            if suffix.rstrip().endswith("[]"):
                # Function parameters declared as arrays are pointers. Handle
                # the C spellings used for argv vectors as well as byte buffers
                # instead of collapsing `char *argv[]` into a single pointer.
                array_types = {
                    "char": "*mutc_char",
                    "char16_t": "*mutu16",
                    "uint8_t": "*mutu8",
                    "const uint8_t": "*constu8",
                    "char *": "*mut*mutc_char",
                    "const char *": "*mut*constc_char",
                }
                try:
                    return array_types[c_type]
                except KeyError as error:
                    raise ValueError(
                        f"unsupported C array parameter: {parameter}"
                    ) from error
            return C_TYPES[c_type]
    raise ValueError(f"unsupported C parameter: {parameter}")


def c_result_type(result: str) -> str:
    normalized = re.sub(r"\s+", " ", result.strip())
    normalized = re.sub(
        r"^(?:(?:static|extern|inline|_public_|__inline__)\s+)+", "", normalized
    )
    normalized = re.sub(r"\b(?:UnitNameFlags|UnitType)\b", "int", normalized)
    normalized = re.sub(r"\bVirtualization\b", "int", normalized)
    normalized = re.sub(r"\s*\*\s*", " *", normalized)
    try:
        return C_TYPES[normalized]
    except KeyError as error:
        raise ValueError(f"unsupported C result: {normalized}") from error


def header_inventory(
    path: Path, only_symbols: frozenset[str] | None = None
) -> list[tuple[str, Signature]]:
    declarations: list[tuple[str, Signature]] = []
    prototype = re.compile(
        r"^(.+?(?:\s|\*))(rs_[A-Za-z0-9_]+)\(([^)]*)\);$", re.MULTILINE
    )
    for raw_result, name, raw_parameters in prototype.findall(path.read_text()):
        if only_symbols is not None and name not in only_symbols:
            continue
        parameters = ()
        if raw_parameters.strip() and raw_parameters.strip() != "void":
            parameters = tuple(c_parameter_type(parameter) for parameter in raw_parameters.split(","))
        declarations.append((name, (parameters, c_result_type(raw_result))))
    return declarations


def normalize_rust_type(type_name: str) -> str:
    """Normalize libc aliases to the Linux C types used by the headers."""

    normalized = re.sub(r"\s+", "", type_name)
    aliases = {
        "libc::c_char": "c_char",
        "libc::c_int": "i32",
        "libc::c_uint": "u32",
        "libc::c_ulong": "c_ulong",
        "libc::c_long": "c_long",
        "libc::c_void": "c_void",
        "libc::gid_t": "u32",
        "libc::intmax_t": "i64",
        "libc::off_t": "i64",
        "libc::pid_t": "i32",
        "libc::uid_t": "u32",
        "libc::mode_t": "u32",
        "c_char": "c_char",
        "c_int": "i32",
        "c_uint": "u32",
        "c_long": "c_long",
        "gid_t": "u32",
        "intmax_t": "i64",
        "off_t": "i64",
        "pid_t": "i32",
        "rlim_t": "u64",
        "uid_t": "u32",
        "libc::stat": "stat",
        "libc::file_handle": "file_handle",
        "libc::dirent": "dirent",
        "libc::statfs": "statfs",
        "libc::statx": "statx",
        "libc::statx_timestamp": "statx_timestamp",
        "StatFsType": "c_long",
        "XStatXFlags": "u32",
        "SipHashState": "siphash",
        "CDualTimestamp": "DualTimestamp",
    }
    for alias, canonical in aliases.items():
        normalized = normalized.replace(alias, canonical)
    return normalized


def rust_inventory(path: Path) -> list[tuple[str, Signature, bool, int]]:
    exports: list[tuple[str, Signature, bool, int]] = []
    text = path.read_text()
    patterns = (
        (
            re.compile(
                r"#\[(?:unsafe\()?export_name\s*=\s*\"(rs_[A-Za-z0-9_]+)\"\)?\]\s*"
                r"pub\s+(unsafe\s+)?extern\s+\"C\"\s+fn\s+"
                r"(rs_[A-Za-z0-9_]+)\s*\((.*?)\)\s*"
                r"(?:->\s*([^\{]+?))?\s*\{",
                re.DOTALL,
            ),
            True,
        ),
        (
            re.compile(
                r"#\[(?:unsafe\(no_mangle\)|no_mangle)\]\s*"
                r"pub\s+(unsafe\s+)?extern\s+\"C\"\s+fn\s+"
                r"(rs_[A-Za-z0-9_]+)\s*\((.*?)\)\s*"
                r"(?:->\s*([^\{]+?))?\s*\{",
                re.DOTALL,
            ),
            False,
        ),
    )
    matches: list[tuple[int, str, str | None, str, str, str | None]] = []
    for pattern, has_export_name in patterns:
        for match in pattern.finditer(text):
            if has_export_name:
                exported_name, unsafe_marker, function_name, raw_parameters, raw_result = (
                    match.groups()
                )
                if exported_name != function_name:
                    raise ValueError(
                        f"{path}: export_name {exported_name} differs from function {function_name}"
                    )
            else:
                unsafe_marker, function_name, raw_parameters, raw_result = match.groups()
                exported_name = function_name
            matches.append(
                (
                    match.start(),
                    exported_name,
                    unsafe_marker,
                    function_name,
                    raw_parameters,
                    raw_result,
                )
            )

    for start, exported_name, unsafe_marker, _, raw_parameters, raw_result in sorted(matches):
        parameters = []
        for parameter in raw_parameters.split(","):
            if not parameter.strip():
                continue
            if ":" not in parameter:
                raise ValueError(f"{path}: cannot parse Rust parameter: {parameter}")
            _, type_name = parameter.split(":", 1)
            parameters.append(normalize_rust_type(type_name))
        line = text.count("\n", 0, start) + 1
        metadata = re.search(
            r"((?:(?:\s*///[^\n]*|\s*#\[[^\n]*\])\n)+)\s*$",
            text[max(0, start - 2000) : start],
        )
        item_metadata = metadata.group(1) if metadata else ""
        if "#[cfg" in item_metadata:
            raise ValueError(f"{path}:{line}: reviewed C ABI export is cfg-disabled")
        if unsafe_marker and "# Safety" not in item_metadata:
            raise ValueError(f"{path}:{line}: unsafe C ABI export lacks a safety contract")
        exports.append(
            (
                exported_name,
                (tuple(parameters), normalize_rust_type(raw_result or "()")),
                bool(unsafe_marker),
                line,
            )
        )
    return exports


def format_signature(signature: Signature) -> str:
    parameters, result = signature
    return f"({', '.join(parameters)}) -> {result}"


def allocator_boundary_is_c_compatible(path: Path) -> bool:
    text = path.read_text()
    try:
        format_devnum = text.split('#[unsafe(export_name = "rs_format_devnum")]', 1)[1].split(
            '#[unsafe(export_name = "rs_device_path_parse_major_minor")]', 1
        )[0]
        make_major_minor = text.split(
            '#[unsafe(export_name = "rs_device_path_make_major_minor")]',
            1,
        )[1].split(
            '#[unsafe(export_name = "rs_device_path_make_inaccessible")]',
            1,
        )[0]
    except IndexError:
        return False
    return (
        "fn allocate_c_string" in text
        and "std::alloc" not in text
        and "format!(" not in text
        and "unreachable!(" not in text
        and "const DEVNUM_FORMAT_MAX: usize = U32_DECIMAL_MAX + 1 + U32_DECIMAL_MAX;" in text
        and "if n > output.len()" in text
        and "libc::malloc(size)" in make_major_minor
        and make_major_minor.count("libc::malloc(") == 1
        and "allocate_c_string" not in make_major_minor
        and "libc::malloc" not in format_devnum
    )


def misc_inline_abi_boundary_is_reviewed() -> bool:
    header, hex_source, symbols = PARTIAL_SURFACES["misc_inline_abi"]
    format_header = PARTIAL_SURFACES["format_bytes_full"][0]
    devnum_source, format_source, xattr_source = PARTIAL_EXTRA_SOURCES["misc_inline_abi"]
    test = PARTIAL_SHADOW_TESTS["misc_inline_abi"][0]
    header_text = header.read_text()
    hex_text = hex_source.read_text()
    devnum_text = devnum_source.read_text()
    format_text = format_source.read_text()
    xattr_text = xattr_source.read_text()
    test_text = test.read_text()

    required_header = (
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <sys/types.h>",
        "bool rs_devnum_is_zero(dev_t d);",
        "bool rs_xattr_is_acl(const char *name);",
        "int rs_unhexmem(const char *p, void **ret_data, size_t *ret_size);",
        "ssize_t rs_base64mem(const void *p, size_t l, char **ret);",
    )
    try:
        unhex = hex_text.split('#[unsafe(export_name = "rs_unhexmem")]', 1)[1].split(
            '#[unsafe(export_name = "rs_base64mem")]', 1
        )[0]
        base64 = hex_text.split('#[unsafe(export_name = "rs_base64mem")]', 1)[1].split(
            '#[unsafe(export_name = "rs_unbase64mem")]', 1
        )[0]
        unbase64 = hex_text.split('#[unsafe(export_name = "rs_unbase64mem")]', 1)[1].split(
            "#[cfg(test)]", 1
        )[0]
        format_bytes = format_text.split(
            '#[unsafe(export_name = "rs_format_bytes")]', 1
        )[1].split("#[cfg(test)]", 1)[0]
    except IndexError:
        return False

    return (
        len(symbols) == 7
        and all(snippet in header_text for snippet in required_header)
        and '#include "rust/misc_inline_abi.h"' in test_text
        and '#include "rust/format_util.h"' in test_text
        and "char* rs_format_bytes(char *buf, size_t l, uint64_t t);" in format_header.read_text()
        and all(f"{symbol}(" in test_text for symbol in symbols)
        and "Rust FFI — devnum" not in test_text
        and "unhex_decode_into(" in unhex
        and "unbase64_decode_into(" in unbase64
        and "base64_encode_into(" in base64
        and all("libc::malloc(" in facade for facade in (unhex, base64, unbase64))
        and all("std::alloc" not in facade for facade in (unhex, base64, unbase64))
        and "*ret_data =" in unhex
        and "*ret_data =" in unbase64
        and "*ret =" in base64
        and "format_bytes_default_into(" in format_bytes
        and "libc::malloc" not in format_bytes
        and "format!(" not in format_bytes
        and "String" not in format_bytes
        and "Vec" not in format_bytes
        and "pub extern \"C\" fn rs_devnum_is_zero" in devnum_text
        and "pub extern \"C\" fn rs_devnum_set_and_equal" in devnum_text
        and "CStr::from_ptr(name)" in xattr_text
    )


def misc_validator_registered_boundary_is_reviewed() -> bool:
    header, source, symbols = PARTIAL_SURFACES["misc_validator_registered"]
    mount_header, mount_source, mount_symbols = PARTIAL_SURFACES[
        "mount_propagation_validator"
    ]
    test = PARTIAL_SHADOW_TESTS["misc_validator_registered"][0].read_text()
    header_text = header.read_text()
    source_text = source.read_text()
    mount_header_text = mount_header.read_text()
    mount_source_text = mount_source.read_text()
    required_header = (
        "bool rs_nice_is_valid(int n);",
        "bool rs_sched_policy_is_valid(int policy);",
        "bool rs_oom_score_adjust_is_valid(int oa);",
        "bool rs_nft_identifier_valid(const char *s);",
        "bool rs_valid_gecos(const char *d);",
        "bool rs_log_namespace_name_valid(const char *s);",
        "bool rs_valid_home(const char *p);",
        "bool rs_valid_shell(const char *p);",
        "bool rs_bus_property_is_timestamp(const char *name);",
    )
    required_source = (
        "fn nft_identifier_valid_bytes(id: &[u8])",
        "fn valid_gecos_bytes(value: &[u8])",
        "fn valid_home_bytes(path: &[u8])",
        "fn log_namespace_name_valid_bytes(name: &[u8])",
        "fn bus_property_is_timestamp_bytes(name: &[u8])",
        "process_nice_is_valid(n)",
        "process_sched_policy_is_valid(policy)",
        "process_oom_score_adjust_is_valid(oa)",
        "CStr::from_ptr",
    )
    return (
        all(snippet in header_text for snippet in required_header)
        and all(snippet in source_text for snippet in required_source)
        and "#include <stdbool.h>" in mount_header_text
        and "bool rs_mount_propagation_flag_is_valid(unsigned long flag);" in mount_header_text
        and "pub extern \"C\" fn rs_mount_propagation_flag_is_valid(flag: c_ulong) -> bool" in mount_source_text
        and '#include "rust/misc_validators.h"' in test
        and '#include "rust/mountpoint_util.h"' in test
        and "Rust FFI - these need forward declarations" not in test
        and all(f"{symbol}(" not in test.split('#include "rust/misc_validators.h"', 1)[0] for symbol in symbols | mount_symbols)
    )
def time_util_formatting_boundary_is_reviewed() -> bool:
    header, source, symbols = PARTIAL_SURFACES["time_util_formatting"]
    header_text = header.read_text()
    source_text = source.read_text()
    test_text = PARTIAL_SHADOW_TESTS["time_util_formatting"][0].read_text()
    try:
        facade = source_text.split(
            "pub unsafe extern \"C\" fn rs_format_timespan", 1
        )[1].split("/// Safe internal implementation", 1)[0]
    except IndexError:
        return False
    return (
        symbols
        == frozenset(
            {
                "rs_parse_gmtoff",
                "rs_format_timespan",
                "rs_timestamp_style_to_string",
                "rs_timestamp_style_from_string",
            }
        )
        and "int rs_parse_gmtoff(const char *t, long *ret);" in header_text
        and "char *rs_format_timespan(char *buf, size_t l, usec_t t, usec_t accuracy);"
        in header_text
        and '#include "rust/time_util.h"' in test_text
        and "append_u64_decimal(" in source_text
        and "format_timespan_segment(" in source_text
        and "for entry in TIMESPAN_TABLE" in facade
        and "format!(" not in facade
        and "Vec" not in facade
        and "String" not in facade
        and "libc::malloc" not in facade
    )


def devnum_parser_matches_current_c() -> bool:
    source = SURFACES["devnum_util"][1].read_text()
    test = SHADOW_TESTS["devnum_util"][0].read_text()
    required_source = (
        "fn parse_u32_base0(text: &[u8])",
        "value > libc::c_ulong::MAX as u64",
        "fn path_equal_components(",
        "fn path_startswith_components",
        "parse_devnum_bytes(unsafe { CStr::from_ptr(s) }.to_bytes())",
        "parse_device_path(unsafe { CStr::from_ptr(path) }.to_bytes())",
    )
    required_fixtures = (
        '"010:010"',
        '"08:02"',
        '"8:0x10"',
        '"8:0b10"',
        '"8:0b 10"',
        '"8:0b+10"',
        '"8:0b-1"',
        '"000000000000000000001:0"',
        '"/dev//block/8:2"',
        '"/dev/./block/8:2"',
        '"/home/\\xff"',
    )
    return all(snippet in source for snippet in required_source) and all(
        fixture in test for fixture in required_fixtures
    )


def iovec_authority_is_current() -> bool:
    c_header = IOVEC_C_HEADER.read_text()
    rust_header = SURFACES["iovec_util"][0].read_text()
    rust_source = SURFACES["iovec_util"][1].read_text()
    if "bool iovec_inc_many(" not in c_header:
        return False
    if "iovec_increment" in c_header or "rs_iovec_increment" in rust_header or "rs_iovec_increment" in rust_source:
        return False
    if "#include <stdbool.h>" not in rust_header:
        return False
    if "src/fundamental/iovec-util.h" not in rust_header or "iovec-util-fundamental.h" in rust_source:
        return False
    if "may equal `ret`" not in rust_source or "ret.as_mut()" in rust_source:
        return False
    return all(
        "iovec_increment" not in test.read_text() and "iovec_inc_many" in test.read_text()
        for test in IOVEC_SHADOW_TESTS
    ) and all("iovec-util-fundamental.h" not in test.read_text() for test in IOVEC_INCLUDE_TESTS)


def in_addr_util_boundary_is_reviewed() -> bool:
    """Check the macro-generated ABI against the exact C-address test surface.

    The header uses local mirror types instead of the platform's public socket
    types, so generic signature parsing cannot prove this safely.  Keep the
    single audited forwarding macro, all header declarations, current C names,
    and the registered C comparison fixture in lockstep instead.
    """

    header = IN_ADDR_UTIL_HEADER.read_text()
    source = IN_ADDR_UTIL_SOURCE.read_text()
    tests = tuple(path.read_text() for path in IN_ADDR_UTIL_SHADOW_TESTS)
    test = "\n".join(tests)
    declared = set(re.findall(r"\b(rs_[A-Za-z0-9_]+)\s*\(", header))
    forwarded = set(
        re.findall(r'ffi_forward!\(\s*"(rs_[A-Za-z0-9_]+)"', source)
    )
    called = set(
        re.findall(r"\b(rs_[A-Za-z0-9_]+)\s*\(", "\n".join(c_function_bodies(test)))
    )
    authority = "\n".join(path.read_text() for path in IN_ADDR_UTIL_C_AUTHORITIES)
    required_source = (
        "macro_rules! ffi_forward",
        "#[unsafe(export_name = $symbol)]",
        'pub unsafe extern "C" fn',
        "allocates with the C allocator (`libc::malloc`)",
        "(*u).in6.s6_addr[j] &= 0xFF << shift;",
        "if rs_in4_addr_prefixlen_to_netmask(&mut mask, prefixlen).is_null()",
        "if !ret_start.is_null() {",
        "(*ret_start) = start;",
    )
    required_fixtures = (
        "in4_addr_mask(&ac, 33)",
        "rs_in4_addr_mask((struct rs_InAddr*)&ar, 33)",
        'in_addr_from_string(AF_INET, "255.255.255.0", &addr)',
        "memcmp(&c_start, &rs_start, sizeof(c_start))",
    )
    return (
        len(declared) == 58
        and declared == forwarded
        and declared <= called
        and all(
            re.search(rf"\b{re.escape(symbol.removeprefix('rs_'))}\s*\(", authority)
            for symbol in declared
        )
        and all(snippet in source for snippet in required_source)
        and all(snippet in test for snippet in required_fixtures)
        and all(
            registered_rust_shadow_test(test_path, TEST_MESON.read_text())
            for test_path in IN_ADDR_UTIL_SHADOW_TESTS
        )
    )


def ether_addr_util_boundary_is_reviewed() -> bool:
    """Keep the fixed-layout hardware-address mirror ABI and C fixture aligned.

    The public shadow header deliberately mirrors two C structs with local
    names, so generic scalar signature normalization cannot establish layout
    fidelity. This pins every header declaration to its explicit Rust facade,
    current C authority, and the registered byte-for-byte comparison fixture.
    """

    header = ETHER_ADDR_UTIL_HEADER.read_text()
    source = ETHER_ADDR_UTIL_SOURCE.read_text()
    test = ETHER_ADDR_UTIL_SHADOW_TEST.read_text()
    declared = set(re.findall(r"\b(rs_[A-Za-z0-9_]+)\s*\(", header))
    exported = set(
        re.findall(r'pub unsafe extern "C" fn\s+(rs_[A-Za-z0-9_]+)\b', source)
    )
    called = set(
        re.findall(r"\b(rs_[A-Za-z0-9_]+)\s*\(", "\n".join(c_function_bodies(test)))
    )
    authority = "\n".join(path.read_text() for path in ETHER_ADDR_UTIL_C_AUTHORITIES)
    required_source = (
        "#[repr(C)]\npub struct RsHwAddrData",
        "#[repr(C)]\npub struct RsEtherAddr",
        "libc::memcmp",
        "CStr::from_ptr(s)",
        "ret.bytes.fill(0)",
    )
    required_fixtures = (
        "parse_address_non_utf8_keeps_outputs",
        "rs_parse_hw_addr_full(invalid, 0, &r_hw)",
        "rs_hw_addr_to_string_full(&r_addr, 1 << 0, r_buf)",
        "rs_ether_addr_mark_random(&r)",
    )
    return (
        len(declared) == 16
        and declared == exported
        and declared <= called
        and all(
            re.search(rf"\b{re.escape(symbol.removeprefix('rs_'))}\s*\(", authority)
            for symbol in declared
        )
        and "#include <stdbool.h>" in header
        and "neither allocates nor transfers ownership" in header
        and all(snippet in source for snippet in required_source)
        and all(snippet in test for snippet in required_fixtures)
        and registered_rust_shadow_test(ETHER_ADDR_UTIL_SHADOW_TEST, TEST_MESON.read_text())
    )


def user_util_boundary_is_reviewed() -> bool:
    source = SURFACES["user_util"][1].read_text()
    header = SURFACES["user_util"][0].read_text()
    tests = "\n".join(test.read_text() for test in SHADOW_TESTS["user_util"])
    return (
        "#include <stdbool.h>" in header
        and "#include <sys/types.h>" in header
        and "fn c_text" in source
        and "unsafe fn c_text" in source
        and "char::is_control" not in source
        and "format!(" not in source
        and "!password.is_null() &&" in source
        and "hashed_password_is_locked_or_invalid(NULL)" in tests
        and "user\\xc2\\x85name" in tests
    )


def basic_validators_boundary_is_reviewed() -> bool:
    source = SURFACES["basic_validators"][1].read_text()
    header = SURFACES["basic_validators"][0].read_text()
    test = SHADOW_TESTS["basic_validators"][0].read_text()
    return (
        '#include "pidref.h"' in header
        and "const PidRef *pidref" in header
        and re.search(
            r"#\[repr\(C\)\]\s*pub struct PidRef \{\s*"
            r"pid: libc::pid_t,\s*fd: libc::c_int,\s*fd_id: u64,\s*\}",
            source,
        )
        and "libc::EREMOTE" in source
        and "libc::CLD_EXITED" in source
        and "checked_next_power_of_two().unwrap_or(l)" in source
        and "pub extern \"C\" fn rs_file_offset_beyond_memory_size(x: libc::off_t)" in source
        and "RsPidRef" not in test
        and "rust/basic_validators.h" in test
    )


def errno_util_boundary_is_reviewed() -> bool:
    source = SURFACES["errno_util"][1].read_text()
    core = (ROOT / "src/basic/rust/errno_classify.rs").read_text()
    tests = "\n".join(test.read_text() for test in SHADOW_TESTS["errno_util"])
    return (
        "use libc::intmax_t;" in core
        and "crate::ffi::Errno" not in core
        and "Vec<" not in core
        and "intmax_t::MIN" in core
        and "fn systemd_strerror_r(" in source
        and 'link_name = "strerror_r_gnu"' in source
        and "errnum.checked_abs()" in source
        and "fallback.checked_abs().map_or(-libc::EINVAL" in source
        and "errnum.checked_abs().unwrap_or(libc::EINVAL)" in source
        and "fn strerrorname_np(errnum: libc::c_int)" in source
        and '#[cfg(not(target_env = "gnu"))]' in source
        and "errno_from_name_bytes(bytes)" in source
        and "rs_errno_from_name(NULL)" in tests
        and "rs_strerror_or_eof(0, NULL, 0)" in tests
        and "rs_errno_or_else(INT_MIN)" in tests
        and "rs_RET_NERRNO(-1) == -EINVAL" in tests
        and "#if HAVE_SECCOMP" in tests
        and "rs_ERRNO_IS_NEG_SECCOMP_FATAL(0)" in tests
    )


def percent_util_boundary_is_reviewed() -> bool:
    source = SURFACES["percent_util"][1].read_text()
    tests = "\n".join(test.read_text() for test in SHADOW_TESTS["percent_util"])
    return (
        "fn safe_atoi_bytes(s: &[u8]) -> Result<i32, i32>" in source
        and "CString::new(&s[cursor..])" in source
        and "libc::strtol(start, &mut end, base as libc::c_int)" in source
        and "clear_errno();" in source
        and "let errno = get_errno();" in source
        and "if unsafe { *end } != 0" in source
        and "value as libc::c_int as libc::c_long != value" in source
        and "v > (i32::MAX - q) / 10" in source
        and "v > (i32::MAX - q) / 100" in source
        and "CStr::from_ptr(p)" in source
        and ".trim()" not in source
        and ".parse::<" not in source
        and "Vec<" not in source
        and '"999999999999999999999999x%"' in tests
        and '"\\xff%"' in tests
        and '"+0b10%"' in tests
        and '"\\v0b10%"' in tests
        and "parse_percent_target_libc_parity" in tests
        and "rs_parse_percent_unbounded(NULL)" in tests
        and "rs_parse_percent(NULL)" in tests
        and "rs_parse_permille_unbounded(NULL)" in tests
        and "rs_parse_permille(NULL)" in tests
        and "rs_parse_permyriad_unbounded(NULL)" in tests
        and "rs_parse_permyriad(NULL)" in tests
    )


def uid_configuration_is_authoritative() -> bool:
    source = SURFACES["uid_classification"][1].read_text()
    root_meson = ROOT_MESON.read_text()
    meson_options = MESON_OPTIONS.read_text()
    basic_meson = MESON.read_text()
    test_meson = TEST_MESON.read_text()
    rust_bindings = (
        ('GREETER_UID_MIN', 'SYSTEMD_GREETER_UID_MIN', '0x0000_ECA2'),
        ('GREETER_UID_MAX', 'SYSTEMD_GREETER_UID_MAX', '0x0000_ED21'),
        ('DYNAMIC_UID_MIN', 'SYSTEMD_DYNAMIC_UID_MIN', '0x0000_EF00'),
        ('DYNAMIC_UID_MAX', 'SYSTEMD_DYNAMIC_UID_MAX', '0x0000_FFEF'),
        ('CONTAINER_UID_MIN', 'SYSTEMD_CONTAINER_UID_MIN', '0x0008_0000'),
        ('CONTAINER_UID_MAX', 'SYSTEMD_CONTAINER_UID_MAX', '0x6FFF_FFFF'),
        ('FOREIGN_UID_MIN', 'SYSTEMD_FOREIGN_UID_MIN', '0x7FFE_0000'),
        ('FOREIGN_UID_MAX', 'SYSTEMD_FOREIGN_UID_MAX', '0x7FFE_FFFF'),
    )
    meson_environment = (
        ('SYSTEMD_GREETER_UID_MIN', 'greeter_uid_min', 'greeter_uid_min'),
        ('SYSTEMD_GREETER_UID_MAX', 'greeter_uid_max', 'greeter_uid_max'),
        ('SYSTEMD_DYNAMIC_UID_MIN', 'dynamic_uid_min', 'dynamic_uid_min'),
        ('SYSTEMD_DYNAMIC_UID_MAX', 'dynamic_uid_max', 'dynamic_uid_max'),
        ('SYSTEMD_CONTAINER_UID_MIN', 'container_uid_min', 'container_uid_base_min'),
        ('SYSTEMD_CONTAINER_UID_MAX', 'container_uid_max', 'container_uid_base_max + 0xFFFF'),
        ('SYSTEMD_FOREIGN_UID_MIN', 'foreign_uid_min', 'foreign_uid_base'),
        ('SYSTEMD_FOREIGN_UID_MAX', 'foreign_uid_max', 'foreign_uid_base + 0xFFFF'),
    )
    argv_binding = """(out, manifest, target_dir, cargo,
 errno_to_name_rust,
 greeter_uid_min, greeter_uid_max,
 dynamic_uid_min, dynamic_uid_max,
 container_uid_min, container_uid_max,
 foreign_uid_min, foreign_uid_max,
 seccomp_arch_loongarch64, seccomp_arch_riscv64,
 have_xz, have_lz4, have_zstd, have_zlib, have_bzip2) = sys.argv[1:21]"""
    command_arguments = """'@0@'.format(greeter_uid_min),
                           '@0@'.format(greeter_uid_max),
                           '@0@'.format(dynamic_uid_min),
                           '@0@'.format(dynamic_uid_max),
                           '@0@'.format(container_uid_base_min),
                           '@0@'.format(container_uid_base_max + 0xFFFF),
                           '@0@'.format(foreign_uid_base),
                           '@0@'.format(foreign_uid_base + 0xFFFF)"""
    configured_c_ranges = (
        ("GREETER_UID_MIN", "greeter_uid_min"),
        ("GREETER_UID_MAX", "greeter_uid_max"),
        ("DYNAMIC_UID_MIN", "dynamic_uid_min"),
        ("DYNAMIC_UID_MAX", "dynamic_uid_max"),
        ("CONTAINER_UID_BASE_MIN", "container_uid_base_min"),
        ("CONTAINER_UID_BASE_MAX", "container_uid_base_max"),
        ("FOREIGN_UID_BASE", "foreign_uid_base"),
    )
    option_defaults = (
        ("greeter-uid-min", "0x0000ECA2"),
        ("greeter-uid-max", "0x0000ED21"),
        ("dynamic-uid-min", "0x0000EF00"),
        ("dynamic-uid-max", "0x0000FFEF"),
        ("container-uid-base-min", "0x00080000"),
        ("container-uid-base-max", "0x6FFF0000"),
        ("foreign-uid-base", "0x7FFE0000"),
    )
    rust_invariants = (
        "assert!(GREETER_UID_MIN <= GREETER_UID_MAX);",
        "assert!(DYNAMIC_UID_MIN <= DYNAMIC_UID_MAX);",
        "assert!(CONTAINER_UID_MIN <= CONTAINER_UID_MAX);",
        "assert!(FOREIGN_UID_MIN <= FOREIGN_UID_MAX);",
        "assert!(CONTAINER_UID_MIN & 0xffff == 0);",
        "assert!(CONTAINER_UID_MAX & 0xffff == 0xffff);",
        "assert!(FOREIGN_UID_MIN & 0xffff == 0);",
        "assert!(FOREIGN_UID_MAX & 0xffff == 0xffff);",
    )
    return (
        all(
            re.search(
                rf"pub const {constant}: libc::uid_t =\s*"
                rf'configured_u32\(option_env!\("{environment}"\), {default}\);',
                source,
            )
            for constant, environment, default in rust_bindings
        )
        and all(
            basic_meson.count(f'env["{environment}"] = {argument}') == 1
            and basic_meson.count(f"'@0@'.format({expression})") == 1
            for environment, argument, expression in meson_environment
        )
        and argv_binding in basic_meson
        and command_arguments in basic_meson
        and all(
            root_meson.count(f"conf.set('{name}', {value})") == 1
            for name, value in configured_c_ranges
        )
        and all(
            re.search(
                rf"option\('{re.escape(option)}',\s*type\s*:\s*'integer',\s*"
                rf"value\s*:\s*{default},",
                meson_options,
            )
            for option, default in option_defaults
        )
        and "container_uid_base_min % 0x10000 != 0" in root_meson
        and "container_uid_base_max > 0xffff0000" in root_meson
        and "foreign_uid_base > 0xffff0000" in root_meson
        and "greeter_uid_min > greeter_uid_max" in root_meson
        and "dynamic_uid_min > dynamic_uid_max" in root_meson
        and "configured UID boundary overflows uid_t" in source
        and all(invariant in source for invariant in rust_invariants)
        and "uid-classification-const.c" not in test_meson
    )


def unaligned_boundary_is_reviewed() -> bool:
    source = SURFACES["unaligned"][1].read_text()
    header = SURFACES["unaligned"][0].read_text()
    test = SHADOW_TESTS["unaligned"][0].read_text()
    return (
        header.count("const void *p") == 6
        and header.count("void *p") == 12
        and "use libc::c_void;" in source
        and "unsafe fn read_c_bytes<const N: usize>(p: *const c_void)" in source
        and "unsafe fn write_c_bytes<const N: usize>(p: *mut c_void" in source
        and "std::ptr::read(p.cast::<[u8; N]>())" in source
        and "std::ptr::write(p.cast::<[u8; N]>(), bytes)" in source
        and "uint64_t c_storage[3], rust_storage[3];" in test
        and "for (size_t offset = 1; offset < sizeof(type); offset++)" in test
        and "memcmp(c_bytes + offset," in test
    )


def safe_math_boundary_is_reviewed() -> bool:
    source = SURFACES["safe_math"][1].read_text()
    header = SURFACES["safe_math"][0].read_text()
    test = SHADOW_TESTS["safe_math"][0].read_text()
    return (
        "pub fn align_power2(u: libc::c_ulong) -> libc::c_ulong" in source
        and "libc::c_ulong::BITS - leading_zeros" in source
        and "a != 0 && b > (u64::MAX / a)" in source
        and "x.saturating_add(y)" in source
        and "unsigned long rs_ALIGN_POWER2(unsigned long u);" in header
        and '#include "rust/safe_math.h"' in test
        and "uint64_t rs_u64_multiply_safe(" not in test
        and "UINT64_MAX / 3 + 1" in test
        and "ALIGN_POWER2(ULONG_MAX)" in test
        and "size_add(SIZE_MAX, SIZE_MAX)" in test
    )


def at_flags_boundary_is_reviewed() -> bool:
    source = SURFACES["at_flags_util"][1].read_text()
    header = SURFACES["at_flags_util"][0].read_text()
    test = SHADOW_TESTS["at_flags_util"][0].read_text()
    return (
        "pub const AT_SYMLINK_FOLLOW: i32 = libc::AT_SYMLINK_FOLLOW;" in source
        and "pub const AT_SYMLINK_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;" in source
        and source.count("unwrap_or(-libc::EINVAL)") == 2
        and "int rs_at_flags_normalize_nofollow(int flags);" in header
        and "int rs_at_flags_normalize_follow(int flags);" in header
        and '#include "rust/at_flags_util.h"' in test
        and "int rs_at_flags_normalize_nofollow(" not in test
        and "AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW" in test
        and "rs_at_flags_normalize_nofollow(flags) == -EINVAL" in test
        and "rs_at_flags_normalize_follow(flags) == -EINVAL" in test
    )


def ioprio_boundary_is_reviewed() -> bool:
    source = SURFACES["ioprio_util"][1].read_text()
    header = SURFACES["ioprio_util"][0].read_text()
    test = SHADOW_TESTS["ioprio_util"][0].read_text()
    return (
        "let priolevel = data & IOPRIO_LEVEL_MASK;" in source
        and "let priohint = (data >> IOPRIO_HINT_SHIFT) & IOPRIO_HINT_MASK;" in source
        and "if prioclass < 0 || prioclass >= IOPRIO_NR_CLASSES" in source
        and "data < 0" not in source
        and "int rs_ioprio_prio_value(int class, int data);" in header
        and '#include "rust/ioprio_util.h"' in test
        and "int rs_ioprio_prio_value(" not in test
        and "ioprio_prio_value(IOPRIO_CLASS_BE, -1)" in test
        and "ioprio_prio_value(IOPRIO_CLASS_BE, INT_MAX)" in test
    )


def time_arithmetic_boundary_is_reviewed() -> bool:
    header, source, _ = PARTIAL_SURFACES["time_util_arithmetic"]
    source_text = source.read_text()
    header_text = header.read_text()
    types = (ROOT / "src/basic/rust/time_util/types.rs").read_text()
    test = PARTIAL_SHADOW_TESTS["time_util_arithmetic"][0].read_text()
    target_libc_time_layouts = (
        "pub type LibcTimespec = libc::timespec;" in types
        and "pub type LibcTimeval = libc::timeval;" in types
    )
    return (
        (types.count("#[repr(C)]") >= 4 or target_libc_time_layouts)
        and "pub struct DualTimestamp" in types
        and "pub struct TripleTimestamp" in types
        and '#include "time-util.h"' in header_text
        and "bool rs_dual_timestamp_is_set(const dual_timestamp *ts);" in header_text
        and "usec_t rs_usec_sub_signed(usec_t timestamp, int64_t delta);" in header_text
        and source_text.count('#[unsafe(no_mangle)]') == 6
        and source_text.count('pub extern "C" fn rs_') == 4
        and source_text.count('pub unsafe extern "C" fn rs_') == 2
        and source_text.count("# Safety") == 2
        and source_text.count("if ts.is_null()") == 2
        and "a.checked_add(b).unwrap_or(limit).min(limit)" in source_text
        and "if timestamp == USEC_INFINITY" in source_text
        and "if delta == i64::MIN" in source_text
        and '#include "rust/time_util.h"' in test
        and "bool rs_timestamp_is_set(" not in test
        and "!rs_dual_timestamp_is_set(NULL)" in test
        and "rs_usec_sub_signed(100, INT64_MIN)" in test
    )


def install_change_boundary_is_reviewed() -> bool:
    header, source, _ = PARTIAL_SURFACES["install_change"]
    header_text = header.read_text()
    source_text = source.read_text()
    test = PARTIAL_SHADOW_TESTS["install_change"][0].read_text()
    return (
        '#include "install.h"' in header_text
        and "bool rs_install_changes_have_modification(const InstallChange *changes, size_t n_changes);" in header_text
        and "#[repr(C)]\npub struct InstallChange" in source_text
        and "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn rs_install_changes_have_modification(" in source_text
        and "# Safety" in source_text
        and "std::slice::from_raw_parts(changes, n_changes)" in source_text
        and "Only its `type_` field is inspected." in source_text
        and '#include "rust/install.h"' in test
        and "RsInstallChange" not in test
        and "bool rs_install_changes_have_modification(" not in test
        and "INSTALL_CHANGE_IS_MASKED" in test
        and "rs_install_changes_have_modification(NULL, 0)" in test
    )

def virt_boundary_is_reviewed() -> bool:
    source = SURFACES["virt"][1].read_text()
    header = SURFACES["virt"][0].read_text()
    tests = "\n".join(test.read_text() for test in SHADOW_TESTS["virt"])
    return (
        "macro_rules! virtualization_table" in source
        and "const VIRTUALIZATION_TABLE: &[FfiEntry]" in source
        and "ffi_string_table::to_str(VIRTUALIZATION_TABLE" in source
        and "ffi_string_table::to_ptr(VIRTUALIZATION_TABLE" in source
        and "ffi_string_table::from_ptr(VIRTUALIZATION_TABLE" in source
        and "(VM_FIRST..=VM_LAST).contains(&value)" in source
        and "(CONTAINER_FIRST..=CONTAINER_LAST).contains(&value)" in source
        and "#include <stdbool.h>" in header
        and "bool rs_VIRTUALIZATION_IS_VM(int value);" in header
        and '#include "rust/virt.h"' in tests
        and "bool rs_VIRTUALIZATION_IS_VM(" not in tests
        and "rs_virtualization_from_string(NULL)" in tests
        and "rs_VIRTUALIZATION_IS_VM(100)" in tests
        and "rs_VIRTUALIZATION_IS_CONTAINER(-1)" in tests
    )


def rlimit_boundary_is_reviewed() -> bool:
    source = SURFACES["rlimit_util"][1].read_text()
    header = SURFACES["rlimit_util"][0].read_text()
    test = SHADOW_TESTS["rlimit_util"][1].read_text()
    return (
        "const RLIMIT_TABLE: &[FfiEntry]" in source
        and "crate::parse_util::rs_safe_atou64" in source
        and "malloc(allocation_size)" in source
        and "ptr::copy_nonoverlapping" in source
        and "if limit.is_null() || ret.is_null()" in source
        and "Output is written only after successful parse" in source
        and "#include <sys/resource.h>" in header
        and '#include "rust/rlimit_util.h"' in test
        and "int rs_rlimit_parse_nice(" not in test
        and 'rlimit_parse_one(RLIMIT_NOFILE, "0x400"' in test
        and 'rlimit_parse_one(RLIMIT_NICE, "+0x13"' in test
        and "rs_rlimit_from_string(NULL) == -EINVAL" in test
        and "rs_rlimit_format(NULL, &rs_ret) == -EINVAL" in test
    )


def procfs_boundary_is_reviewed() -> bool:
    header = SURFACES["procfs_util"][0].read_text()
    source = SURFACES["procfs_util"][1].read_text()
    test = SHADOW_TESTS["procfs_util"][0].read_text()
    return (
        "crate::extract_word::extract_first_word(s, None, 0)" in source
        and "fn parse_u64_systemd_bytes(input: &[u8])" in source
        and "v.checked_mul(1024).ok_or(Errno::EOVERFLOW)" in source
        and "fn procfs_tasks_set_limit_at(" in source
        and "fn procfs_cpu_get_usage_at(path: &Path)" in source
        and "fn procfs_memory_get_at(path: &Path)" in source
        and "OpenOptions::new().write(true).open(path)" in source
        and "line.len().saturating_add(content_len) >= LONG_LINE_MAX" in source
        and "libc::sysconf(libc::_SC_CLK_TCK)" in source
        and "if s.is_null() || ret.is_null()" in source
        and "unsafe { *ret = value }" in source
        and all(
            symbol in header
            for symbol in (
                "rs_procfs_get_pid_max",
                "rs_procfs_get_threads_max",
                "rs_procfs_tasks_set_limit",
                "rs_procfs_tasks_get_current",
                "rs_procfs_cpu_get_usage",
                "rs_procfs_memory_get",
            )
        )
        and '#include "rust/procfs_util.h"' in test
        and "int rs_convert_meminfo_value_to_uint64_bytes(" not in test
        and '"0x10 kB"' in test
        and '"\\"16\\" kB"' in test
        and '"/ kB"' in test
        and "rs_convert_meminfo_value_to_uint64_bytes(NULL, &rr) == -EINVAL" in test
        and "assert_same_procfs_single(procfs_get_pid_max, rs_procfs_get_pid_max)" in test
        and "assert_same_procfs_single(procfs_cpu_get_usage, rs_procfs_cpu_get_usage)" in test
        and "rs_procfs_memory_get(&rust_total, &rust_used)" in test
        and "rs_procfs_tasks_set_limit(0) == -EINVAL" in test
    )


def import_util_boundary_is_reviewed() -> bool:
    """Pin the five byte-string import/reboot facades to their C contracts."""

    header = SURFACES["import_util"][0].read_text()
    source = SURFACES["import_util"][1].read_text()
    test = SHADOW_TESTS["import_util"][0].read_text()
    return (
        "#include <stdbool.h>" in header
        and "#include <stddef.h>" in header
        and "fresh malloc(3) allocations" in header
        and "fn skip_protocol_and_hostname(url: &[u8])" in source
        and "fn import_url_last_component_range(url: &[u8])" in source
        and "fn import_url_change_suffix_prefix_end(" in source
        and "fn raw_strip_suffixes_end(name: &[u8])" in source
        and "libc::NAME_MAX as usize" in source
        and "fn malloc_c_bytes(bytes: &[u8])" in source
        and "fn malloc_changed_url(" in source
        and "CStr::from_ptr" in source
        and ".to_str()" not in source
        and source.count("#[unsafe(no_mangle)]") == 5
        and '#include "rust/import_util.h"' in test
        and "int rs_import_url_last_component(" not in test
        and "bool rs_reboot_parameter_is_valid(" not in test
        and 'static const char non_utf8_url[] = "x://host/\\xff.raw";' in test
        and "raw_strip_suffixes(\"\", &c_ret)" in test
        and "maximum_length[NAME_MAX + 1] = 0;" in test
    )


def stat_verification_boundary_is_reviewed() -> bool:
    """Pin target-native stat/statx and path semantics for verification helpers."""

    header = SURFACES["stat_util"][0].read_text()
    verification = SURFACE_EXTRA_SOURCES["stat_util"][0].read_text()
    path_header, path_source, _ = PARTIAL_SURFACES["is_device_path"]
    path_header_text = path_header.read_text()
    path_source_text = path_source.read_text()
    test = (ROOT / "tests-extra/test-stat-verify-rust.c").read_text()
    try:
        device_path = path_source_text.split("// ── is_device_path", 1)[1].split(
            "/// Check if path starts with /dev/", 1
        )[0]
    except IndexError:
        return False

    required_safe_cores = (
        "fn mode_verify_regular(mode: libc::mode_t)",
        "fn mode_verify_directory(mode: libc::mode_t)",
        "fn mode_verify_socket(mode: libc::mode_t)",
        "fn stat_verify_regular(st: &libc::stat)",
        "fn statx_verify_regular(stx: &libc::statx)",
        "fn stat_verify_directory(st: &libc::stat)",
        "fn statx_verify_directory(stx: &libc::statx)",
        "fn stat_verify_symlink(st: &libc::stat)",
        "fn stat_verify_socket(st: &libc::stat)",
        "fn statx_verify_socket(stx: &libc::statx)",
        "fn stat_verify_linked(st: &libc::stat)",
        "fn stat_verify_device_node(st: &libc::stat)",
        "fn stat_may_be_dev_null(st: &libc::stat)",
        "fn stat_is_empty(st: &libc::stat)",
        "fn inode_type_can_hardlink(m: libc::mode_t)",
        "fn mode_verify_block(mode: libc::mode_t)",
        "fn mode_verify_char(mode: libc::mode_t)",
        "fn mode_verify_regular_or_block(mode: libc::mode_t)",
        "fn stat_verify_block(st: &libc::stat)",
        "fn stat_verify_char(st: &libc::stat)",
        "fn stat_verify_regular_or_block(st: &libc::stat)",
    )
    required_header = (
        "int rs_stat_verify_regular(const struct stat *st);",
        "int rs_statx_verify_regular(const struct statx *stx);",
        "bool rs_stat_may_be_dev_null(struct stat *st);",
        "bool rs_stat_is_empty(struct stat *st);",
        "bool rs_inode_type_can_hardlink(mode_t m);",
        "int rs_stat_verify_block(const struct stat *st);",
        "int rs_stat_verify_char(const struct stat *st);",
        "int rs_stat_verify_regular_or_block(const struct stat *st);",
    )
    return (
        all(core in verification for core in required_safe_cores)
        and all(declaration in header for declaration in required_header)
        and verification.count("#[unsafe(no_mangle)]") == 15
        and "*const std::ffi::c_void" not in verification
        and "*const u8" not in verification
        and "stat_st_" not in verification
        and "statx_stx_" not in verification
        and ".add(" not in verification
        and "st.st_nlink == 0" in verification
        and "st.st_size <= 0" in verification
        and "stx.stx_mask & libc::STATX_TYPE" in verification
        and "libc::EBADFD" in verification
        and "libc::ENOTBLK" in verification
        and "libc::ENODATA" in verification
        and "as i32" not in verification
        and "as i64" not in verification
        and "rs_is_device_path" not in header
        and "fn is_device_path_bytes(path: &[u8])" in device_path
        and "fn next_path_component_bytes" in device_path
        and "libc::NAME_MAX as usize" in device_path
        and "CStr::from_ptr(path)" in device_path
        and ".to_bytes()" in device_path
        and ".to_str()" not in device_path
        and device_path.count("#[unsafe(no_mangle)]") == 1
        and "bool rs_is_device_path(const char *path);" in path_header_text
        and "mode_t, off_t, nlink_t, struct stat, and struct statx" in header
        and '#include "rust/stat_util.h"' in test
        and '#include "rust/path_util.h"' in test
        and "Rust FFI forward declarations" not in test
        and "bool rs_inode_type_can_hardlink(" not in test
        and "(nlink_t) INT32_MAX + 1U" in test
        and "st.st_size = -1;" in test
        and "stat_verify_block(&st) == rs_stat_verify_block(&st)" in test
        and "stat_verify_char(&st) == rs_stat_verify_char(&st)" in test
        and "stat_verify_regular_or_block(&st) == rs_stat_verify_regular_or_block(&st)" in test
        and "rs_stat_verify_block(NULL) == -EINVAL" in test
        and "rs_stat_verify_char(NULL) == -EINVAL" in test
        and "rs_stat_verify_regular_or_block(NULL) == -EINVAL" in test
        and 'static const char non_utf8_device[] = "/dev/\\xff";' in test
        and 'rs_is_device_path("/./dev/foo")' in test
        and "NAME_MAX + 1" in test
    )


def stat_inode_boundary_is_reviewed() -> bool:
    """Pin inode helpers to native libc layouts and exact current-C ordering."""

    header, parent = SURFACES["stat_util"]
    verification, inode, filesystem, descriptor, moderate, _xstatx, _inode_same, _hash = SURFACE_EXTRA_SOURCES["stat_util"]
    header_text = header.read_text()
    parent_text = parent.read_text()
    inode_text = inode.read_text()
    all_stat_rust = "\n".join(
        (
            parent_text,
            verification.read_text(),
            inode_text,
            filesystem.read_text(),
            descriptor.read_text(),
        )
    )
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()

    required_safe_cores = (
        "fn inode_type_can_chattr(mode: libc::mode_t)",
        "fn inode_type_name(mode: libc::mode_t)",
        "fn inode_type_from_bytes(name: &[u8])",
        "fn inode_compare(a: &libc::stat, b: &libc::stat)",
        "fn inode_unmodified_compare(a: &libc::stat, b: &libc::stat)",
        "fn stat_inode_same(a: &libc::stat, b: &libc::stat)",
        "fn stat_inode_unmodified(a: &libc::stat, b: &libc::stat)",
        "fn statx_has_type_and_inode(stx: &libc::statx)",
        "fn statx_inode_same(a: &libc::statx, b: &libc::statx)",
        "fn statx_mount_same(a: &libc::statx, b: &libc::statx)",
    )
    required_header = (
        "bool rs_inode_type_can_chattr(mode_t mode);",
        "const char *rs_inode_type_to_string(mode_t m);",
        "mode_t rs_inode_type_from_string(const char *s);",
        "int rs_inode_compare_func(const struct stat *a, const struct stat *b);",
        "int rs_inode_unmodified_compare_func(const struct stat *a, const struct stat *b);",
        "bool rs_stat_inode_same(const struct stat *a, const struct stat *b);",
        "bool rs_stat_inode_unmodified(const struct stat *a, const struct stat *b);",
        "bool rs_statx_inode_same(const struct statx *a, const struct statx *b);",
        "int rs_statx_mount_same(const struct statx *a, const struct statx *b);",
    )
    forbidden_layout_shortcuts = (
        "*const c_void",
        "*const std::ffi::c_void",
        "*const u8",
        "stat_st_",
        "from_raw_parts",
        "write_unaligned",
        "byte offset",
        "raw byte offset",
    )
    required_native_fields = (
        ".st_dev",
        ".st_ino",
        ".st_mode",
        ".st_mtime",
        ".st_mtime_nsec",
        ".st_size",
        ".st_rdev",
    )
    return (
        all(core in inode_text for core in required_safe_cores)
        and all(declaration in header_text for declaration in required_header)
        and inode_text.count("#[unsafe(no_mangle)]") == 9
        and all(shortcut not in all_stat_rust for shortcut in forbidden_layout_shortcuts)
        and not re.search(r"\.(?:add|offset)\(\s*\d+", all_stat_rust)
        and all(field in inode_text for field in required_native_fields)
        and all(
            field in inode_text
            for field in (
                ".stx_mask",
                ".stx_mode",
                ".stx_dev_major",
                ".stx_dev_minor",
                ".stx_ino",
                ".stx_mnt_id",
            )
        )
        and "libc::STATX_TYPE | libc::STATX_INO" in inode_text
        and "libc::STATX_MNT_ID" in inode_text
        and "const STATX_MNT_ID_UNIQUE: u32 = 0x4000;" in inode_text
        and "-libc::ENODATA" in inode_text
        and inode_text.count(".cmp(") >= 7
        and 'Some(c"reg")' in inode_text
        and "CStr::from_ptr(name)" in inode_text
        and ".to_bytes()" in inode_text
        and "return -libc::EINVAL;" in inode_text
        and "return false;" in inode_text
        and "return MODE_INVALID as libc::mode_t;" in inode_text
        and '#include "chattr-util.h"' in test
        and '#include "stat-util.h"' in test
        and '#include "rust/stat_util.h"' in test
        and "Rust FFI forward declarations" not in test
        and "(const void*)" not in test
        and "(dev_t) -1" in test
        and "st_mtim.tv_sec = -2" in test
        and "st_mtim.tv_nsec = -2" in test
        and "st_size = -2" in test
        and "== -1" in test
        and "== 0" in test
        and "== 1" in test
        and "rs_inode_compare_func(NULL" in test
        and "rs_inode_unmodified_compare_func(NULL" in test
        and "rs_stat_inode_same(NULL" in test
        and "stat_inode_unmodified(&a, &b) == rs_stat_inode_unmodified(&a, &b)" in test
        and "statx_inode_same(&a, &b) == rs_statx_inode_same(&a, &b)" in test
        and "statx_mount_same(&a, &b) == rs_statx_mount_same(&a, &b)" in test
        and "STATX_MNT_ID_UNIQUE" in test
        and "rs_stat_inode_unmodified(NULL" in test
        and "rs_statx_inode_same(NULL" in test
        and "rs_statx_mount_same(NULL" in test
    )


def stat_vfs_boundary_is_reviewed() -> bool:
    """Pin native statvfs field widths and current-C overflow/output ordering."""

    header = SURFACES["stat_util"][0].read_text()
    filesystem = SURFACE_EXTRA_SOURCES["stat_util"][2].read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    forbidden_layout_shortcuts = (
        "*const c_void",
        "*const std::ffi::c_void",
        "*const u8",
        "statvfs_f_",
        "from_raw_parts",
        "write_unaligned",
        "x86_64",
        "byte offset",
        "raw byte offset",
    )
    return (
        "fn vfs_free_bytes_from_statvfs(statvfs: &libc::statvfs) -> (u64, bool)"
        in filesystem
        and filesystem.count("#[unsafe(no_mangle)]") == 11
        and all(shortcut not in filesystem for shortcut in forbidden_layout_shortcuts)
        and "MaybeUninit::<libc::statvfs>::uninit()" in filesystem
        and "libc::fstatvfs(fd, statvfs.as_mut_ptr())" in filesystem
        and "statvfs.f_frsize as u64" in filesystem
        and "statvfs.f_bfree as u64" in filesystem
        and "fragment_size.overflowing_mul(free_blocks)" in filesystem
        and "unsafe { ret.write(bytes) };" in filesystem
        and filesystem.index("unsafe { ret.write(bytes) };")
        < filesystem.index("return -libc::ERANGE;")
        and "crate::ffi::get_errno()" in filesystem
        and "-libc::EIO" in filesystem
        and "if fd < 0 || ret.is_null()" in filesystem
        and "return -libc::EINVAL;" in filesystem
        and "int rs_vfs_free_bytes(int fd, uint64_t *ret);" in header
        and "vfs_free_bytes(STDIN_FILENO, &c_value)" in test
        and "rs_vfs_free_bytes(STDIN_FILENO, &rust_value)" in test
        and "rs_vfs_free_bytes(-1, &rust_value) == -EINVAL" in test
        and "rs_vfs_free_bytes(0, NULL) == -EINVAL" in test
    )


def stat_descriptor_boundary_is_reviewed() -> bool:
    """Pin descriptor/path verification to native fstatat and exact C policy."""

    header = SURFACES["stat_util"][0].read_text()
    descriptor = SURFACE_EXTRA_SOURCES["stat_util"][3].read_text()
    test = (ROOT / "tests-extra/test-stat-verify-rust.c").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "int rs_verify_regular_at(int fd, const char *path, bool follow);",
        "int rs_fd_verify_regular(int fd);",
        "int rs_fd_verify_directory(int fd);",
        "int rs_is_dir_at(int fd, const char *path, bool follow);",
        "int rs_is_dir(const char *path, bool follow);",
        "int rs_fd_verify_symlink(int fd);",
        "int rs_is_symlink(const char *path);",
        "int rs_fd_verify_socket(int fd);",
        "int rs_is_socket(const char *path);",
        "int rs_fd_verify_linked(int fd);",
        "int rs_fd_verify_block(int fd);",
        "int rs_is_device_node(const char *path);",
        "int rs_fd_verify_regular_or_block(int fd);",
    )
    required_verifications = (
        "Verification::Regular => stat_verify_regular(st)",
        "Verification::Directory => stat_verify_directory(st)",
        "Verification::Symlink => stat_verify_symlink(st)",
        "Verification::Socket => stat_verify_socket(st)",
        "Verification::Linked => stat_verify_linked(st)",
        "Verification::Block => stat_verify_block(st)",
        "Verification::DeviceNode => stat_verify_device_node(st)",
        "Verification::RegularOrBlock => stat_verify_regular_or_block(st)",
    )
    forbidden_layout_shortcuts = (
        "*const c_void",
        "*const std::ffi::c_void",
        "*const u8",
        "stat_st_",
        "from_raw_parts",
        "write_unaligned",
        "x86_64",
        "byte offset",
        "raw byte offset",
    )
    return (
        descriptor.count("#[unsafe(no_mangle)]") == 13
        and {"fd-util.c", "fd-util.h"} <= authority_names
        and all(declaration in header for declaration in required_header)
        and all(pin in descriptor for pin in required_verifications)
        and all(shortcut not in descriptor for shortcut in forbidden_layout_shortcuts)
        and "fn verify_stat(st: &libc::stat, verification: Verification)"
        in descriptor
        and "fn verify_stat_at(" in descriptor
        and "MaybeUninit::<libc::stat>::uninit()" in descriptor
        and "libc::fstatat(fd, path.as_ptr(), st.as_mut_ptr(), flags)" in descriptor
        and "libc::AT_EMPTY_PATH" in descriptor
        and "libc::AT_SYMLINK_NOFOLLOW" in descriptor
        and "pub(super) const XAT_FDROOT: libc::c_int = -8192;" in descriptor
        and "resolve_at_path" in descriptor
        and ".checked_add(1)" in descriptor
        and ".try_reserve_exact(capacity)" in descriptor
        and ".map_err(|_| -libc::ENOMEM)?" in descriptor
        and "CString::new(rooted)" in descriptor
        and "CStr::from_ptr(path)" in descriptor
        and "crate::ffi::get_errno()" in descriptor
        and "libc::c_int::from(result >= 0)" in descriptor
        and "if fd == libc::AT_FDCWD || fd == XAT_FDROOT" in descriptor
        and "if fd == XAT_FDROOT" in descriptor
        and '#include "rust/stat_util.h"' in test
        and "verify_regular_at(AT_FDCWD, \".\", false) ==" in test
        and "fd_verify_directory(AT_FDCWD) == rs_fd_verify_directory(AT_FDCWD)"
        in test
        and "socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC" in test
        and "is_device_node(\"/dev/null\") == rs_is_device_node(\"/dev/null\")"
        in test
        and "rs_verify_regular_at(-1, NULL, false) == -EBADF" in test
        and "rs_verify_regular_at(AT_FDCWD, NULL, true) == -EINVAL" in test
        and "rs_is_dir(NULL, true) == -EINVAL" in test
        and "rs_is_symlink(NULL) == -EINVAL" in test
        and "rs_is_socket(NULL) == -EINVAL" in test
        and "rs_is_device_node(NULL) == -EINVAL" in test
    )


def stat_filesystem_boundary_is_reviewed() -> bool:
    """Pin statfs adapters, filesystem groups, and read-only policy."""

    header = SURFACES["stat_util"][0].read_text()
    parent = SURFACES["stat_util"][1].read_text()
    filesystem = SURFACE_EXTRA_SOURCES["stat_util"][2].read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "int rs_xstatfsat(int dir_fd, const char *path, struct statfs *ret);",
        "int rs_is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value);",
        "int rs_fd_is_read_only_fs(int fd);",
        "int rs_path_is_read_only_fs(const char *path);",
        "bool rs_is_temporary_fs(const struct statfs *statfs);",
        "bool rs_is_network_fs(const struct statfs *statfs);",
        "int rs_fd_is_temporary_fs(int fd);",
        "int rs_fd_is_network_fs(int fd);",
        "int rs_path_is_temporary_fs(const char *path);",
        "int rs_path_is_network_fs(const char *path);",
    )
    required_magics = (
        "const AFS_FS_MAGIC: u64 = 0x6b41_4653;",
        "const AFS_SUPER_MAGIC: u64 = 0x5346_414f;",
        "const CEPH_SUPER_MAGIC: u64 = 0x00c3_6400;",
        "const CIFS_SUPER_MAGIC: u64 = 0xff53_4d42;",
        "const SMB2_SUPER_MAGIC: u64 = 0xfe53_4d42;",
        "const GFS2_MAGIC: u64 = 0x0116_1970;",
        "const NCP_SUPER_MAGIC: u64 = 0x564c;",
        "const NFS_SUPER_MAGIC: u64 = 0x6969;",
        "const OCFS2_SUPER_MAGIC: u64 = 0x7461_636f;",
        "const ORANGEFS_DEVREQ_MAGIC: u64 = 0x2003_0528;",
        "const SMB_SUPER_MAGIC: u64 = 0x517b;",
        "const RAMFS_MAGIC: u64 = 0x8584_58f6;",
        "const TMPFS_MAGIC: u64 = 0x0102_1994;",
    )
    forbidden_layout_shortcuts = (
        "*const c_void",
        "*const std::ffi::c_void",
        "*const u8",
        "statfs_f_",
        "from_raw_parts",
        "write_unaligned",
        "x86_64",
        "byte offset",
        "raw byte offset",
    )
    return (
        filesystem.count("#[unsafe(no_mangle)]") == 11
        and {"fd-util.c", "filesystem-sets.py", "fs-util.c", "magic.h"}
        <= authority_names
        and all(declaration in header for declaration in required_header)
        and all(magic in filesystem for magic in required_magics)
        and all(shortcut not in filesystem for shortcut in forbidden_layout_shortcuts)
        and '#[cfg(target_arch = "s390x")]' in parent
        and "type StatFsType = libc::c_uint;" in parent
        and 'any(target_env = "musl", target_os = "android")' in parent
        and "type StatFsType = libc::c_ulong;" in parent
        and 'target_arch = "x86_64"' in parent
        and 'target_pointer_width = "32"' in parent
        and "type StatFsType = i64;" in parent
        and "type StatFsType = libc::c_long;" in parent
        and "fn is_fs_type(statfs: &libc::statfs, magic_value: StatFsType)"
        in parent
        and "fn xfstatfs(fd: libc::c_int) -> Result<libc::statfs, libc::c_int>"
        in filesystem
        and "fn xstatfsat(" in filesystem
        and "fn is_temporary_fs(statfs: &libc::statfs)" in filesystem
        and "fn is_network_fs(statfs: &libc::statfs)" in filesystem
        and "fn fd_is_read_only_fs(fd: libc::c_int)" in filesystem
        and "MaybeUninit::<libc::statfs>::uninit()" in filesystem
        and "libc::fstatfs(fd, statfs.as_mut_ptr())" in filesystem
        and 'libc::statfs(c".".as_ptr(), statfs.as_mut_ptr())' in filesystem
        and 'libc::statfs(c"/".as_ptr(), statfs.as_mut_ptr())' in filesystem
        and "libc::openat(dir_fd, path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC)"
        in filesystem
        and "OwnedFd::from_raw_fd(fd)" in filesystem
        and "libc::faccessat(fd, c\"\".as_ptr(), mode, libc::AT_EMPTY_PATH)"
        in filesystem
        and "const ST_RDONLY: u64 = 1;" in filesystem
        and "statfs.f_flags as u64 & ST_RDONLY" in filesystem
        and "access_fd(fd, libc::W_OK) == -libc::EROFS" in filesystem
        and "unsafe { ret.write(statfs) };" in filesystem
        and "statfs.f_type as StatFsType == magic_value" in filesystem
        and "CStr::from_ptr(path)" in filesystem
        and "crate::ffi::get_errno()" in filesystem
        and '#include "rust/stat_util.h"' in test
        and "xstatfsat(AT_FDCWD, NULL, &c_statfs)" in test
        and "is_fs_type_at(AT_FDCWD, NULL, c_statfs.f_type) ==" in test
        and "fd_is_read_only_fs(AT_FDCWD) == rs_fd_is_read_only_fs(AT_FDCWD)"
        in test
        and "path_is_read_only_fs(\".\") == rs_path_is_read_only_fs(\".\")"
        in test
        and "synthetic.f_type = TMPFS_MAGIC;" in test
        and "synthetic.f_type = RAMFS_MAGIC;" in test
        and "synthetic.f_type = NFS_SUPER_MAGIC;" in test
        and "rs_xstatfsat(-1, NULL, &rust_statfs) == -EBADF" in test
        and "rs_xstatfsat(AT_FDCWD, NULL, NULL) == -EINVAL" in test
        and "rs_path_is_read_only_fs(NULL) == -EINVAL" in test
        and "rs_path_is_temporary_fs(NULL) == -EINVAL" in test
        and "rs_path_is_network_fs(NULL) == -EINVAL" in test
    )


def stat_moderate_boundary_is_reviewed() -> bool:
    """Pin directory/null/inline-fs/proc helpers to current-C composition."""

    header = SURFACES["stat_util"][0].read_text()
    moderate = SURFACE_EXTRA_SOURCES["stat_util"][4].read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "int rs_dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup);",
        "int rs_dir_is_empty(const char *path, bool ignore_hidden_or_backup);",
        "bool rs_null_or_empty(struct stat *st);",
        "int rs_null_or_empty_path_with_root(const char *path, const char *root);",
        "int rs_null_or_empty_path(const char *path);",
        "int rs_fd_is_fs_type(int fd, statfs_f_type_t magic_value);",
        "int rs_path_is_fs_type(const char *path, statfs_f_type_t magic_value);",
        "int rs_proc_mounted(void);",
    )
    required_backup_suffixes = (
        'b"ignore"',
        'b"rpmnew"',
        'b"rpmsave"',
        'b"rpmorig"',
        'b"dpkg-old"',
        'b"dpkg-new"',
        'b"dpkg-tmp"',
        'b"dpkg-dist"',
        'b"dpkg-bak"',
        'b"dpkg-backup"',
        'b"dpkg-remove"',
        'b"ucf-new"',
        'b"ucf-old"',
        'b"ucf-dist"',
        'b"swp"',
        'b"bak"',
        'b"old"',
        'b"new"',
    )
    forbidden_layout_shortcuts = (
        "*const c_void",
        "*const std::ffi::c_void",
        "stat_st_",
        "statfs_f_",
        "write_unaligned",
        "byte offset",
        "raw byte offset",
    )
    return (
        moderate.count("#[unsafe(no_mangle)]") == 8
        and all(declaration in header for declaration in required_header)
        and {"chase.c", "chase.h", "dirent-util.h", "path-util.c", "path-util.h"}
        <= authority_names
        and all(suffix in moderate for suffix in required_backup_suffixes)
        and all(shortcut not in moderate for shortcut in forbidden_layout_shortcuts)
        and "#[repr(C)]\nstruct LinuxDirent64" in moderate
        and "std::mem::offset_of!(LinuxDirent64, d_reclen)" in moderate
        and "std::mem::offset_of!(LinuxDirent64, d_name)" in moderate
        and "fn directory_buffer_has_entry(" in moderate
        and "fn hidden_or_backup_file(name: &[u8])" in moderate
        and 'matches!(name, b"lost+found" | b"aquota.user" | b"aquota.group")'
        in moderate
        and "name.ends_with(b\"~\")" in moderate
        and "MaybeUninit::<[libc::dirent; 16]>::uninit()" in moderate
        and "libc::SYS_getdents64" in moderate
        and "if count as usize > capacity" in moderate
        and "std::slice::from_raw_parts" in moderate
        and "libc::O_DIRECTORY | libc::O_CLOEXEC" in moderate
        and "OwnedFd::from_raw_fd(fd)" in moderate
        and "fn is_dev_null_beneath_root(path: &[u8], root: Option<&[u8]>)"
        in moderate
        and "libc::NAME_MAX as usize" in moderate
        and "fn chase_and_stat(" in moderate
        and "const CHASE_PREFIX_ROOT: libc::c_int = 1 << 0;" in moderate
        and "fn null_or_empty(st: &libc::stat)" in moderate
        and "stat_may_be_dev_null(st) || stat_is_empty(st)" in moderate
        and "is_fs_type_at(fd, None, magic_value)" in moderate
        and "is_fs_type_at(libc::AT_FDCWD, path, magic_value)" in moderate
        and "const PROC_SUPER_MAGIC: u64 = 0x9fa0;" in moderate
        and "struct ErrnoGuard(libc::c_int);" in moderate
        and "set_errno(self.0);" in moderate
        and "if result == -libc::ENOENT" in moderate
        and "CStr::from_ptr(path)" in moderate
        and "return -libc::EINVAL;" in moderate
        and '#include "rust/stat_util.h"' in test
        and "dir_is_empty(directory, false) == rs_dir_is_empty(directory, false)"
        in test
        and "dir_is_empty_at(fd, NULL, true) == rs_dir_is_empty_at(fd, NULL, true)"
        in test
        and "null_or_empty(&st) == rs_null_or_empty(&st)" in test
        and 'null_or_empty_path("/dev/null") == rs_null_or_empty_path("/dev/null")'
        in test
        and "null_or_empty_path_with_root(\"/dev/null\", \"/\") ==" in test
        and "fd_is_fs_type(AT_FDCWD, fs.f_type) ==" in test
        and "path_is_fs_type(NULL, fs.f_type) ==" in test
        and "int c_result = proc_mounted();" in test
        and "int rust_result = rs_proc_mounted();" in test
        and "assert_se(errno == EUCLEAN);" in test
        and "rs_null_or_empty_path(NULL) == -EINVAL" in test
        and "rs_dir_is_empty_at(-1, NULL, false) == -EBADF" in test
    )


def stat_xstatx_boundary_is_reviewed() -> bool:
    """Pin native statx negotiation, XAT root, errno, and output ordering."""

    header = SURFACES["stat_util"][0].read_text()
    parent = SURFACES["stat_util"][1].read_text()
    xstatx = SURFACE_EXTRA_SOURCES["stat_util"][5].read_text()
    c_source = (ROOT / "src/basic/stat-util.c").read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    meson = (ROOT / "src/basic/meson.build").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "int rs_xstatx_full(int fd,",
        "XStatXFlags xstatx_flags,",
        "unsigned mandatory_mask,",
        "unsigned optional_mask,",
        "uint64_t mandatory_attributes,",
        "int rs_xstatx(int fd,",
        "struct statx *ret);",
    )
    forbidden_layout_shortcuts = (
        "#[repr(C)]",
        "struct Statx",
        "struct statx {",
        "from_raw_parts",
        "offset_of!",
        "SYS_statx",
        "syscall(",
        "target_arch",
        "target_pointer_width",
    )
    required_source_contract = (
        "type XStatXFlags = libc::c_uint;",
        "const XSTATX_MNT_ID_BEST: XStatXFlags = 1 << 0;",
        "const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x4000;",
        "libc::STATX_MNT_ID | STATX_MNT_ID_UNIQUE",
        "fn native_statx(",
        "MaybeUninit::<libc::statx>::zeroed()",
        "libc::statx(fd, path.as_ptr(), flags, mask, statx.as_mut_ptr())",
        "resolve_at_path(fd, path)?",
        "libc::AT_EMPTY_PATH",
        "mandatory_mask & optional_mask != 0",
        "(mandatory_mask | optional_mask) & STATX_MNT_ID_MASK != 0",
        "request_mask |= STATX_MNT_ID_MASK",
        "statx.stx_mask & STATX_MNT_ID_MASK == 0",
        "!flags_set(statx.stx_mask, mandatory_mask)",
        "!attributes_set(statx.stx_attributes_mask, mandatory_attributes)",
        "flags_set(statx.stx_mask, optional_mask)",
        "Err(-libc::EUNATCH)",
        "Err(-libc::EBADF)",
        "Err(-libc::EINVAL)",
        "crate::ffi::get_errno()",
        "unsafe { ret.write(statx) };",
    )
    required_vectors = (
        'xstatx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, &c_statx)',
        'rs_xstatx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, &rust_statx)',
        "STATX_BASIC_STATS, STATX_BTIME, 0, &c_statx",
        "XAT_FDROOT, NULL, 0, XSTATX_MNT_ID_BEST",
        "STATX_MNT_ID | STATX_MNT_ID_UNIQUE",
        "xstatx(fd, NULL, 0, STATX_TYPE | STATX_INO, &c_statx)",
        "UINT64_C(1) << 63",
        "c_result == -EUNATCH",
        "memcmp(&c_statx, &sentinel, sizeof(c_statx)) == 0",
        "memcmp(&rust_statx, &sentinel, sizeof(rust_statx)) == 0",
        "STATX_TYPE, STATX_TYPE, 0, &rust_statx) == -EINVAL",
        "STATX_TYPE, NULL) == -EINVAL",
        "rs_xstatx_full(-1, NULL",
    )
    required_current_c = (
        "int xstatx_full(int fd,",
        "assert(wildcard_fd_is_valid(fd));",
        "assert((mandatory_mask & optional_mask) == 0);",
        "resolve_xat_fdroot(&fd, &path, &p);",
        "unsigned request_mask = mandatory_mask|optional_mask;",
        "request_mask |= STATX_MNT_ID|STATX_MNT_ID_UNIQUE;",
        "statx_flags|(isempty(path) ? AT_EMPTY_PATH : 0)",
        "!(sx.stx_mask & (STATX_MNT_ID|STATX_MNT_ID_UNIQUE))",
        "!FLAGS_SET(sx.stx_mask, mandatory_mask)",
        "!FLAGS_SET(sx.stx_attributes_mask, mandatory_attributes)",
        "*ret = sx;",
        "return FLAGS_SET(sx.stx_mask, optional_mask);",
    )
    return (
        xstatx.count("#[unsafe(no_mangle)]") == 2
        and {"stat-util.c", "stat-util.h", "fd-util.c", "fd-util.h"} <= authority_names
        and all(declaration in header for declaration in required_header)
        and all(contract in xstatx for contract in required_source_contract)
        and all(shortcut not in xstatx for shortcut in forbidden_layout_shortcuts)
        and "mod xstatx;" in parent
        and "pub use xstatx::{rs_xstatx, rs_xstatx_full};" in parent
        and "'rust/stat_util/xstatx.rs'," in meson
        and xstatx.index("unsafe { ret.write(statx) };")
        > xstatx.index("!attributes_set(statx.stx_attributes_mask, mandatory_attributes)")
        and all(vector in test for vector in required_vectors)
        and all(contract in c_source for contract in required_current_c)
    )


def stat_inode_same_boundary_is_reviewed() -> bool:
    """Pin file-handle/mount identity and exact fatal-versus-fallback policy."""

    header = SURFACES["stat_util"][0].read_text()
    parent = SURFACES["stat_util"][1].read_text()
    inode = SURFACE_EXTRA_SOURCES["stat_util"][1].read_text()
    inode_same = SURFACE_EXTRA_SOURCES["stat_util"][6].read_text()
    c_source = (ROOT / "src/basic/stat-util.c").read_text()
    mount_source = (ROOT / "src/basic/mountpoint-util.c").read_text()
    mount_rust = (ROOT / "src/basic/rust/mountpoint_util.rs").read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    meson = (ROOT / "src/basic/meson.build").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "int rs_inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);",
        "int rs_inode_same(const char *filea, const char *fileb, int flags);",
        "int rs_fd_inode_same(int fda, int fdb);",
    )
    forbidden_layout_shortcuts = (
        "#[repr(C)]",
        "struct NativeFileHandle { handle_bytes:",
        "SYS_name_to_handle_at",
        "syscall(",
        "target_arch",
        "target_pointer_width",
        "offset(4)",
        "add(8)",
    )
    required_rust_contract = (
        "const ORIGINAL_MAX_HANDLE_SIZE: usize = 128;",
        "const AT_HANDLE_MNT_ID_UNIQUE: libc::c_int = 0x001;",
        "const AT_HANDLE_FID: libc::c_int = libc::AT_REMOVEDIR;",
        "offset_of!(libc::file_handle, f_handle)",
        "align_of::<libc::file_handle>()",
        "alloc_zeroed(layout)",
        "dealloc(self.pointer.as_ptr().cast::<u8>(), self.layout)",
        "libc::name_to_handle_at(fd, path.as_ptr(), handle.as_mut_ptr(), mount_id, flags)",
        "flags | AT_HANDLE_MNT_ID_UNIQUE",
        "flags | AT_HANDLE_FID",
        "flags & !AT_HANDLE_FID",
        "is_name_to_handle_at_fatal_error(error)",
        "MountIdRequest::PreferUnique",
        "MountIdRequest::RequireUnique",
        "statx_unique_mount_id(fd, path, flags)",
        "error == -libc::EUNATCH",
        "handle.reported_size()",
        "reported_size <= size",
        "libc::c_uint::MAX as usize",
        "OwnedFd::from_raw_fd(pinned)",
        "libc::O_PATH",
        "libc::O_NOFOLLOW",
        "flags & libc::AT_NO_AUTOMOUNT == 0",
        "flags & !INODE_SAME_FLAGS != 0",
        "flags & libc::AT_SYMLINK_NOFOLLOW != 0",
        "flags |= libc::AT_EMPTY_PATH",
        "if handle_a != handle_b",
        "if mount_a.value() == mount_b.value()",
        "libc::fstatat(fd, path.as_ptr(), stat.as_mut_ptr(), flags)",
        "stat_inode_same(&stat_a, &stat_b)",
    )
    required_current_c = (
        "int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags)",
        "(isempty(filea) || isempty(fileb)) && !FLAGS_SET(flags, AT_EMPTY_PATH)",
        "fda >= 0 && fda == fdb && isempty(filea) && isempty(fileb)",
        "if (!FLAGS_SET(flags, AT_NO_AUTOMOUNT))",
        "openat(fda, filea, O_PATH|O_CLOEXEC|",
        "name_to_handle_at_try_fid(",
        "if (is_name_to_handle_at_fatal_error(r))",
        "have_unique_mntid ? NULL : &_mntidb",
        "have_unique_mntid ? &mntidb : NULL",
        "if (!file_handle_equal(ha, hb))",
        "if (mntida == mntidb)",
        "if (fstatat(fda, strempty(filea), &sta, flags) < 0)",
        "return stat_inode_same(&sta, &stb);",
    )
    required_mount_c = (
        "#define ORIGINAL_MAX_HANDLE_SZ 128",
        "flags|AT_HANDLE_MNT_ID_UNIQUE",
        "if (errno == EOVERFLOW)",
        "if (errno != EINVAL)",
        "at_flags_normalize_nofollow",
        "STATX_MNT_ID_UNIQUE",
        "if (r != -EUNATCH || !ret_mnt_id)",
        "if (h->handle_bytes <= n)",
        "n > UINT_MAX - offsetof(struct file_handle, f_handle)",
        "flags | AT_HANDLE_FID",
        "flags & ~AT_HANDLE_FID",
    )
    required_mount_rust = (
        "pub fn is_name_to_handle_at_fatal_error(err: i32) -> bool",
        "errno_is_neg_not_supported(err)",
        "errno_is_neg_privilege(err)",
        "err == -EOVERFLOW || err == -EINVAL",
        "r == -EOPNOTSUPP",
        "r == -ENOTTY",
        "r == -ENOSYS",
        "r == -EAFNOSUPPORT",
        "r == -EPFNOSUPPORT",
        "r == -EPROTONOSUPPORT",
        "r == -ESOCKTNOSUPPORT",
        "r == -ENOPROTOOPT",
        "r == -EACCES || r == -EPERM",
    )
    required_vectors = (
        "inode_same(path_a, path_b, 0) == rs_inode_same(path_a, path_b, 0)",
        "fd_inode_same(fd_a, fd_b) == rs_fd_inode_same(fd_a, fd_b)",
        "AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) ==",
        "AT_NO_AUTOMOUNT) ==",
        "rs_inode_same(NULL, path_b, 0) == -EINVAL",
        "rs_inode_same_at(-1, path_a",
        "AT_REMOVEDIR) == -EINVAL",
    )
    return (
        inode_same.count("#[unsafe(no_mangle)]") == 3
        and inode_same.count('pub unsafe extern "C" fn') == 2
        and inode_same.count("/// # Safety") == 2
        and {"stat-util.c", "stat-util.h", "mountpoint-util.c", "mountpoint-util.h"}
        <= authority_names
        and all(declaration in header for declaration in required_header)
        and all(contract in inode_same for contract in required_rust_contract)
        and all(shortcut not in inode_same for shortcut in forbidden_layout_shortcuts)
        and "pub(super) fn stat_inode_same" in inode
        and "mod inode_same;" in parent
        and "pub use inode_same::{rs_fd_inode_same, rs_inode_same, rs_inode_same_at};"
        in parent
        and "'rust/stat_util/inode_same.rs'," in meson
        and all(contract in c_source for contract in required_current_c)
        and all(contract in mount_source for contract in required_mount_c)
        and all(contract in mount_rust for contract in required_mount_rust)
        and all(vector in test for vector in required_vectors)
    )


def stat_inode_hash_boundary_is_reviewed() -> bool:
    """Pin native field widths/order and canonical SipHash state compression."""

    header = SURFACES["stat_util"][0].read_text()
    parent = SURFACES["stat_util"][1].read_text()
    inode = SURFACE_EXTRA_SOURCES["stat_util"][1].read_text()
    hash_source = SURFACE_EXTRA_SOURCES["stat_util"][7].read_text()
    c_source = (ROOT / "src/basic/stat-util.c").read_text()
    siphash_header = (ROOT / "src/basic/siphash24.h").read_text()
    test = (ROOT / "tests-extra/test-stat-util-rust.c").read_text()
    meson = (ROOT / "src/basic/meson.build").read_text()
    authority_names = {path.name for path in C_AUTHORITIES["stat_util"]}
    required_header = (
        "void rs_inode_hash_func(const struct stat *q, struct siphash *state);",
        "void rs_inode_unmodified_hash_func(const struct stat *q, struct siphash *state);",
    )
    forbidden_layout_shortcuts = (
        "st_dev as",
        "st_ino as",
        "st_mtime as",
        "st_mtime_nsec as",
        "st_size as",
        "st_rdev as",
        "from_raw_parts",
        "offset_of!",
        "target_arch",
        "target_pointer_width",
        "struct SipHashState {\n    v0:",
    "u64::from_ne_bytes",
        "to_ne_bytes",
    )
    required_rust_contract = (
        '#[repr(C)]\npub struct SipHashState {\n    _private: [u8; 0],\n}',
        "fn siphash24_compress(",
        "state: *mut SipHashState",
        "NonNull<SipHashState>",
        "PhantomData<&'a mut SipHashState>",
        "std::mem::size_of::<T>()",
        "fn inode_hash(stat: &libc::stat, state: &mut SipHashCompressor<'_>)",
        "state.compress(&stat.st_dev);",
        "state.compress(&stat.st_ino);",
        "let file_type: libc::mode_t = inode_type(stat.st_mode);",
        "state.compress(&file_type);",
        "fn inode_unmodified_hash(stat: &libc::stat, state: &mut SipHashCompressor<'_>)",
        "state.compress(&stat.st_mtime);",
        "state.compress(&stat.st_mtime_nsec);",
        "inode_type(stat.st_mode) == S_IFREG as libc::mode_t",
        "state.compress(&stat.st_size);",
        "let invalid = u64::MAX;",
        "value == S_IFCHR as libc::mode_t || value == S_IFBLK as libc::mode_t",
        "state.compress(&stat.st_rdev);",
        "let invalid: libc::dev_t = !0;",
    )
    required_current_c = (
        "void inode_hash_func(const struct stat *q, struct siphash *state)",
        "siphash24_compress_typesafe(q->st_dev, state);",
        "siphash24_compress_typesafe(q->st_ino, state);",
        "mode_t type = q->st_mode & S_IFMT;",
        "siphash24_compress_typesafe(type, state);",
        "void inode_unmodified_hash_func(const struct stat *q, struct siphash *state)",
        "inode_hash_func(q, state);",
        "siphash24_compress_typesafe(q->st_mtim.tv_sec, state);",
        "siphash24_compress_typesafe(q->st_mtim.tv_nsec, state);",
        "if (S_ISREG(q->st_mode))",
        "siphash24_compress_typesafe(q->st_size, state);",
        "uint64_t invalid = UINT64_MAX;",
        "if (S_ISCHR(q->st_mode) || S_ISBLK(q->st_mode))",
        "siphash24_compress_typesafe(q->st_rdev, state);",
        "dev_t invalid = (dev_t) -1;",
    )
    required_siphash_abi = (
        "struct siphash {",
        "uint64_t v0;",
        "uint64_t padding;",
        "size_t inlen;",
        "void siphash24_compress(const void *in, size_t inlen, struct siphash *state);",
        "siphash24_compress(&(in), sizeof(typeof(in)), (state))",
    )
    required_vectors = (
        '#include "siphash24.h"',
        "struct siphash state;",
        "siphash24_init(&state, key);",
        "rs_inode_unmodified_hash_func(st, &state);",
        "rs_inode_hash_func(st, &state);",
        "siphash24_finalize(&state)",
        ".st_dev = (dev_t) -1",
        ".st_ino = (ino_t) -1",
        ".st_mtim = { .tv_sec = -2, .tv_nsec = -3 }",
        ".st_size = -4",
        ".st_rdev = (dev_t) -5",
        "inode_compare_func(&a, &b) == 0",
        "inode_unmodified_compare_func(&a, &b) == 0",
        "a.st_mode = b.st_mode = S_IFDIR",
        "a.st_mode = b.st_mode = S_IFCHR",
        "a.st_mode = b.st_mode = S_IFREG",
    )
    return (
        hash_source.count("#[unsafe(no_mangle)]") == 2
        and hash_source.count('pub unsafe extern "C" fn') == 2
        and hash_source.count("/// # Safety") == 2
        and {"stat-util.c", "stat-util.h", "siphash24.c", "siphash24.h"}
        <= authority_names
        and all(declaration in header for declaration in required_header)
        and all(contract in hash_source for contract in required_rust_contract)
        and all(shortcut not in hash_source for shortcut in forbidden_layout_shortcuts)
        and "pub(super) fn inode_type" in inode
        and "mod hash;" in parent
        and "pub use hash::{rs_inode_hash_func, rs_inode_unmodified_hash_func};"
        in parent
        and "'rust/stat_util/hash.rs'," in meson
        and all(contract in c_source for contract in required_current_c)
        and all(contract in siphash_header for contract in required_siphash_abi)
        and all(vector in test for vector in required_vectors)
    )


def registered_rust_shadow_test(test: Path, test_meson: str) -> bool:
    test_meson = strip_meson_comments(test_meson)
    stem = test.stem
    pattern = re.compile(
        rf"rust_test_exe\s*=\s*executable\(\s*'{re.escape(stem)}',"
        rf"(?P<body>.*?)^\s*\)\s*^"
        rf"\s*test\(\s*'{re.escape(stem)}'\s*,\s*rust_test_exe\s*\)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(test_meson)
    return bool(
        match
        and test.name in match.group("body")
        and "link_with : [libshared, rust_staticlib]" in match.group("body")
    )


def tests_cover_declared_surface(
    name: str, declarations: list[tuple[str, Signature]], test_meson: str
) -> bool:
    tests = SHADOW_TESTS[name]
    if any(not registered_rust_shadow_test(test, test_meson) for test in tests):
        return False
    called = set().union(
        *(
            set(
                re.findall(
                    r"\b(rs_[A-Za-z0-9_]+)\s*\(",
                    "\n".join(c_function_bodies(test.read_text())),
                )
            )
            for test in tests
        )
    )
    if not set(symbol for symbol, _ in declarations).issubset(called):
        return False
    if name == "uid_classification":
        test = tests[0].read_text()
        required_false_paths = (
            "gid_is_dynamic(UINT32_MAX) == rs_gid_is_dynamic(UINT32_MAX)",
            "gid_is_container(UINT32_MAX) == rs_gid_is_container(UINT32_MAX)",
            "gid_is_foreign(UINT32_MAX) == rs_gid_is_foreign(UINT32_MAX)",
            "gid_is_transient(GREETER_UID_MIN) == rs_gid_is_transient(GREETER_UID_MIN)",
        )
        return all(fixture in test for fixture in required_false_paths)
    return True


def declarations_match_c_authority(
    name: str, declarations: list[tuple[str, Signature]]
) -> tuple[bool, int, int]:
    """Compare current C signatures, with explicit macro-family curation."""

    authority = "\n".join(path.read_text() for path in C_AUTHORITIES[name])
    code = mask_c_non_code(authority)
    parsed = 0
    curated = 0
    for symbol, expected in declarations:
        c_name = symbol.removeprefix("rs_")
        direct = re.search(
            rf"^([A-Za-z_][A-Za-z0-9_ \t*]*?(?:\s|\*))"
            rf"{re.escape(c_name)}\(([^)]*)\)\s*(?:\{{|;)",
            code,
            flags=re.MULTILINE,
        )
        if direct:
            raw_result, raw_parameters = direct.groups()
            try:
                parameters = ()
                if raw_parameters.strip() and raw_parameters.strip() != "void":
                    parameters = tuple(
                        c_parameter_type(parameter)
                        for parameter in raw_parameters.split(",")
                    )
                actual = (parameters, c_result_type(raw_result))
            except ValueError:
                return False, parsed, curated
            if actual != expected:
                return False, parsed, curated
            parsed += 1
            continue
        for suffix in ("_to_string", "_from_string"):
            if c_name.endswith(suffix):
                table = c_name.removesuffix(suffix)
                if re.search(
                    rf"\bDEFINE_STRING_TABLE_LOOKUP(?:_WITH_BOOLEAN)?\(\s*{re.escape(table)}\s*,",
                    authority,
                ):
                    break
        else:
            table = None
        if table is not None:
            actual = (
                (("i32",), "*constc_char")
                if c_name.endswith("_to_string")
                else (("*constc_char",), "i32")
            )
            if actual != expected:
                return False, parsed, curated
            curated += 1
            continue
        if c_name.startswith("ERRNO_IS_") and not c_name.startswith("ERRNO_IS_NEG_"):
            suffix = c_name.removeprefix("ERRNO_IS_")
            if re.search(rf"\b_DEFINE_ABS_WRAPPER\(\s*{re.escape(suffix)}\s*\)", authority):
                if expected != (("i64",), "bool"):
                    return False, parsed, curated
                curated += 1
                continue
        return False, parsed, curated
    return True, parsed, curated


def dns_type_predicates_boundary_is_reviewed() -> bool:
    header = SURFACES["dns_type_predicates"][0].read_text()
    source = SURFACES["dns_type_predicates"][1].read_text()
    test = SHADOW_TESTS["dns_type_predicates"][0].read_text()
    c_source = (ROOT / "src/shared/dns-type.c").read_text()
    declarations = dict(header_inventory(SURFACES["dns_type_predicates"][0]))
    authority: dict[str, Signature] = {}

    for symbol, signature in declarations.items():
        c_symbol = symbol.removeprefix("rs_")
        pattern = re.compile(
            rf"^([A-Za-z_][A-Za-z0-9_ \t*]*?(?:\s|\*))"
            rf"{re.escape(c_symbol)}\(([^)]*)\)\s*\{{",
            re.MULTILINE,
        )
        match = pattern.search(mask_c_non_code(c_source))
        if not match:
            return False
        raw_result, raw_parameters = match.groups()
        parameters = ()
        if raw_parameters.strip() and raw_parameters.strip() != "void":
            parameters = tuple(
                c_parameter_type(parameter) for parameter in raw_parameters.split(",")
            )
        authority[symbol] = (parameters, c_result_type(raw_result))

    return (
        declarations == authority
        and "#include <stdbool.h>" in header
        and "#include <stdint.h>" in header
        and "borrowed static storage" in header.lower()
        and "must not be freed" in header
        and "libc::AF_UNSPEC" in source
        and "error.errno().to_neg_errno()" in source
        and source.count("The returned pointer is never null and must not be freed.") == 3
        and "for (uint32_t value = 0; value <= UINT16_MAX; value++)" in test
        and "for (uint16_t value = 0; value <= UINT8_MAX; value++)" in test
        and "borrowed static storage" in test
    )


def image_name_boundary_is_reviewed() -> bool:
    """Pin the byte policy and borrowed-pointer contract to current C.

    Generic signature checks cannot establish either that an invalid UTF-8 C
    string is rejected before becoming a Rust `str`, or that
    os_release_pretty_name() returns borrowed input/static storage rather than
    a Rust allocation. Keep those two deliberately small ABI boundaries
    explicit and source-reviewable.
    """

    validators = PARTIAL_SURFACES["image_name_is_valid"][1].read_text()
    image_class_header = PARTIAL_SURFACES["os_release_pretty_name"][0].read_text()
    image_class = PARTIAL_SURFACES["os_release_pretty_name"][1].read_text()
    test = PARTIAL_SHADOW_TESTS["image_name_is_valid"][0].read_text()
    return (
        "fn image_name_is_valid_bytes(s: &[u8]) -> bool" in validators
        and "s.len() > NAME_MAX" in validators
        and "std::str::from_utf8(s).is_err()" in validators
        and "CStr::from_ptr(s)" in validators
        and "image_name_is_valid_bytes(unsafe { CStr::from_ptr(s) }.to_bytes())" in validators
        and "c\"Linux\".as_ptr()" in image_class
        and "return pretty_name;" in image_class
        and "return name;" in image_class
        and "must not be freed" in image_class_header
        and '"image name"' in test
        and '"image\\xc3\\x28"' in test
    )


def alloc_util_multiply_boundary_is_reviewed() -> bool:
    """Pin multiply allocation behavior to the current inline C helpers.

    The signature check alone cannot tell a Rust `Vec` pointer from a
    malloc-compatible result. The registered test frees these values in C, so
    require the source-level allocator and the two distinct zero-size rules.
    """

    header, source, _ = PARTIAL_SURFACES["alloc_util_multiply"]
    test = PARTIAL_SHADOW_TESTS["alloc_util_multiply"][0].read_text()
    source_text = source.read_text()
    header_text = header.read_text()
    return (
        "use crate::ffi;" in source_text
        and "need.checked_mul(size).map(|total| total.max(1))" in source_text
        and "product.checked_add(1)" in source_text
        and "ffi::malloc(allocation_len)" in source_text
        and "ptr::copy_nonoverlapping" in source_text
        and "if copy_len != 0 && p.is_null()" in source_text
        and "*destination.cast::<u8>().add(copy_len) = 0" in source_text
        and "void *rs_malloc_multiply(size_t need, size_t size);" in header_text
        and '#include "rust/alloc_util.h"' in test
        and "void* rs_malloc_multiply(" not in test
        and "malloc_multiply(SIZE_MAX, 2)" in test
        and "memdup_suffix0_multiply(data, 0, 5)" in test
    )


def alloc_util_boundary_is_reviewed() -> bool:
    """Pin C allocator ownership and exact zero/overflow/free-many behavior."""

    header, source, _ = PARTIAL_SURFACES["alloc_util"]
    test = PARTIAL_SHADOW_TESTS["alloc_util"][0].read_text()
    source_text = source.read_text()
    header_text = header.read_text()
    return (
        "pub unsafe extern \"C\" fn rs_memdup(" in source_text
        and "let allocation_len = l.max(1);" in source_text
        and "pub unsafe extern \"C\" fn rs_memdup_suffix0(" in source_text
        and "suffix0_allocation_size(l)" in source_text
        and "pub unsafe extern \"C\" fn rs_free_many(" in source_text
        and "if n == 0" in source_text
        and "ffi::free(*slot)" in source_text
        and "*slot = ptr::null_mut()" in source_text
        and "void *rs_memdup(const void *p, size_t l);" in header_text
        and "void *rs_memdup_suffix0(const void *p, size_t l);" in header_text
        and "void rs_free_many(void **p, size_t n);" in header_text
        and '#include "rust/alloc_util.h"' in test
        and "rs_memdup(NULL, 0)" in test
        and "rs_memdup_suffix0(NULL, 0)" in test
        and "rs_memdup_suffix0(data, SIZE_MAX)" in test
        and "rs_free_many(NULL, 0)" in test
    )


def escape_boundary_is_reviewed() -> bool:
    """Pin the byte-oriented C allocation boundary for the escape helpers."""

    header = PARTIAL_SURFACES["escape"][0].read_text()
    source = "\n".join(
        path.read_text()
        for path in (
            PARTIAL_SURFACES["escape"][1],
            *PARTIAL_EXTRA_SOURCES["escape"],
        )
    )

    core_test, test, extra_test = (
        path.read_text() for path in PARTIAL_SHADOW_TESTS["escape"]
    )
    return (
        "fn try_escape_buffer(input_len: usize) -> Result<Vec<u8>, ()>" in source
        and "checked_mul(4)" in source
        and ".and_then(|n| n.checked_add(1))" in source
        and "fn try_octescape_full(s: &[u8], bad: &[u8])" in source
        and "fn try_decescape(s: &[u8], bad: &[u8])" in source
        and "fn try_strcpy_backslash_escaped(s: &[u8], bad: &[u8])" in source
        and "(0xFDD0..=0xFDEF).contains(&c)" in source
        and "c & 0xFFFE != 0xFFFE" in source
        and "fn malloc_c_string(bytes: &[u8]) -> *mut c_char" in source
        and "crate::ffi::malloc(allocation_size)" in source
        and "fn try_cunescape_with_prefix(" in source
        and "pub fn try_cunescape_bytes(" in source
        and "pub fn try_cunescape_into(" in source
        and "pub(crate) fn cescape_char_into" in source
        and "let mut escaped = [0; 4];" in source
        and "cescape_char_into(c as u8, &mut escaped)" in source
        and "let mut required = prefix.len();" in source
        and "output.fill(0);" in source
        and "first pass validated every escape" in source
        and "fn try_xescape_full(" in source
        and "fn try_shell_maybe_quote(" in source
        and "fn append_backslash_escaped(" in source
        and 'const SHELL_QUOTE_BYTES: &[u8] = b" \\t\\n\\r\\"\\\\`$*?[\'()<>|&;!";' in source
        and "Publication is deliberately last" in source
        and "unsafe fn cescape_input" in source
        and "pub unsafe extern \"C\" fn rs_cescape_char" in source
        and "pub unsafe extern \"C\" fn rs_cescape_length" in source
        and "pub unsafe extern \"C\" fn rs_cescape(" in source
        and "pub unsafe extern \"C\" fn rs_cunescape_one" in source
        and "pub unsafe extern \"C\" fn rs_cunescape(" in source
        and "rs_cunescape_length_with_prefix(" in source
        and "try_reserve_exact(source.len().saturating_mul(4))" in source
        and source.count("#[unsafe(no_mangle)]") >= 12
        and ".to_str()" not in source
        and "#include <sys/types.h>" in header
        and "int rs_cescape_char(char c, char *buf);" in header
        and "char* rs_cescape_length(const char *s, size_t n);" in header
        and "char* rs_cescape(const char *s);" in header
        and "int rs_cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit, bool accept_nul);" in header
        and "ssize_t rs_cunescape(const char *s, unsigned flags, char **ret);" in header
        and "fresh malloc(3) allocation" in header
        and '#include "rust/escape.h"' in test
        and "static const char binary[]" in test
        and "static const char malformed[]" in test
        and '"\\xef\\xbf\\xbe"' in test
        and "rs_decescape(\"a\", 1, NULL) == NULL" in test
        and "rs_shell_escape(\"hello\", NULL) == NULL" in test
        and '#include "rust/escape.h"' in extra_test
        and "static const char escaped_nul[]" in extra_test
        and "UNESCAPE_ACCEPT_NUL" in extra_test
        and 'streq(c_r, "\\\"hello world\\\"")' in extra_test
        and "Failure must not publish an allocation through ret." in extra_test
        and "rs_xescape_full(NULL, NULL, 3, 0) == NULL" in extra_test
        and "rs_quote_command_line(NULL, SHELL_ESCAPE_EMPTY) == NULL" in extra_test
        and "cescape_length_binary_and_null_contract" in core_test
        and "cunescape_one_length_nul_and_eight_bit_contract" in core_test
        and "cunescape_explicit_length_and_failure_publication" in core_test
        and "rs_cunescape_length_with_prefix(escaped, sizeof(escaped)" in core_test
        and "rs_cunescape(\"\\\\q\", 0, &rs_str) == -EINVAL" in core_test
        and "rs_cunescape_one(\"n\", SIZE_MAX, &rs_value, NULL, false) == -EINVAL" in core_test
        and "test_try_cunescape_into_zeroes_tail_and_does_not_publish_on_error" in source
    )


def header_inline_boundary_is_reviewed() -> bool:
    """Pin the three inline-header facades to safe byte/scalar cores."""

    source = PARTIAL_SURFACES["utf8_header_inline"][1].read_text()
    utf8_header = PARTIAL_SURFACES["utf8_header_inline"][0].read_text()
    terminal_header = PARTIAL_SURFACES["terminal_header_inline"][0].read_text()
    terminal_source = PARTIAL_SURFACES["terminal_header_inline"][1].read_text()
    path_header = PARTIAL_SURFACES["path_header_inline"][0].read_text()
    test = PARTIAL_SHADOW_TESTS["utf8_header_inline"][0].read_text()
    path_source = ROOT / "src/basic/rust/path_util.rs"
    escape_source = ROOT / "src/basic/rust/string_util_escape.rs"
    return (
        "fn utf8_is_valid_bytes(bytes: &[u8]) -> bool" in source
        and "fn ascii_is_valid_bytes(bytes: &[u8]) -> bool" in source
        and "valid_utf8_character(&bytes[offset..])" in source
        and "try_utf8_escape_non_printable(bytes, usize::MAX, false)" in source
        and "malloc_c_string(&escaped)" in source
        and "skip_dev_prefix_offset(bytes)" in source
        and "pub(crate) fn skip_dev_prefix_offset(path: &[u8]) -> usize" in path_source.read_text()
        and "pub(crate) fn valid_utf8_character(bytes: &[u8])" in escape_source.read_text()
        and "CStr::from_ptr(input)" in source
        and source.count("#[unsafe(no_mangle)]") == 7
        and "bool rs_utf16_is_surrogate(char16_t c);" in utf8_header
        and "char32_t rs_utf16_surrogate_pair_to_unichar(char16_t lead, char16_t trail);" in utf8_header
        and "bool rs_osc_char_is_valid(char c);" in terminal_header
        and "bool rs_vtnr_is_valid(unsigned n);" in terminal_header
        and "#include <stdbool.h>" in terminal_header
        and "pub extern \"C\" fn rs_osc_char_is_valid(c: c_char) -> bool" in terminal_source
        and "pub extern \"C\" fn rs_vtnr_is_valid(number: c_uint) -> bool" in terminal_source
        and "const char *rs_skip_dev_prefix(const char *p);" in path_header
        and '#include "rust/utf8.h"' in test
        and '#include "rust/terminal_util.h"' in test
        and '#include "rust/path_util.h"' in test
        and "Rust FFI — utf8.h inline wrappers" not in test
        and '"\\xc0\\x80"' in test
        and '"\\xef\\xbf\\xbe"' in test
        and '"/./dev///tty0"' in test
        and "utf16_surrogate_pair_to_unichar(0, 0)" in test
    )


def path_byte_abi_boundary_is_reviewed() -> bool:
    """Pin registered pure path APIs to one byte core and exact C ownership."""

    header, source, symbols = PARTIAL_SURFACES["path_byte_abi"]
    source_text = source.read_text()
    header_text = header.read_text()
    funcs_test, extra_test = (
        path.read_text() for path in PARTIAL_SHADOW_TESTS["path_byte_abi"]
    )
    return (
        len(symbols) == 22
        and source_text.count("#[unsafe(no_mangle)]") == 22
        and "fn first_component(" in source_text
        and "fn last_component(" in source_text
        and "fn path_compare_bytes(" in source_text
        and "fn path_startswith_offset(" in source_text
        and "fn simplify_bytes(" in source_text
        and "fn path_is_valid_bytes(" in source_text
        and "fn make_relative_bytes(" in source_text
        and "fn split_prefix_filename_bytes(" in source_text
        and "CStr::from_ptr(path)" in source_text
        and "libc::malloc(size)" in source_text
        and "libc::O_DIRECTORY" in source_text
        and "use std::path" not in source_text
        and "std::path::Path::" not in source_text
        and ".to_str()" not in source_text
        and "to_string_lossy" not in source_text
        and "from_utf8" not in source_text
        and '#include "path-util.h"' in header_text
        and "PathStartWithFlags flags" in header_text
        and "PathSimplifyFlags flags" in header_text
        and "char * const *strv" in header_text
        and '#include "rust/path_util.h"' in funcs_test
        and '#include "rust/path_util.h"' in extra_test
        and "Rust FFI forward declarations" not in funcs_test
        and "/* Rust FFI */" not in extra_test
        and 'static const char non_utf8_path[] = "//\\xff///x";' in funcs_test
        and "published == UINT_TO_PTR(1)" in funcs_test
        and "rs_ret == O_DIRECTORY" in extra_test
        and 'path_split_prefix_filename("/foo/\\xff/"' in extra_test
    )


def gpt_unit_install_predicates_are_reviewed() -> bool:
    """Pin raw C scalar/layout boundaries for the seven inline predicates."""

    gpt_header, gpt_source, _ = PARTIAL_SURFACES["gpt_partition_predicates"]
    unit_header, unit_source, _ = PARTIAL_SURFACES["unit_install_predicates"]
    install_header, install_source, _ = PARTIAL_SURFACES["install_change_predicate"]
    test = PARTIAL_SHADOW_TESTS["gpt_partition_predicates"][0].read_text()
    gpt_text = gpt_source.read_text()
    unit_text = unit_source.read_text()
    install_text = install_source.read_text()
    return (
        "#[repr(C)]" in gpt_text
        and "pub struct GptPartitionType" in gpt_text
        and "pub uuid: [u8; 16]" in gpt_text
        and "pub name: *const c_char" in gpt_text
        and "pub arch: c_int" in gpt_text
        and "pub designator: c_int" in gpt_text
        and "without ever constructing a Rust enum" in gpt_text
        and "gpt_partition_type_knows_read_only_designator(type_.designator)" in gpt_text
        and "gpt_partition_type_knows_growfs_designator(type_.designator)" in gpt_text
        and "gpt_partition_type_knows_no_auto_designator(type_.designator)" in gpt_text
        and "gpt_partition_type_has_filesystem_designator(type_.designator)" in gpt_text
        and "PARTITION_ROOT_VERITY_SIG" in gpt_text
        and "PARTITION_SWAP" in gpt_text
        and "#[unsafe(no_mangle)]\npub extern \"C\" fn rs_unit_type_may_alias" in unit_text
        and "#[unsafe(no_mangle)]\npub extern \"C\" fn rs_unit_type_may_template" in unit_text
        and "unit_type_may_alias_raw(type_)" in unit_text
        and "unit_type_may_template_raw(type_)" in unit_text
        and "pub const fn install_change_type_valid_raw(type_: i32) -> bool" in install_text
        and "INSTALL_CHANGE_ERRNO_MAX: i32 = -4095" in install_text
        and "(INSTALL_CHANGE_ERRNO_MAX..INSTALL_CHANGE_TYPE_MAX).contains(&type_)" in install_text
        and "#include \"gpt.h\"" in gpt_header.read_text()
        and "bool rs_gpt_partition_type_knows_read_only(GptPartitionType type);" in gpt_header.read_text()
        and "bool rs_unit_type_may_alias(int type);" in unit_header.read_text()
        and "bool rs_INSTALL_CHANGE_TYPE_VALID(int type);" in install_header.read_text()
        and '#include "rust/gpt_util.h"' in test
        and '#include "rust/unit_file.h"' in test
        and '#include "rust/install.h"' in test
        and "Rust FFI — GPT functions" not in test
        and "gpt_from(-1)" in test
        and "unit_type_may_alias(-1)" in test
        and "_UNIT_TYPE_MAX" in test
    )


def strv_escape_and_fnmatch_boundary_is_reviewed() -> bool:
    """Pin C-owned vector semantics at the two remaining strv ABI edges.

    The generic signature gate proves the ABI. This small review pin also
    prevents an apparently harmless refactor from replacing libc fnmatch,
    leaking a Rust allocation to C, or rolling back the prefix that current C
    intentionally leaves changed after a later allocation failure.
    """

    header, source, _ = PARTIAL_SURFACES["strv_escape_and_fnmatch"]
    header_text = header.read_text()
    source_text = source.read_text()
    escape_test, fnmatch_test = (
        path.read_text() for path in PARTIAL_SHADOW_TESTS["strv_escape_and_fnmatch"]
    )
    return (
        "char **rs_strv_shell_escape(char **l, const char *bad);" in header_text
        and "bool rs_strv_fnmatch_full(char * const *patterns, const char *s, int flags, size_t *ret_matched_pos);"
        in header_text
        and "fn first_fnmatch<'a>(" in source_text
        and "unsafe { fnmatch(pattern.as_ptr(), subject.as_ptr(), flags) == 0 }" in source_text
        and "std::iter::from_fn(||" in source_text
        and "*ret_matched_pos = SIZE_MAX" in source_text
        and "try_strcpy_backslash_escaped(entry.to_bytes(), bad.to_bytes())" in source_text
        and "malloc_c_string(&escaped)" in source_text
        and "free(entry.cast::<c_void>());" in source_text
        and "One-at-a-time replacement preserves no-rollback." in source_text
        and '#include "rust/strv.h"' in fnmatch_test
        and "FNM_NOESCAPE" in fnmatch_test
        and "char * const empty[] = { NULL };" in fnmatch_test
        and '#include "rust/strv.h"' in escape_test
        and "strv_shell_escape(c_arr, NULL) == c_arr" in escape_test
        and "rs_strv_shell_escape(rs_arr, NULL) == rs_arr" in escape_test
    )


def strv_extend_and_filter_boundary_is_reviewed() -> bool:
    """Pin the ownership and rollback rules of two allocating strv helpers."""

    header, source, _ = PARTIAL_SURFACES["strv_extend_and_filter"]
    header_text = header.read_text()
    source_text = source.read_text()
    test = PARTIAL_SHADOW_TESTS["strv_extend_and_filter"][0].read_text()
    return (
        "char **rs_strv_filter_prefix(char * const *l, const char *prefix);" in header_text
        and "int rs_strv_extend_strv(char ***a, char * const *b, bool filter_duplicates);"
        in header_text
        and "fn cstr_has_prefix(entry: &CStr, prefix: &[u8]) -> bool" in source_text
        and "entry.to_bytes().starts_with(prefix)" in source_text
        and "return unsafe { rs_strv_copy_n(l, SIZE_MAX) };" in source_text
        and "let copied = calloc(slots" in source_text
        and "free((*copied.add(index)).cast::<c_void>());" in source_text
        and "fn strv_contains_cstr(l: *const *mut c_char, needle: &CStr) -> bool" in source_text
        and "p >= SIZE_MAX - q" in source_text
        and "reallocarray(" in source_text
        and "for index in 0..added" in source_text
        and "*extended.add(p) = std::ptr::null_mut();" in source_text
        and '#include "rust/strv.h"' in test
        and "strv_filter_prefix(input, NULL)" in test
        and "rs_strv_filter_prefix(input, NULL)" in test
        and "strv_extend_strv(&c_r, dup_src, true)" in test
        and "rs_strv_extend_strv(&rs_r, dup_src, true)" in test
    )


def udev_util_boundary_is_reviewed() -> bool:
    """Pin the two intentionally different udev byte contracts to C.

    The whitespace function accepts a bounded, potentially non-NUL fixed
    field and permits exact in-place replacement. The character sanitizer is
    instead a NUL-string byte transform, preserving every ``\\x`` prefix and
    validating one UTF-8 scalar at a time. Generic ABI signature checks cannot
    establish those ownership or byte-boundary rules.
    """

    header, source, _ = PARTIAL_SURFACES["udev_util"]
    test = PARTIAL_SHADOW_TESTS["udev_util"][0].read_text()
    header_text = header.read_text()
    source_text = source.read_text()
    return (
        "fn udev_replace_whitespace_bytes(input: &[u8]) -> Vec<u8>" in source_text
        and "LEADING_WHITESPACE.contains(&input[source])" in source_text
        and "if output.len() >= len.saturating_sub(1)" in source_text
        and "fn valid_utf8_unichar_len(bytes: &[u8]) -> Option<usize>" in source_text
        and "if byte == b'\\\\' && index + 1 < string_len && bytes[index + 1] == b'x'" in source_text
        and "CStr::from_ptr(str_)" in source_text
        and "Some(unsafe { CStr::from_ptr(allow) }.to_bytes())" in source_text
        and "udev_replace_chars(bytes, allow)" in source_text
        and ".to_owned()" not in source_text
        and "*to.cast::<u8>().add(output) = 0" in source_text
        and "str_ == to" in source_text
        and "NUL-terminated allow-list" in header_text
        and '#include "rust/udev_util.h"' in test
        and "Rust FFI forward declarations" not in test
        and '"\\vhello"' in test
        and '"test\\\\xGG"' in test
        and "(char) 0xff" in test
        and '"a\\tb"' in test
    )


def strv_registered_boundary_is_reviewed() -> bool:
    """Pin ownership and publication rules for the registered strv facade."""

    header, source, _ = PARTIAL_SURFACES["strv_registered"]
    header_text = header.read_text()
    source_text = source.read_text()
    production = source_text.split("#[cfg(test)]", 1)[0]
    tests = tuple(
        path.read_text() for path in PARTIAL_SHADOW_TESTS["strv_registered"]
    )

    def section(symbol: str) -> str:
        start = source_text.find(f"fn {symbol}(")
        if start < 0:
            return ""
        end = source_text.find("\n// ──", start)
        return source_text[start:] if end < 0 else source_text[start:end]

    push = section("rs_strv_push_with_size")
    consume = section("rs_strv_consume_with_size")
    consume_inline = section("rs_strv_consume")
    join = section("rs_strv_join_full")
    split_newlines = section("rs_strv_split_newlines_full")
    rebreak = section("rs_strv_rebreak_lines")

    return (
        "Functions named push/insert transfer their string only on" in header_text
        and "consume variants take ownership regardless of success" in header_text
        and "Every vector is NULL-terminated." in header_text
        and all('#include "rust/strv.h"' in test for test in tests)
        and all("/* Rust FFI */" not in test for test in tests)
        and "reallocarray(" in push
        and "free(value.cast())" not in push
        and "rs_strv_push_with_size(l, n, value)" in consume
        and "free(value.cast())" in consume
        and "rs_strv_consume_with_size(l, std::ptr::null_mut(), s)" in consume_inline
        and 'b" \\0"' in join
        and 'const NEWLINE: &[u8] = b"\\n\\r\\0";' in source_text
        and "rs_strv_split_full(&mut l, s, NEWLINE.as_ptr().cast(), flags)" in split_newlines
        and "rs_utf8_encoded_to_unichar(p, &mut unichar)" in rebreak
        and "return encoded_len;" in rebreak
        and "w = 0;" in rebreak
        and "unsafe { *ret =" in source_text
        and "unsafe fn free_owned_strv" in production
        and "CString::into_raw" not in production
        and "Vec::into_raw_parts" not in production
    )


def string_mutation_registered_boundary_is_reviewed() -> bool:
    """Pin byte mutation, ownership, and runtime-signal inline contracts."""

    string_header, string_source, _ = PARTIAL_SURFACES["string_mutation_registered"]
    signal_header, signal_source, _ = PARTIAL_SURFACES["signal_inline_registered"]
    line_source = PARTIAL_EXTRA_SOURCES["string_mutation_registered"][0]
    mutation_test, inline_test = (
        path.read_text() for path in PARTIAL_SHADOW_TESTS["string_mutation_registered"]
    )
    string_header_text = string_header.read_text()
    string_source_text = string_source.read_text()
    signal_header_text = signal_header.read_text()
    signal_source_text = signal_source.read_text()
    line_source_text = line_source.read_text()
    return (
        "Returned interior" in string_header_text
        and "pointers borrow their input." in string_header_text
        and "C-allocator ownership through their output parameters" in string_header_text
        and '#include "rust/string_util.h"' in mutation_test
        and '#include "rust/string_util.h"' in inline_test
        and '#include "rust/signal_util.h"' in inline_test
        and "/* Rust FFI */" not in mutation_test
        and "/* Rust FFI */" not in inline_test
        and 'c" \\t\\n\\r".as_ptr()' in string_source_text
        and "unsafe fn c_string_contains_byte" in string_source_text
        and "preserves C behavior when bad aliases s" in string_source_text
        and string_source_text.count("unsafe { c_string_contains_byte(bad,") == 2
        and "let flags = if separators.is_null() { 0 } else { 1 << 6 };" in line_source_text
        and "if s.is_null() || ret.is_null()" in line_source_text
        and 'char * const *words' in string_header_text
        and "const char *rs_signal_to_string_with_check(int signo);" in signal_header_text
        and "static SIGNAL_NAME_BUFFER: UnsafeCell<[c_char; 32]>" in signal_source_text
        and "rs_get_sigrtmin(), rs_get_sigrtmax()" in signal_source_text
        and "signo > 0 && signo < unsafe { rs_get_nsig() }" in signal_source_text
        and "(char) 0xff" in mutation_test
        and 'rs_delete_chars(c, "")' in mutation_test
        and 'rs_string_contains_word_strv("a,,b", ","' in mutation_test
        and "rs_signal_to_string_with_check(SIGRTMIN)" in inline_test
    )


def main() -> int:
    meson = MESON.read_text()
    test_meson = TEST_MESON.read_text()
    rust_ci = RUST_CI.read_text()
    total_declarations = 0
    total_exports = 0
    authority_parsed = 0
    authority_curated = 0
    for name, (header, source) in SURFACES.items():
        declarations = header_inventory(header)
        try:
            source_paths = (source, *SURFACE_EXTRA_SOURCES.get(name, ()))
            exports = [
                export
                for source_path in source_paths
                for export in rust_inventory(source_path)
            ]
        except ValueError as error:
            return fail(str(error))

        declared_names = [symbol for symbol, _ in declarations]
        exported_names = [symbol for symbol, _, _, _ in exports]
        if duplicate := duplicates(declared_names):
            return fail(f"{header}: duplicate declarations: {duplicate}")
        if duplicate := duplicates(exported_names):
            return fail(f"{name}: duplicate C ABI exports: {duplicate}")
        declared = dict(declarations)
        exported = {symbol: signature for symbol, signature, _, _ in exports}
        if missing := sorted(declared.keys() - exported.keys()):
            return fail(f"{header}: declarations without explicit Rust C ABI: {missing}")
        if extra := sorted(exported.keys() - declared.keys()):
            return fail(f"{source}: explicit C ABI exports absent from header: {extra}")
        if mismatches := {
            symbol: (declared[symbol], exported[symbol])
            for symbol in declared.keys() & exported.keys()
            if declared[symbol] != exported[symbol]
        }:
            formatted = "; ".join(
                f"{symbol}: C {format_signature(expected)} Rust {format_signature(actual)}"
                for symbol, (expected, actual) in sorted(mismatches.items())
            )
            return fail(f"{name}: Rust C ABI signature mismatch: {formatted}")
        for source_path in source_paths:
            source_meson_path = source_path.relative_to(MESON.parent).as_posix()
            if f"'{source_meson_path}'," not in meson:
                return fail(f"basic Meson rust_sources omits {source_path.name}")
        if not tests_cover_declared_surface(name, declarations, test_meson):
            return fail(f"{name}: registered C shadow tests do not call every declared Rust export")
        authority_ok, parsed, curated = declarations_match_c_authority(name, declarations)
        if not authority_ok:
            return fail(
                f"{name}: declared Rust ABI signatures do not match parsed/curated current C authority"
            )
        authority_parsed += parsed
        authority_curated += curated
        total_declarations += len(declarations)
        total_exports += len(exports)

    for name, (header, source, reviewed_symbols) in PARTIAL_SURFACES.items():
        declarations = header_inventory(header, reviewed_symbols)
        try:
            exports = [
                export
                for source_path in (source, *PARTIAL_EXTRA_SOURCES.get(name, ()))
                for export in rust_inventory(source_path)
                if export[0] in reviewed_symbols
            ]
        except ValueError as error:
            return fail(str(error))

        declared = dict(declarations)
        exported = {symbol: signature for symbol, signature, _, _ in exports}
        if set(declared) != reviewed_symbols:
            return fail(f"{name}: reviewed declarations differ from expected set")
        if set(exported) != reviewed_symbols:
            return fail(f"{name}: reviewed symbols lack explicit Rust C ABI definitions")
        if mismatches := {
            symbol: (declared[symbol], exported[symbol])
            for symbol in reviewed_symbols
            if declared[symbol] != exported[symbol]
        }:
            formatted = "; ".join(
                f"{symbol}: C {format_signature(expected)} Rust {format_signature(actual)}"
                for symbol, (expected, actual) in sorted(mismatches.items())
            )
            return fail(f"{name}: reviewed Rust C ABI signature mismatch: {formatted}")
        source_meson_path = source.relative_to(MESON.parent).as_posix()
        if f"'{source_meson_path}'," not in meson:
            return fail(f"basic Meson rust_sources omits {source.name}")

        tests = PARTIAL_SHADOW_TESTS[name]
        if any(not registered_rust_shadow_test(test, test_meson) for test in tests):
            return fail(f"{name}: reviewed C comparison test is not registered")
        called = set().union(
            *(
                set(
                    re.findall(
                        r"\b(rs_[A-Za-z0-9_]+)\s*\(",
                        "\n".join(c_function_bodies(test.read_text())),
                    )
                )
                for test in tests
            )
        )
        if not reviewed_symbols.issubset(called):
            return fail(f"{name}: reviewed C comparison test omits a reviewed symbol")
        authority = "\n".join(path.read_text() for path in PARTIAL_C_AUTHORITIES[name])
        authority_code = mask_c_non_code(authority)
        if name == "format_bytes_full":
            # The project defines FormatBytesFlag as a target-default enum;
            # its reviewed ABI uses the canonical C `int` representation.
            authority_code = authority_code.replace("FormatBytesFlag", "int")
        # GCC allocation/ownership annotations such as `_alloc_(1, 2)` and
        # `_malloc_` precede inline declarations in current alloc-util.h.
        # They are not part of the C calling signature, so remove them before
        # parsing the canonical return and parameter types.
        authority_code = re.sub(
            r"\b_[A-Za-z0-9_]+_\s*(?:\([^)]*\))?", "", authority_code
        )
        for symbol, expected in declarations:
            c_symbol = (
                "MurmurHash2"
                if name == "murmurhash2" and symbol == "rs_MurmurHash2"
                else symbol.removeprefix("rs_")
            )
            if name == "strv_registered" and symbol == "rs_strv_contains":
                if "#define strv_contains(l, s) (!!strv_find((l), (s)))" not in authority:
                    return fail(
                        "strv_registered: strv_contains macro no longer matches current C authority"
                    )
                authority_curated += 1
                continue
            if name == "strv_registered" and symbol == "rs_strv_free_and_replace":
                # The C API is a lvalue-consuming macro, not a callable
                # function. The Rust export deliberately exposes both
                # lvalue slots so it can preserve free/assign/NULL ordering.
                if (
                    not re.search(
                        r"#define\s+strv_free_and_replace\s*\(\s*a\s*,\s*b\s*\)"
                        r"\s*\\\s*\n\s*free_and_replace_full\s*\(\s*a\s*,\s*b\s*,\s*strv_free\s*\)",
                        authority,
                    )
                    or expected
                    != (("*mut*mut*mutc_char", "*mut*mut*mutc_char"), "()")
                ):
                    return fail(
                        "strv_registered: strv_free_and_replace macro or two-slot ownership ABI changed"
                    )
                authority_curated += 1
                continue
            if name == "replace_var" and symbol == "rs_replace_var":
                expected_signature = (
                    ("*constc_char", "Option<ReplaceVarLookup>", "*mutc_void"),
                    "*mutc_char",
                )
                normalized_authority = re.sub(r"\s+", " ", authority)
                expected_c_signature = (
                    "char* replace_var(const char *text, char *(*lookup)(const char *variable, "
                    "void *userdata), void *userdata)"
                )
                if expected != expected_signature or expected_c_signature not in normalized_authority:
                    return fail(
                        "replace_var: callback ABI no longer matches the current C declaration"
                    )
                authority_curated += 1
                continue
            if name == "efivars_util" and symbol == "rs_efi_guid_to_id128":
                # The C authority returns sd_id128_t by value, while this
                # deliberately audited facade uses caller storage to avoid
                # the by-value-union ABI variance on aarch64.
                if (
                    expected != (("*constc_void", "*mutu8"), "i32")
                    or not re.search(
                        r"\bsd_id128_t\s+efi_guid_to_id128\s*\(\s*const\s+void\s*\*\s*guid\s*\)",
                        authority,
                    )
                ):
                    return fail(
                        "efivars_util: efi_guid_to_id128 output-pointer ABI no longer matches C authority"
                    )
                authority_curated += 1
                continue
            if name == "efivars_util" and symbol == "rs_efi_id128_to_guid":
                # See the paired output-pointer facade above. The input is a
                # 16-byte sd_id128_t representation rather than a by-value C
                # union so the Rust declaration has one stable ABI.
                if (
                    expected != (("*constu8", "*mutc_void"), "()")
                    or not re.search(
                        r"\bvoid\s+efi_id128_to_guid\s*\(\s*sd_id128_t\s+id\s*,\s*void\s*\*\s*ret_guid\s*\)",
                        authority,
                    )
                ):
                    return fail(
                        "efivars_util: efi_id128_to_guid pointer ABI no longer matches C authority"
                    )
                authority_curated += 1
                continue
            if name == "signal_inline_registered" and symbol == "rs_signal_is_valid":
                if (
                    "static inline bool SIGNAL_VALID(int signo)" not in authority
                    or "return signo > 0 && signo < _NSIG;" not in authority
                ):
                    return fail(
                        "signal_inline_registered: SIGNAL_VALID inline authority changed"
                    )
                authority_curated += 1
                continue
            string_table_lookup = {
                "confidential_virt": (
                    "confidential_virtualization",
                    "ConfidentialVirtualization",
                ),
                "locale_util": ("locale_variable", "LocaleVariable"),
                "image_class": ("image_class", "ImageClass"),
            }.get(name)
            if string_table_lookup is not None:
                table, table_type = string_table_lookup
                if (
                    f"DEFINE_STRING_TABLE_LOOKUP({table}, {table_type});" not in authority
                    or f"DECLARE_STRING_TABLE_LOOKUP({table}, {table_type});" not in authority
                    or f"{table}_table" not in authority
                ):
                    return fail(
                        f"{name}: current C string-table lookup authority changed"
                    )
                authority_curated += 1
                continue
            for suffix in ("_to_string", "_from_string"):
                if c_symbol.endswith(suffix):
                    table = c_symbol.removesuffix(suffix)
                    if re.search(
                        rf"\bDEFINE_STRING_TABLE_LOOKUP(?:_WITH_BOOLEAN)?\(\s*{re.escape(table)}\s*,",
                        authority,
                    ):
                        actual = (
                            (("i32",), "*constc_char")
                            if suffix == "_to_string"
                            else (("*constc_char",), "i32")
                        )
                        if actual != expected:
                            return fail(
                                f"{name}: current C string-table signature mismatch for {symbol}"
                            )
                        authority_curated += 1
                        break
                    if suffix == "_to_string" and re.search(
                        rf"\bDEFINE_STRING_TABLE_LOOKUP_TO_STRING\(\s*{re.escape(table)}\s*,",
                        authority,
                    ):
                        if (("i32",), "*constc_char") != expected:
                            return fail(
                                f"{name}: current C to-string table signature mismatch for {symbol}"
                            )
                        authority_curated += 1
                        break
                    if suffix == "_from_string" and re.search(
                        rf"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\(\s*{re.escape(table)}\s*,",
                        authority,
                    ):
                        if (("*constc_char",), "i32") != expected:
                            return fail(
                                f"{name}: current C fallback string-table signature mismatch for {symbol}"
                            )
                        authority_curated += 1
                        break
            else:
                table = None
            if table is not None:
                continue
            if c_symbol.endswith("_to_string_alloc"):
                table = c_symbol.removesuffix("_to_string_alloc")
                if re.search(
                    rf"\bDEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK\(\s*{re.escape(table)}\s*,",
                    authority,
                ):
                    if (("i32", "*mut*mutc_char"), "i32") != expected:
                        return fail(
                            f"{name}: current C fallback string-table signature mismatch for {symbol}"
                        )
                    authority_curated += 1
                    continue
            match = re.search(
                rf"^[ \t]*(?!return\b)([A-Za-z_][A-Za-z0-9_ \t*]*?(?:\s|\*))"
                rf"{re.escape(c_symbol)}\s*\(([^)]*)\)\s*(?:\{{|;)",
                authority_code,
                flags=re.MULTILINE,
            )
            if not match:
                return fail(f"{name}: reviewed symbol lacks current C authority: {symbol}")
            raw_result, raw_parameters = match.groups()
            try:
                parameters = ()
                if raw_parameters.strip() and raw_parameters.strip() != "void":
                    parameters = tuple(
                        c_parameter_type(parameter)
                        for parameter in raw_parameters.split(",")
                    )
                actual = (parameters, c_result_type(raw_result))
            except ValueError as error:
                return fail(f"{name}: cannot parse current C authority for {symbol}: {error}")
            if actual != expected:
                return fail(
                    f"{name}: current C authority signature mismatch for {symbol}: "
                    f"header={format_signature(expected)} C={format_signature(actual)}"
                )
            authority_parsed += 1

        total_declarations += len(declarations)
        total_exports += len(exports)

    securebits_symbols = PARTIAL_SURFACES["exit_status_securebits"][2]
    shared_securebits = dict(
        header_inventory(SHARED_EXIT_STATUS_HEADER, securebits_symbols)
    )
    basic_securebits = dict(
        header_inventory(
            PARTIAL_SURFACES["exit_status_securebits"][0],
            securebits_symbols,
        )
    )
    if shared_securebits != basic_securebits or set(shared_securebits) != securebits_symbols:
        return fail(
            "shared exit_status.h duplicate secure-bits declaration must exactly "
            "match the reviewed basic header signature"
        )

    exit_lookup_symbols = PARTIAL_SURFACES["exit_status_lookup"][2]
    shared_exit_lookup = dict(
        header_inventory(SHARED_EXIT_STATUS_HEADER, exit_lookup_symbols)
    )
    basic_exit_lookup = dict(
        header_inventory(
            PARTIAL_SURFACES["exit_status_lookup"][0],
            exit_lookup_symbols,
        )
    )
    if (
        shared_exit_lookup != basic_exit_lookup
        or set(shared_exit_lookup) != exit_lookup_symbols
    ):
        return fail(
            "shared exit_status.h duplicate lookup declarations must exactly "
            "match the reviewed basic header signatures"
        )

    if not allocator_boundary_is_c_compatible(SURFACES["devnum_util"][1]):
        return fail(
            "devnum_util C ABI formatting must be allocation-free and its device path must use one libc::malloc"
        )
    if not misc_inline_abi_boundary_is_reviewed():
        return fail(
            "misc inline ABI must use its self-contained header, fallible C-owned codec buffers, and allocation-free format facade"
        )
    if not misc_validator_registered_boundary_is_reviewed():
        return fail(
            "misc validator ABI must retain byte-oriented C-string policy, scalar cores, and canonical headers"
        )
    if not time_util_formatting_boundary_is_reviewed():
        return fail(
            "time formatting ABI must preserve target-width timezone parsing and allocation-free bounded timespan output"
        )
    if not devnum_parser_matches_current_c():
        return fail(
            "devnum_util must preserve safe_atou(base=0), normalized path components, and raw C bytes"
        )
    if not dns_type_predicates_boundary_is_reviewed():
        return fail(
            "dns_type_predicates must match current C signatures, negative errno, exhaustive scalar domains, and borrowed static strings"
        )
    if not iovec_authority_is_current():
        return fail("iovec C ABI no longer matches iovec_inc_many() or its self-contained header/test surface")
    if not in_addr_util_boundary_is_reviewed():
        return fail(
            "in_addr_util must keep every mirror-header declaration behind the audited C forwarding ABI, "
            "with C allocator ownership and boundary/error comparison coverage"
        )
    if not ether_addr_util_boundary_is_reviewed():
        return fail(
            "ether_addr_util must keep every fixed-layout shadow declaration behind an audited C ABI facade, "
            "with byte-oriented parsing and registered C comparison coverage"
        )
    if not user_util_boundary_is_reviewed():
        return fail(
            "user_util C ABI must remain allocation-free, NULL-correct, byte-oriented, and self-contained"
        )
    if not image_name_boundary_is_reviewed():
        return fail(
            "image-name ABI must preserve byte-level UTF-8 validation and borrowed os-release name storage"
        )
    if not escape_boundary_is_reviewed():
        return fail(
            "escape ABI must preserve checked byte lengths, current UTF-8 byte policy, C allocation ownership, and fail-closed pointers"
        )
    if not header_inline_boundary_is_reviewed():
        return fail(
            "header inline ABI must use safe UTF/path/terminal cores, exact self-contained headers, and registered edge comparisons"
        )
    if not path_byte_abi_boundary_is_reviewed():
        return fail(
            "path byte ABI must preserve component bytes/cursors, borrowed offsets, in-place writes, native O_DIRECTORY, and C allocator ownership"
        )
    if not gpt_unit_install_predicates_are_reviewed():
        return fail(
            "GPT/unit/install inline ABI must preserve raw enum handling, native GPT layout, exact sets, and canonical headers/tests"
        )
    if not strv_escape_and_fnmatch_boundary_is_reviewed():
        return fail(
            "strv escape/fnmatch ABI must preserve libc flags, ordered sentinel handling, C allocation ownership, and no-rollback replacement"
        )
    if not strv_extend_and_filter_boundary_is_reviewed():
        return fail(
            "strv extend/filter ABI must preserve byte prefixes, C allocation ownership, duplicate order, and rollback semantics"
        )
    if not strv_registered_boundary_is_reviewed():
        return fail(
            "registered strv ABI must preserve C allocation ownership, push/consume distinction, "
            "transactional publication, byte-exact joining, and canonical shared headers"
        )
    if not string_mutation_registered_boundary_is_reviewed():
        return fail(
            "registered string mutation/inline ABI must preserve byte mutation, empty-vs-NULL sets, "
            "output ownership, explicit-separator splitting, runtime signal constants, and canonical headers"
        )
    if not udev_util_boundary_is_reviewed():
        return fail(
            "udev_util must preserve bounded/in-place whitespace, byte-oriented UTF-8, malformed \\\\x, and C-string ownership semantics"
        )
    if not alloc_util_boundary_is_reviewed():
        return fail(
            "alloc-util ABI must preserve checked C allocation, zero-length non-NULL results, suffix overflow, slot nulling, and free() ownership"
        )
    if not alloc_util_multiply_boundary_is_reviewed():
        return fail(
            "alloc-util multiply ABI must preserve checked C allocation, copy, suffix-NUL, and free() ownership"
        )
    if not basic_validators_boundary_is_reviewed():
        return fail(
            "basic_validators must use the real PidRef/libc ABI and preserve target-width overflow behavior"
        )
    if not errno_util_boundary_is_reviewed():
        return fail(
            "errno_util must preserve target libc classifiers, GNU strerror ownership, and fail-closed inputs"
        )
    if not percent_util_boundary_is_reviewed():
        return fail(
            "percent_util must preserve byte-level safe_atoi ordering, target-long overflow, and fail-closed C strings"
        )
    if not uid_configuration_is_authoritative():
        return fail(
            "uid_classification must receive every configurable range from Meson and reject stale C helpers"
        )
    if not unaligned_boundary_is_reviewed():
        return fail(
            "unaligned must expose exact void-pointer ABI with alignment-one fixed-byte copies"
        )
    if not safe_math_boundary_is_reviewed():
        return fail(
            "safe_math must preserve target-width unsigned-long alignment and current C overflow sentinels"
        )
    if not at_flags_boundary_is_reviewed():
        return fail(
            "at_flags_util must use target libc flags and fail closed without unwinding on contradictions"
        )
    if not ioprio_boundary_is_reviewed():
        return fail(
            "ioprio_util must mask packed level/hint data exactly like current Linux before class validation"
        )
    if not time_arithmetic_boundary_is_reviewed():
        return fail(
            "time_util arithmetic must keep C-compatible timestamps, exact saturation, and explicit NULL-safe pointer contracts"
        )
    if not install_change_boundary_is_reviewed():
        return fail(
            "install-change must use the canonical InstallChange C type, exact repr-C ABI, and a documented read-only pointer contract"
        )
    if not virt_boundary_is_reviewed():
        return fail(
            "virt must use one NUL-backed table and raw-int range predicates without invalid enum construction"
        )
    if not rlimit_boundary_is_reviewed():
        return fail(
            "rlimit_util must preserve systemd base-zero parsing, output-on-success, C allocation, and NULL-safe boundaries"
        )
    if not procfs_boundary_is_reviewed():
        return fail(
            "procfs_util must use canonical word/base-zero parsing, exact overflow errno, and output-on-success C ABI"
        )
    if not import_util_boundary_is_reviewed():
        return fail(
            "import_util must preserve byte-string URL/suffix rules, target NAME_MAX, libc allocation ownership, and canonical test/header coverage"
        )
    if not stat_verification_boundary_is_reviewed():
        return fail(
            "stat verification must preserve native stat/statx/mode/off/link widths, exact errno/path bytes, and canonical header/test coverage"
        )
    if not stat_inode_boundary_is_reviewed():
        return fail(
            "stat inode helpers must preserve native libc layouts, signed/native ordering, exact current-C names, and canonical header/test coverage"
        )
    if not stat_vfs_boundary_is_reviewed():
        return fail(
            "stat vfs helper must preserve native statvfs fields, wrapped overflow output ordering, errno propagation, and canonical header/test coverage"
        )
    if not stat_descriptor_boundary_is_reviewed():
        return fail(
            "stat descriptor verification must preserve fstatat flags, XAT roots, errno/type policy, and canonical header/test coverage"
        )
    if not stat_filesystem_boundary_is_reviewed():
        return fail(
            "stat filesystem adapters must preserve native statfs, filesystem groups, read-only policy, errno/output semantics, and canonical coverage"
        )
    if not stat_moderate_boundary_is_reviewed():
        return fail(
            "stat moderate helpers must preserve bounded getdents, hidden/backup policy, root chase, inline fs-type composition, proc errno, and canonical coverage"
        )
    if not stat_xstatx_boundary_is_reviewed():
        return fail(
            "stat xstatx must preserve native libc layout, mount-ID fallback, mandatory/optional masks, supported attributes, errno, and output ordering"
        )
    if not stat_inode_same_boundary_is_reviewed():
        return fail(
            "stat inode_same must preserve pinned paths, native file handles, unique/ordinary mount IDs, fatal/fallback errors, and final fstatat identity"
        )
    if not stat_inode_hash_boundary_is_reviewed():
        return fail(
            "stat inode hashes must preserve target-native field bytes/order, comparison conditionals, typed sentinels, and canonical SipHash state ABI"
        )
    bus_header = SURFACES["bus_type_util"][0].read_text()
    if "#include <sys/types.h>" not in bus_header or "const dev_t *" not in bus_header:
        return fail("bus_type_util dev_t comparison declaration must be self-contained and use dev_t")
    required_ci_tests = {
        test.stem
        for tests in (*SHADOW_TESTS.values(), *PARTIAL_SHADOW_TESTS.values())
        for test in tests
    }
    required_ci_tests.update(test.stem for test in CATALOG.ci_only_shadow_tests)
    required_ci_tests.update(
        {
            "test-ether-addr-util-rust",
            "test-seccomp-util-rust",
            "test-string-util-rust",
            "test-string-util-extra-rust",
            "test-string-util-extra2-rust",
            "test-string-util-extra7-rust",
            "test-escape-extra2-rust",
            "test-make-cstring-rust",
            "test-strreplace-rust",
        }
    )
    reviewed_job = re.search(
        r"^  rust-meson-reviewed-shadows:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        rust_ci,
        re.MULTILINE | re.DOTALL,
    )
    compile_step = (
        re.search(
            r"^\s{6}- name: Compile reviewed Rust shadow targets\n"
            r"(?P<body>.*?)(?=^\s{6}- name:|\Z)",
            reviewed_job.group("body"),
            re.MULTILINE | re.DOTALL,
        )
        if reviewed_job
        else None
    )
    run_step = (
        re.search(
            r"^\s{6}- name: Run reviewed C-versus-Rust comparisons\n"
            r"(?P<body>.*?)(?=^\s{6}- name:|\Z)",
            reviewed_job.group("body"),
            re.MULTILINE | re.DOTALL,
        )
        if reviewed_job
        else None
    )
    compile_command = (
        re.search(
            r"^\s+run:\s*>-\s*$\n(?P<command>(?:^\s{10,}\S.*(?:\n|\Z))+)",
            compile_step.group("body"),
            re.MULTILINE,
        )
        if compile_step
        else None
    )
    run_command = (
        re.search(
            r"^\s+run:\s*>-\s*$\n(?P<command>(?:^\s{10,}\S.*(?:\n|\Z))+)",
            run_step.group("body"),
            re.MULTILINE,
        )
        if run_step
        else None
    )
    compile_words = (
        re.findall(
            r"\b(?:systemd_basic_rs|test-[A-Za-z0-9_-]+)\b",
            compile_command.group("command"),
        )
        if compile_command
        else []
    )
    run_words = (
        re.findall(
            r"\b(?:systemd_basic_rs|test-[A-Za-z0-9_-]+)\b",
            run_command.group("command"),
        )
        if run_command
        else []
    )
    if (
        not reviewed_job
        or not compile_command
        or not run_command
        or "meson compile -C build-rust-reviewed" not in compile_command.group("command")
        or "meson test -C build-rust-reviewed" not in run_command.group("command")
        or "--no-rebuild" not in run_command.group("command")
        or "--print-errorlogs" not in run_command.group("command")
        or "#" in compile_command.group("command")
        or "#" in run_command.group("command")
        or Counter(compile_words)
        != Counter(["systemd_basic_rs", *required_ci_tests])
        or Counter(run_words) != Counter(required_ci_tests)
    ):
        return fail(
            "reviewed basic Rust ABI CI must compile exactly systemd_basic_rs plus "
            "the reviewed targets, then run each target exactly once"
        )

    print(
        "basic Rust ABI inventory: "
        f"declared={total_declarations} exported={total_exports} "
        f"signatures={total_declarations} duplicates=0 "
        f"C-authority-parsed={authority_parsed} C-authority-curated={authority_curated} "
        f"complete-surfaces={len(SURFACES)} reviewed-partial-surfaces={len(PARTIAL_SURFACES)} "
        f"meson-ci-tests={len(required_ci_tests)} allocator=libc "
        "devnum-authority=current iovec-authority=current user-authority=current "
        "uid-config=meson errno=target-libc unaligned=byte-copy validators=repr-C"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
