// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.nsflags; authority=src/shared/nsflags.c,src/shared/nsflags.h,src/basic/namespace-util.c,src/basic/namespace-util.h
//
// Namespace flag classification utilities. The Rust-facing helpers are pure
// computation; the narrow C ABI facade allocates owned output with libc so it
// remains compatible with C's free(3) and strv_free() ownership contracts.

use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::mem::size_of;
use std::ptr;

use crate::ffi;

// ── CLONE_* flag values from linux/sched.h ────────────────────────────────

pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWTIME: u64 = 0x00000080;

const EINVAL: c_int = -libc::EINVAL;
const ENOMEM: c_int = -libc::ENOMEM;

// ── Namespace info table ──────────────────────────────────────────────────
// Mirrors namespace_info[] from namespace-util.c. Only proc_name and
// clone_flag fields are needed for pure flag operations.

struct NamespaceInfo {
    proc_name: &'static str,
    proc_name_c: &'static [u8],
    clone_flag: u64,
}

static NAMESPACE_INFO: &[NamespaceInfo] = &[
    NamespaceInfo {
        proc_name: "cgroup",
        proc_name_c: b"cgroup\0",
        clone_flag: CLONE_NEWCGROUP,
    },
    NamespaceInfo {
        proc_name: "ipc",
        proc_name_c: b"ipc\0",
        clone_flag: CLONE_NEWIPC,
    },
    NamespaceInfo {
        proc_name: "net",
        proc_name_c: b"net\0",
        clone_flag: CLONE_NEWNET,
    },
    NamespaceInfo {
        proc_name: "mnt",
        proc_name_c: b"mnt\0",
        clone_flag: CLONE_NEWNS,
    },
    NamespaceInfo {
        proc_name: "pid",
        proc_name_c: b"pid\0",
        clone_flag: CLONE_NEWPID,
    },
    NamespaceInfo {
        proc_name: "user",
        proc_name_c: b"user\0",
        clone_flag: CLONE_NEWUSER,
    },
    NamespaceInfo {
        proc_name: "uts",
        proc_name_c: b"uts\0",
        clone_flag: CLONE_NEWUTS,
    },
    NamespaceInfo {
        proc_name: "time",
        proc_name_c: b"time\0",
        clone_flag: CLONE_NEWTIME,
    },
];

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful port of C namespace_single_flag_to_string().
/// Returns the proc_name for a single namespace flag, or None if not found.
pub fn namespace_single_flag_to_string(flag: u64) -> Option<&'static str> {
    NAMESPACE_INFO
        .iter()
        .find(|info| info.clone_flag == flag)
        .map(|info| info.proc_name)
}

/// Faithful port of C namespace_flags_to_strv().
/// Converts a flags bitmask to a Vec of proc_name strings.
pub fn namespace_flags_to_strv(flags: u64) -> Vec<String> {
    NAMESPACE_INFO
        .iter()
        .filter(|info| (flags & info.clone_flag) == info.clone_flag)
        .map(|info| info.proc_name.to_string())
        .collect()
}

/// Faithful port of C namespace_flags_to_string().
/// Converts a flags bitmask to a space-separated string.
/// Returns an empty string for flags == 0.
pub fn namespace_flags_to_string(flags: u64) -> String {
    let names = namespace_flags_to_strv(flags);
    names.join(" ")
}

/// Faithful port of C namespace_flags_from_string().
/// Parses C-whitespace-separated namespace proc_names into a flags bitmask.
/// Like `extract_first_word(..., NULL, 0)`, a backslash quotes the next byte.
/// Returns Err(-EINVAL) if any word is not a recognized namespace name.
pub fn namespace_flags_from_string(name: &str) -> Result<u64, i32> {
    namespace_flags_from_bytes(name.as_bytes())
}

/// Parse C's ASCII-whitespace-delimited namespace names without assuming
/// UTF-8. This is shared by the ordinary Rust API and the C ABI facade, so
/// non-UTF-8 C strings fail with `-EINVAL` rather than being lossy-decoded.
fn namespace_flags_from_bytes(name: &[u8]) -> Result<u64, i32> {
    let mut flags: u64 = 0;
    let mut offset = 0;

    while offset < name.len() {
        while offset < name.len() && c_whitespace(name[offset]) {
            offset += 1;
        }
        if offset == name.len() {
            break;
        }

        let word = parse_namespace_word(name, &mut offset)?;
        let found = NAMESPACE_INFO
            .iter()
            .find(|info| info.proc_name_c[..info.proc_name_c.len() - 1].eq(word));
        match found {
            Some(info) => flags |= info.clone_flag,
            None => return Err(EINVAL),
        }
    }

    Ok(flags)
}

/// Reproduce `extract_first_word(..., NULL, 0)` for this tiny fixed namespace
/// vocabulary. With zero flags, that C helper uses `WHITESPACE` (space, tab,
/// newline, and carriage return) as separators and strips a backslash before
/// the next byte.
fn parse_namespace_word<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], i32> {
    const MAX_NAMESPACE_NAME_LEN: usize = 6; // "cgroup"
    let mut word = [0; MAX_NAMESPACE_NAME_LEN];
    let mut length = 0usize;

    while *offset < input.len() {
        let mut byte = input[*offset];
        *offset += 1;
        if c_whitespace(byte) {
            break;
        }
        if byte == b'\\' {
            if *offset == input.len() {
                return Err(EINVAL);
            }
            byte = input[*offset];
            *offset += 1;
        }
        if length == MAX_NAMESPACE_NAME_LEN {
            return Err(EINVAL);
        }
        word[length] = byte;
        length += 1;
    }

    // The caller only needs equality against eight static ASCII names. Avoid
    // returning the stack buffer by mapping it immediately through the table.
    NAMESPACE_INFO
        .iter()
        .find(|info| info.proc_name_c[..info.proc_name_c.len() - 1].eq(&word[..length]))
        .map(|info| &info.proc_name_c[..info.proc_name_c.len() - 1])
        .ok_or(EINVAL)
}

#[inline]
const fn c_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

#[inline]
fn selected_by_c_flags(flags: c_ulong, info: &NamespaceInfo) -> bool {
    let clone_flag = info.clone_flag as c_ulong;
    (flags & clone_flag) == clone_flag
}

/// Allocate a NUL-terminated, space-separated namespace name list using the
/// C allocator. The caller owns the successful allocation with free(3).
fn allocate_namespace_string(flags: c_ulong) -> Result<*mut c_char, c_int> {
    let mut count = 0usize;
    let mut string_bytes = 0usize;
    for info in NAMESPACE_INFO {
        if selected_by_c_flags(flags, info) {
            count += 1;
            string_bytes = string_bytes
                .checked_add(info.proc_name_c.len() - 1)
                .ok_or(ENOMEM)?;
        }
    }

    let allocation_size = string_bytes
        .checked_add(count.saturating_sub(1))
        .and_then(|size| size.checked_add(1))
        .ok_or(ENOMEM)?;
    let allocation = ffi::malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return Err(ENOMEM);
    }

    // SAFETY: `allocation` owns `allocation_size` writable bytes. Every
    // source is immutable static storage; the calculated separators and final
    // NUL occupy exactly the remaining destination positions.
    unsafe {
        let mut cursor = allocation;
        let mut needs_separator = false;
        for info in NAMESPACE_INFO {
            if !selected_by_c_flags(flags, info) {
                continue;
            }
            if needs_separator {
                *cursor = b' ';
                cursor = cursor.add(1);
            }
            let name = &info.proc_name_c[..info.proc_name_c.len() - 1];
            ptr::copy_nonoverlapping(name.as_ptr(), cursor, name.len());
            cursor = cursor.add(name.len());
            needs_separator = true;
        }
        *cursor = 0;
    }

    Ok(allocation.cast::<c_char>())
}

/// Free the partially-populated C `char **` allocation constructed below.
///
/// # Safety
///
/// `vector` must be the C-allocator vector returned by `calloc`, and its
/// first `populated` elements must be unique C-allocator string bases.
unsafe fn free_partial_namespace_strv(vector: *mut *mut c_char, populated: usize) {
    for index in 0..populated {
        // SAFETY: guaranteed by this helper's contract and the construction
        // loop in `allocate_namespace_strv`.
        unsafe { ffi::free((*vector.add(index)).cast::<c_void>()) };
    }
    // SAFETY: `vector` is the owning C-allocator base pointer.
    unsafe { ffi::free(vector.cast::<c_void>()) };
}

/// Allocate a NULL-terminated C string vector using the C allocator for both
/// the vector and every element, exactly matching `strv_extend()` ownership.
fn allocate_namespace_strv(flags: c_ulong) -> Result<*mut *mut c_char, c_int> {
    let count = NAMESPACE_INFO
        .iter()
        .filter(|info| selected_by_c_flags(flags, info))
        .count();
    if count == 0 {
        return Ok(ptr::null_mut());
    }

    let vector_bytes = count
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<*mut c_char>()))
        .ok_or(ENOMEM)?;
    let vector = ffi::calloc(1, vector_bytes).cast::<*mut c_char>();
    if vector.is_null() {
        return Err(ENOMEM);
    }

    let mut index = 0usize;
    for info in NAMESPACE_INFO {
        if !selected_by_c_flags(flags, info) {
            continue;
        }

        let string = ffi::malloc(info.proc_name_c.len()).cast::<c_char>();
        if string.is_null() {
            // SAFETY: the preceding loop iterations populated exactly
            // `index` slots of the C-allocator vector.
            unsafe { free_partial_namespace_strv(vector, index) };
            return Err(ENOMEM);
        }
        // SAFETY: `string` owns exactly proc_name_c.len() writable bytes and
        // the source is static NUL-terminated storage of that same length.
        unsafe {
            ptr::copy_nonoverlapping(
                info.proc_name_c.as_ptr().cast::<c_char>(),
                string,
                info.proc_name_c.len(),
            );
            *vector.add(index) = string;
        }
        index += 1;
    }

    Ok(vector)
}

/// C ABI facade for `namespace_single_flag_to_string()`.
///
/// The result borrows immutable process-lifetime storage and must not be
/// freed. Unknown or combined flags return NULL.
#[unsafe(no_mangle)]
pub extern "C" fn rs_namespace_single_flag_to_string(flag: c_ulong) -> *const c_char {
    NAMESPACE_INFO
        .iter()
        .find(|info| info.clone_flag as c_ulong == flag)
        .map_or(ptr::null(), |info| {
            info.proc_name_c.as_ptr().cast::<c_char>()
        })
}

/// C ABI facade for `namespace_flags_to_strv()`.
///
/// A successful non-empty result is a NULL-terminated string vector whose
/// strings and vector base all come from libc allocation; C callers must
/// release it with `strv_free()`. Empty flags produce a NULL vector, matching
/// C's empty strv representation.
///
/// # Safety
///
/// `ret` must point to writable `char **` storage. On success it receives the
/// owned allocation; on error its prior value is unchanged. NULL is outside
/// the C API's asserted precondition and fails closed with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_namespace_flags_to_strv(
    flags: c_ulong,
    ret: *mut *mut *mut c_char,
) -> c_int {
    if ret.is_null() {
        return EINVAL;
    }

    match allocate_namespace_strv(flags) {
        Ok(vector) => {
            // SAFETY: `ret` is non-NULL and the entry point contract requires
            // writable storage for one char** result.
            unsafe { *ret = vector };
            0
        }
        Err(error) => error,
    }
}

/// C ABI facade for `namespace_flags_to_string()`.
///
/// On success the caller owns a fresh libc allocation and must release it
/// with free(3). The empty flag set returns an allocated empty string.
///
/// # Safety
///
/// `ret` must point to writable `char *` storage. On error its prior value is
/// unchanged. NULL is outside C's asserted precondition and fails closed with
/// `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_namespace_flags_to_string(
    flags: c_ulong,
    ret: *mut *mut c_char,
) -> c_int {
    if ret.is_null() {
        return EINVAL;
    }

    match allocate_namespace_string(flags) {
        Ok(string) => {
            // SAFETY: `ret` is non-NULL and the entry point contract requires
            // writable storage for one char* result.
            unsafe { *ret = string };
            0
        }
        Err(error) => error,
    }
}

/// C ABI facade for `namespace_flags_from_string()`.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated C string and `ret` must
/// point to writable unsigned-long storage. On error `ret` remains unchanged.
/// A NULL argument is outside C's asserted precondition and returns
/// `-EINVAL` without dereferencing either pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_namespace_flags_from_string(
    name: *const c_char,
    ret: *mut c_ulong,
) -> c_int {
    if name.is_null() || ret.is_null() {
        return EINVAL;
    }

    // SAFETY: guaranteed by this entry point's documented C-string contract.
    let parsed = unsafe { namespace_flags_from_bytes(CStr::from_ptr(name).to_bytes()) };
    match parsed {
        Ok(flags) => {
            // SAFETY: guaranteed by this entry point's documented output
            // pointer contract; the write occurs only after successful parse.
            unsafe { *ret = flags as c_ulong };
            0
        }
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── namespace_single_flag_to_string tests ──────────────────────────

    #[test]
    fn test_single_flag_to_string_known() {
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWNS), Some("mnt"));
        assert_eq!(
            namespace_single_flag_to_string(CLONE_NEWCGROUP),
            Some("cgroup")
        );
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWUTS), Some("uts"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWIPC), Some("ipc"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWUSER), Some("user"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWPID), Some("pid"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWNET), Some("net"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWTIME), Some("time"));
    }

    #[test]
    fn test_single_flag_to_string_unknown() {
        assert_eq!(namespace_single_flag_to_string(0), None);
        assert_eq!(namespace_single_flag_to_string(0xFFFFFFFF), None);
        assert_eq!(namespace_single_flag_to_string(1), None);
    }

    #[test]
    fn test_single_flag_to_string_combined_flags() {
        let combined = CLONE_NEWNS | CLONE_NEWNET;
        assert_eq!(namespace_single_flag_to_string(combined), None);
    }

    // ── namespace_flags_to_strv tests ──────────────────────────────────

    #[test]
    fn test_flags_to_strv_empty() {
        let result = namespace_flags_to_strv(0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_flags_to_strv_single() {
        let result = namespace_flags_to_strv(CLONE_NEWNS);
        assert_eq!(result, vec!["mnt"]);
    }

    #[test]
    fn test_flags_to_strv_multiple() {
        let flags = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID;
        let result = namespace_flags_to_strv(flags);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"mnt".to_string()));
        assert!(result.contains(&"net".to_string()));
        assert!(result.contains(&"pid".to_string()));
    }

    #[test]
    fn test_flags_to_strv_all_flags() {
        let flags = CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET
            | CLONE_NEWTIME;
        let result = namespace_flags_to_strv(flags);
        assert_eq!(result.len(), 8);
    }

    // ── namespace_flags_to_string tests ────────────────────────────────

    #[test]
    fn test_flags_to_string_empty() {
        let result = namespace_flags_to_string(0);
        assert_eq!(result, "");
    }

    #[test]
    fn test_flags_to_string_single() {
        let result = namespace_flags_to_string(CLONE_NEWNS);
        assert_eq!(result, "mnt");
    }

    #[test]
    fn test_flags_to_string_multiple() {
        let flags = CLONE_NEWNS | CLONE_NEWNET;
        let result = namespace_flags_to_string(flags);
        let parts: Vec<&str> = result.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts.contains(&"mnt"));
        assert!(parts.contains(&"net"));
    }

    #[test]
    fn test_flags_to_string_all() {
        let flags = CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET
            | CLONE_NEWTIME;
        let result = namespace_flags_to_string(flags);
        let parts: Vec<&str> = result.split(' ').collect();
        assert_eq!(parts.len(), 8);
    }

    // ── namespace_flags_from_string tests ──────────────────────────────

    #[test]
    fn test_flags_from_string_single() {
        assert_eq!(namespace_flags_from_string("mnt"), Ok(CLONE_NEWNS));
    }

    #[test]
    fn test_flags_from_string_all_names() {
        let tests = [
            ("cgroup", CLONE_NEWCGROUP),
            ("ipc", CLONE_NEWIPC),
            ("net", CLONE_NEWNET),
            ("mnt", CLONE_NEWNS),
            ("pid", CLONE_NEWPID),
            ("user", CLONE_NEWUSER),
            ("uts", CLONE_NEWUTS),
            ("time", CLONE_NEWTIME),
        ];
        for (name, expected) in tests {
            assert_eq!(
                namespace_flags_from_string(name),
                Ok(expected),
                "Failed for {name}"
            );
        }
    }

    #[test]
    fn test_flags_from_string_multiple() {
        assert_eq!(
            namespace_flags_from_string("mnt net pid"),
            Ok(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID)
        );
    }

    #[test]
    fn test_flags_from_string_with_extra_spaces() {
        assert_eq!(
            namespace_flags_from_string("  mnt   net  "),
            Ok(CLONE_NEWNS | CLONE_NEWNET)
        );
    }

    #[test]
    fn test_flags_from_string_uses_c_whitespace() {
        assert_eq!(
            namespace_flags_from_string("\tmnt\nnet\ruser "),
            Ok(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER)
        );
        assert_eq!(namespace_flags_from_string("mnt\u{b}net"), Err(EINVAL));
        assert_eq!(namespace_flags_from_string("mnt\u{c}net"), Err(EINVAL));
    }

    #[test]
    fn test_flags_from_string_empty() {
        assert_eq!(namespace_flags_from_string(""), Ok(0));
    }

    #[test]
    fn test_flags_from_string_invalid() {
        assert!(namespace_flags_from_string("unknown").is_err());
    }

    #[test]
    fn test_flags_from_string_partial_invalid() {
        assert!(namespace_flags_from_string("mnt bogus").is_err());
    }

    // ── roundtrip test ─────────────────────────────────────────────────

    #[test]
    fn test_flags_roundtrip() {
        let original = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID;
        let s = namespace_flags_to_string(original);
        let parsed = namespace_flags_from_string(&s).unwrap();
        assert_eq!(parsed, original);
    }
}
