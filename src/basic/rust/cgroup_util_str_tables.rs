// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/cgroup-util.c (string table subset)
//
// CGroup string table lookups, mask conversion, and escape helpers.
//
// Provides bidirectional mapping between C enum values and string names
// for IO limit types, controllers, OOM modes, and OOM preferences.
// Also includes cg_needs_escape/cg_unescape for cgroup name escaping.

// ── Error constant ────────────────────────────────────────────────────────

const EINVAL: i32 = -libc::EINVAL;
const ENOMEM: i32 = -libc::ENOMEM;

use libc::c_char;
use std::ffi::CStr;
use std::ptr;

use crate::ffi_string_table::{self, Entry as FfiEntry};

// ── Tables ────────────────────────────────────────────────────────────────

/// cgroup_io_limit_type: RBPS_MAX=0, WBPS_MAX=1, RIOPS_MAX=2, WIOPS_MAX=3
static CGROUP_IO_LIMIT_TYPE_TABLE: &[FfiEntry] = &[
    (0, b"IOReadBandwidthMax\0"),
    (1, b"IOWriteBandwidthMax\0"),
    (2, b"IOReadIOPSMax\0"),
    (3, b"IOWriteIOPSMax\0"),
];

/// cgroup_controller: CPU=0..BPF_BIND_NETWORK_INTERFACE=13
static CGROUP_CONTROLLER_TABLE: &[FfiEntry] = &[
    (0, b"cpu\0"),
    (1, b"cpuacct\0"),
    (2, b"cpuset\0"),
    (3, b"io\0"),
    (4, b"blkio\0"),
    (5, b"memory\0"),
    (6, b"devices\0"),
    (7, b"pids\0"),
    (8, b"bpf-firewall\0"),
    (9, b"bpf-devices\0"),
    (10, b"bpf-foreign\0"),
    (11, b"bpf-socket-bind\0"),
    (12, b"bpf-restrict-network-interfaces\0"),
    (13, b"bpf-bind-network-interface\0"),
];

/// managed_oom_mode: AUTO=0, KILL=1
static MANAGED_OOM_MODE_TABLE: &[FfiEntry] = &[(0, b"auto\0"), (1, b"kill\0")];

/// managed_oom_preference: NONE=0, AVOID=1, OMIT=2
static MANAGED_OOM_PREFERENCE_TABLE: &[FfiEntry] =
    &[(0, b"none\0"), (1, b"avoid\0"), (2, b"omit\0")];

const CGROUP_CONTROLLER_MAX: usize = 14;

/// Special cgroup names that must be escaped.
static CGROUP_SPECIAL: &[&str] = &["notify_on_release", "release_agent", "tasks"];

// ── Generic table helpers ─────────────────────────────────────────────────

fn table_to_string(table: &'static [FfiEntry], v: i32) -> Option<&'static str> {
    ffi_string_table::to_str(table, v)
}

fn table_from_string(table: &'static [FfiEntry], s: &str) -> Result<i32, i32> {
    ffi_string_table::from_str(table, s).ok_or(EINVAL)
}

// ── IO limit type ─────────────────────────────────────────────────────────

pub fn cgroup_io_limit_type_to_string(v: i32) -> Option<&'static str> {
    table_to_string(CGROUP_IO_LIMIT_TYPE_TABLE, v)
}

pub fn cgroup_io_limit_type_from_string(s: &str) -> Result<i32, i32> {
    table_from_string(CGROUP_IO_LIMIT_TYPE_TABLE, s)
}

// ── Controller ────────────────────────────────────────────────────────────

pub fn cgroup_controller_to_string(v: i32) -> Option<&'static str> {
    table_to_string(CGROUP_CONTROLLER_TABLE, v)
}

pub fn cgroup_controller_from_string(s: &str) -> Result<i32, i32> {
    table_from_string(CGROUP_CONTROLLER_TABLE, s)
}

// ── Managed OOM mode ──────────────────────────────────────────────────────

pub fn managed_oom_mode_to_string(v: i32) -> Option<&'static str> {
    table_to_string(MANAGED_OOM_MODE_TABLE, v)
}

pub fn managed_oom_mode_from_string(s: &str) -> Result<i32, i32> {
    table_from_string(MANAGED_OOM_MODE_TABLE, s)
}

// ── Managed OOM preference ────────────────────────────────────────────────

pub fn managed_oom_preference_to_string(v: i32) -> Option<&'static str> {
    table_to_string(MANAGED_OOM_PREFERENCE_TABLE, v)
}

pub fn managed_oom_preference_from_string(s: &str) -> Result<i32, i32> {
    table_from_string(MANAGED_OOM_PREFERENCE_TABLE, s)
}

// ── Filename validation ───────────────────────────────────────────────────

/// Check if a byte sequence is a valid filename (no '/' or NUL, not "." or "..").
fn filename_is_valid(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    if p == "." || p == ".." {
        return false;
    }
    !p.bytes().any(|b| b == b'/' || b == b'\0')
}

// ── cg_needs_escape ───────────────────────────────────────────────────────

/// Check if a cgroup name needs escaping.
///
/// Names need escaping if they start with '_' or '.', match special names,
/// start with "cgroup.", or start with a controller name followed by '.'.
pub fn cg_needs_escape(p: &str) -> bool {
    if p.is_empty() {
        return true;
    }
    if !filename_is_valid(p) {
        return true;
    }
    let first = p.as_bytes()[0];
    if first == b'_' || first == b'.' {
        return true;
    }
    for special in CGROUP_SPECIAL {
        if p == *special {
            return true;
        }
    }
    if p.starts_with("cgroup.") {
        return true;
    }
    for c in 0..CGROUP_CONTROLLER_MAX {
        if let Some(name) = cgroup_controller_to_string(c as i32) {
            if p.starts_with(name) && p.as_bytes().get(name.len()) == Some(&b'.') {
                return true;
            }
        }
    }
    false
}

// ── cg_unescape ───────────────────────────────────────────────────────────

/// Unescape a cgroup name by stripping a leading underscore.
pub fn cg_unescape(p: &str) -> &str {
    if p.starts_with('_') { &p[1..] } else { p }
}

// ── C ABI facade ─────────────────────────────────────────────────────────
//
// The ordinary Rust API intentionally uses `&str`.  The C boundary must not:
// Cgroup names are byte strings, and valid non-UTF-8 names must retain the
// same behavior as the C implementation.  These small tables are NUL-backed
// process-lifetime literals, never Rust `&str` pointers.

macro_rules! ffi_string_table {
    ($to_fn:ident, $from_fn:ident, $table:ident) => {
        /// C ABI facade returning a borrowed process-lifetime C string, or NULL.
        #[unsafe(no_mangle)]
        pub extern "C" fn $to_fn(value: i32) -> *const c_char {
            ffi_string_table::to_ptr($table, value)
        }

        /// C ABI facade.
        ///
        /// # Safety
        ///
        /// `input` must be null or point to a live NUL-terminated C string
        /// for the duration of this call; ownership remains with C.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $from_fn(input: *const c_char) -> i32 {
            // SAFETY: this is the documented precondition of this C entry point.
            unsafe { ffi_string_table::from_ptr($table, input, EINVAL) }
        }
    };
}

ffi_string_table!(
    rs_cgroup_io_limit_type_to_string,
    rs_cgroup_io_limit_type_from_string,
    CGROUP_IO_LIMIT_TYPE_TABLE
);
ffi_string_table!(
    rs_cgroup_controller_to_string,
    rs_cgroup_controller_from_string,
    CGROUP_CONTROLLER_TABLE
);
ffi_string_table!(
    rs_managed_oom_mode_to_string,
    rs_managed_oom_mode_from_string,
    MANAGED_OOM_MODE_TABLE
);
ffi_string_table!(
    rs_managed_oom_preference_to_string,
    rs_managed_oom_preference_from_string,
    MANAGED_OOM_PREFERENCE_TABLE
);

/// Exact byte-oriented C ABI facade for `cg_needs_escape`.
///
/// # Safety
///
/// `input` must be null or point to a live NUL-terminated C string for this
/// call. The function borrows it only; ownership remains with C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cg_needs_escape(input: *const c_char) -> bool {
    if input.is_null() {
        return true;
    }

    // SAFETY: `input` is non-null and this C ABI requires a live C string.
    if !unsafe { crate::path_util::rs_filename_is_valid(input) } {
        return true;
    }
    // SAFETY: `input` is non-null and this C ABI requires a live C string.
    let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    if matches!(bytes.first(), Some(b'_' | b'.')) {
        return true;
    }
    if matches!(bytes, b"notify_on_release" | b"release_agent" | b"tasks")
        || bytes.starts_with(b"cgroup.")
    {
        return true;
    }

    CGROUP_CONTROLLER_TABLE.iter().any(|&(_, controller)| {
        let controller = ffi_string_table::entry_cstr(controller).to_bytes();
        bytes
            .strip_prefix(controller)
            .is_some_and(|suffix| suffix.starts_with(b"."))
    })
}

/// Borrowed-pointer facade for `cg_unescape`; it never allocates or frees.
/// The mutable pointer type matches C's historical signature but does not
/// grant ownership of, or extend the mutability contract for, the input.
///
/// # Safety
///
/// `input` must be null or point to a live NUL-terminated C string. A
/// non-null result borrows that same allocation, possibly one byte into it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cg_unescape(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: this C ABI requires `input` to point to a live C string. A
    // leading underscore necessarily has an in-bounds successor (at least NUL).
    if unsafe { *input } == b'_' as c_char {
        // SAFETY: explained above; we only return a borrowed interior pointer.
        unsafe { input.add(1) }.cast_mut()
    } else {
        input.cast_mut()
    }
}

// ── cg_mask_to_string ─────────────────────────────────────────────────────

/// Convert a CGroupMask bitmask to a space-separated string of controller names.
pub fn cg_mask_to_string(mask: u32) -> Option<String> {
    if mask == 0 {
        return None;
    }

    let mut parts: Vec<&str> = Vec::new();
    for &(idx, name) in CGROUP_CONTROLLER_TABLE {
        if (idx as usize) >= CGROUP_CONTROLLER_MAX || idx < 0 {
            continue;
        }
        let controller_mask = 1u32 << (idx as u32);
        if (mask & controller_mask) != 0 {
            parts.push(ffi_string_table::entry_str(name));
        }
    }

    if parts.is_empty() {
        return None;
    }

    Some(parts.join(" "))
}

// ── cg_mask_from_string ───────────────────────────────────────────────────

/// Convert a space-separated string of controller names to a CGroupMask bitmask.
/// Unknown names are silently ignored.
pub fn cg_mask_from_string(s: &str) -> u32 {
    let mut mask: u32 = 0;

    for word in s.split(|c: char| c == ' ' || c == '\t') {
        if word.is_empty() {
            continue;
        }
        if let Ok(idx) = cgroup_controller_from_string(word) {
            if idx >= 0 && (idx as usize) < CGROUP_CONTROLLER_MAX {
                mask |= 1u32 << (idx as u32);
            }
        }
    }

    mask
}

// ── Allocation-owning cgroup helpers ─────────────────────────────────────
//
// `cgroup-util.c` returns strings that are released by the C caller with
// `free(3)`.  Keep that allocator boundary here rather than exposing Rust
// allocation provenance across the ABI.  The parsing and formatting logic
// itself remains ordinary safe Rust over byte slices.

fn c_malloc_string(bytes: &[u8]) -> Result<*mut c_char, i32> {
    let allocation = bytes.len().checked_add(1).ok_or(ENOMEM)?;
    let output = crate::ffi::malloc(allocation).cast::<c_char>();
    if output.is_null() {
        return Err(ENOMEM);
    }

    // SAFETY: `malloc` above returned `bytes.len() + 1` writable bytes. The
    // source is a live Rust slice and the ranges do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), bytes.len());
        *output.add(bytes.len()) = 0;
    }
    Ok(output)
}

fn cgroup_mask_to_bytes(mask: u32) -> Result<Option<Vec<u8>>, i32> {
    if mask == 0 {
        return Ok(None);
    }

    let capacity = CGROUP_CONTROLLER_TABLE
        .iter()
        .map(|(_, name)| name.len())
        .sum::<usize>();
    let mut output = Vec::new();
    output.try_reserve(capacity).map_err(|_| ENOMEM)?;
    for &(index, name) in CGROUP_CONTROLLER_TABLE {
        let controller_mask = 1_u32 << index;
        if mask & controller_mask == 0 {
            continue;
        }

        if !output.is_empty() {
            output.push(b' ');
        }
        // Every table literal is a C string. Drop only its trailing NUL.
        output.extend_from_slice(&name[..name.len() - 1]);
    }

    // C asserts here for a nonzero mask which contains no valid controller
    // bit. Treat that violated API precondition as a recoverable EINVAL at the
    // Rust boundary rather than returning a null string which C would never.
    if output.is_empty() {
        return Err(EINVAL);
    }
    Ok(Some(output))
}

/// Parse one `extract_first_word(..., NULL, 0)` word without converting the
/// C byte string to UTF-8. With flags zero, quotes are ordinary bytes and a
/// backslash quotes exactly the following byte; a final backslash is EINVAL.
fn next_default_word(input: &[u8], mut offset: usize) -> Result<Option<(Vec<u8>, usize)>, i32> {
    const WHITESPACE: &[u8] = b" \t\n\r";

    while offset < input.len() && WHITESPACE.contains(&input[offset]) {
        offset += 1;
    }
    if offset == input.len() {
        return Ok(None);
    }

    let mut word = Vec::new();
    word.try_reserve(input.len() - offset).map_err(|_| ENOMEM)?;
    while offset < input.len() && !WHITESPACE.contains(&input[offset]) {
        if input[offset] == b'\\' {
            offset += 1;
            if offset == input.len() {
                return Err(EINVAL);
            }
        }
        word.push(input[offset]);
        offset += 1;
    }

    while offset < input.len() && WHITESPACE.contains(&input[offset]) {
        offset += 1;
    }
    Ok(Some((word, offset)))
}

fn cgroup_mask_from_bytes(input: &[u8]) -> Result<u32, i32> {
    let mut mask = 0_u32;
    let mut offset = 0;
    while let Some((word, next)) = next_default_word(input, offset)? {
        if let Some(&(index, _)) = CGROUP_CONTROLLER_TABLE
            .iter()
            .find(|(_, name)| name.get(..name.len() - 1) == Some(word.as_slice()))
        {
            mask |= 1_u32 << index;
        }
        offset = next;
    }
    Ok(mask)
}

/// C ABI for `cg_mask_to_string()`.
///
/// # Safety
/// `ret` must be a non-null writable `char **`. On success, the non-null
/// result is allocated by the process C allocator and is owned by the caller,
/// which must release it with `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cg_mask_to_string(mask: u32, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return EINVAL;
    }

    let bytes = match cgroup_mask_to_bytes(mask) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // SAFETY: `ret` was checked non-null and is writable by contract.
            unsafe { *ret = ptr::null_mut() };
            return 0;
        }
        Err(error) => return error,
    };
    let output = match c_malloc_string(&bytes) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` was checked non-null and is writable by contract. `output`
    // is a live C-allocator allocation transferred to the caller.
    unsafe { *ret = output };
    0
}

/// C ABI for `cg_mask_from_string()`.
///
/// # Safety
/// `input` must be a non-null live NUL-terminated C string and `ret` must be
/// a non-null writable `unsigned int *`. `*ret` is changed only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cg_mask_from_string(input: *const c_char, ret: *mut u32) -> i32 {
    if input.is_null() || ret.is_null() {
        return EINVAL;
    }
    // SAFETY: `input` is non-null and the C ABI contract requires a live
    // NUL-terminated string for the duration of this call.
    let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    let mask = match cgroup_mask_from_bytes(bytes) {
        Ok(mask) => mask,
        Err(error) => return error,
    };
    // SAFETY: `ret` was checked non-null and is writable by contract.
    unsafe { *ret = mask };
    0
}

/// C ABI for `cg_split_spec()`.
///
/// # Safety
/// `spec` must be a non-null live NUL-terminated C string. Each non-null
/// output pointer must be writable for one pointer. Successful non-null
/// outputs are C-allocator allocations owned by the caller and released with
/// `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cg_split_spec(
    spec: *const c_char,
    ret_controller: *mut *mut c_char,
    ret_path: *mut *mut c_char,
) -> i32 {
    if spec.is_null() {
        return EINVAL;
    }
    // SAFETY: `spec` is non-null and the C ABI contract requires a live
    // NUL-terminated string for the duration of this call.
    let bytes = unsafe { CStr::from_ptr(spec) }.to_bytes();

    let (controller, path_offset) = if bytes.is_empty() || bytes[0] == b'/' {
        (None, None)
    } else if let Some(colon) = bytes.iter().position(|&byte| byte == b':') {
        (Some(&bytes[..colon]), Some(colon + 1))
    } else {
        (Some(bytes), None)
    };

    // C allocates the optional controller before it validates the path, so
    // retain that error precedence and clean it up on all later failures.
    let controller_copy = if !ret_controller.is_null() {
        match controller {
            Some(controller) => match c_malloc_string(controller) {
                Ok(copy) => copy,
                Err(error) => return error,
            },
            None => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    };

    let path = path_offset.and_then(|offset| (!bytes[offset..].is_empty()).then_some(offset));
    let path = path.or_else(|| (!bytes.is_empty() && bytes[0] == b'/').then_some(0));
    if let Some(offset) = path {
        // SAFETY: `offset` is within the C string bytes, so this derives a
        // pointer to a NUL-terminated suffix of the same live allocation.
        let path_ptr = unsafe { spec.add(offset) };
        // SAFETY: `path_ptr` is the validated live C-string suffix above.
        if !unsafe { crate::path_util::rs_path_is_absolute(path_ptr) }
            // SAFETY: same live C-string suffix as above.
            || !unsafe { crate::path_util::rs_path_is_safe(path_ptr) }
        {
            // SAFETY: this temporary was allocated by the C allocator above.
            unsafe { crate::ffi::free(controller_copy.cast()) };
            return EINVAL;
        }
    }

    if !ret_path.is_null() {
        let result = if let Some(offset) = path {
            // SAFETY: as above, `offset` addresses a NUL-terminated suffix;
            // `ret_path` is writable by this FFI function's contract.
            unsafe { crate::path_util::rs_path_simplify_alloc(spec.add(offset), ret_path) }
        } else {
            // SAFETY: `ret_path` is writable by this FFI function's contract.
            unsafe { *ret_path = ptr::null_mut() };
            0
        };
        if result < 0 {
            // SAFETY: this temporary was allocated by the C allocator above.
            unsafe { crate::ffi::free(controller_copy.cast()) };
            return result;
        }
    }

    if !ret_controller.is_null() {
        // SAFETY: `ret_controller` is writable by the FFI contract; ownership
        // of the C allocation (or null) transfers to the caller.
        unsafe { *ret_controller = controller_copy };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_io_limit_type_to_string_valid() {
        assert_eq!(
            cgroup_io_limit_type_to_string(0),
            Some("IOReadBandwidthMax")
        );
        assert_eq!(
            cgroup_io_limit_type_to_string(1),
            Some("IOWriteBandwidthMax")
        );
        assert_eq!(cgroup_io_limit_type_to_string(2), Some("IOReadIOPSMax"));
        assert_eq!(cgroup_io_limit_type_to_string(3), Some("IOWriteIOPSMax"));
    }

    #[test]
    fn test_cgroup_io_limit_type_to_string_invalid() {
        assert_eq!(cgroup_io_limit_type_to_string(-1), None);
        assert_eq!(cgroup_io_limit_type_to_string(4), None);
        assert_eq!(cgroup_io_limit_type_to_string(99), None);
    }

    #[test]
    fn test_cgroup_io_limit_type_from_string_valid() {
        assert_eq!(
            cgroup_io_limit_type_from_string("IOReadBandwidthMax"),
            Ok(0)
        );
        assert_eq!(
            cgroup_io_limit_type_from_string("IOWriteBandwidthMax"),
            Ok(1)
        );
        assert_eq!(cgroup_io_limit_type_from_string("IOReadIOPSMax"), Ok(2));
        assert_eq!(cgroup_io_limit_type_from_string("IOWriteIOPSMax"), Ok(3));
    }

    #[test]
    fn test_cgroup_io_limit_type_from_string_invalid() {
        assert!(cgroup_io_limit_type_from_string("invalid").is_err());
        assert!(cgroup_io_limit_type_from_string("").is_err());
    }

    #[test]
    fn test_cgroup_controller_to_string_valid() {
        assert_eq!(cgroup_controller_to_string(0), Some("cpu"));
        assert_eq!(cgroup_controller_to_string(1), Some("cpuacct"));
        assert_eq!(cgroup_controller_to_string(3), Some("io"));
        assert_eq!(cgroup_controller_to_string(5), Some("memory"));
        assert_eq!(cgroup_controller_to_string(7), Some("pids"));
        assert_eq!(
            cgroup_controller_to_string(13),
            Some("bpf-bind-network-interface")
        );
    }

    #[test]
    fn test_cgroup_controller_to_string_invalid() {
        assert_eq!(cgroup_controller_to_string(-1), None);
        assert_eq!(cgroup_controller_to_string(14), None);
        assert_eq!(cgroup_controller_to_string(99), None);
    }

    #[test]
    fn test_cgroup_controller_from_string_all() {
        assert_eq!(cgroup_controller_from_string("cpu"), Ok(0));
        assert_eq!(cgroup_controller_from_string("cpuacct"), Ok(1));
        assert_eq!(cgroup_controller_from_string("cpuset"), Ok(2));
        assert_eq!(cgroup_controller_from_string("io"), Ok(3));
        assert_eq!(cgroup_controller_from_string("blkio"), Ok(4));
        assert_eq!(cgroup_controller_from_string("memory"), Ok(5));
        assert_eq!(cgroup_controller_from_string("devices"), Ok(6));
        assert_eq!(cgroup_controller_from_string("pids"), Ok(7));
        assert_eq!(cgroup_controller_from_string("bpf-firewall"), Ok(8));
        assert_eq!(cgroup_controller_from_string("bpf-devices"), Ok(9));
        assert_eq!(cgroup_controller_from_string("bpf-foreign"), Ok(10));
        assert_eq!(cgroup_controller_from_string("bpf-socket-bind"), Ok(11));
        assert_eq!(
            cgroup_controller_from_string("bpf-restrict-network-interfaces"),
            Ok(12)
        );
        assert_eq!(
            cgroup_controller_from_string("bpf-bind-network-interface"),
            Ok(13)
        );
    }

    #[test]
    fn test_cgroup_controller_from_string_invalid() {
        assert!(cgroup_controller_from_string("invalid").is_err());
        assert!(cgroup_controller_from_string("").is_err());
    }

    #[test]
    fn test_managed_oom_mode_to_string() {
        assert_eq!(managed_oom_mode_to_string(0), Some("auto"));
        assert_eq!(managed_oom_mode_to_string(1), Some("kill"));
        assert_eq!(managed_oom_mode_to_string(2), None);
        assert_eq!(managed_oom_mode_to_string(-1), None);
    }

    #[test]
    fn test_managed_oom_mode_from_string() {
        assert_eq!(managed_oom_mode_from_string("auto"), Ok(0));
        assert_eq!(managed_oom_mode_from_string("kill"), Ok(1));
        assert!(managed_oom_mode_from_string("invalid").is_err());
    }

    #[test]
    fn test_managed_oom_preference_to_string() {
        assert_eq!(managed_oom_preference_to_string(0), Some("none"));
        assert_eq!(managed_oom_preference_to_string(1), Some("avoid"));
        assert_eq!(managed_oom_preference_to_string(2), Some("omit"));
        assert_eq!(managed_oom_preference_to_string(3), None);
        assert_eq!(managed_oom_preference_to_string(-1), None);
    }

    #[test]
    fn test_managed_oom_preference_from_string() {
        assert_eq!(managed_oom_preference_from_string("none"), Ok(0));
        assert_eq!(managed_oom_preference_from_string("avoid"), Ok(1));
        assert_eq!(managed_oom_preference_from_string("omit"), Ok(2));
        assert!(managed_oom_preference_from_string("invalid").is_err());
    }

    #[test]
    fn test_cg_mask_to_string_single_controller() {
        assert_eq!(cg_mask_to_string(1), Some("cpu".to_string()));
    }

    #[test]
    fn test_cg_mask_to_string_multiple_controllers() {
        let mask: u32 = (1 << 0) | (1 << 5) | (1 << 7);
        assert_eq!(cg_mask_to_string(mask), Some("cpu memory pids".to_string()));
    }

    #[test]
    fn test_cg_mask_to_string_zero_mask() {
        assert_eq!(cg_mask_to_string(0), None);
    }

    #[test]
    fn test_cg_mask_from_string_single() {
        assert_eq!(cg_mask_from_string("cpu"), 1);
    }

    #[test]
    fn test_cg_mask_from_string_multiple() {
        assert_eq!(
            cg_mask_from_string("cpu memory pids"),
            (1 << 0) | (1 << 5) | (1 << 7)
        );
    }

    #[test]
    fn test_cg_mask_from_string_with_tabs() {
        assert_eq!(cg_mask_from_string("cpu\tmemory"), (1 << 0) | (1 << 5));
    }

    #[test]
    fn test_cg_mask_from_string_unknown_ignored() {
        assert_eq!(
            cg_mask_from_string("cpu unknown memory"),
            (1 << 0) | (1 << 5)
        );
    }

    #[test]
    fn test_cg_mask_from_string_empty() {
        assert_eq!(cg_mask_from_string(""), 0);
    }

    #[test]
    fn test_cg_mask_roundtrip() {
        let original: u32 = (1 << 0) | (1 << 3) | (1 << 5);
        let s = cg_mask_to_string(original).unwrap();
        assert_eq!(cg_mask_from_string(&s), original);
    }

    #[test]
    fn test_cg_needs_escape_empty() {
        assert!(cg_needs_escape(""));
    }

    #[test]
    fn test_cg_needs_escape_normal() {
        assert!(!cg_needs_escape("myapp"));
        assert!(!cg_needs_escape("user.slice"));
        assert!(!cg_needs_escape("system.service"));
    }

    #[test]
    fn test_cg_needs_escape_underscore_prefix() {
        assert!(cg_needs_escape("_foo"));
    }

    #[test]
    fn test_cg_needs_escape_dot_prefix() {
        assert!(cg_needs_escape(".hidden"));
    }

    #[test]
    fn test_cg_needs_escape_special_names() {
        assert!(cg_needs_escape("notify_on_release"));
        assert!(cg_needs_escape("release_agent"));
        assert!(cg_needs_escape("tasks"));
    }

    #[test]
    fn test_cg_needs_escape_cgroup_prefix() {
        assert!(cg_needs_escape("cgroup.something"));
        assert!(cg_needs_escape("cgroup.clone_children"));
    }

    #[test]
    fn test_cg_needs_escape_controller_dot() {
        assert!(cg_needs_escape("cpu.something"));
        assert!(cg_needs_escape("memory.something"));
        assert!(cg_needs_escape("pids.something"));
    }

    #[test]
    fn test_cg_needs_escape_controller_no_dot() {
        assert!(!cg_needs_escape("cpu"));
        assert!(!cg_needs_escape("memory"));
    }

    #[test]
    fn test_cg_needs_escape_invalid_filename() {
        assert!(cg_needs_escape("foo/bar"));
    }

    #[test]
    fn test_cg_unescape_normal() {
        assert_eq!(cg_unescape("myapp"), "myapp");
    }

    #[test]
    fn test_cg_unescape_escaped() {
        assert_eq!(cg_unescape("_myapp"), "myapp");
    }

    #[test]
    fn test_cg_unescape_double_underscore() {
        assert_eq!(cg_unescape("__myapp"), "_myapp");
    }

    #[test]
    fn test_cg_mask_to_string_all_controllers() {
        let mask: u32 = (1 << 14) - 1;
        let s = cg_mask_to_string(mask).unwrap();
        assert!(s.contains(' '));
        assert!(s.starts_with("cpu"));
    }
}
