// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.capability-list; authority=src/basic/capability-list.c,src/basic/capability-list.h,src/basic/parse-util.c,src/basic/parse-util.h,src/basic/generate-capability-list.sh,src/basic/capability-to-name.awk,src/basic/meson.build,src/include/meson.build,src/include/uapi/linux/capability.h,tools/generate-gperfs.py
//
// Linux capability name/value lookups — pure data, no syscalls.
//
// The C tables are generated for the selected target from
// <linux/capability.h>. The static table below mirrors the vendored UAPI
// authority in this tree. The C-vs-Rust fixture exhausts the target-generated
// C table, but this source alone must not be treated as a claim that an
// arbitrary build host cannot add newer capability names.

use std::ffi::{CStr, CString, c_char, c_int, c_uint};

use crate::capability_util::CAP_LIMIT;
use crate::ffi::Errno;
use crate::ffi_string_table::{self, Entry as FfiEntry};

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLookupError {
    InvalidArgument,
    NotFound,
}

pub type CapabilityLookupResult<T> = Result<T, CapabilityLookupError>;

// Names, safe Rust conversion, and borrowed C ABI pointers share one
// NUL-backed source of truth.
static CAPABILITY_TABLE: &[FfiEntry] = &[
    (0, b"cap_chown\0"),
    (1, b"cap_dac_override\0"),
    (2, b"cap_dac_read_search\0"),
    (3, b"cap_fowner\0"),
    (4, b"cap_fsetid\0"),
    (5, b"cap_kill\0"),
    (6, b"cap_setgid\0"),
    (7, b"cap_setuid\0"),
    (8, b"cap_setpcap\0"),
    (9, b"cap_linux_immutable\0"),
    (10, b"cap_net_bind_service\0"),
    (11, b"cap_net_broadcast\0"),
    (12, b"cap_net_admin\0"),
    (13, b"cap_net_raw\0"),
    (14, b"cap_ipc_lock\0"),
    (15, b"cap_ipc_owner\0"),
    (16, b"cap_sys_module\0"),
    (17, b"cap_sys_rawio\0"),
    (18, b"cap_sys_chroot\0"),
    (19, b"cap_sys_ptrace\0"),
    (20, b"cap_sys_pacct\0"),
    (21, b"cap_sys_admin\0"),
    (22, b"cap_sys_boot\0"),
    (23, b"cap_sys_nice\0"),
    (24, b"cap_sys_resource\0"),
    (25, b"cap_sys_time\0"),
    (26, b"cap_sys_tty_config\0"),
    (27, b"cap_mknod\0"),
    (28, b"cap_lease\0"),
    (29, b"cap_audit_write\0"),
    (30, b"cap_audit_control\0"),
    (31, b"cap_setfcap\0"),
    (32, b"cap_mac_override\0"),
    (33, b"cap_mac_admin\0"),
    (34, b"cap_syslog\0"),
    (35, b"cap_wake_alarm\0"),
    (36, b"cap_block_suspend\0"),
    (37, b"cap_audit_read\0"),
    (38, b"cap_perfmon\0"),
    (39, b"cap_bpf\0"),
    (40, b"cap_checkpoint_restore\0"),
];

// ── Public API ────────────────────────────────────────────────────────────

/// Look up a capability name by its numeric ID.
/// Returns `Some(name)` if the ID is known, `None` otherwise.
/// Port of C `capability_to_name()`.
pub fn capability_to_name(id: i32) -> Option<&'static str> {
    ffi_string_table::to_str(CAPABILITY_TABLE, id)
}

/// Format a capability as a string: returns the name if known,
/// or formats as "0x{hex}" for unknown capabilities within the valid range.
/// Port of C `capability_to_string()`.
pub fn capability_to_string(id: i32) -> Option<String> {
    if id < 0 || id > CAP_LIMIT {
        return None;
    }
    match capability_to_name(id) {
        Some(name) => Some(name.to_string()),
        None => Some(format!("0x{:x}", id as u32)),
    }
}

/// Parse a capability name or numeric string to its integer ID.
/// Accepts names like "cap_chown" and numeric strings like "0".
/// Port of C `capability_from_name()`.
pub fn capability_from_name(name: &str) -> CapabilityLookupResult<i32> {
    let name = CString::new(name).map_err(|_| CapabilityLookupError::InvalidArgument)?;

    // SAFETY: `name` is a live NUL-terminated C string for this call.
    let result = unsafe { capability_from_c_ptr(name.as_ptr()) };
    if result >= 0 {
        Ok(result)
    } else {
        Err(CapabilityLookupError::NotFound)
    }
}

/// Return the number of compiled-in capability names, capped at CAP_LIMIT+1.
/// Port of C `capability_list_length()`.
pub fn capability_list_length() -> u32 {
    let from_table = CAPABILITY_TABLE
        .last()
        .map_or(0, |(id, _)| id.saturating_add(1)) as u32;
    let limit = (CAP_LIMIT + 1) as u32;
    from_table.min(limit)
}

fn capability_from_name_bytes(name: &[u8]) -> Option<i32> {
    CAPABILITY_TABLE.iter().find_map(|&(id, bytes)| {
        bytes[..bytes.len() - 1]
            .eq_ignore_ascii_case(name)
            .then_some(id)
    })
}

/// Parse a borrowed C capability name with `safe_atoi()`'s exact numeric
/// grammar before applying the generated gperf table's ASCII case folding.
///
/// # Safety
///
/// `name` must point to a live NUL-terminated C string for the duration of
/// this call.
unsafe fn capability_from_c_ptr(name: *const c_char) -> c_int {
    if name.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut id = 0;
    // SAFETY: this function's caller supplies a live C string; `id` is a
    // writable local. The shared parser mirrors C `safe_atoi()`.
    if unsafe { crate::parse_util::rs_safe_atoi(name, &mut id) } >= 0 {
        return if (0..=CAP_LIMIT).contains(&id) {
            id
        } else {
            Errno::EINVAL.to_neg_errno()
        };
    }

    // SAFETY: guaranteed by this function's contract and checked for NULL.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    capability_from_name_bytes(name).unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
}

/// C ABI facade for `capability_to_name()`. Returned pointers are borrowed
/// statics and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn rs_capability_to_name(id: c_int) -> *const c_char {
    ffi_string_table::to_ptr(CAPABILITY_TABLE, id)
}

/// C ABI facade for `capability_to_string()`.
///
/// Known IDs return a borrowed static and do not use `buf`. Unknown IDs in the
/// valid mask range are rendered into caller-owned storage and return `buf`,
/// exactly like C. No allocation or ownership transfer occurs.
///
/// # Safety
///
/// For every C-valid invocation, `buf` must address at least
/// `CAPABILITY_TO_STRING_MAX` (five) writable bytes. It may overlap no borrowed
/// static returned by this module. A NULL buffer on the numeric-fallback path
/// is rejected with NULL instead of invoking C's undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_capability_to_string(id: c_int, buf: *mut c_char) -> *const c_char {
    if !(0..=CAP_LIMIT).contains(&id) {
        return std::ptr::null();
    }

    let name = rs_capability_to_name(id);
    if !name.is_null() {
        return name;
    }
    if buf.is_null() {
        return std::ptr::null();
    }

    let value = id as u8;
    let hex = b"0123456789abcdef";
    let mut rendered = [0 as c_char; 5];
    rendered[0] = b'0' as c_char;
    rendered[1] = b'x' as c_char;
    let len = if value < 16 {
        rendered[2] = hex[value as usize] as c_char;
        4
    } else {
        rendered[2] = hex[(value >> 4) as usize] as c_char;
        rendered[3] = hex[(value & 0x0f) as usize] as c_char;
        5
    };

    // SAFETY: required by this facade's caller contract. `rendered` contains
    // exactly `len` initialized bytes, including its terminating NUL.
    unsafe { std::ptr::copy_nonoverlapping(rendered.as_ptr(), buf, len) };
    buf
}

/// C ABI facade for `capability_from_name()`.
///
/// # Safety
///
/// A non-NULL `name` must point to a live NUL-terminated C string for the
/// duration of this call. NULL, which C asserts against, fails closed with
/// `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_capability_from_name(name: *const c_char) -> c_int {
    // SAFETY: this facade forwards its documented string contract unchanged.
    unsafe { capability_from_c_ptr(name) }
}

/// C ABI facade for `capability_list_length()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_capability_list_length() -> c_uint {
    capability_list_length()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_to_name_valid() {
        assert_eq!(capability_to_name(0), Some("cap_chown"));
        assert_eq!(capability_to_name(21), Some("cap_sys_admin"));
        assert_eq!(capability_to_name(40), Some("cap_checkpoint_restore"));
    }

    #[test]
    fn test_capability_to_name_invalid() {
        assert_eq!(capability_to_name(-1), None);
        assert_eq!(capability_to_name(41), None);
        assert_eq!(capability_to_name(100), None);
    }

    #[test]
    fn test_capability_to_name_boundaries() {
        assert_eq!(capability_to_name(0), Some("cap_chown"));
        assert_eq!(capability_to_name(40), Some("cap_checkpoint_restore"));
    }

    #[test]
    fn test_capability_to_string_known() {
        assert_eq!(capability_to_string(0), Some("cap_chown".to_string()));
        assert_eq!(capability_to_string(13), Some("cap_net_raw".to_string()));
        assert_eq!(
            capability_to_string(40),
            Some("cap_checkpoint_restore".to_string())
        );
    }

    #[test]
    fn test_capability_to_string_hex_fallback() {
        assert_eq!(capability_to_string(41), Some("0x29".to_string()));
        assert_eq!(capability_to_string(62), Some("0x3e".to_string()));
    }

    #[test]
    fn test_capability_to_string_invalid() {
        assert!(capability_to_string(-1).is_none());
        assert!(capability_to_string(63).is_none());
    }

    #[test]
    fn test_capability_from_name_valid() {
        assert_eq!(capability_from_name("cap_chown"), Ok(0));
        assert_eq!(capability_from_name("cap_sys_admin"), Ok(21));
        assert_eq!(capability_from_name("cap_net_raw"), Ok(13));
        assert_eq!(capability_from_name("cap_checkpoint_restore"), Ok(40));
    }

    #[test]
    fn test_capability_from_name_numeric() {
        assert_eq!(capability_from_name("0"), Ok(0));
        assert_eq!(capability_from_name("21"), Ok(21));
        assert_eq!(capability_from_name("40"), Ok(40));
        assert_eq!(capability_from_name("62"), Ok(62));
    }

    #[test]
    fn test_capability_from_name_invalid() {
        assert!(capability_from_name("nonexistent").is_err());
        assert!(capability_from_name("").is_err());
        assert!(capability_from_name("63").is_err());
        assert!(capability_from_name("-1").is_err());
    }

    #[test]
    fn test_capability_from_name_ascii_case_insensitive() {
        assert_eq!(capability_from_name("CAP_CHOWN"), Ok(0));
        assert_eq!(capability_from_name("Cap_Chown"), Ok(0));
    }

    #[test]
    fn test_capability_list_length() {
        let len = capability_list_length();
        assert!(len > 0);
        assert_eq!(len, 41);
    }

    #[test]
    fn test_capability_roundtrip() {
        for i in 0..41 {
            let name = capability_to_name(i);
            assert!(
                name.is_some(),
                "capability_to_name({}) should return a name",
                i
            );
            let back = capability_from_name(name.unwrap());
            assert_eq!(back, Ok(i), "roundtrip for cap {} failed", i);
        }
    }

    #[test]
    fn test_capability_from_name_all_table_entries() {
        for &(value, name) in CAPABILITY_TABLE {
            let name = ffi_string_table::entry_str(name);
            let result = capability_from_name(name);
            assert_eq!(result, Ok(value), "lookup failed for {name}");
        }
    }
}
