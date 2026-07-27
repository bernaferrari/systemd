// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/test-udev-builtin.c
//
// Tests the UDEV_BUILTIN_CMD_TO_PTR / PTR_TO_UDEV_BUILTIN_CMD macros
// from udev-builtin.h. These macros convert between UdevBuiltinCommand
// enum values and opaque void* pointers for use in hash maps and tables.
//
// The C source defines a single TEST(udev_builtin_cmd_to_ptr) which
// verifies round-trip conversion: CMD → PTR → CMD == original.
// It also checks edge cases (NULL, invalid pointers → _UDEV_BUILTIN_INVALID).

use std::ptr;

pub const SOURCE_PATH: &str = "src/udev/test-udev-builtin.c";
pub const SOURCE_TEXT: &str = include_str!("../test-udev-builtin.c");

// ── Builtin command enum values (from udev-def.h) ─────────────────────────

/// Builtin command IDs matching the C `UdevBuiltinCommand` enum.
/// Values are conditional on compile-time features (HAVE_BLKID, HAVE_KMOD,
/// HAVE_TPM2, HAVE_ACL), so they may shift. We define the unconditional ones.
pub const UDEV_BUILTIN_BTRFS: i32 = 0;
pub const UDEV_BUILTIN_DISSECT_IMAGE: i32 = 1;
pub const UDEV_BUILTIN_FACTORY_RESET: i32 = 2;
pub const UDEV_BUILTIN_HWDB: i32 = 3;
pub const UDEV_BUILTIN_INPUT_ID: i32 = 4;
pub const UDEV_BUILTIN_KEYBOARD: i32 = 5;
pub const UDEV_BUILTIN_NET_DRIVER: i32 = 6;
pub const UDEV_BUILTIN_NET_ID: i32 = 7;
pub const UDEV_BUILTIN_NET_LINK: i32 = 8;
pub const UDEV_BUILTIN_PATH_ID: i32 = 9;
pub const UDEV_BUILTIN_USB_ID: i32 = 10;
pub const _UDEV_BUILTIN_MAX: i32 = 11;
pub const _UDEV_BUILTIN_INVALID: i32 = -22; // -EINVAL

// When HAVE_BLKID is enabled, BLKID is inserted before BTRFS.
// The Rust crate does not have feature gates for this, so we treat
// BLKID as a separate value that the C conditional may or may not include.
pub const UDEV_BUILTIN_BLKID: i32 = -1; // sentinel: only valid when HAVE_BLKID

// ── Macro-equivalent functions ────────────────────────────────────────────

/// Equivalent to the C macro `UDEV_BUILTIN_CMD_TO_PTR(u)`:
///   _u < 0 ? NULL : (void*)(intptr_t)(_u + 1)
///
/// Encodes a builtin command as an opaque pointer. Negative values
/// (including `_UDEV_BUILTIN_INVALID`) map to NULL.
#[inline]
pub fn udev_builtin_cmd_to_ptr(cmd: i32) -> *mut std::ffi::c_void {
    if cmd < 0 {
        ptr::null_mut()
    } else {
        (cmd as isize + 1) as *mut std::ffi::c_void
    }
}

/// Equivalent to the C macro `PTR_TO_UDEV_BUILTIN_CMD(p)`:
///   _p && (intptr_t)(_p) <= _UDEV_BUILTIN_MAX
///       ? (UdevBuiltinCommand)((intptr_t)_p - 1)
///       : _UDEV_BUILTIN_INVALID
///
/// Decodes an opaque pointer back to a builtin command. NULL and
/// out-of-range pointers yield `_UDEV_BUILTIN_INVALID`.
#[inline]
pub fn ptr_to_udev_builtin_cmd(p: *const std::ffi::c_void) -> i32 {
    if p.is_null() {
        return _UDEV_BUILTIN_INVALID;
    }
    let val = p as isize;
    if val <= _UDEV_BUILTIN_MAX as isize {
        (val - 1) as i32
    } else {
        _UDEV_BUILTIN_INVALID
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_is_embedded() {
        assert!(!super::SOURCE_TEXT.is_empty());
        assert!(super::SOURCE_PATH.ends_with(".c"));
    }

    #[test]
    fn cmd_to_ptr_valid() {
        // Mirrors: assert_se(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BTRFS));
        assert!(!udev_builtin_cmd_to_ptr(UDEV_BUILTIN_BTRFS).is_null());
        assert!(!udev_builtin_cmd_to_ptr(UDEV_BUILTIN_USB_ID).is_null());
    }

    #[test]
    fn cmd_to_ptr_invalid_yields_null() {
        // Negative values → NULL
        assert!(udev_builtin_cmd_to_ptr(_UDEV_BUILTIN_INVALID).is_null());
        assert!(udev_builtin_cmd_to_ptr(-1).is_null());
    }

    #[test]
    fn roundtrip_btrfs() {
        // assert_se(PTR_TO_UDEV_BUILTIN_CMD(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BTRFS)) == UDEV_BUILTIN_BTRFS);
        let ptr = udev_builtin_cmd_to_ptr(UDEV_BUILTIN_BTRFS);
        assert_eq!(ptr_to_udev_builtin_cmd(ptr), UDEV_BUILTIN_BTRFS);
    }

    #[test]
    fn roundtrip_usb_id() {
        let ptr = udev_builtin_cmd_to_ptr(UDEV_BUILTIN_USB_ID);
        assert_eq!(ptr_to_udev_builtin_cmd(ptr), UDEV_BUILTIN_USB_ID);
    }

    #[test]
    fn null_yields_invalid() {
        // assert_se(PTR_TO_UDEV_BUILTIN_CMD(NULL) == _UDEV_BUILTIN_INVALID);
        assert_eq!(ptr_to_udev_builtin_cmd(ptr::null()), _UDEV_BUILTIN_INVALID);
    }

    #[test]
    fn out_of_range_yields_invalid() {
        // assert_se(PTR_TO_UDEV_BUILTIN_CMD((void*) 10000) == _UDEV_BUILTIN_INVALID);
        assert_eq!(
            ptr_to_udev_builtin_cmd(10000 as *const std::ffi::c_void),
            _UDEV_BUILTIN_INVALID
        );
    }

    #[test]
    fn invalid_roundtrip() {
        // _UDEV_BUILTIN_INVALID → NULL → _UDEV_BUILTIN_INVALID
        let ptr = udev_builtin_cmd_to_ptr(_UDEV_BUILTIN_INVALID);
        assert_eq!(ptr_to_udev_builtin_cmd(ptr), _UDEV_BUILTIN_INVALID);
    }
}
