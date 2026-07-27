// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/install.h
//
// The ABI-facing representation is deliberately isolated from the safe,
// owned install model in src/shared/rust/install.rs. C callers own the array
// and this leaf predicate only observes the discriminant.

use libc::c_char;

/// Exact C layout of `InstallChange` from `src/shared/install.h`.
#[repr(C)]
pub struct InstallChange {
    type_: i32,
    path: *mut c_char,
    source: *mut c_char,
}

const INSTALL_CHANGE_SYMLINK: i32 = 0;
const INSTALL_CHANGE_UNLINK: i32 = 1;
const INSTALL_CHANGE_TYPE_MAX: i32 = 7;
// Current Linux/systemd errno-list.h defines ERRNO_MAX as 4095. Keep the
// raw integer boundary: invalid C enum values must fail closed, not be turned
// into an invalid Rust enum discriminant.
const INSTALL_CHANGE_ERRNO_MAX: i32 = -4095;

/// Exact `INSTALL_CHANGE_TYPE_VALID()` range over C's raw enum ABI.
pub const fn install_change_type_valid_raw(type_: i32) -> bool {
    (INSTALL_CHANGE_ERRNO_MAX..INSTALL_CHANGE_TYPE_MAX).contains(&type_)
}

/// C ABI for `INSTALL_CHANGE_TYPE_VALID()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_INSTALL_CHANGE_TYPE_VALID(type_: i32) -> bool {
    install_change_type_valid_raw(type_)
}

/// C-ABI shadow of `install_changes_have_modification()`.
///
/// # Safety
///
/// `changes` may be null only when `n_changes` is zero. Otherwise it must
/// point to an aligned, initialized, readable array of `n_changes`
/// `InstallChange` values for the duration of this call. The pointed-to
/// `path` and `source` strings are deliberately not read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_install_changes_have_modification(
    changes: *const InstallChange,
    n_changes: usize,
) -> bool {
    if changes.is_null() || n_changes == 0 {
        return false;
    }

    // SAFETY: the non-null, aligned, initialized array contract is documented
    // on this exported function. Only its `type_` field is inspected.
    unsafe { std::slice::from_raw_parts(changes, n_changes) }
        .iter()
        .any(|change| {
            change.type_ == INSTALL_CHANGE_SYMLINK || change.type_ == INSTALL_CHANGE_UNLINK
        })
}
