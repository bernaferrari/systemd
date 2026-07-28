// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.bus-error-util; authority=src/libsystemd/sd-bus/bus-error.c,src/libsystemd/sd-bus/bus-error.h,src/systemd/sd-bus-protocol.h
//
// Narrow C ABI facades for the pure sd_bus_error accessors.

use crate::ffi;
use libc::{c_char, c_int};

/// ABI view of C's `sd_bus_error` from `sd-bus-protocol.h`.
///
/// `name` and `message` are borrowed C-string pointers. This type never takes
/// ownership of them. `_need_free` deliberately remains an `int`: its sign has
/// meaning to the C implementation, even though these accessors only test it
/// for zero.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdBusError {
    name: *const c_char,
    message: *const c_char,
    need_free: c_int,
}

impl Default for SdBusError {
    fn default() -> Self {
        Self {
            name: std::ptr::null(),
            message: std::ptr::null(),
            need_free: 0,
        }
    }
}

impl SdBusError {
    /// Construct the ABI equivalent of `SD_BUS_ERROR_NULL`.
    pub fn null() -> Self {
        Self::default()
    }
}

/// Implements C's `bus_error_is_dirty()` for an ABI-valid error pointer.
///
/// # Safety
/// When non-null, `error` must point to a live, properly aligned
/// `sd_bus_error`-layout value for the duration of this call.
unsafe fn bus_error_is_dirty_raw(error: *const SdBusError) -> bool {
    // SAFETY: upheld by this function's safety contract.
    let Some(error) = (unsafe { error.as_ref() }) else {
        return false;
    };

    !error.name.is_null() || !error.message.is_null() || error.need_free != 0
}

/// Implements C's `sd_bus_error_is_set()` for an ABI-valid error pointer.
///
/// # Safety
/// When non-null, `error` must point to a live, properly aligned
/// `sd_bus_error`-layout value for the duration of this call.
unsafe fn sd_bus_error_is_set_raw(error: *const SdBusError) -> bool {
    // SAFETY: upheld by this function's safety contract.
    unsafe { error.as_ref() }.is_some_and(|error| !error.name.is_null())
}

/// Implements C's `sd_bus_error_has_name()` for ABI-valid inputs.
///
/// # Safety
/// When non-null, `error` must point to a live, properly aligned
/// `sd_bus_error`-layout value. Any non-null `name` field and `name` argument
/// must be live NUL-terminated C strings for the duration of this call.
unsafe fn sd_bus_error_has_name_raw(error: *const SdBusError, name: *const c_char) -> bool {
    // SAFETY: upheld by this function's safety contract.
    let Some(error) = (unsafe { error.as_ref() }) else {
        return false;
    };

    if error.name == name {
        return true;
    }
    if error.name.is_null() || name.is_null() {
        return false;
    }

    // SAFETY: the branch above establishes that both pointers are live,
    // NUL-terminated C strings, as required by this function's contract.
    unsafe { ffi::strcmp(error.name, name) == 0 }
}

/// C ABI facade for `bus_error_is_dirty()`.
///
/// # Safety
/// When non-null, `error` must point to a live C `sd_bus_error` for the
/// duration of the call. Its pointer fields may be null; any non-null field is
/// only inspected as a pointer and is not dereferenced by this accessor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bus_error_is_dirty(error: *mut SdBusError) -> bool {
    // SAFETY: forwarded from this exported function's safety contract.
    unsafe { bus_error_is_dirty_raw(error.cast_const()) }
}

/// C ABI facade for `sd_bus_error_is_set()`.
///
/// # Safety
/// When non-null, `error` must point to a live C `sd_bus_error` for the
/// duration of the call. Its `name` field may be null and is only inspected as
/// a pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_bus_error_is_set(error: *const SdBusError) -> c_int {
    // SAFETY: forwarded from this exported function's safety contract.
    unsafe { c_int::from(sd_bus_error_is_set_raw(error)) }
}

/// C ABI facade for `sd_bus_error_has_name()`.
///
/// # Safety
/// When non-null, `error` must point to a live C `sd_bus_error`. Any non-null
/// `error->name` and `name` argument must be live NUL-terminated C strings
/// for the duration of the call. Their bytes are compared with C `strcmp`, so
/// no UTF-8 interpretation or allocation occurs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sd_bus_error_has_name(
    error: *const SdBusError,
    name: *const c_char,
) -> c_int {
    // SAFETY: forwarded from this exported function's safety contract.
    unsafe { c_int::from(sd_bus_error_has_name_raw(error, name)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(name: *const c_char, message: *const c_char, need_free: c_int) -> SdBusError {
        SdBusError {
            name,
            message,
            need_free,
        }
    }

    #[test]
    fn dirty_tracks_each_c_field() {
        let name = c"org.freedesktop.DBus.Error.Failed";
        let message = c"failed";

        // SAFETY: every input is either null or a pointer to a static C string.
        assert!(!unsafe { bus_error_is_dirty_raw(std::ptr::null()) });
        // SAFETY: the local value has the exact C layout.
        assert!(!unsafe { bus_error_is_dirty_raw(&SdBusError::null()) });
        // SAFETY: the local value has the exact C layout.
        assert!(unsafe { bus_error_is_dirty_raw(&error(name.as_ptr(), std::ptr::null(), 0)) });
        // SAFETY: the local value has the exact C layout.
        assert!(unsafe { bus_error_is_dirty_raw(&error(std::ptr::null(), message.as_ptr(), -1)) });
    }

    #[test]
    fn has_name_preserves_null_and_byte_comparison_semantics() {
        let name = c"org.freedesktop.DBus.Error.Failed";
        let other = c"org.freedesktop.DBus.Error.AccessDenied";
        let unset = SdBusError::null();
        let set = error(name.as_ptr(), std::ptr::null(), 0);

        // SAFETY: each error is a local ABI value and every non-null string is static.
        assert!(unsafe { sd_bus_error_has_name_raw(&unset, std::ptr::null()) });
        // SAFETY: each error is a local ABI value and every non-null string is static.
        assert!(unsafe { sd_bus_error_has_name_raw(&set, name.as_ptr()) });
        // SAFETY: each error is a local ABI value and every non-null string is static.
        assert!(!unsafe { sd_bus_error_has_name_raw(&set, other.as_ptr()) });
        // SAFETY: a null error is explicitly accepted by the C contract.
        assert!(!unsafe { sd_bus_error_has_name_raw(std::ptr::null(), name.as_ptr()) });
    }
}
