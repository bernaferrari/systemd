// Centralized unsafe expression boundary for this low-level adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper validates descriptors, pointers, and
        // ownership before evaluating this expression.
        unsafe { $expression }
    }};
}
// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/backlight/backlight.c
//
// Save and restore backlight brightness at shutdown and boot.

/// PCI class for graphics cards.
const PCI_CLASS_GRAPHICS_CARD: u32 = 0x30000;

/// Default clamp percentage for backlight subsystem.
const DEFAULT_CLAMP_PERCENT: u32 = 1;

/// Path where brightness state is persisted.
const BACKLIGHT_SAVE_DIR: &std::ffi::CStr = c"/var/lib/systemd/backlight/";

/// Read max brightness attribute from a backlight device.
///
/// Returns 1 if valid max_brightness found, 0 if max_brightness is 0, negative on error.
///
/// # Safety
///
/// `device` must reference a live `sd_device` accepted by the linked C
/// implementation, and `ret_max` must be valid for one `u32` write.
unsafe fn read_max_brightness(device: *mut libc::c_void, ret_max: *mut u32) -> i32 {
    // SAFETY: this is the exact device_get_sysattr_unsigned_full declaration
    // from sd-device; the call below supplies its documented pointer types.
    unsafe extern "C" {
        fn device_get_sysattr_unsigned_full(
            device: *mut libc::c_void,
            attr: *const libc::c_char,
            base: u32,
            ret: *mut u32,
        ) -> i32;
    }
    let mut max_brightness = 0;
    // SAFETY: the caller supplies the live device, `max_brightness` is a live
    // output slot, and the attribute name is a static NUL-terminated string.
    let result = unsafe {
        device_get_sysattr_unsigned_full(device, c"max_brightness".as_ptr(), 0, &mut max_brightness)
    };
    if result < 0 {
        return result;
    }

    // SAFETY: the caller guarantees a writable `ret_max` slot.
    unsafe {
        *ret_max = max_brightness;
    }
    if max_brightness == 0 { 0 } else { 1 }
}

/// Read current brightness from a backlight device.
///
/// # Safety
///
/// `device` must reference a live `sd_device`, and `ret_brightness` must be
/// valid for one `u32` write.
unsafe fn read_brightness(
    device: *mut libc::c_void,
    max_brightness: u32,
    ret_brightness: *mut u32,
) -> i32 {
    // SAFETY: this is the exact device_get_sysattr_unsigned_full declaration
    // from sd-device; the call below supplies its documented pointer types.
    unsafe extern "C" {
        fn device_get_sysattr_unsigned_full(
            device: *mut libc::c_void,
            attr: *const libc::c_char,
            base: u32,
            ret: *mut u32,
        ) -> i32;
    }

    let mut brightness: u32 = 0;
    // SAFETY: the caller supplies a live device; `brightness` is a valid output
    // slot and the attribute name is a static NUL-terminated string.
    let r = unsafe {
        device_get_sysattr_unsigned_full(device, c"brightness".as_ptr(), 0, &mut brightness)
    };
    if r < 0 {
        return r;
    }

    if brightness > max_brightness {
        return -libc::EINVAL;
    }

    // SAFETY: the caller guarantees a writable `ret_brightness` slot.
    unsafe {
        *ret_brightness = brightness;
    }
    0
}

/// Clamp brightness to a minimum percentage of max.
///
/// Returns the clamped brightness value.
pub fn clamp_brightness(
    brightness: u32,
    max_brightness: u32,
    percent: u32,
    is_backlight: bool,
) -> u32 {
    let min_brightness = if is_backlight {
        let pct_val = (max_brightness as u64 * percent as u64) / 100;
        std::cmp::max(1u32, pct_val as u32)
    } else {
        0
    };

    if brightness < min_brightness {
        min_brightness
    } else if brightness > max_brightness {
        max_brightness
    } else {
        brightness
    }
}

/// Build the save file path for a backlight device.
///
/// # Safety
///
/// `device` must reference a live `sd_device`, and `ret_path` must be valid
/// for one pointer write. The C allocation functions must use storage that is
/// compatible with `libc::free`.
unsafe fn build_save_file_path(device: *mut libc::c_void, ret_path: *mut *mut libc::c_char) -> i32 {
    // SAFETY: these declarations mirror the sd-device and basic string helper
    // ABIs; calls below validate inputs and preserve C allocator ownership.
    unsafe extern "C" {
        fn sd_device_get_subsystem(dev: *mut libc::c_void, ret: *mut *const libc::c_char) -> i32;
        fn sd_device_get_sysname(dev: *mut libc::c_void, ret: *mut *const libc::c_char) -> i32;
        fn sd_device_get_property_value(
            dev: *mut libc::c_void,
            key: *const libc::c_char,
            ret: *mut *const libc::c_char,
        ) -> i32;
        fn cescape(s: *const libc::c_char) -> *mut libc::c_char;
        fn strextend_with_separator_internal(
            target: *mut *mut libc::c_char,
            separator: *const libc::c_char,
            ...
        ) -> *mut libc::c_char;
    }

    let mut subsystem: *const libc::c_char = std::ptr::null();
    // SAFETY: the caller supplies a live device and `subsystem` is a live
    // output slot.
    let r = unsafe_ffi!(sd_device_get_subsystem(device, &mut subsystem));
    if r < 0 {
        return r;
    }

    let mut sysname: *const libc::c_char = std::ptr::null();
    // SAFETY: the caller supplies a live device and `sysname` is a live output
    // slot.
    let r = unsafe_ffi!(sd_device_get_sysname(device, &mut sysname));
    if r < 0 {
        return r;
    }

    // SAFETY: successful subsystem lookup returns a NUL-terminated C string
    // that remains owned by the device.
    let escaped_subsystem = unsafe_ffi!(cescape(subsystem));
    if escaped_subsystem.is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: successful sysname lookup returns a NUL-terminated C string that
    // remains owned by the device.
    let escaped_sysname = unsafe_ffi!(cescape(sysname));
    if escaped_sysname.is_null() {
        // SAFETY: `cescape` returned this owned allocation.
        unsafe {
            libc::free(escaped_subsystem.cast());
        }
        return -libc::ENOMEM;
    }

    let mut path_id: *const libc::c_char = std::ptr::null();
    // SAFETY: the caller supplies a live device, the property name is a static
    // C string, and `path_id` is a live output slot.
    let has_path_id =
        unsafe_ffi!(sd_device_get_property_value(device, c"ID_PATH".as_ptr(), &mut path_id)) >= 0;

    let escaped_path_id = if has_path_id {
        // SAFETY: successful property lookup returns a NUL-terminated C string
        // that remains owned by the device.
        let escaped = unsafe_ffi!(cescape(path_id));
        if escaped.is_null() {
            // SAFETY: both pointers came from successful `cescape` calls.
            unsafe {
                libc::free(escaped_subsystem.cast());
                libc::free(escaped_sysname.cast());
            }
            return -libc::ENOMEM;
        }
        escaped
    } else {
        std::ptr::null_mut()
    };

    // SAFETY: all appendees are live NUL-terminated strings and the final null
    // terminates the C variadic list. Null target/separator arguments are the
    // expansion used by C's `strjoin` macro.
    let path = unsafe {
        if escaped_path_id.is_null() {
            strextend_with_separator_internal(
                std::ptr::null_mut(),
                std::ptr::null(),
                BACKLIGHT_SAVE_DIR.as_ptr(),
                escaped_subsystem,
                c":".as_ptr(),
                escaped_sysname,
                std::ptr::null::<libc::c_char>(),
            )
        } else {
            strextend_with_separator_internal(
                std::ptr::null_mut(),
                std::ptr::null(),
                BACKLIGHT_SAVE_DIR.as_ptr(),
                escaped_path_id,
                c":".as_ptr(),
                escaped_subsystem,
                c":".as_ptr(),
                escaped_sysname,
                std::ptr::null::<libc::c_char>(),
            )
        }
    };

    // SAFETY: each non-null pointer came from `cescape`, null is accepted by
    // `free`, and none is used after this point.
    unsafe {
        libc::free(escaped_subsystem.cast());
        libc::free(escaped_sysname.cast());
        libc::free(escaped_path_id.cast());
    }

    if path.is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: the caller guarantees a writable pointer output slot.
    unsafe {
        *ret_path = path;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_brightness_backlight() {
        // max=100, percent=1 -> min=1
        assert_eq!(clamp_brightness(0, 100, 1, true), 1);
        assert_eq!(clamp_brightness(50, 100, 1, true), 50);
        assert_eq!(clamp_brightness(200, 100, 1, true), 100);
    }

    #[test]
    fn test_clamp_brightness_leds() {
        // LEDs: min_brightness is always 0
        assert_eq!(clamp_brightness(0, 100, 1, false), 0);
        assert_eq!(clamp_brightness(50, 100, 1, false), 50);
        assert_eq!(clamp_brightness(200, 100, 1, false), 100);
    }

    #[test]
    fn test_pci_class() {
        assert_eq!(PCI_CLASS_GRAPHICS_CARD, 0x30000);
        assert_eq!(DEFAULT_CLAMP_PERCENT, 1);
    }
}
