// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/battery-check/battery-check.c
//
// Check battery level to see whether there's enough charge.

use systemd_shared_rs::unsafe_ffi;

/// Battery low warning message.
const BATTERY_LOW_MESSAGE: &std::ffi::CStr =
    c"Battery level critically low. Please connect your charger or the system will power off in 10 seconds.";

/// AC power restored message.
const BATTERY_RESTORED_MESSAGE: &std::ffi::CStr = c"A.C. power restored, continuing.";

/// Delay before re-checking battery after low warning (10 seconds).
const BATTERY_CHECK_DELAY_USEC: u64 = 10_000_000;

/// Check if the battery is discharging and low.
///
/// Returns >0 if low, 0 if not, negative on error.
///
fn check_battery_low() -> i32 {
    // SAFETY: this no-argument declaration exactly matches battery-check.h.
    unsafe extern "C" {
        fn battery_is_discharging_and_low() -> i32;
    }
    // SAFETY: this C query takes no pointers and has no caller-side safety
    // preconditions.
    unsafe_ffi!( battery_is_discharging_and_low() )
}

/// Sleep safely for the specified duration in microseconds.
///
fn sleep_safe(usec: u64) {
    // SAFETY: this declaration exactly matches time-util.h's usec_t ABI.
    unsafe extern "C" {
        fn usleep_safe(usec: u64) -> i32;
    }
    // SAFETY: `usleep_safe` accepts every `u64` duration and retains no Rust
    // references.
    unsafe_ffi!({
        let _ = usleep_safe(usec);
    })
}

/// Send a message to Plymouth.
///
fn plymouth_send_message(mode: &str, message: &str) -> i32 {
    // SAFETY: this declaration exactly matches the synchronous byte-buffer
    // interface in plymouth-util.h.
    unsafe extern "C" {
        fn plymouth_send_raw(buf: *const libc::c_void, len: usize, flags: i32) -> i32;
    }

    let Some(mode_len) = mode
        .len()
        .checked_add(1)
        .and_then(|length| u8::try_from(length).ok())
    else {
        return -libc::E2BIG;
    };
    let Some(message_len) = message
        .len()
        .checked_add(1)
        .and_then(|length| u8::try_from(length).ok())
    else {
        return -libc::E2BIG;
    };

    let mut buf = Vec::with_capacity(mode.len() + message.len() + 8);
    buf.extend_from_slice(b"C\x02");
    buf.push(mode_len);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0);
    buf.extend_from_slice(b"M\x02");
    buf.push(message_len);
    buf.extend_from_slice(message.as_bytes());
    buf.push(0);

    // SAFETY: `buf` remains alive and readable for the complete synchronous
    // C call; its length describes the exact Plymouth protocol frame.
    unsafe_ffi!( plymouth_send_raw(buf.as_ptr().cast(), buf.len(), libc::SOCK_NONBLOCK) )
}

/// Open the console for writing.
///
fn open_console() -> i32 {
    // SAFETY: this declaration exactly matches terminal-util.h.
    unsafe extern "C" {
        fn open_terminal(path: *const libc::c_char, flags: i32) -> i32;
    }
    // SAFETY: the path is a static NUL-terminated string and the flags are
    // valid `open` flags.
    unsafe_ffi!({
        open_terminal(
            c"/dev/console".as_ptr(),
            libc::O_WRONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    })
}

/// Close a file descriptor.
fn close_fd(fd: i32) {
    if fd >= 0 {
        // SAFETY: non-negative descriptors may be passed to `close`; errors do
        // not affect memory safety and are intentionally ignored here.
        unsafe_ffi!({
            libc::close(fd);
        })
    }
}

/// Run the battery check logic.
///
/// Returns 0 on success (battery OK or restored), negative on error.
///
pub extern "C" fn rs_battery_check_run() -> i32 {
    // SAFETY: these declarations match the logging ABI, including log_internal's
    // C variadic tail; every format string below is static and type-matched.
    unsafe extern "C" {
        fn log_setup();
        fn log_internal(
            level: i32,
            error: i32,
            file: *const libc::c_char,
            line: i32,
            function: *const libc::c_char,
            format: *const libc::c_char,
            ...
        ) -> i32;
    }
    const SOURCE_FILE: &std::ffi::CStr = c"src/battery-check/battery-check.c";
    const FUNCTION: &std::ffi::CStr = c"rs_battery_check_run";

    // SAFETY: `log_setup` takes no arguments and retains no Rust references.
    unsafe_ffi!({
        log_setup();
    });

    // Check battery status
    let r = check_battery_low();
    if r < 0 {
        // SAFETY: the format is a static NUL-terminated string and has no
        // variadic conversion requiring an additional argument.
        unsafe_ffi!({
            log_internal(
                libc::LOG_WARNING,
                r,
                SOURCE_FILE.as_ptr(),
                line!() as i32,
                FUNCTION.as_ptr(),
                c"Failed to check battery status, ignoring: %m".as_ptr(),
            );
        });
        return 0;
    }
    if r == 0 {
        return 0; // Battery OK
    }

    // Battery is low — warn and wait
    // SAFETY: the static format has one `%s` conversion and the corresponding
    // argument is a static NUL-terminated string.
    unsafe_ffi!({
        log_internal(
            libc::LOG_INFO,
            0,
            SOURCE_FILE.as_ptr(),
            line!() as i32,
            FUNCTION.as_ptr(),
            c"%s\n".as_ptr(),
            BATTERY_LOW_MESSAGE.as_ptr(),
        );
    });

    let console_fd = open_console();
    if console_fd < 0 {
        // SAFETY: the format is a static NUL-terminated string and requires no
        // additional variadic argument.
        unsafe_ffi!({
            log_internal(
                libc::LOG_WARNING,
                console_fd,
                SOURCE_FILE.as_ptr(),
                line!() as i32,
                FUNCTION.as_ptr(),
                c"Failed to open console, ignoring: %m".as_ptr(),
            );
        })
    }

    // Send message to plymouth
    plymouth_send_message("shutdown", BATTERY_LOW_MESSAGE.to_str().unwrap());

    // Wait 10 seconds for charger
    sleep_safe(BATTERY_CHECK_DELAY_USEC);

    // Re-check
    let r = check_battery_low();
    if r < 0 {
        // SAFETY: the format is a static NUL-terminated string and requires no
        // additional variadic argument.
        return unsafe_ffi!({
            log_internal(
                libc::LOG_WARNING,
                r,
                SOURCE_FILE.as_ptr(),
                line!() as i32,
                FUNCTION.as_ptr(),
                c"Failed to check battery status, assuming not charged yet, powering off: %m"
                    .as_ptr(),
            )
        });
    }
    if r > 0 {
        // Still low — power off
        // SAFETY: the static format contains no variadic conversions.
        unsafe_ffi!({
            log_internal(
                libc::LOG_INFO,
                0,
                SOURCE_FILE.as_ptr(),
                line!() as i32,
                FUNCTION.as_ptr(),
                c"Battery level critically low, powering off.\n".as_ptr(),
            );
        });
        return r;
    }

    // Battery restored
    // SAFETY: the static format has one `%s` conversion and the corresponding
    // argument is a static NUL-terminated string.
    unsafe_ffi!({
        log_internal(
            libc::LOG_INFO,
            0,
            SOURCE_FILE.as_ptr(),
            line!() as i32,
            FUNCTION.as_ptr(),
            c"%s\n".as_ptr(),
            BATTERY_RESTORED_MESSAGE.as_ptr(),
        );
    });

    if console_fd >= 0 {
        // SAFETY: `console_fd` is an open descriptor, and the static format has
        // one `%s` conversion matched by a static C string.
        unsafe_ffi!({
            libc::dprintf(
                console_fd,
                c"%s\n".as_ptr(),
                BATTERY_RESTORED_MESSAGE.as_ptr(),
            );
        })
    }

    plymouth_send_message("boot-up", BATTERY_RESTORED_MESSAGE.to_str().unwrap());

    close_fd(console_fd);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(BATTERY_CHECK_DELAY_USEC > 0);
        assert!(!BATTERY_LOW_MESSAGE.to_bytes().is_empty());
        assert!(!BATTERY_RESTORED_MESSAGE.to_bytes().is_empty());
    }
}
