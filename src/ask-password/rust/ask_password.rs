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
// PORT-SYNC: src/ask-password/ask-password.c
//
// Query the user for a passphrase, via TTY or a UI agent.

/// Echo mode for password input.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EchoMode {
    Off = 0,
    On = 1,
    Masked = 2,
}

/// Flags controlling ask-password behavior.
pub const ASK_PASSWORD_ACCEPT_CACHED: u32 = 1 << 0;
pub const ASK_PASSWORD_PUSH_CACHE: u32 = 1 << 1;
pub const ASK_PASSWORD_ECHO: u32 = 1 << 2;
pub const ASK_PASSWORD_SILENT: u32 = 1 << 3;
pub const ASK_PASSWORD_NO_TTY: u32 = 1 << 4;
pub const ASK_PASSWORD_NO_AGENT: u32 = 1 << 5;
pub const ASK_PASSWORD_CONSOLE_COLOR: u32 = 1 << 6;
pub const ASK_PASSWORD_NO_CREDENTIAL: u32 = 1 << 7;
pub const ASK_PASSWORD_HIDE_EMOJI: u32 = 1 << 8;
pub const ASK_PASSWORD_HEADLESS: u32 = 1 << 9;
pub const ASK_PASSWORD_USER: u32 = 1 << 10;

/// Default timeout in microseconds (90 seconds).
pub const DEFAULT_TIMEOUT_USEC: u64 = 90_000_000;

/// Ask for a password from the user via TTY or agent.
///
/// # Safety
///
/// Every non-null string pointer must reference a NUL-terminated string for
/// the duration of the call. The linked C implementation must return either
/// null or a null-terminated, `malloc`-allocated string vector.
unsafe fn ask_password_auto(
    message: *const libc::c_char,
    icon: *const libc::c_char,
    id: *const libc::c_char,
    keyring: *const libc::c_char,
    credential: *const libc::c_char,
    timeout: u64,
    flags: u32,
) -> i32 {
    // SAFETY: this declaration mirrors ask-password-api.h's request, flag, and
    // malloc-owned strv output ABI; every call below upholds that C contract.
    unsafe extern "C" {
        fn ask_password_auto(
            req: *const AskPasswordRequest,
            flags: u32,
            ret: *mut *mut *mut libc::c_char,
        ) -> i32;
    }

    #[repr(C)]
    struct AskPasswordRequest {
        message: *const libc::c_char,
        keyring: *const libc::c_char,
        icon: *const libc::c_char,
        id: *const libc::c_char,
        credential: *const libc::c_char,
        flag_file: *const libc::c_char,
        tty_fd: i32,
        hup_fd: i32,
        until: u64,
    }

    let req = AskPasswordRequest {
        message,
        keyring,
        icon,
        id,
        credential,
        flag_file: std::ptr::null(),
        tty_fd: -libc::EBADF,
        hup_fd: -libc::EBADF,
        until: timeout,
    };

    let mut result: *mut *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: `req` and the result slot live for the call; the caller upholds
    // the validity of every non-null string pointer stored in `req`.
    let r = unsafe_ffi!(ask_password_auto(&req, flags, &mut result));
    if r < 0 {
        return r;
    }

    if !result.is_null() {
        // SAFETY: a successful C call returns a null-terminated vector whose
        // entries and vector allocation are all owned by the caller and were
        // allocated with the allocator paired with `libc::free`.
        unsafe {
            let mut p = result;
            while !(*p).is_null() {
                libc::free((*p).cast());
                p = p.add(1);
            }
            libc::free(result.cast());
        }
    }

    0
}

/// Configure ask-password flags from echo mode setting.
pub fn configure_echo(flags: &mut u32, echo_enabled: bool, silent: bool) {
    if echo_enabled {
        *flags |= ASK_PASSWORD_ECHO;
        *flags &= !ASK_PASSWORD_SILENT;
    } else if !silent {
        *flags &= !ASK_PASSWORD_ECHO;
        *flags |= ASK_PASSWORD_SILENT;
    }
}

/// Print password results to stdout.
///
/// # Safety
///
/// `passwords` must be null or point to a readable, null-terminated vector of
/// pointers to NUL-terminated C strings. The vector and strings must remain
/// alive for the duration of the call.
unsafe fn print_passwords(passwords: *mut *mut libc::c_char, newline: bool, no_output: bool) {
    if no_output || passwords.is_null() {
        return;
    }

    // SAFETY: the caller guarantees a readable null-terminated vector and
    // valid C strings; the traversal never writes through either pointer.
    unsafe {
        let mut p = passwords;
        while !(*p).is_null() {
            let pwd = *p;
            if newline {
                libc::puts(pwd);
            } else {
                libc::fputs(pwd, libc::stdout);
            }
            libc::fflush(libc::stdout);
            p = p.add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_mode_values() {
        assert_eq!(EchoMode::Off as i32, 0);
        assert_eq!(EchoMode::On as i32, 1);
        assert_eq!(EchoMode::Masked as i32, 2);
    }

    #[test]
    fn test_flag_constants() {
        assert!(ASK_PASSWORD_PUSH_CACHE > 0);
        assert!(ASK_PASSWORD_ECHO > 0);
        assert!(ASK_PASSWORD_USER > 0);
    }

    #[test]
    fn test_configure_echo() {
        let mut flags: u32 = 0;
        configure_echo(&mut flags, true, false);
        assert!(flags & ASK_PASSWORD_ECHO);
        assert!(!(flags & ASK_PASSWORD_SILENT));

        configure_echo(&mut flags, false, false);
        assert!(!(flags & ASK_PASSWORD_ECHO));
        assert!(flags & ASK_PASSWORD_SILENT);
    }
}
