// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.signal-util; authority=src/basic/signal-util.c,src/basic/signal-util.h

use std::cell::UnsafeCell;
use std::ffi::{CStr, c_char};

use crate::ffi::Errno;

const SIGRTMIN_DEFAULT: i32 = 34;
const SIGRTMAX_DEFAULT: i32 = 64;
const NSIG_DEFAULT: i32 = 65;

// SAFETY: the linked C fixture supplies these pointer-free runtime constants
// with the exact declarations in rust/signal_util.h.
unsafe extern "C" {
    fn rs_get_sigrtmin() -> i32;
    fn rs_get_sigrtmax() -> i32;
    fn rs_get_nsig() -> i32;
}

thread_local! {
    static SIGNAL_NAME_BUFFER: UnsafeCell<[c_char; 32]> =
        const { UnsafeCell::new([0; 32]) };
}

const SIGNAL_TABLE: &[(i32, &str)] = &[
    (1, "HUP"),
    (2, "INT"),
    (3, "QUIT"),
    (4, "ILL"),
    (5, "TRAP"),
    (6, "ABRT"),
    (7, "BUS"),
    (8, "FPE"),
    (9, "KILL"),
    (10, "USR1"),
    (11, "SEGV"),
    (12, "USR2"),
    (13, "PIPE"),
    (14, "ALRM"),
    (15, "TERM"),
    (16, "STKFLT"),
    (17, "CHLD"),
    (18, "CONT"),
    (19, "STOP"),
    (20, "TSTP"),
    (21, "TTIN"),
    (22, "TTOU"),
    (23, "URG"),
    (24, "XCPU"),
    (25, "XFSZ"),
    (26, "VTALRM"),
    (27, "PROF"),
    (28, "WINCH"),
    (29, "IO"),
    (30, "PWR"),
    (31, "SYS"),
];

fn safe_atoi(value: &str) -> Result<i32, Errno> {
    if value.is_empty() {
        return Err(Errno::EINVAL);
    }

    value.parse::<i32>().map_err(|error| {
        if matches!(
            error.kind(),
            std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
        ) {
            Errno::ERANGE
        } else {
            Errno::EINVAL
        }
    })
}

fn static_signal_to_string(signo: i32) -> Option<&'static str> {
    SIGNAL_TABLE
        .iter()
        .find_map(|(signal, name)| (*signal == signo).then_some(*name))
}

fn static_signal_to_c_string(signo: i32) -> Option<&'static CStr> {
    Some(match signo {
        x if x == libc::SIGHUP => c"HUP",
        x if x == libc::SIGINT => c"INT",
        x if x == libc::SIGQUIT => c"QUIT",
        x if x == libc::SIGILL => c"ILL",
        x if x == libc::SIGTRAP => c"TRAP",
        x if x == libc::SIGABRT => c"ABRT",
        x if x == libc::SIGBUS => c"BUS",
        x if x == libc::SIGFPE => c"FPE",
        x if x == libc::SIGKILL => c"KILL",
        x if x == libc::SIGUSR1 => c"USR1",
        x if x == libc::SIGSEGV => c"SEGV",
        x if x == libc::SIGUSR2 => c"USR2",
        x if x == libc::SIGPIPE => c"PIPE",
        x if x == libc::SIGALRM => c"ALRM",
        x if x == libc::SIGTERM => c"TERM",
        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "sparc",
            target_arch = "sparc64",
        )))]
        x if x == libc::SIGSTKFLT => c"STKFLT",
        x if x == libc::SIGCHLD => c"CHLD",
        x if x == libc::SIGCONT => c"CONT",
        x if x == libc::SIGSTOP => c"STOP",
        x if x == libc::SIGTSTP => c"TSTP",
        x if x == libc::SIGTTIN => c"TTIN",
        x if x == libc::SIGTTOU => c"TTOU",
        x if x == libc::SIGURG => c"URG",
        x if x == libc::SIGXCPU => c"XCPU",
        x if x == libc::SIGXFSZ => c"XFSZ",
        x if x == libc::SIGVTALRM => c"VTALRM",
        x if x == libc::SIGPROF => c"PROF",
        x if x == libc::SIGWINCH => c"WINCH",
        x if x == libc::SIGIO => c"IO",
        x if x == libc::SIGPWR => c"PWR",
        x if x == libc::SIGSYS => c"SYS",
        _ => return None,
    })
}

fn write_signal_number(buffer: &mut [c_char; 32], prefix: &[u8], value: i32) {
    let mut position = 0;
    for &byte in prefix {
        buffer[position] = byte as c_char;
        position += 1;
    }

    if value < 0 {
        buffer[position] = b'-' as c_char;
        position += 1;
    }

    let mut digits = [0_u8; 10];
    let mut count = 0;
    let mut value = value.unsigned_abs();
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for &digit in digits[..count].iter().rev() {
        buffer[position] = digit as c_char;
        position += 1;
    }
    buffer[position] = 0;
}

fn static_signal_from_c_bytes(name: &[u8]) -> Option<i32> {
    [
        (libc::SIGHUP, b"HUP".as_slice()),
        (libc::SIGINT, b"INT".as_slice()),
        (libc::SIGQUIT, b"QUIT".as_slice()),
        (libc::SIGILL, b"ILL".as_slice()),
        (libc::SIGTRAP, b"TRAP".as_slice()),
        (libc::SIGABRT, b"ABRT".as_slice()),
        (libc::SIGBUS, b"BUS".as_slice()),
        (libc::SIGFPE, b"FPE".as_slice()),
        (libc::SIGKILL, b"KILL".as_slice()),
        (libc::SIGUSR1, b"USR1".as_slice()),
        (libc::SIGSEGV, b"SEGV".as_slice()),
        (libc::SIGUSR2, b"USR2".as_slice()),
        (libc::SIGPIPE, b"PIPE".as_slice()),
        (libc::SIGALRM, b"ALRM".as_slice()),
        (libc::SIGTERM, b"TERM".as_slice()),
        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "sparc",
            target_arch = "sparc64",
        )))]
        (libc::SIGSTKFLT, b"STKFLT".as_slice()),
        (libc::SIGCHLD, b"CHLD".as_slice()),
        (libc::SIGCONT, b"CONT".as_slice()),
        (libc::SIGSTOP, b"STOP".as_slice()),
        (libc::SIGTSTP, b"TSTP".as_slice()),
        (libc::SIGTTIN, b"TTIN".as_slice()),
        (libc::SIGTTOU, b"TTOU".as_slice()),
        (libc::SIGURG, b"URG".as_slice()),
        (libc::SIGXCPU, b"XCPU".as_slice()),
        (libc::SIGXFSZ, b"XFSZ".as_slice()),
        (libc::SIGVTALRM, b"VTALRM".as_slice()),
        (libc::SIGPROF, b"PROF".as_slice()),
        (libc::SIGWINCH, b"WINCH".as_slice()),
        (libc::SIGIO, b"IO".as_slice()),
        (libc::SIGPWR, b"PWR".as_slice()),
        (libc::SIGSYS, b"SYS".as_slice()),
    ]
    .into_iter()
    .find_map(|(signal, candidate)| (name == candidate).then_some(signal))
}

fn dynamic_signal_to_c_string(signo: i32) -> *const c_char {
    // SAFETY: these helpers are supplied by the linked C translation unit and
    // return the process's runtime signal constants without pointer effects.
    let (realtime_min, realtime_max) = unsafe { (rs_get_sigrtmin(), rs_get_sigrtmax()) };
    SIGNAL_NAME_BUFFER.with(|cell| {
        // SAFETY: this thread exclusively accesses its own thread-local buffer.
        let buffer = unsafe { &mut *cell.get() };
        if (realtime_min..=realtime_max).contains(&signo) {
            write_signal_number(buffer, b"RTMIN+", signo - realtime_min);
        } else {
            write_signal_number(buffer, b"", signo);
        }
        buffer.as_ptr()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_signal_is_valid(signo: i32) -> bool {
    // SAFETY: the helper has no pointer contract and returns the runtime bound.
    signo > 0 && signo < unsafe { rs_get_nsig() }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_signal_to_string_with_check(signo: i32) -> *const c_char {
    if !rs_signal_is_valid(signo) {
        return std::ptr::null();
    }
    static_signal_to_c_string(signo)
        .map(CStr::as_ptr)
        .unwrap_or_else(|| dynamic_signal_to_c_string(signo))
}

/// C ABI for `signal_to_string()`.
///
/// The result is either a borrowed immutable C string with static storage or
/// the module's thread-local formatting buffer. It is never caller-owned.
#[unsafe(no_mangle)]
pub extern "C" fn rs_signal_to_string(signo: i32) -> *const c_char {
    static_signal_to_c_string(signo)
        .map(CStr::as_ptr)
        .unwrap_or_else(|| dynamic_signal_to_c_string(signo))
}

/// C ABI for `signal_from_string()`.
///
/// # Safety
///
/// `s` must be a live NUL-terminated C string for this call, matching the C
/// function's non-NULL input precondition. The bytes are borrowed only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_signal_from_string(s: *const c_char) -> i32 {
    let mut signo = 0;
    // SAFETY: `s` satisfies the C-string precondition above and `signo` is a
    // writable local. This preserves `safe_atoi()`'s decimal/base and errno
    // semantics used by the C authority.
    if unsafe { crate::parse_util::rs_safe_atoi(s, &mut signo) } >= 0 {
        return if rs_signal_is_valid(signo) {
            signo
        } else {
            Errno::ERANGE.to_neg_errno()
        };
    }

    let mut input = s;
    // SAFETY: `s` is a live NUL-terminated string under this function's
    // contract; the bytes are only inspected during this call.
    let mut bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    if bytes.starts_with(b"SIG") {
        // SAFETY: the prefix length was checked against the borrowed C string.
        input = unsafe { input.add(3) };
        bytes = &bytes[3..];
    }

    if let Some(signo) = static_signal_from_c_bytes(bytes) {
        return signo;
    }

    if let Some(rest) = bytes.strip_prefix(b"RTMIN") {
        if rest.is_empty() {
            // SAFETY: the helper has no pointer contract and returns the
            // process runtime's SIGRTMIN value.
            return unsafe { rs_get_sigrtmin() };
        }
        if rest[0] != b'+' {
            return Errno::EINVAL.to_neg_errno();
        }

        // SAFETY: `input + 5` is the checked RTMIN suffix and therefore a
        // live NUL-terminated C string; `signo` is a writable local.
        let r = unsafe { crate::parse_util::rs_safe_atoi(input.add(5), &mut signo) };
        if r < 0 {
            return r;
        }

        // SAFETY: the helpers have no pointer effects and expose the C
        // runtime's dynamic real-time signal bounds.
        let (realtime_min, realtime_max) = unsafe { (rs_get_sigrtmin(), rs_get_sigrtmax()) };
        if signo < 0 || signo > realtime_max - realtime_min {
            return Errno::ERANGE.to_neg_errno();
        }
        return signo + realtime_min;
    }

    if let Some(rest) = bytes.strip_prefix(b"RTMAX") {
        if rest.is_empty() {
            // SAFETY: the helper has no pointer contract and returns the
            // process runtime's SIGRTMAX value.
            return unsafe { rs_get_sigrtmax() };
        }
        if rest[0] != b'-' {
            return Errno::EINVAL.to_neg_errno();
        }

        // SAFETY: `input + 5` is the checked RTMAX suffix and therefore a
        // live NUL-terminated C string; `signo` is a writable local.
        let r = unsafe { crate::parse_util::rs_safe_atoi(input.add(5), &mut signo) };
        if r < 0 {
            return r;
        }

        // SAFETY: the helpers have no pointer effects and expose the C
        // runtime's dynamic real-time signal bounds.
        let (realtime_min, realtime_max) = unsafe { (rs_get_sigrtmin(), rs_get_sigrtmax()) };
        if signo > 0 || signo < realtime_min - realtime_max {
            return Errno::ERANGE.to_neg_errno();
        }
        return signo + realtime_max;
    }

    Errno::EINVAL.to_neg_errno()
}

/// C ABI for `parse_signo()`.
///
/// # Safety
///
/// `s` must be a live NUL-terminated C string. If `ret` is non-NULL, it must
/// be writable for one `int`; its value is changed only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_signo(s: *const c_char, ret: *mut i32) -> i32 {
    let mut signo = 0;
    // SAFETY: this forwards `parse_signo()`'s C-string and optional-output
    // contracts to the shared C-compatible numeric parser.
    let r = unsafe { crate::parse_util::rs_safe_atoi(s, &mut signo) };
    if r < 0 {
        return r;
    }
    if !rs_signal_is_valid(signo) {
        return Errno::EINVAL.to_neg_errno();
    }
    if !ret.is_null() {
        // SAFETY: guaranteed by this function's documented C ABI contract.
        unsafe { *ret = signo };
    }
    0
}

/// C ABI for the inline `si_code_from_process()` predicate.
///
/// This has the same scalar domain as the C inline: every negative `si_code`
/// is process-originated, as are the `SI_USER` and `SI_QUEUE` values. No
/// pointer, allocation, or ownership boundary is involved.
#[unsafe(no_mangle)]
pub extern "C" fn rs_si_code_from_process(si_code: i32) -> bool {
    si_code_from_process(si_code)
}

fn static_signal_from_string(name: &str) -> Option<i32> {
    SIGNAL_TABLE
        .iter()
        .find_map(|(signal, candidate)| (*candidate == name).then_some(*signal))
}

pub const fn signal_is_valid(signo: i32) -> bool {
    signo > 0 && signo < NSIG_DEFAULT
}

pub fn signal_to_string(signo: i32) -> String {
    if let Some(name) = static_signal_to_string(signo) {
        return name.to_string();
    }

    if (SIGRTMIN_DEFAULT..=SIGRTMAX_DEFAULT).contains(&signo) {
        format!("RTMIN+{}", signo - SIGRTMIN_DEFAULT)
    } else {
        signo.to_string()
    }
}

pub fn signal_to_string_with_check(signo: i32) -> Option<String> {
    signal_is_valid(signo).then(|| signal_to_string(signo))
}

pub fn signal_from_string(value: &str) -> Result<i32, Errno> {
    if let Ok(signo) = safe_atoi(value) {
        return if signal_is_valid(signo) {
            Ok(signo)
        } else {
            Err(Errno::ERANGE)
        };
    }

    let value = value.strip_prefix("SIG").unwrap_or(value);

    if let Some(signo) = static_signal_from_string(value) {
        return Ok(signo);
    }

    if let Some(rest) = value.strip_prefix("RTMIN") {
        if rest.is_empty() {
            return Ok(SIGRTMIN_DEFAULT);
        }
        if !rest.starts_with('+') {
            return Err(Errno::EINVAL);
        }

        let offset = safe_atoi(rest)?;
        if !(0..=SIGRTMAX_DEFAULT - SIGRTMIN_DEFAULT).contains(&offset) {
            return Err(Errno::ERANGE);
        }
        return Ok(SIGRTMIN_DEFAULT + offset);
    }

    if let Some(rest) = value.strip_prefix("RTMAX") {
        if rest.is_empty() {
            return Ok(SIGRTMAX_DEFAULT);
        }
        if !rest.starts_with('-') {
            return Err(Errno::EINVAL);
        }

        let offset = safe_atoi(rest)?;
        if offset > 0 || offset < SIGRTMIN_DEFAULT - SIGRTMAX_DEFAULT {
            return Err(Errno::ERANGE);
        }
        return Ok(SIGRTMAX_DEFAULT + offset);
    }

    Err(Errno::EINVAL)
}

pub fn parse_signo(value: &str) -> Result<i32, Errno> {
    let signo = safe_atoi(value)?;
    if signal_is_valid(signo) {
        Ok(signo)
    } else {
        Err(Errno::EINVAL)
    }
}

#[cfg(target_os = "linux")]
pub fn si_code_from_process(si_code: i32) -> bool {
    si_code < 0 || matches!(si_code, libc::SI_USER | libc::SI_QUEUE)
}

#[cfg(not(target_os = "linux"))]
pub fn si_code_from_process(si_code: i32) -> bool {
    si_code < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_validity_matches_range() {
        assert!(signal_is_valid(1));
        assert!(signal_is_valid(64));
        assert!(!signal_is_valid(0));
        assert!(!signal_is_valid(65));
    }

    #[test]
    fn signal_to_string_prefers_static_names() {
        assert_eq!(signal_to_string(1), "HUP");
        assert_eq!(signal_to_string(15), "TERM");
        assert_eq!(signal_to_string(31), "SYS");
    }

    #[test]
    fn signal_to_string_formats_realtime_values() {
        assert_eq!(signal_to_string(SIGRTMIN_DEFAULT), "RTMIN+0");
        assert_eq!(signal_to_string(SIGRTMIN_DEFAULT + 7), "RTMIN+7");
    }

    #[test]
    fn signal_to_string_formats_unknown_values_numerically() {
        assert_eq!(signal_to_string(32), "32");
        assert_eq!(signal_to_string(-1), "-1");
    }

    #[test]
    fn signal_to_string_with_check_rejects_invalid_values() {
        assert_eq!(signal_to_string_with_check(15), Some("TERM".to_string()));
        assert_eq!(signal_to_string_with_check(0), None);
    }

    #[test]
    fn signal_from_string_accepts_numeric_names_and_prefixes() {
        assert_eq!(signal_from_string("15"), Ok(15));
        assert_eq!(signal_from_string("TERM"), Ok(15));
        assert_eq!(signal_from_string("SIGTERM"), Ok(15));
    }

    #[test]
    fn signal_from_string_handles_rtmin_and_rtmax_forms() {
        assert_eq!(signal_from_string("RTMIN"), Ok(SIGRTMIN_DEFAULT));
        assert_eq!(signal_from_string("RTMIN+5"), Ok(SIGRTMIN_DEFAULT + 5));
        assert_eq!(signal_from_string("RTMAX"), Ok(SIGRTMAX_DEFAULT));
        assert_eq!(signal_from_string("RTMAX-5"), Ok(SIGRTMAX_DEFAULT - 5));
    }

    #[test]
    fn signal_from_string_preserves_c_error_behavior() {
        assert_eq!(signal_from_string("0"), Err(Errno::ERANGE));
        assert_eq!(signal_from_string("RTMIN-1"), Err(Errno::EINVAL));
        assert_eq!(signal_from_string("RTMIN+99"), Err(Errno::ERANGE));
        assert_eq!(signal_from_string("BOGUS"), Err(Errno::EINVAL));
    }

    #[test]
    fn parse_signo_requires_numeric_valid_input() {
        assert_eq!(parse_signo("9"), Ok(9));
        assert_eq!(parse_signo("0"), Err(Errno::EINVAL));
        assert_eq!(parse_signo("TERM"), Err(Errno::EINVAL));
    }

    #[test]
    fn si_code_from_process_matches_documented_rule() {
        assert!(si_code_from_process(-2));
        #[cfg(target_os = "linux")]
        {
            assert!(si_code_from_process(libc::SI_USER));
            assert!(si_code_from_process(libc::SI_QUEUE));
        }
        assert!(!si_code_from_process(42));
    }
}
