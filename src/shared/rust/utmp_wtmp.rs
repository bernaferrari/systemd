// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/utmp-wtmp.c, src/shared/utmp-wtmp.h
//
// UTMP/WTMP database access for login/logout records.
//
// Manages utmp (key/value table of current sessions) and wtmp
// (append-only log of session history) records. Provides functions
// to write shutdown, reboot, init process, and dead process entries.
//
// utmp maintains one entry per entry type/user (key/value semantics).
// wtmp is an append-only log where each entry is appended to the end.

use crate::ffi::*;
use std::ffi::CStr;
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Mutex;

// ── Constants ────────────────────────────────────────────────────────────

/// utmp record type: run-level change.
pub const RUN_LVL: i16 = 1;
/// utmp record type: system boot.
pub const BOOT_TIME: i16 = 2;
/// utmp record type: time change (new).
pub const NEW_TIME: i16 = 3;
/// utmp record type: time change (old).
pub const OLD_TIME: i16 = 4;
/// utmp record type: init process spawned.
pub const INIT_PROCESS: i16 = 5;
/// utmp record type: login process (e.g. getty).
pub const LOGIN_PROCESS: i16 = 6;
/// utmp record type: user login session.
pub const USER_PROCESS: i16 = 7;
/// utmp record type: process terminated.
pub const DEAD_PROCESS: i16 = 8;
/// utmp record type: accounting record.
pub const ACCOUNTING: i16 = 9;

const USEC_PER_SEC: u64 = 1_000_000;

/// Path to the utmp database (current sessions).
const UTMPX_FILE: &[u8] = b"/var/run/utmp\0";
/// Path to the wtmp database (session history log).
const WTMPX_FILE: &[u8] = b"/var/log/wtmp\0";

/// libc's utmp cursor and selected database path are process-global state.
static UTMP_LOCK: Mutex<()> = Mutex::new(());

// ── Error type ───────────────────────────────────────────────────────────

/// Errors from utmp/wtmp operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtmpError {
    /// OS-level error (encapsulates an errno value).
    Errno(i32),
    /// An invalid argument was provided.
    InvalidArgument(&'static str),
}

impl UtmpError {
    /// Convenience constant for invalid argument errors.
    pub const EINVAL: Self = Self::InvalidArgument("invalid argument");
}

impl fmt::Display for UtmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(e) => write!(f, "utmp/wtmp OS error (errno {e})"),
            Self::InvalidArgument(msg) => write!(f, "utmp/wtmp: {msg}"),
        }
    }
}

impl std::error::Error for UtmpError {}

// ── errno helpers ────────────────────────────────────────────────────────

/// Read the current thread-local errno value.
fn get_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Clear errno to zero before a call that may not set it on success.
///
/// `updwtmpx(3)` has no formal error return, so we defensively check
/// errno after the call. Clearing first avoids false positives from
/// leftover errno values.
fn clear_errno() {
    crate::ffi::clear_errno();
}

// ── Record structures ────────────────────────────────────────────────────

/// Exact libc representation of an exit status attached to a utmp record.
pub type UtmpxExit = libc::__exit_status;

/// Exact libc representation used for all utmp/wtmp storage and FFI calls.
pub type Utmpx = libc::utmpx;

/// Construct an all-zero libc utmpx record.
///
/// Every public field is an integer or integer array, so the all-zero bit
/// pattern is valid. Zeroing the complete object also initializes padding
/// before the record is copied to libc.
fn zeroed_utmpx() -> Utmpx {
    // SAFETY: libc::utmpx contains only integer fields, integer arrays, and
    // padding on supported Linux targets; zero is valid for every field.
    unsafe_ffi!(MaybeUninit::<Utmpx>::zeroed().assume_init())
}

/// Construct an all-zero libc exit status.
#[cfg(test)]
fn zeroed_utmpx_exit() -> UtmpxExit {
    // SAFETY: both libc::__exit_status fields are c_short integers.
    unsafe_ffi!(MaybeUninit::<UtmpxExit>::zeroed().assume_init())
}

/// Copy a libc utmpx record exactly, including its target-specific padding.
fn copy_utmpx(source: &Utmpx) -> Utmpx {
    let mut destination = MaybeUninit::<Utmpx>::uninit();
    // SAFETY: source is a live initialized libc::utmpx and destination is
    // correctly aligned, non-overlapping storage for exactly one record.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), 1);
        destination.assume_init()
    })
}

#[cfg(test)]
fn utmpx_exit_eq(left: &UtmpxExit, right: &UtmpxExit) -> bool {
    left.e_termination == right.e_termination && left.e_exit == right.e_exit
}

/// Compare initialized public fields, never padding bytes.
#[cfg(test)]
fn utmpx_eq(left: &Utmpx, right: &Utmpx) -> bool {
    left.ut_type == right.ut_type
        && left.ut_pid == right.ut_pid
        && left.ut_line == right.ut_line
        && left.ut_id == right.ut_id
        && left.ut_user == right.ut_user
        && left.ut_host == right.ut_host
        && utmpx_exit_eq(&left.ut_exit, &right.ut_exit)
        && left.ut_session == right.ut_session
        && left.ut_tv.tv_sec == right.ut_tv.tv_sec
        && left.ut_tv.tv_usec == right.ut_tv.tv_usec
        && left.ut_addr_v6 == right.ut_addr_v6
}

// ── Private helpers: fixed-buffer string operations ──────────────────────

/// Copy a Rust string into a fixed-size C char buffer.
///
/// If the string fits (including NUL terminator), it is NUL-terminated.
/// If it does not fit, the buffer is filled with as many bytes as possible
/// without a trailing NUL (matches `strncpy` semantics for utmp fields).
fn copy_str_to_fixed(buf: &mut [libc::c_char], src: &str) {
    let bytes = src.as_bytes();
    let len = buf.len();
    let n = bytes.len().min(len);
    for (i, &b) in bytes.iter().enumerate().take(n) {
        buf[i] = b as libc::c_char;
    }
    if n < len {
        buf[n] = 0;
    }
}

/// Copy a NUL-terminated C string into a fixed-size buffer.
fn copy_cstr_to_fixed(buf: &mut [libc::c_char], src: *const libc::c_char) {
    if src.is_null() {
        return;
    }
    // SAFETY: caller guarantees src is a valid NUL-terminated C string.
    let bytes = unsafe_ffi!(CStr::from_ptr(src)).to_bytes();
    let len = buf.len();
    let n = bytes.len().min(len);
    for (i, &b) in bytes.iter().enumerate().take(n) {
        buf[i] = b as libc::c_char;
    }
    if n < len {
        buf[n] = 0;
    }
}

/// Copy the suffix of `src` into a fixed-size buffer.
///
/// If `src` is shorter than the buffer, copies the whole string NUL-terminated.
/// Otherwise, copies only the last `buf.len()` bytes without a NUL terminator.
/// This matches the C `copy_suffix()` behavior for utmp ID fields.
fn copy_suffix_to_fixed(buf: &mut [libc::c_char], src: &str) {
    let bytes = src.as_bytes();
    let buf_len = buf.len();
    if bytes.len() < buf_len {
        copy_str_to_fixed(buf, src);
    } else {
        // Copy last buf_len bytes without NUL terminator.
        let start = bytes.len() - buf_len;
        for (i, &b) in bytes[start..].iter().enumerate() {
            buf[i] = b as libc::c_char;
        }
    }
}

// ── Private helpers: timestamp and entry initialization ──────────────────

/// Get the current realtime clock in microseconds.
fn now_realtime_usec() -> u64 {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: gettimeofday with null timezone pointer is always safe.
    unsafe_ffi!({
        libc::gettimeofday(&mut tv, ptr::null_mut());
    });
    (tv.tv_sec as u64) * USEC_PER_SEC + (tv.tv_usec as u64)
}

/// Set the timestamp on a utmp entry.
///
/// If `t` is `None`, uses the current realtime clock.
fn init_timestamp(store: &mut Utmpx, t: Option<u64>) {
    // The C API treats zero as "now", rather than as the Unix epoch.
    let usec = t
        .filter(|value| *value > 0)
        .unwrap_or_else(now_realtime_usec);
    store.ut_tv.tv_sec = (usec / USEC_PER_SEC) as _;
    store.ut_tv.tv_usec = (usec % USEC_PER_SEC) as _;
}

/// Initialize a utmp entry with timestamp, kernel release, line, and ID.
///
/// Sets `ut_line` to "~" and `ut_id` to "~~" (convention for system records).
fn init_entry(store: &mut Utmpx, t: Option<u64>) {
    init_timestamp(store, t);

    let mut uts = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uts` is correctly aligned writable storage for one `utsname`.
    if unsafe_ffi!(libc::uname(uts.as_mut_ptr())) >= 0 {
        // SAFETY: a successful uname call initializes the complete utsname
        // record before this success-only read.
        let uts = unsafe_ffi!(uts.assume_init());
        copy_cstr_to_fixed(&mut store.ut_host, uts.release.as_ptr());
    }

    copy_str_to_fixed(&mut store.ut_line, "~");
    copy_str_to_fixed(&mut store.ut_id, "~~");
}

// ── Private helpers: utmp/wtmp write operations ──────────────────────────

/// Write an entry to the utmp database (key/value table).
///
/// utmp maintains one entry per type/ID. If utmp is disabled (ENOENT),
/// the error is silently ignored.
fn write_entry_utmp(store: &Utmpx) -> Result<(), UtmpError> {
    // setutxent()/pututxline()/endutxent() use process-global cursor state and
    // are not thread-safe. Serialize the complete transaction.
    let _guard = UTMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: `store` is the exact libc record type and the filename is a
    // static NUL-terminated C string.
    unsafe_ffi!({
        if libc::utmpxname(UTMPX_FILE.as_ptr().cast()) < 0 {
            return Err(UtmpError::Errno(get_errno()));
        }

        libc::setutxent();
        let result = libc::pututxline(store);
        libc::endutxent();

        if result.is_null() {
            let e = get_errno();
            if e == libc::ENOENT {
                // utmp file does not exist — not an error (feature disabled).
                return Ok(());
            }
            return Err(UtmpError::Errno(e));
        }
    });
    Ok(())
}

/// Append an entry to the wtmp database (append-only log).
///
/// Since `updwtmpx(3)` has no formal error return, we defensively check
/// errno. ENOENT (disabled) and EROFS (read-only filesystem) are silently
/// ignored.
fn write_entry_wtmp(store: &Utmpx) -> Result<(), UtmpError> {
    clear_errno();
    // SAFETY: updwtmpx is thread-safe.
    unsafe_ffi!({
        crate::ffi::updwtmpx(WTMPX_FILE.as_ptr().cast(), store);
    });
    match get_errno() {
        0 => Ok(()),
        e if e == libc::ENOENT => Ok(()),
        e if e == libc::EROFS => Ok(()),
        e => Err(UtmpError::Errno(e)),
    }
}

/// Write entries to both utmp and wtmp.
///
/// Returns the utmp error if it failed; otherwise returns the wtmp result.
fn write_utmp_wtmp(store_utmp: &Utmpx, store_wtmp: &Utmpx) -> Result<(), UtmpError> {
    // Match C: attempt both databases even when the utmp write fails, then
    // prefer the utmp error over the wtmp result.
    let utmp_result = write_entry_utmp(store_utmp);
    let wtmp_result = write_entry_wtmp(store_wtmp);
    utmp_result.and(wtmp_result)
}

/// Write the same entry to both utmp and wtmp.
fn write_entry_both(store: &Utmpx) -> Result<(), UtmpError> {
    write_utmp_wtmp(store, store)
}

fn validate_init_process_inputs(
    id: &str,
    pid: u32,
    sid: u32,
    line: Option<&str>,
    ut_type: i16,
    user: Option<&str>,
) -> Result<(libc::pid_t, libc::pid_t), UtmpError> {
    if id.is_empty()
        || id.as_bytes().contains(&0)
        || line.is_some_and(|value| value.as_bytes().contains(&0))
        || user.is_some_and(|value| value.as_bytes().contains(&0))
        || (ut_type == USER_PROCESS && user.is_none())
    {
        return Err(UtmpError::EINVAL);
    }

    let pid = libc::pid_t::try_from(pid).map_err(|_| UtmpError::EINVAL)?;
    let sid = libc::pid_t::try_from(sid).map_err(|_| UtmpError::EINVAL)?;
    Ok((pid, sid))
}

fn validate_dead_process_inputs(id: &str, pid: u32) -> Result<libc::pid_t, UtmpError> {
    if id.is_empty() || id.as_bytes().contains(&0) {
        return Err(UtmpError::EINVAL);
    }
    libc::pid_t::try_from(pid).map_err(|_| UtmpError::EINVAL)
}

// ── Public API ───────────────────────────────────────────────────────────

/// Write a shutdown record to utmp/wtmp.
///
/// Creates a `RUN_LVL` entry with user "shutdown".
pub fn utmp_put_shutdown() -> Result<(), UtmpError> {
    let mut store = zeroed_utmpx();
    init_entry(&mut store, None);
    store.ut_type = RUN_LVL;
    copy_str_to_fixed(&mut store.ut_user, "shutdown");
    write_entry_both(&store)
}

/// Write a reboot record to utmp/wtmp.
///
/// Creates a `BOOT_TIME` entry with user "reboot".
/// If `timestamp` is `None`, uses the current time.
pub fn utmp_put_reboot(timestamp: Option<u64>) -> Result<(), UtmpError> {
    let mut store = zeroed_utmpx();
    init_entry(&mut store, timestamp);
    store.ut_type = BOOT_TIME;
    copy_str_to_fixed(&mut store.ut_user, "reboot");
    write_entry_both(&store)
}

/// Write an init process record (and optional login/user records) to utmp/wtmp.
///
/// This writes up to three entries depending on `ut_type`:
/// - Always: an `INIT_PROCESS` record
/// - If `ut_type` is `LOGIN_PROCESS` or `USER_PROCESS`: a `LOGIN_PROCESS` record
/// - If `ut_type` is `USER_PROCESS`: a `USER_PROCESS` record with the given `user`
///
/// # Errors
///
/// Returns [`UtmpError::EINVAL`] if `id` is empty, or if `ut_type` is
/// `USER_PROCESS` but `user` is `None`.
pub fn utmp_put_init_process(
    id: &str,
    pid: u32,
    sid: u32,
    line: Option<&str>,
    ut_type: i16,
    user: Option<&str>,
) -> Result<(), UtmpError> {
    let (pid, sid) = validate_init_process_inputs(id, pid, sid, line, ut_type, user)?;

    let mut store = zeroed_utmpx();
    store.ut_type = INIT_PROCESS;
    store.ut_pid = pid;
    store.ut_session = sid as _;
    init_timestamp(&mut store, None);
    copy_suffix_to_fixed(&mut store.ut_id, id);

    if let Some(l) = line {
        copy_str_to_fixed(&mut store.ut_line, l);
    }

    write_entry_both(&store)?;

    if ut_type == LOGIN_PROCESS || ut_type == USER_PROCESS {
        store.ut_type = LOGIN_PROCESS;
        write_entry_both(&store)?;
    }

    if ut_type == USER_PROCESS {
        store.ut_type = USER_PROCESS;
        if let Some(u) = user {
            copy_str_to_fixed(&mut store.ut_user, u);
        }
        write_entry_both(&store)?;
    }

    Ok(())
}

/// Write a dead process record to utmp/wtmp.
///
/// Looks up the existing utmp entry matching `id` and `pid`, then writes
/// a `DEAD_PROCESS` record. The utmp entry retains the original timestamp
/// while the wtmp entry gets a fresh timestamp.
///
/// Returns `Ok(())` if no matching entry is found (nothing to do).
///
/// # Errors
///
/// Returns [`UtmpError::EINVAL`] if `id` is empty.
pub fn utmp_put_dead_process(id: &str, pid: u32, code: i32, status: i32) -> Result<(), UtmpError> {
    let pid = validate_dead_process_inputs(id, pid)?;

    let mut lookup = zeroed_utmpx();
    // getutxid searches for DEAD_PROCESS, LOGIN_PROCESS, USER_PROCESS too.
    lookup.ut_type = INIT_PROCESS;
    copy_suffix_to_fixed(&mut lookup.ut_id, id);

    // libc's utmp cursor is process-global. Keep it locked until the returned
    // internal record has been copied into Rust-owned storage.
    let found = {
        let _guard = UTMP_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: `lookup` is an exact libc record; any returned pointer is
        // copied before endutxent() invalidates libc's internal storage.
        unsafe_ffi!({
            libc::setutxent();
            let ptr = libc::getutxid(&lookup);
            let found = if ptr.is_null() {
                None
            } else {
                // Copy libc's internal record before endutxent() may invalidate it.
                Some(copy_utmpx(&*ptr))
            };
            libc::endutxent();
            found
        })
    };

    let Some(mut store) = found else {
        return Ok(());
    };

    if store.ut_pid != pid {
        return Ok(());
    }

    store.ut_type = DEAD_PROCESS;
    store.ut_exit.e_termination = code as libc::c_short;
    store.ut_exit.e_exit = status as libc::c_short;

    // Clear user, host, and timestamp for the utmp entry.
    store.ut_user.fill(0);
    store.ut_host.fill(0);
    store.ut_tv.tv_sec = 0;
    store.ut_tv.tv_usec = 0;

    // wtmp gets a fresh timestamp.
    let mut store_wtmp = copy_utmpx(&store);
    init_timestamp(&mut store_wtmp, None);

    write_utmp_wtmp(&store, &store_wtmp)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_ut_type_constants_match_linux_utmpx() {
        assert_eq!(RUN_LVL, 1);
        assert_eq!(BOOT_TIME, 2);
        assert_eq!(NEW_TIME, 3);
        assert_eq!(OLD_TIME, 4);
        assert_eq!(INIT_PROCESS, 5);
        assert_eq!(LOGIN_PROCESS, 6);
        assert_eq!(USER_PROCESS, 7);
        assert_eq!(DEAD_PROCESS, 8);
        assert_eq!(ACCOUNTING, 9);
    }

    #[test]
    fn test_usecs_per_sec() {
        assert_eq!(USEC_PER_SEC, 1_000_000);
    }

    // ── UtmpxExit ────────────────────────────────────────────────────────

    #[test]
    fn test_utmpx_exit_default() {
        let exit = zeroed_utmpx_exit();
        assert_eq!(exit.e_termination, 0);
        assert_eq!(exit.e_exit, 0);
    }

    #[test]
    fn test_utmpx_exit_equality() {
        let a = UtmpxExit {
            e_termination: 1,
            e_exit: 2,
        };
        let b = UtmpxExit {
            e_termination: 1,
            e_exit: 2,
        };
        assert!(utmpx_exit_eq(&a, &b));
        let c = UtmpxExit {
            e_termination: 9,
            e_exit: 0,
        };
        assert!(!utmpx_exit_eq(&a, &c));
    }

    // ── Utmpx ────────────────────────────────────────────────────────────

    #[test]
    fn test_utmpx_default_is_zeroed() {
        let u = zeroed_utmpx();
        assert_eq!(u.ut_type, 0);
        assert_eq!(u.ut_pid, 0);
        assert_eq!(u.ut_session, 0);
        assert!(utmpx_exit_eq(&u.ut_exit, &zeroed_utmpx_exit()));
        assert_eq!(u.ut_tv.tv_sec, 0);
        assert_eq!(u.ut_tv.tv_usec, 0);
        assert!(u.ut_addr_v6.iter().all(|&v| v == 0));
    }

    #[test]
    fn test_utmpx_equality() {
        let a = zeroed_utmpx();
        let mut b = zeroed_utmpx();
        assert!(utmpx_eq(&a, &b));

        b.ut_pid = 42;
        assert!(!utmpx_eq(&a, &b));

        let mut c = zeroed_utmpx();
        c.ut_type = BOOT_TIME;
        assert!(!utmpx_eq(&a, &c));
    }

    #[test]
    fn test_utmpx_clone_and_copy() {
        let mut a = zeroed_utmpx();
        a.ut_type = BOOT_TIME;
        a.ut_pid = 1234;
        let b = copy_utmpx(&a);
        assert_eq!(b.ut_type, BOOT_TIME);
        assert_eq!(b.ut_pid, 1234);

        let c = copy_utmpx(&b);
        assert!(utmpx_eq(&c, &b));
    }

    // ── copy_str_to_fixed ────────────────────────────────────────────────

    #[test]
    fn test_copy_str_to_fixed_short() {
        let mut buf = [0 as libc::c_char; 32];
        copy_str_to_fixed(&mut buf, "hello");
        assert_eq!(
            &buf[..6],
            &[
                b'h' as libc::c_char,
                b'e' as libc::c_char,
                b'l' as libc::c_char,
                b'l' as libc::c_char,
                b'o' as libc::c_char,
                0,
            ]
        );
    }

    #[test]
    fn test_copy_str_to_fixed_exact_fit() {
        // "hello" = 5 bytes + 1 NUL = exactly 6
        let mut buf = [0 as libc::c_char; 6];
        copy_str_to_fixed(&mut buf, "hello");
        assert_eq!(
            &buf[..],
            &[
                b'h' as libc::c_char,
                b'e' as libc::c_char,
                b'l' as libc::c_char,
                b'l' as libc::c_char,
                b'o' as libc::c_char,
                0,
            ]
        );
    }

    #[test]
    fn test_copy_str_to_fixed_truncated() {
        let mut buf = [0 as libc::c_char; 4];
        copy_str_to_fixed(&mut buf, "hello world");
        // Truncated: "hell" with no NUL terminator (matches strncpy semantics)
        assert_eq!(
            &buf[..],
            &[
                b'h' as libc::c_char,
                b'e' as libc::c_char,
                b'l' as libc::c_char,
                b'l' as libc::c_char,
            ]
        );
    }

    #[test]
    fn test_copy_str_to_fixed_empty() {
        let mut buf = [42 as libc::c_char; 8];
        copy_str_to_fixed(&mut buf, "");
        assert_eq!(buf[0], 0); // NUL-terminated empty string
    }

    // ── copy_suffix_to_fixed ─────────────────────────────────────────────

    #[test]
    fn test_copy_suffix_to_fixed_short() {
        let mut buf = [0 as libc::c_char; 32];
        copy_suffix_to_fixed(&mut buf, "abc");
        assert_eq!(
            &buf[..4],
            &[
                b'a' as libc::c_char,
                b'b' as libc::c_char,
                b'c' as libc::c_char,
                0,
            ]
        );
    }

    #[test]
    fn test_copy_suffix_to_fixed_exact() {
        let mut buf = [0 as libc::c_char; 3];
        copy_suffix_to_fixed(&mut buf, "abc");
        // Exact fit: no NUL terminator (matches C behavior)
        assert_eq!(
            &buf[..],
            &[
                b'a' as libc::c_char,
                b'b' as libc::c_char,
                b'c' as libc::c_char,
            ]
        );
    }

    #[test]
    fn test_copy_suffix_to_fixed_long() {
        let mut buf = [0 as libc::c_char; 3];
        copy_suffix_to_fixed(&mut buf, "abcdef");
        assert_eq!(
            &buf[..],
            &[
                b'd' as libc::c_char,
                b'e' as libc::c_char,
                b'f' as libc::c_char,
            ]
        );
    }

    #[test]
    fn test_copy_suffix_to_fixed_empty() {
        let mut buf = [42 as libc::c_char; 4];
        copy_suffix_to_fixed(&mut buf, "");
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_copy_suffix_to_fixed_one_byte_over() {
        let mut buf = [0 as libc::c_char; 3];
        copy_suffix_to_fixed(&mut buf, "abcd");
        // "abcd" is 4 bytes, buf is 3 → copy last 3: "bcd"
        assert_eq!(
            &buf[..],
            &[
                b'b' as libc::c_char,
                b'c' as libc::c_char,
                b'd' as libc::c_char,
            ]
        );
    }

    // ── init_timestamp ───────────────────────────────────────────────────

    #[test]
    fn test_init_timestamp_specific() {
        let mut store = zeroed_utmpx();
        init_timestamp(&mut store, Some(1_700_000_000_000_000));
        assert_eq!(store.ut_tv.tv_sec, 1_700_000_000);
        assert_eq!(store.ut_tv.tv_usec, 0);
    }

    #[test]
    fn test_init_timestamp_with_fractional_usecs() {
        let mut store = zeroed_utmpx();
        init_timestamp(&mut store, Some(1_500_000_001_000_234));
        assert_eq!(store.ut_tv.tv_sec, 1_500_000_001);
        assert_eq!(store.ut_tv.tv_usec, 234);
    }

    #[test]
    fn test_init_timestamp_zero_usecs() {
        let mut store = zeroed_utmpx();
        init_timestamp(&mut store, Some(0));
        assert!(store.ut_tv.tv_sec > 0);
        assert!((0..USEC_PER_SEC as _).contains(&store.ut_tv.tv_usec));
    }

    // ── init_entry ───────────────────────────────────────────────────────

    #[test]
    fn test_init_entry_populates_line_and_id() {
        let mut store = zeroed_utmpx();
        init_entry(&mut store, Some(0));
        assert_eq!(&store.ut_line[..2], &[b'~' as libc::c_char, 0]);
        assert_eq!(
            &store.ut_id[..3],
            &[b'~' as libc::c_char, b'~' as libc::c_char, 0]
        );
    }

    // ── UtmpError ────────────────────────────────────────────────────────

    #[test]
    fn test_utmp_error_display() {
        let e = UtmpError::Errno(2);
        assert!(e.to_string().contains("errno 2"));

        let e = UtmpError::InvalidArgument("bad id");
        assert!(e.to_string().contains("bad id"));
    }

    #[test]
    fn test_utmp_error_equality() {
        assert_eq!(UtmpError::Errno(2), UtmpError::Errno(2));
        assert_ne!(UtmpError::Errno(2), UtmpError::Errno(3));
        assert_eq!(UtmpError::EINVAL, UtmpError::EINVAL);
        assert_ne!(UtmpError::EINVAL, UtmpError::Errno(libc::EINVAL));
    }

    #[test]
    fn test_utmp_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UtmpError>();
    }

    #[test]
    fn test_utmp_error_debug() {
        let e = UtmpError::Errno(13);
        let debug = format!("{:?}", e);
        assert!(debug.contains("Errno(13)"));

        let e = UtmpError::EINVAL;
        let debug = format!("{:?}", e);
        assert!(debug.contains("InvalidArgument"));
    }

    // ── Input validation ─────────────────────────────────────────────────

    #[test]
    fn test_init_process_rejects_empty_id() {
        let result = validate_init_process_inputs("", 1, 1, None, INIT_PROCESS, None);
        assert_eq!(result.unwrap_err(), UtmpError::EINVAL);
    }

    #[test]
    fn test_init_process_rejects_user_process_without_user() {
        let result = validate_init_process_inputs("si", 1, 1, None, USER_PROCESS, None);
        assert_eq!(result.unwrap_err(), UtmpError::EINVAL);
    }

    #[test]
    fn test_dead_process_rejects_empty_id() {
        let result = validate_dead_process_inputs("", 1);
        assert_eq!(result.unwrap_err(), UtmpError::EINVAL);
    }

    #[test]
    fn test_inputs_reject_embedded_nul() {
        assert_eq!(
            validate_init_process_inputs("s\0i", 1, 1, None, INIT_PROCESS, None),
            Err(UtmpError::EINVAL)
        );
        assert_eq!(
            validate_init_process_inputs("si", 1, 1, Some("tty\0x"), INIT_PROCESS, None),
            Err(UtmpError::EINVAL)
        );
        assert_eq!(
            validate_init_process_inputs("si", 1, 1, None, USER_PROCESS, Some("u\0ser")),
            Err(UtmpError::EINVAL)
        );
        assert_eq!(
            validate_dead_process_inputs("s\0i", 1),
            Err(UtmpError::EINVAL)
        );
    }

    #[test]
    fn test_inputs_reject_pid_values_outside_pid_t() {
        assert_eq!(
            validate_init_process_inputs("si", u32::MAX, 1, None, INIT_PROCESS, None),
            Err(UtmpError::EINVAL)
        );
        assert_eq!(
            validate_init_process_inputs("si", 1, u32::MAX, None, INIT_PROCESS, None),
            Err(UtmpError::EINVAL)
        );
        assert_eq!(
            validate_dead_process_inputs("si", u32::MAX),
            Err(UtmpError::EINVAL)
        );
    }

    #[test]
    fn test_valid_inputs_are_accepted_without_touching_utmp() {
        assert_eq!(
            validate_init_process_inputs("si", 1, 1, None, INIT_PROCESS, None),
            Ok((1, 1))
        );
        assert_eq!(
            validate_init_process_inputs("si", 1, 1, Some("tty1"), USER_PROCESS, Some("user")),
            Ok((1, 1))
        );
        assert_eq!(validate_dead_process_inputs("si", 1), Ok(1));
    }
}
