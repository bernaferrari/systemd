// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/errno-util.c, src/basic/errno-list.c
//
// Errno utility functions and errno name/value lookups.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
/* removed: use i32 */

use std::ffi::CStr;
use std::ptr;

use crate::ffi::Errno;

// ── Constants ──────────────────────────────────────────────────────────────

pub const ERRNO_MAX: i32 = 4095;
pub const ERRNO_BUF_LEN: usize = 1024;

// ── OS errno access ────────────────────────────────────────────────────────

fn get_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Returns -errno, or `-EINVAL` if errno is not positive.
/// Mirrors C `negative_errno()`.
pub fn negative_errno() -> i32 {
    let e = get_errno();
    if e <= 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    -e
}

/// Wraps syscall return values: if ret < 0, returns -errno.
/// Mirrors C `RET_NERRNO(ret)`.
pub fn ret_nerrno(ret: i32) -> i32 {
    if ret < 0 { negative_errno() } else { ret }
}

/// Returns -errno if set, otherwise -|fallback|.
/// Mirrors C `errno_or_else(fallback)`.
pub fn errno_or_else(fallback: i32) -> i32 {
    let e = get_errno();
    if e > 0 {
        return -e;
    }
    fallback.checked_abs().map_or(-libc::EINVAL, |error| -error)
}

// ── strerror_or_eof ────────────────────────────────────────────────────────

/// Return an error message string for errnum, or "Unexpected EOF" for 0.
/// Mirrors C `strerror_or_eof()`.
pub fn strerror_or_eof(errnum: i32) -> String {
    if errnum != 0 {
        let error = errnum.checked_abs().unwrap_or(libc::EINVAL);
        std::io::Error::from_raw_os_error(error).to_string()
    } else {
        "Unexpected EOF".to_string()
    }
}

// ── errno-from-name lookup table ────────────────────────────────────────────

static ERRNO_FROM_NAME_TABLE: &[(&[u8], i32)] = &[
    (b"E2BIG", libc::E2BIG),
    (b"EACCES", libc::EACCES),
    (b"EADDRINUSE", libc::EADDRINUSE),
    (b"EADDRNOTAVAIL", libc::EADDRNOTAVAIL),
    (b"EADV", libc::EADV),
    (b"EAFNOSUPPORT", libc::EAFNOSUPPORT),
    (b"EAGAIN", libc::EAGAIN),
    (b"EALREADY", libc::EALREADY),
    (b"EBADE", libc::EBADE),
    (b"EBADF", libc::EBADF),
    (b"EBADFD", libc::EBADFD),
    (b"EBADMSG", libc::EBADMSG),
    (b"EBADR", libc::EBADR),
    (b"EBADRQC", libc::EBADRQC),
    (b"EBADSLT", libc::EBADSLT),
    (b"EBFONT", libc::EBFONT),
    (b"EBUSY", libc::EBUSY),
    (b"ECANCELED", libc::ECANCELED),
    (b"ECHILD", libc::ECHILD),
    (b"ECHRNG", libc::ECHRNG),
    (b"ECOMM", libc::ECOMM),
    (b"ECONNABORTED", libc::ECONNABORTED),
    (b"ECONNREFUSED", libc::ECONNREFUSED),
    (b"ECONNRESET", libc::ECONNRESET),
    (b"EDEADLK", libc::EDEADLK),
    (b"EDEADLOCK", libc::EDEADLOCK),
    (b"EDESTADDRREQ", libc::EDESTADDRREQ),
    (b"EDOM", libc::EDOM),
    (b"EDOTDOT", libc::EDOTDOT),
    (b"EDQUOT", libc::EDQUOT),
    (b"EEXIST", libc::EEXIST),
    (b"EFAULT", libc::EFAULT),
    (b"EFBIG", libc::EFBIG),
    (b"EHOSTDOWN", libc::EHOSTDOWN),
    (b"EHOSTUNREACH", libc::EHOSTUNREACH),
    (b"EIDRM", libc::EIDRM),
    (b"EILSEQ", libc::EILSEQ),
    (b"EINPROGRESS", libc::EINPROGRESS),
    (b"EINTR", libc::EINTR),
    (b"EINVAL", libc::EINVAL),
    (b"EIO", libc::EIO),
    (b"EISCONN", libc::EISCONN),
    (b"EISDIR", libc::EISDIR),
    (b"EISNAM", libc::EISNAM),
    (b"EKEYEXPIRED", libc::EKEYEXPIRED),
    (b"EKEYREJECTED", libc::EKEYREJECTED),
    (b"EKEYREVOKED", libc::EKEYREVOKED),
    (b"EL2HLT", libc::EL2HLT),
    (b"EL2NSYNC", libc::EL2NSYNC),
    (b"EL3HLT", libc::EL3HLT),
    (b"EL3RST", libc::EL3RST),
    (b"ELIBACC", libc::ELIBACC),
    (b"ELIBBAD", libc::ELIBBAD),
    (b"ELIBEXEC", libc::ELIBEXEC),
    (b"ELIBMAX", libc::ELIBMAX),
    (b"ELIBSCN", libc::ELIBSCN),
    (b"ELNRNG", libc::ELNRNG),
    (b"ELOOP", libc::ELOOP),
    (b"EMEDIUMTYPE", libc::EMEDIUMTYPE),
    (b"EMFILE", libc::EMFILE),
    (b"EMLINK", libc::EMLINK),
    (b"EMSGSIZE", libc::EMSGSIZE),
    (b"EMULTIHOP", libc::EMULTIHOP),
    (b"ENAMETOOLONG", libc::ENAMETOOLONG),
    (b"ENAVAIL", libc::ENAVAIL),
    (b"ENETDOWN", libc::ENETDOWN),
    (b"ENETRESET", libc::ENETRESET),
    (b"ENETUNREACH", libc::ENETUNREACH),
    (b"ENFILE", libc::ENFILE),
    (b"ENOANO", libc::ENOANO),
    (b"ENOBUFS", libc::ENOBUFS),
    (b"ENOCSI", libc::ENOCSI),
    (b"ENODATA", libc::ENODATA),
    (b"ENODEV", libc::ENODEV),
    (b"ENOENT", libc::ENOENT),
    (b"ENOEXEC", libc::ENOEXEC),
    (b"ENOKEY", libc::ENOKEY),
    (b"ENOLCK", libc::ENOLCK),
    (b"ENOLINK", libc::ENOLINK),
    (b"ENOMEDIUM", libc::ENOMEDIUM),
    (b"ENOMEM", libc::ENOMEM),
    (b"ENOMSG", libc::ENOMSG),
    (b"ENONET", libc::ENONET),
    (b"ENOPKG", libc::ENOPKG),
    (b"ENOPROTOOPT", libc::ENOPROTOOPT),
    (b"ENOSPC", libc::ENOSPC),
    (b"ENOSR", libc::ENOSR),
    (b"ENOSTR", libc::ENOSTR),
    (b"ENOSYS", libc::ENOSYS),
    (b"ENOTBLK", libc::ENOTBLK),
    (b"ENOTCONN", libc::ENOTCONN),
    (b"ENOTDIR", libc::ENOTDIR),
    (b"ENOTEMPTY", libc::ENOTEMPTY),
    (b"ENOTNAM", libc::ENOTNAM),
    (b"ENOTRECOVERABLE", libc::ENOTRECOVERABLE),
    (b"ENOTSOCK", libc::ENOTSOCK),
    (b"ENOTSUP", libc::ENOTSUP),
    (b"ENOTTY", libc::ENOTTY),
    (b"ENOTUNIQ", libc::ENOTUNIQ),
    (b"ENXIO", libc::ENXIO),
    (b"EOPNOTSUPP", libc::EOPNOTSUPP),
    (b"EOVERFLOW", libc::EOVERFLOW),
    (b"EOWNERDEAD", libc::EOWNERDEAD),
    (b"EPERM", libc::EPERM),
    (b"EPFNOSUPPORT", libc::EPFNOSUPPORT),
    (b"EPIPE", libc::EPIPE),
    (b"EPROTO", libc::EPROTO),
    (b"EPROTONOSUPPORT", libc::EPROTONOSUPPORT),
    (b"EPROTOTYPE", libc::EPROTOTYPE),
    (b"ERANGE", libc::ERANGE),
    (b"EREMCHG", libc::EREMCHG),
    (b"EREMOTE", libc::EREMOTE),
    (b"EREMOTEIO", libc::EREMOTEIO),
    (b"ERESTART", libc::ERESTART),
    (b"ERFKILL", libc::ERFKILL),
    (b"EHWPOISON", libc::EHWPOISON),
    (b"EROFS", libc::EROFS),
    (b"ESHUTDOWN", libc::ESHUTDOWN),
    (b"ESOCKTNOSUPPORT", libc::ESOCKTNOSUPPORT),
    (b"ESPIPE", libc::ESPIPE),
    (b"ESRCH", libc::ESRCH),
    (b"ESRMNT", libc::ESRMNT),
    (b"ESTALE", libc::ESTALE),
    (b"ESTRPIPE", libc::ESTRPIPE),
    (b"ETIME", libc::ETIME),
    (b"ETIMEDOUT", libc::ETIMEDOUT),
    (b"ETOOMANYREFS", libc::ETOOMANYREFS),
    (b"ETXTBSY", libc::ETXTBSY),
    (b"EUCLEAN", libc::EUCLEAN),
    (b"EUNATCH", libc::EUNATCH),
    (b"EUSERS", libc::EUSERS),
    (b"EWOULDBLOCK", libc::EWOULDBLOCK),
    (b"EXDEV", libc::EXDEV),
    (b"EXFULL", libc::EXFULL),
];

// ── errno-to-name lookup table ──────────────────────────────────────────────

// The generated list uses the same target-preprocessor output as the C table.
// Its C strings have static storage, so the C ABI never receives Rust-owned
// allocation.
#[cfg(not(target_env = "gnu"))]
include!(env!("SYSTEMD_ERRNO_TO_NAME_RS"));

// ── errno_from_name ────────────────────────────────────────────────────────

fn errno_from_name_bytes(name: &[u8]) -> Result<i32, i32> {
    if name.is_empty() {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    for &(entry_name, val) in ERRNO_FROM_NAME_TABLE {
        if name == entry_name {
            return Ok(val);
        }
    }
    Err(Errno::EINVAL.to_neg_errno())
}

pub fn errno_from_name(name: &str) -> Result<i32, i32> {
    errno_from_name_bytes(name.as_bytes())
}

// ── errno_name_no_fallback ─────────────────────────────────────────────────

#[cfg(target_env = "gnu")]
// SAFETY: this declaration binds glibc's immutable errno-name lookup; each
// call validates the returned pointer before constructing a CStr.
unsafe extern "C" {
    fn strerrorname_np(errnum: libc::c_int) -> *const libc::c_char;
}

pub fn errno_name_no_fallback_cstr(id: i32) -> Result<&'static CStr, i32> {
    let Some(id) = id.checked_abs() else {
        return Err(Errno::EINVAL.to_neg_errno());
    };
    if id == 0 {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    #[cfg(target_env = "gnu")]
    {
        // SAFETY: glibc returns either NULL or a pointer to an immutable
        // process-lifetime errno-name string, matching errno-list.c.
        let name = unsafe_ffi!(strerrorname_np(id));
        if name.is_null() {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        // SAFETY: the non-null pointer returned by strerrorname_np() is a
        // NUL-terminated string with static storage duration.
        return Ok(unsafe_ffi!(CStr::from_ptr(name)));
    }

    #[cfg(not(target_env = "gnu"))]
    {
        ERRNO_TO_NAME_TABLE
            .iter()
            .find_map(|&(candidate, name)| (candidate == id).then_some(name))
            .ok_or_else(|| Errno::EINVAL.to_neg_errno())
    }
}

pub fn errno_name_no_fallback(id: i32) -> Result<&'static str, i32> {
    errno_name_no_fallback_cstr(id)?
        .to_str()
        .map_err(|_| Errno::EINVAL.to_neg_errno())
}

// ── errno_is_valid ─────────────────────────────────────────────────────────

pub fn errno_is_valid(n: i32) -> bool {
    n > 0 && n <= ERRNO_MAX
}

// ── C ABI for errno-return helpers ─────────────────────────────────────────

/// Exact C ABI façade for `negative_errno()`.
///
/// Invalid nonpositive errno values, including `INT_MIN`, fail closed as
/// `-EINVAL`, matching the C helper's assert-return branch without invoking
/// signed-overflow undefined behavior.
#[unsafe(no_mangle)]
pub extern "C" fn rs_negative_errno() -> libc::c_int {
    negative_errno()
}

/// Exact C ABI façade for `RET_NERRNO()`.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn rs_RET_NERRNO(ret: libc::c_int) -> libc::c_int {
    ret_nerrno(ret)
}

/// Exact C ABI façade for `errno_or_else()`.
///
/// C's `ABS(INT_MIN)` is undefined. Rust instead returns `-EINVAL` for that
/// input when errno is unset, providing a deterministic fail-closed boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_errno_or_else(fallback: libc::c_int) -> libc::c_int {
    errno_or_else(fallback)
}

// systemd makes the GNU strerror_r contract available on every supported
// libc. musl provides it through src/libc/musl/string.c.
// SAFETY: this declaration is called only through the buffer-validating
// rs_strerror_or_eof adapter below.
unsafe extern "C" {
    #[cfg_attr(target_env = "musl", link_name = "strerror_r_gnu")]
    #[cfg_attr(not(target_env = "musl"), link_name = "strerror_r")]
    fn systemd_strerror_r(
        errnum: libc::c_int,
        buf: *mut libc::c_char,
        buflen: libc::size_t,
    ) -> *mut libc::c_char;
}

/// C ABI for `strerror_or_eof()`.
///
/// The returned pointer is either static libc/Rust storage or aliases `buf`;
/// Rust allocation ownership never crosses this boundary.
///
/// # Safety
///
/// For nonzero `errnum`, `buf` must be non-null and writable for `buflen`
/// bytes. The returned pointer follows the GNU `strerror_r()` lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strerror_or_eof(
    errnum: libc::c_int,
    buf: *mut libc::c_char,
    buflen: usize,
) -> *const libc::c_char {
    if errnum == 0 {
        return c"Unexpected EOF".as_ptr();
    }
    if buf.is_null() || buflen == 0 {
        return ptr::null();
    }
    let Some(errnum) = errnum.checked_abs() else {
        return ptr::null();
    };

    // SAFETY: the caller supplies the writable buffer and the checked
    // positive errno is representable by the C entry point.
    unsafe_ffi!(systemd_strerror_r(errnum, buf, buflen))
}

/// C ABI for `errno_from_name()`.
///
/// # Safety
///
/// `name` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_errno_from_name(name: *const libc::c_char) -> libc::c_int {
    if name.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: guaranteed by this entry point's caller contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(name)).to_bytes();
    errno_from_name_bytes(bytes).unwrap_or_else(|error| error)
}

/// C ABI for `errno_name_no_fallback()`.
///
/// The returned pointer has static lifetime and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn rs_errno_name_no_fallback(id: libc::c_int) -> *const libc::c_char {
    errno_name_no_fallback_cstr(id)
        .map(CStr::as_ptr)
        .unwrap_or_else(|_| ptr::null())
}

// ── C errno-classification ABI ────────────────────────────────────────────

/* These symbols deliberately use C's `intmax_t`, rather than Rust's `i64`.
 * `errno-util.h` accepts `intmax_t`, and preserving that type is what makes
 * the wrapper correct on every target even when `long` has a different width.
 * The safe core owns all classification; this layer only fixes the exported C
 * symbol names and calling convention. */

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_TRANSIENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_transient(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_TRANSIENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_transient(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_DISCONNECT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_disconnect(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_DISCONNECT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_disconnect(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_ACCEPT_AGAIN(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_accept_again(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_ACCEPT_AGAIN(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_accept_again(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_RESOURCE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_resource(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_RESOURCE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_resource(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_NOT_SUPPORTED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_not_supported(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NOT_SUPPORTED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_not_supported(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_ioctl_not_supported(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_IOCTL_NOT_SUPPORTED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_ioctl_not_supported(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_PRIVILEGE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_privilege(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_PRIVILEGE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_privilege(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_FS_WRITE_REFUSED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_fs_write_refused(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_FS_WRITE_REFUSED(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_fs_write_refused(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_DISK_SPACE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_disk_space(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_DISK_SPACE(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_disk_space(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_DEVICE_ABSENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_device_absent(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_DEVICE_ABSENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_device_absent(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_device_absent_or_empty(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_device_absent_or_empty(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_XATTR_ABSENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_xattr_absent(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_XATTR_ABSENT(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_xattr_absent(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_SECCOMP_FATAL(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_neg_seccomp_fatal(r)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_SECCOMP_FATAL(r: libc::intmax_t) -> bool {
    crate::errno_classify::errno_is_seccomp_fatal(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errno_from_name_common() {
        assert_eq!(errno_from_name("EPERM"), Ok(libc::EPERM));
        assert_eq!(errno_from_name("ENOENT"), Ok(libc::ENOENT));
        assert_eq!(errno_from_name("EINVAL"), Ok(libc::EINVAL));
        assert_eq!(errno_from_name("ENOMEM"), Ok(libc::ENOMEM));
        assert_eq!(errno_from_name("EACCES"), Ok(libc::EACCES));
        assert_eq!(errno_from_name("EAGAIN"), Ok(libc::EAGAIN));
        assert_eq!(errno_from_name("EWOULDBLOCK"), Ok(libc::EWOULDBLOCK));
        assert_eq!(errno_from_name("EPIPE"), Ok(libc::EPIPE));
    }

    #[test]
    fn test_errno_from_name_high_values() {
        assert_eq!(
            errno_from_name("ENOTRECOVERABLE"),
            Ok(libc::ENOTRECOVERABLE)
        );
        assert_eq!(errno_from_name("ERFKILL"), Ok(libc::ERFKILL));
        assert_eq!(errno_from_name("EHWPOISON"), Ok(libc::EHWPOISON));
        assert_eq!(errno_from_name("ECANCELED"), Ok(libc::ECANCELED));
    }

    #[test]
    fn test_errno_from_name_invalid() {
        assert_eq!(errno_from_name("INVALID_ERRNO"), Err(-libc::EINVAL));
        assert_eq!(errno_from_name(""), Err(-libc::EINVAL));
        assert_eq!(errno_from_name("eperm"), Err(-libc::EINVAL));
    }

    #[test]
    fn test_errno_from_name_aliases() {
        assert_eq!(errno_from_name("EDEADLK"), Ok(libc::EDEADLK));
        assert_eq!(errno_from_name("EDEADLOCK"), Ok(libc::EDEADLOCK));
        assert_eq!(errno_from_name("ENOTSUP"), Ok(libc::ENOTSUP));
        assert_eq!(errno_from_name("EOPNOTSUPP"), Ok(libc::EOPNOTSUPP));
    }

    #[test]
    fn test_errno_name_no_fallback_common() {
        assert_eq!(errno_name_no_fallback(libc::EPERM), Ok("EPERM"));
        assert_eq!(errno_name_no_fallback(libc::ENOENT), Ok("ENOENT"));
        assert_eq!(errno_name_no_fallback(libc::EINVAL), Ok("EINVAL"));
        assert_eq!(errno_name_no_fallback(libc::ENOMEM), Ok("ENOMEM"));
        assert_eq!(errno_name_no_fallback(libc::EAGAIN), Ok("EAGAIN"));
        assert_eq!(errno_name_no_fallback(libc::EDEADLK), Ok("EDEADLK"));
        assert_eq!(errno_name_no_fallback(libc::EOPNOTSUPP), Ok("EOPNOTSUPP"));
    }

    #[test]
    fn test_errno_name_no_fallback_negative() {
        assert_eq!(errno_name_no_fallback(-libc::EPERM), Ok("EPERM"));
        assert_eq!(errno_name_no_fallback(-libc::EINVAL), Ok("EINVAL"));
    }

    #[test]
    fn test_errno_name_no_fallback_zero() {
        assert!(errno_name_no_fallback(0).is_err());
    }

    #[test]
    fn test_errno_name_no_fallback_not_found() {
        assert!(errno_name_no_fallback(999).is_err());
    }

    #[test]
    fn test_errno_name_no_fallback_boundary() {
        assert!(errno_name_no_fallback(libc::EPERM).is_ok());
        assert!(errno_name_no_fallback(libc::EHWPOISON).is_ok());
        assert!(errno_name_no_fallback(ERRNO_MAX).is_err());
        assert!(errno_name_no_fallback(i32::MIN).is_err());
    }

    #[test]
    fn test_strerror_or_eof_nonzero() {
        let result = strerror_or_eof(libc::EINVAL);
        assert!(!result.is_empty());
        assert_ne!(result, "Unexpected EOF");
    }

    #[test]
    fn test_strerror_or_eof_zero() {
        assert_eq!(strerror_or_eof(0), "Unexpected EOF");
    }

    #[test]
    fn test_strerror_or_eof_negative() {
        let result = strerror_or_eof(-libc::EINVAL);
        assert!(!result.is_empty());
        assert_eq!(strerror_or_eof(i32::MIN), strerror_or_eof(libc::EINVAL));
    }

    #[test]
    fn test_errno_is_valid_range() {
        assert!(errno_is_valid(1));
        assert!(errno_is_valid(ERRNO_MAX));
        assert!(!errno_is_valid(0));
        assert!(!errno_is_valid(ERRNO_MAX + 1));
        assert!(!errno_is_valid(-1));
    }
}
