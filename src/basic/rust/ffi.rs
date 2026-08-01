// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: N/A (FFI conventions, not ported from a C file)
//
// Error types, utility constants, and thin libc adapters for systemd Rust
// modules. Keep C allocation and byte-string semantics at this boundary.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// ── C stdlib FFI wrappers ─────────────────────────────────────────────────

/// Execute one libc operation after the enclosing adapter has validated its
/// pointer, ownership, and lifetime contract. Keeping the call itself here
/// makes the public wrappers' safe null/size behavior easy to audit.
macro_rules! libc_call {
    ($operation:expr) => {{
        // SAFETY: upheld by the documented contract of the enclosing adapter.
        unsafe_ffi!({ $operation })
    }};
}

/// Allocate `size` bytes. Returns null on failure (size == 0).
pub fn malloc(size: usize) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `libc::malloc` accepts any `size_t` value. The returned allocation
    // uses the C allocator because these pointers cross the C ABI boundary.
    libc_call!(libc::malloc(size))
}

/// Free a C-allocator allocation.
///
/// # Safety
/// `ptr` must either be null or be the unique, still-live base pointer returned
/// by this process's C allocator (for example `malloc`, `calloc`, `realloc`,
/// `strdup`, or `strndup`). It must not have been freed or reallocated already,
/// and it must not originate from Rust's global allocator or an interior offset.
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: upheld by this function's contract.
    libc_call!(libc::free(ptr));
}

/// Allocate zeroed memory for `nmemb` elements of `size` bytes each.
pub fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    if nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `libc::calloc` accepts `size_t` operands and performs the required
    // multiplication overflow check. The allocation may be released by C.
    libc_call!(libc::calloc(nmemb, size))
}

/// Reallocate a C-allocator allocation to `size` bytes.
///
/// # Safety
/// `ptr` must be null or satisfy [`free`]'s allocation and exclusive-ownership
/// requirements. On success (including a zero-sized request), ownership of the
/// old allocation is consumed; callers must use only the returned pointer and
/// must not access or free `ptr` again.
pub unsafe fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        return malloc(size);
    }
    if size == 0 {
        // SAFETY: `realloc` has the same ownership precondition as `free`.
        unsafe_ffi!(free(ptr));
        return ptr::null_mut();
    }
    // SAFETY: upheld by this function's contract.
    libc_call!(libc::realloc(ptr, size))
}

/// Reallocate a C-allocator array to `nmemb * size` bytes with overflow check.
///
/// # Safety
/// `ptr` must satisfy [`realloc`]'s requirements. Except when the requested
/// size overflows, this function consumes `ptr` exactly as [`realloc`] does.
/// On overflow, `ptr` remains valid and owned by the caller.
pub unsafe fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    if nmemb == 0 || size == 0 {
        // SAFETY: `reallocarray` consumes the same C allocation as `realloc`.
        unsafe_ffi!(free(ptr));
        return ptr::null_mut();
    }
    match nmemb.checked_mul(size) {
        // SAFETY: `ptr` satisfies this function's `realloc`-equivalent contract.
        Some(total) => unsafe_ffi!(realloc(ptr, total)),
        None => ptr::null_mut(),
    }
}

/// Return the length of a C string (excluding NUL terminator).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strlen(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string.
    libc_call!(libc::strlen(s))
}

/// Compare two C strings. Returns <0, 0, >0 like C strcmp.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    let empty = c"";
    let s1 = if s1.is_null() { empty.as_ptr() } else { s1 };
    let s2 = if s2.is_null() { empty.as_ptr() } else { s2 };

    // SAFETY: both pointers are valid NUL-terminated C strings, either supplied
    // by the caller or replaced above with the static empty string.
    libc_call!(libc::strcmp(s1, s2))
}

/// Compare two C strings, case-insensitively.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    let empty = c"";
    let s1 = if s1.is_null() { empty.as_ptr() } else { s1 };
    let s2 = if s2.is_null() { empty.as_ptr() } else { s2 };

    // SAFETY: both pointers are valid NUL-terminated C strings, either supplied
    // by the caller or replaced above with the static empty string.
    libc_call!(libc::strcasecmp(s1, s2))
}

/// Compare at most `n` characters of two C strings.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }

    let empty = c"";
    let s1 = if s1.is_null() { empty.as_ptr() } else { s1 };
    let s2 = if s2.is_null() { empty.as_ptr() } else { s2 };

    // SAFETY: both pointers are valid for C string comparison, either supplied
    // by the caller or replaced above with the static empty string.
    libc_call!(libc::strncmp(s1, s2, n))
}

/// Duplicate a C string. Caller must free the result.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string.
    libc_call!(libc::strdup(s))
}

/// Duplicate at most `n` bytes of a C string. Caller must free the result.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the caller guarantees that `s` is valid through its terminating
    // NUL or the first `n` bytes, whichever comes first.
    libc_call!(libc::strndup(s, n))
}

/// Find first occurrence of `c` in string `s`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strchr(s: *const c_char, c: c_int) -> *const c_char {
    if s.is_null() {
        return ptr::null();
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string.
    libc_call!(libc::strchr(s, c))
}

/// Find last occurrence of `c` in string `s`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strrchr(s: *const c_char, c: c_int) -> *const c_char {
    if s.is_null() {
        return ptr::null();
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string.
    libc_call!(libc::strrchr(s, c))
}

/// Find first occurrence of `needle` in `haystack`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strstr(haystack: *const c_char, needle: *const c_char) -> *const c_char {
    if haystack.is_null() || needle.is_null() {
        return ptr::null();
    }

    // SAFETY: the caller guarantees that both pointers are valid NUL-terminated
    // C strings.
    libc_call!(libc::strstr(haystack, needle))
}

/// Get length of prefix of `s` consisting entirely of characters in `accept`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    if s.is_null() || accept.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that both pointers are valid NUL-terminated
    // C strings.
    libc_call!(libc::strspn(s, accept))
}

/// Compare `n` bytes of memory.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
///
/// Keep this wrapper out of line so LLVM cannot replace a fixed-size call
/// with a sign-normalized comparison when C exposes libc's exact result.
#[inline(never)]
pub unsafe fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }

    // SAFETY: the caller guarantees that both pointers are readable for `n`
    // bytes.
    libc_call!(libc::memcmp(s1, s2, n))
}

/// Copy `n` bytes from `src` to `dest`. Returns `dest`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n == 0 {
        return dest;
    }

    // SAFETY: the caller guarantees that both regions are valid for `n` bytes
    // and do not overlap.
    libc_call!(libc::memcpy(dest, src, n))
}

/// Copy `n` bytes from `src` to `dest` (memory areas may overlap). Returns `dest`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n == 0 {
        return dest;
    }

    // SAFETY: the caller guarantees that both regions are valid for `n` bytes.
    libc_call!(libc::memmove(dest, src, n))
}

/// Set `n` bytes of memory at `s` to `c`. Returns `s`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
pub unsafe fn memset(s: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    if n == 0 {
        return s;
    }

    // SAFETY: the caller guarantees that `s` is writable for `n` bytes.
    libc_call!(libc::memset(s, c, n))
}

/// # Safety
/// buf must be valid for size bytes, fmt must be a valid format string.
#[inline]
pub unsafe fn snprintf(buf: *mut c_char, size: usize, fmt: *const c_char) -> c_int {
    // SAFETY: upheld by this function's contract.
    libc_call!(libc::snprintf(buf, size, fmt))
}

/// Match a filename against a shell pattern.
/// Returns 0 on match, FNM_NOMATCH on no match.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int {
    if pattern.is_null() || string.is_null() {
        return libc::FNM_NOMATCH;
    }

    // SAFETY: the caller guarantees that both pointers are valid NUL-terminated
    // C strings. `flags` is passed through unchanged.
    libc_call!(libc::fnmatch(pattern, string, flags))
}

/// Get the current errno value.
pub fn get_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Clear errno (set to 0).
pub fn clear_errno() {
    // SAFETY: this writes thread-local `errno` via the platform's libc accessor.
    unsafe_ffi!({
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            *libc::__errno_location() = 0;
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd",
        ))]
        {
            *libc::__error() = 0;
        }
    })
}

/// Parse a string as unsigned long. Returns the parsed value.
/// `endptr` receives a pointer to the first unparsed character.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strtoul(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> u64 {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string
    // and that `endptr`, when non-null, is writable.
    libc_call!(libc::strtoul(s, endptr, base) as u64)
}

/// Parse a string as signed long. Returns the parsed value.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strtol(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> i64 {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string
    // and that `endptr`, when non-null, is writable.
    libc_call!(libc::strtol(s, endptr, base) as i64)
}

/// Parse a string as signed long long. Returns the parsed value.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strtoll(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> i64 {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string
    // and that `endptr`, when non-null, is writable.
    libc_call!(libc::strtoll(s, endptr, base))
}

/// Parse a string as unsigned long long. Returns the parsed value.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn strtoull(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> u64 {
    if s.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees that `s` is a valid NUL-terminated C string
    // and that `endptr`, when non-null, is writable.
    libc_call!(libc::strtoull(s, endptr, base))
}

// ── Error Types ────────────────────────────────────────────────────────────

/// Linux errno values used across the systemd basic utilities.
/// Each constant holds the positive value; use `.to_neg_errno()` for C-style returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    EDEADLK = 35,
    ENAMETOOLONG = 36,
    ENOLCK = 37,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENOMSG = 42,
    EIDRM = 43,
    ENODATA = 61,
    ENONET = 64,
    ENOLINK = 67,
    EPROTO = 71,
    EBADMSG = 74,
    EOVERFLOW = 75,
    ENOTUNIQ = 76,
    EBADFD = 77,
    EREMCHG = 78,
    ELIBACC = 79,
    ELIBBAD = 80,
    ELIBSCN = 81,
    ELIBMAX = 82,
    ELIBEXEC = 83,
    EILSEQ = 84,
    ERESTART = 85,
    ESTRPIPE = 86,
    EUSERS = 87,
    ENOTSOCK = 88,
    EDESTADDRREQ = 89,
    EMSGSIZE = 90,
    EPROTOTYPE = 91,
    ENOPROTOOPT = 92,
    EPROTONOSUPPORT = 93,
    ESOCKTNOSUPPORT = 94,
    EOPNOTSUPP = 95,
    EPFNOSUPPORT = 96,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    ENETDOWN = 100,
    ENETUNREACH = 101,
    ENETRESET = 102,
    ECONNABORTED = 103,
    ECONNRESET = 104,
    ENOBUFS = 105,
    EISCONN = 106,
    ENOTCONN = 107,
    ESHUTDOWN = 108,
    ETOOMANYREFS = 109,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EHOSTDOWN = 112,
    EHOSTUNREACH = 113,
    EALREADY = 114,
    EINPROGRESS = 115,
    ESTALE = 116,
    EDQUOT = 122,
    ENOMEDIUM = 123,
    EMEDIUMTYPE = 124,
    ECANCELED = 125,
    ENOKEY = 126,
    EKEYEXPIRED = 127,
    EKEYREVOKED = 128,
    EKEYREJECTED = 129,
    EOWNERDEAD = 130,
    ENOTRECOVERABLE = 131,
    ERFKILL = 132,
    EHWPOISON = 133,
    EUNATCH = 49,
}

impl Errno {
    /// Convert to negative errno for C return convention.
    #[inline(always)]
    pub const fn to_neg_errno(self) -> c_int {
        -(self as i32)
    }

    /// Create from a positive errno value.
    #[inline]
    pub const fn from_raw(val: i32) -> Option<Self> {
        match val {
            1 => Some(Self::EPERM),
            2 => Some(Self::ENOENT),
            3 => Some(Self::ESRCH),
            4 => Some(Self::EINTR),
            5 => Some(Self::EIO),
            6 => Some(Self::ENXIO),
            7 => Some(Self::E2BIG),
            8 => Some(Self::ENOEXEC),
            9 => Some(Self::EBADF),
            10 => Some(Self::ECHILD),
            11 => Some(Self::EAGAIN),
            12 => Some(Self::ENOMEM),
            13 => Some(Self::EACCES),
            14 => Some(Self::EFAULT),
            15 => Some(Self::ENOTBLK),
            16 => Some(Self::EBUSY),
            17 => Some(Self::EEXIST),
            18 => Some(Self::EXDEV),
            19 => Some(Self::ENODEV),
            20 => Some(Self::ENOTDIR),
            21 => Some(Self::EISDIR),
            22 => Some(Self::EINVAL),
            23 => Some(Self::ENFILE),
            24 => Some(Self::EMFILE),
            25 => Some(Self::ENOTTY),
            26 => Some(Self::ETXTBSY),
            27 => Some(Self::EFBIG),
            28 => Some(Self::ENOSPC),
            29 => Some(Self::ESPIPE),
            30 => Some(Self::EROFS),
            31 => Some(Self::EMLINK),
            32 => Some(Self::EPIPE),
            33 => Some(Self::EDOM),
            34 => Some(Self::ERANGE),
            35 => Some(Self::EDEADLK),
            36 => Some(Self::ENAMETOOLONG),
            37 => Some(Self::ENOLCK),
            38 => Some(Self::ENOSYS),
            39 => Some(Self::ENOTEMPTY),
            40 => Some(Self::ELOOP),
            42 => Some(Self::ENOMSG),
            43 => Some(Self::EIDRM),
            61 => Some(Self::ENODATA),
            64 => Some(Self::ENONET),
            67 => Some(Self::ENOLINK),
            71 => Some(Self::EPROTO),
            74 => Some(Self::EBADMSG),
            75 => Some(Self::EOVERFLOW),
            76 => Some(Self::ENOTUNIQ),
            77 => Some(Self::EBADFD),
            78 => Some(Self::EREMCHG),
            79 => Some(Self::ELIBACC),
            80 => Some(Self::ELIBBAD),
            81 => Some(Self::ELIBSCN),
            82 => Some(Self::ELIBMAX),
            83 => Some(Self::ELIBEXEC),
            84 => Some(Self::EILSEQ),
            85 => Some(Self::ERESTART),
            86 => Some(Self::ESTRPIPE),
            87 => Some(Self::EUSERS),
            88 => Some(Self::ENOTSOCK),
            89 => Some(Self::EDESTADDRREQ),
            90 => Some(Self::EMSGSIZE),
            91 => Some(Self::EPROTOTYPE),
            92 => Some(Self::ENOPROTOOPT),
            93 => Some(Self::EPROTONOSUPPORT),
            94 => Some(Self::ESOCKTNOSUPPORT),
            95 => Some(Self::EOPNOTSUPP),
            96 => Some(Self::EPFNOSUPPORT),
            97 => Some(Self::EAFNOSUPPORT),
            98 => Some(Self::EADDRINUSE),
            99 => Some(Self::EADDRNOTAVAIL),
            100 => Some(Self::ENETDOWN),
            101 => Some(Self::ENETUNREACH),
            102 => Some(Self::ENETRESET),
            103 => Some(Self::ECONNABORTED),
            104 => Some(Self::ECONNRESET),
            105 => Some(Self::ENOBUFS),
            106 => Some(Self::EISCONN),
            107 => Some(Self::ENOTCONN),
            108 => Some(Self::ESHUTDOWN),
            109 => Some(Self::ETOOMANYREFS),
            110 => Some(Self::ETIMEDOUT),
            111 => Some(Self::ECONNREFUSED),
            112 => Some(Self::EHOSTDOWN),
            113 => Some(Self::EHOSTUNREACH),
            114 => Some(Self::EALREADY),
            115 => Some(Self::EINPROGRESS),
            116 => Some(Self::ESTALE),
            122 => Some(Self::EDQUOT),
            123 => Some(Self::ENOMEDIUM),
            124 => Some(Self::EMEDIUMTYPE),
            125 => Some(Self::ECANCELED),
            126 => Some(Self::ENOKEY),
            127 => Some(Self::EKEYEXPIRED),
            128 => Some(Self::EKEYREVOKED),
            129 => Some(Self::EKEYREJECTED),
            130 => Some(Self::EOWNERDEAD),
            131 => Some(Self::ENOTRECOVERABLE),
            132 => Some(Self::ERFKILL),
            133 => Some(Self::EHWPOISON),
            _ => None,
        }
    }

    /// Create from a negative errno value (as returned from C functions).
    #[inline]
    pub const fn from_neg_errno(val: c_int) -> Option<Self> {
        if val >= 0 {
            return None;
        }
        Self::from_raw(val.wrapping_neg())
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::EPERM => "EPERM",
            Self::ENOENT => "ENOENT",
            Self::ESRCH => "ESRCH",
            Self::EINTR => "EINTR",
            Self::EIO => "EIO",
            Self::ENXIO => "ENXIO",
            Self::E2BIG => "E2BIG",
            Self::ENOEXEC => "ENOEXEC",
            Self::EBADF => "EBADF",
            Self::ECHILD => "ECHILD",
            Self::EAGAIN => "EAGAIN",
            Self::ENOMEM => "ENOMEM",
            Self::EACCES => "EACCES",
            Self::EFAULT => "EFAULT",
            Self::ENOTBLK => "ENOTBLK",
            Self::EBUSY => "EBUSY",
            Self::EEXIST => "EEXIST",
            Self::EXDEV => "EXDEV",
            Self::ENODEV => "ENODEV",
            Self::ENOTDIR => "ENOTDIR",
            Self::EISDIR => "EISDIR",
            Self::EINVAL => "EINVAL",
            Self::ENFILE => "ENFILE",
            Self::EMFILE => "EMFILE",
            Self::ENOTTY => "ENOTTY",
            Self::ETXTBSY => "ETXTBSY",
            Self::EFBIG => "EFBIG",
            Self::ENOSPC => "ENOSPC",
            Self::ESPIPE => "ESPIPE",
            Self::EROFS => "EROFS",
            Self::EMLINK => "EMLINK",
            Self::EPIPE => "EPIPE",
            Self::EDOM => "EDOM",
            Self::ERANGE => "ERANGE",
            Self::EDEADLK => "EDEADLK",
            Self::ENAMETOOLONG => "ENAMETOOLONG",
            Self::ENOLCK => "ENOLCK",
            Self::ENOSYS => "ENOSYS",
            Self::ENOTEMPTY => "ENOTEMPTY",
            Self::ELOOP => "ELOOP",
            Self::ENOMSG => "ENOMSG",
            Self::EIDRM => "EIDRM",
            Self::ENODATA => "ENODATA",
            Self::ENONET => "ENONET",
            Self::ENOLINK => "ENOLINK",
            Self::EPROTO => "EPROTO",
            Self::EBADMSG => "EBADMSG",
            Self::EOVERFLOW => "EOVERFLOW",
            Self::ENOTUNIQ => "ENOTUNIQ",
            Self::EBADFD => "EBADFD",
            Self::EREMCHG => "EREMCHG",
            Self::ELIBACC => "ELIBACC",
            Self::ELIBBAD => "ELIBBAD",
            Self::ELIBSCN => "ELIBSCN",
            Self::ELIBMAX => "ELIBMAX",
            Self::ELIBEXEC => "ELIBEXEC",
            Self::EILSEQ => "EILSEQ",
            Self::ERESTART => "ERESTART",
            Self::ESTRPIPE => "ESTRPIPE",
            Self::EUSERS => "EUSERS",
            Self::ENOTSOCK => "ENOTSOCK",
            Self::EDESTADDRREQ => "EDESTADDRREQ",
            Self::EMSGSIZE => "EMSGSIZE",
            Self::EPROTOTYPE => "EPROTOTYPE",
            Self::ENOPROTOOPT => "ENOPROTOOPT",
            Self::EPROTONOSUPPORT => "EPROTONOSUPPORT",
            Self::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
            Self::EOPNOTSUPP => "EOPNOTSUPP",
            Self::EPFNOSUPPORT => "EPFNOSUPPORT",
            Self::EAFNOSUPPORT => "EAFNOSUPPORT",
            Self::EADDRINUSE => "EADDRINUSE",
            Self::EADDRNOTAVAIL => "EADDRNOTAVAIL",
            Self::ENETDOWN => "ENETDOWN",
            Self::ENETUNREACH => "ENETUNREACH",
            Self::ENETRESET => "ENETRESET",
            Self::ECONNABORTED => "ECONNABORTED",
            Self::ECONNRESET => "ECONNRESET",
            Self::ENOBUFS => "ENOBUFS",
            Self::EISCONN => "EISCONN",
            Self::ENOTCONN => "ENOTCONN",
            Self::ESHUTDOWN => "ESHUTDOWN",
            Self::ETOOMANYREFS => "ETOOMANYREFS",
            Self::ETIMEDOUT => "ETIMEDOUT",
            Self::ECONNREFUSED => "ECONNREFUSED",
            Self::EHOSTDOWN => "EHOSTDOWN",
            Self::EHOSTUNREACH => "EHOSTUNREACH",
            Self::EALREADY => "EALREADY",
            Self::EINPROGRESS => "EINPROGRESS",
            Self::ESTALE => "ESTALE",
            Self::EDQUOT => "EDQUOT",
            Self::ENOMEDIUM => "ENOMEDIUM",
            Self::EMEDIUMTYPE => "EMEDIUMTYPE",
            Self::ECANCELED => "ECANCELED",
            Self::ENOKEY => "ENOKEY",
            Self::EKEYEXPIRED => "EKEYEXPIRED",
            Self::EKEYREVOKED => "EKEYREVOKED",
            Self::EKEYREJECTED => "EKEYREJECTED",
            Self::EOWNERDEAD => "EOWNERDEAD",
            Self::ENOTRECOVERABLE => "ENOTRECOVERABLE",
            Self::ERFKILL => "ERFKILL",
            Self::EHWPOISON => "EHWPOISON",
            Self::EUNATCH => "EUNATCH",
        }
    }
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), *self as i32)
    }
}

impl From<i32> for Errno {
    fn from(val: i32) -> Self {
        Self::from_raw(val.abs()).unwrap_or(Self::EINVAL)
    }
}

/// Internal error type for all Rust code in this crate.
/// Wraps an errno; can be extended with domain-specific variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdError {
    Errno(Errno),
}

impl SdError {
    /// Convert to negative errno for C return convention.
    #[inline(always)]
    pub const fn to_neg_errno(self) -> c_int {
        match self {
            SdError::Errno(e) => e.to_neg_errno(),
        }
    }
}

impl From<Errno> for SdError {
    #[inline]
    fn from(e: Errno) -> Self {
        SdError::Errno(e)
    }
}

/// Internal Result type.
pub type SdResult<T> = Result<T, SdError>;

// ── String Helpers ─────────────────────────────────────────────────────────

/// Allocate a C string on the heap and return a raw pointer.
///
/// The result uses the C allocator and must be released with [`free`].
/// Returns null on interior NUL.
pub fn alloc_c_string(val: &str) -> *mut c_char {
    let Ok(value) = CString::new(val) else {
        return ptr::null_mut();
    };

    // SAFETY: `value` is a live NUL-terminated C string for the duration of
    // this call. `strdup` makes a C-allocator-owned copy.
    libc_call!(libc::strdup(value.as_ptr()))
}

// ── Constants ──────────────────────────────────────────────────────────────

/// Whitespace characters — mirrors WHITESPACE from string-util.h.
pub const WHITESPACE: &[u8] = b" \t\n\r";

/// Check if a byte is whitespace per systemd's definition.
#[inline]
pub const fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// Corresponds to SIZE_MAX from C.
pub const SIZE_MAX: usize = usize::MAX;

#[cfg(test)]
mod tests {
    use super::*;

    // ── to_neg_errno tests ─────────────────────────────────────────────

    #[test]
    fn test_to_neg_errno_basic() {
        assert_eq!(Errno::EINVAL.to_neg_errno(), -22);
        assert_eq!(Errno::ENOENT.to_neg_errno(), -2);
        assert_eq!(Errno::ENOMEM.to_neg_errno(), -12);
        assert_eq!(Errno::EPERM.to_neg_errno(), -1);
        assert_eq!(Errno::EAGAIN.to_neg_errno(), -11);
    }

    #[test]
    fn test_to_neg_errno_high_values() {
        assert_eq!(Errno::ERANGE.to_neg_errno(), -34);
        assert_eq!(Errno::EHWPOISON.to_neg_errno(), -133);
        assert_eq!(Errno::EOWNERDEAD.to_neg_errno(), -130);
    }

    #[test]
    fn test_to_neg_errno_is_negative() {
        assert!(Errno::EINVAL.to_neg_errno() < 0);
        assert!(Errno::EPERM.to_neg_errno() < 0);
        assert!(Errno::EHWPOISON.to_neg_errno() < 0);
    }

    // ── from_raw tests ────────────────────────────────────────────────

    #[test]
    fn test_from_raw_valid_values() {
        assert_eq!(Errno::from_raw(1), Some(Errno::EPERM));
        assert_eq!(Errno::from_raw(2), Some(Errno::ENOENT));
        assert_eq!(Errno::from_raw(22), Some(Errno::EINVAL));
        assert_eq!(Errno::from_raw(12), Some(Errno::ENOMEM));
        assert_eq!(Errno::from_raw(34), Some(Errno::ERANGE));
        assert_eq!(Errno::from_raw(133), Some(Errno::EHWPOISON));
    }

    #[test]
    fn test_from_raw_sparse_values() {
        assert_eq!(Errno::from_raw(42), Some(Errno::ENOMSG));
        assert_eq!(Errno::from_raw(61), Some(Errno::ENODATA));
        assert_eq!(Errno::from_raw(74), Some(Errno::EBADMSG));
        assert_eq!(Errno::from_raw(122), Some(Errno::EDQUOT));
    }

    #[test]
    fn test_from_raw_invalid_values() {
        assert_eq!(Errno::from_raw(0), None);
        assert_eq!(Errno::from_raw(-1), None);
        assert_eq!(Errno::from_raw(41), None);
        assert_eq!(Errno::from_raw(134), None);
        assert_eq!(Errno::from_raw(i32::MAX), None);
        assert_eq!(Errno::from_raw(i32::MIN), None);
    }

    #[test]
    fn test_from_raw_roundtrip() {
        let all_errnos = [
            Errno::EPERM,
            Errno::ENOENT,
            Errno::ESRCH,
            Errno::EINTR,
            Errno::EIO,
            Errno::EINVAL,
            Errno::ENOMEM,
            Errno::EAGAIN,
            Errno::ERANGE,
            Errno::EHWPOISON,
        ];
        for e in all_errnos {
            let val = e as i32;
            assert_eq!(Errno::from_raw(val), Some(e));
        }
    }

    // ── from_neg_errno tests ──────────────────────────────────────────

    #[test]
    fn test_from_neg_errno_valid() {
        assert_eq!(Errno::from_neg_errno(-22), Some(Errno::EINVAL));
        assert_eq!(Errno::from_neg_errno(-2), Some(Errno::ENOENT));
        assert_eq!(Errno::from_neg_errno(-12), Some(Errno::ENOMEM));
        assert_eq!(Errno::from_neg_errno(-1), Some(Errno::EPERM));
        assert_eq!(Errno::from_neg_errno(-133), Some(Errno::EHWPOISON));
    }

    #[test]
    fn test_from_neg_errno_positive_returns_none() {
        assert_eq!(Errno::from_neg_errno(0), None);
        assert_eq!(Errno::from_neg_errno(1), None);
        assert_eq!(Errno::from_neg_errno(22), None);
        assert_eq!(Errno::from_neg_errno(i32::MAX), None);
    }

    #[test]
    fn test_from_neg_errno_invalid_negative() {
        assert_eq!(Errno::from_neg_errno(-41), None);
        assert_eq!(Errno::from_neg_errno(-134), None);
        assert_eq!(Errno::from_neg_errno(i32::MIN), None);
    }

    #[test]
    fn test_from_neg_errno_roundtrip() {
        let all_errnos = [
            Errno::EPERM,
            Errno::ENOENT,
            Errno::ESRCH,
            Errno::EINTR,
            Errno::EIO,
            Errno::EINVAL,
            Errno::ENOMEM,
            Errno::EAGAIN,
            Errno::ERANGE,
            Errno::EHWPOISON,
        ];
        for e in all_errnos {
            let neg = e.to_neg_errno();
            assert_eq!(Errno::from_neg_errno(neg), Some(e));
        }
    }

    // ── SdError tests ─────────────────────────────────────────────────

    #[test]
    fn test_sd_error_from_errno() {
        let err: SdError = Errno::EINVAL.into();
        assert_eq!(err, SdError::Errno(Errno::EINVAL));
    }

    #[test]
    fn test_sd_error_to_neg_errno() {
        let err: SdError = Errno::EINVAL.into();
        assert_eq!(err.to_neg_errno(), -22);

        let err: SdError = Errno::ENOMEM.into();
        assert_eq!(err.to_neg_errno(), -12);
    }

    #[test]
    fn test_errno_equality() {
        assert_eq!(Errno::EINVAL, Errno::EINVAL);
        assert_ne!(Errno::EINVAL, Errno::ENOMEM);
    }

    #[test]
    fn test_errno_copy_and_clone() {
        let e1 = Errno::EINVAL;
        let e2 = e1;
        assert_eq!(e1, e2);

        let e3 = e1;
        assert_eq!(e1, e3);
    }

    #[test]
    fn test_errno_debug() {
        let e = Errno::EINVAL;
        let debug_str = format!("{:?}", e);
        assert!(debug_str.contains("EINVAL"));
    }

    #[test]
    fn test_errno_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Errno::EINVAL);
        set.insert(Errno::ENOMEM);
        set.insert(Errno::EINVAL);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_all_errno_from_raw_roundtrip() {
        for val in 0..=133 {
            if let Some(e) = Errno::from_raw(val) {
                assert_eq!(Errno::from_raw(e as i32), Some(e));
                assert_eq!(Errno::from_neg_errno(e.to_neg_errno()), Some(e));
                assert_eq!(e.to_neg_errno(), -(val as c_int));
            }
        }
    }

    // ── is_whitespace / WHITESPACE tests ───────────────────────────────

    #[test]
    fn test_is_whitespace() {
        assert!(is_whitespace(b' '));
        assert!(is_whitespace(b'\t'));
        assert!(is_whitespace(b'\n'));
        assert!(is_whitespace(b'\r'));
        assert!(!is_whitespace(b'a'));
        assert!(!is_whitespace(b'0'));
        assert!(!is_whitespace(0));
    }

    #[test]
    fn test_whitespace_constant() {
        assert_eq!(WHITESPACE, b" \t\n\r");
    }

    #[test]
    fn test_size_max_constant() {
        assert_eq!(SIZE_MAX, usize::MAX);
    }
}
