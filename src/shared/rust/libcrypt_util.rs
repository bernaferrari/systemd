// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/libcrypt-util.c, src/shared/libcrypt-util.h
//
// Password hashing utilities backed by libcrypt (libxcrypt).
//
// Provides dynamic loading of libcrypt through systemd's C loader policy, salt generation,
// password hashing, and password verification. The module uses a
// three-state cache (unloaded / loaded / failed) to avoid redundant loader
// attempts. The C source remains the authority for its non-glibc static
// implementation.
//
// The C function-table bridge is the configuration and loader authority. It
// enforces HAVE_LIBCRYPT, uses the dynamic loader on glibc, and publishes the
// statically linked musl compatibility functions on non-glibc builds.

use std::env;
use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by libcrypt operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptError {
    /// libcrypt is not available on this system or platform.
    Unsupported,
    /// The shared library could not be opened via dlopen.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// crypt_ra() or crypt_gensalt_ra() returned a null pointer.
    CryptFailed(String),
    /// The password hash prefix is invalid or unrecognized.
    InvalidPrefix(String),
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "libcrypt is not available; password hashing disabled"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libcrypt: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libcrypt symbol not found: {}", sym)
            }
            Self::CryptFailed(msg) => write!(f, "crypt operation failed: {}", msg),
            Self::InvalidPrefix(msg) => write!(f, "Invalid hash prefix: {}", msg),
        }
    }
}

impl std::error::Error for CryptError {}

impl From<CryptError> for i32 {
    fn from(e: CryptError) -> i32 {
        match e {
            CryptError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            CryptError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            // `dlopen_many_sym_or_warn()` distinguishes an unavailable
            // optional library from an ABI-incompatible library.
            CryptError::SymbolNotFound(_) => Errno::ELIBBAD.to_neg_errno(),
            CryptError::CryptFailed(_) => Errno::EINVAL.to_neg_errno(),
            CryptError::InvalidPrefix(_) => Errno::EINVAL.to_neg_errno(),
        }
    }
}

// ── Library constants ───────────────────────────────────────────────────────

/// Shared library sonames to try, in preference order.
///
/// Different distributions ship libxcrypt under different names:
/// - Fedora/CentOS/Arch: `libcrypt.so.2`
/// - Debian/Ubuntu/OpenSUSE: `libcrypt.so.1` (or `.1.1` on some arches)
const LIBCRYPT_CANDIDATES: &[&str] = &["libcrypt.so.2", "libcrypt.so.1", "libcrypt.so.1.1"];

/// Symbols required from libcrypt for password hashing.
const REQUIRED_SYMBOLS: &[&str] = &["crypt_gensalt_ra", "crypt_preferred_method", "crypt_ra"];

/// Environment variable that overrides the default hash prefix.
const CRYPT_PREFIX_ENV: &str = "SYSTEMD_CRYPT_PREFIX";

// ── Dlopen state ───────────────────────────────────────────────────────────

/// Cached function pointers. They are private to the library object that owns
/// the dlopen handle.
///
/// Each alias is the exact declaration in libxcrypt's <crypt.h>; pointers are
/// created only after `resolve_required()` validates the corresponding named
/// symbol against a live library handle.
type CryptGensaltRa = unsafe extern "C" fn(
    prefix: *const libc::c_char,
    count: libc::c_ulong,
    rbytes: *const libc::c_char,
    nrbytes: i32,
) -> *mut libc::c_char;

type CryptPreferredMethod = unsafe extern "C" fn() -> *const libc::c_char;

type CryptRa = unsafe extern "C" fn(
    phrase: *const libc::c_char,
    setting: *const libc::c_char,
    data: *mut *mut c_void,
    size: *mut i32,
) -> *mut libc::c_char;

#[repr(C)]
struct CCryptSymbols {
    crypt_gensalt_ra: Option<CryptGensaltRa>,
    crypt_preferred_method: Option<CryptPreferredMethod>,
    crypt_ra: Option<CryptRa>,
}

struct CryptSymbols {
    crypt_gensalt_ra: CryptGensaltRa,
    crypt_preferred_method: CryptPreferredMethod,
    crypt_ra: CryptRa,
}

/// Caches both success and failure. `OnceLock` serializes initialization and
/// publishes only a fully resolved library object.
static LIBCRYPT: OnceLock<Result<CryptSymbols, CryptError>> = OnceLock::new();

// `crypt_ra()` allocates this opaque workspace with the C allocator. Its
// contents can include password-derived material, so use systemd's exact C
// erase-and-free helper rather than guessing the allocation size from the
// libcrypt output parameter.
// SAFETY: callers pass only a null pointer or a live allocation returned by
// `crypt_ra()`, which is precisely the ownership contract of erase_and_free().
unsafe extern "C" {
    #[link_name = "libcrypt_get_functions"]
    fn c_libcrypt_get_functions(ret: *mut CCryptSymbols) -> libc::c_int;

    fn erase_and_free(pointer: *mut c_void) -> *mut c_void;
}

/// Own the temporary allocation returned through `crypt_ra()`'s `data` out
/// parameter. The C implementation uses `_cleanup_(erase_and_freep)` for the
/// same lifetime and scrubbing semantics.
struct CryptData(*mut c_void);

impl Drop for CryptData {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is either null or the still-owned allocation
            // returned by `crypt_ra()` through its `data` out-parameter. The
            // C helper securely erases its allocator-known extent and frees it.
            unsafe { erase_and_free(self.0) };
        }
    }
}

// ── Feature description ─────────────────────────────────────────────────────

/// Returns the human-readable description of the libcrypt feature.
pub fn libcrypt_feature_description() -> &'static str {
    "Support for hashing passwords"
}

/// Returns the list of candidate library sonames tried during loading.
pub fn libcrypt_library_candidates() -> &'static [&'static str] {
    LIBCRYPT_CANDIDATES
}

/// Returns the set of required symbol names.
pub fn libcrypt_required_symbols() -> &'static [&'static str] {
    REQUIRED_SYMBOLS
}

// ── Core: dlopen_libcrypt ──────────────────────────────────────────────────

/// Dynamically load libcrypt and resolve the required symbols.
///
/// Idempotent: after the first call the result (success or failure) is cached
/// and subsequent calls return the same result without retrying.
///
/// Returns `Ok(())` on success, or a `CryptError` describing the failure.
pub fn dlopen_libcrypt() -> Result<(), CryptError> {
    crypt_library().map(|_| ())
}

/// Return the one immutable library object, caching an exact failure as well
/// as a success. This is the only access path for resolved symbols.
fn crypt_library() -> Result<&'static CryptSymbols, CryptError> {
    LIBCRYPT
        .get_or_init(load_libcrypt)
        .as_ref()
        .map_err(Clone::clone)
}

/// Ask C to publish the exact functions selected by the configured build.
///
/// On glibc this runs C's cached `dlopen_libcrypt()` and returns pointers kept
/// alive by its process-lifetime handle. On musl the same table contains the
/// statically linked compatibility implementation. A build configured without
/// libcrypt returns EOPNOTSUPP before publishing any pointer.
fn load_libcrypt() -> Result<CryptSymbols, CryptError> {
    let mut symbols = CCryptSymbols {
        crypt_gensalt_ra: None,
        crypt_preferred_method: None,
        crypt_ra: None,
    };

    // SAFETY: `symbols` is writable, correctly aligned C-layout storage. C
    // initializes every field only on success and never retains the pointer.
    let result = unsafe { c_libcrypt_get_functions(&mut symbols) };
    if result != 0 {
        let errno = if result < 0 {
            result.checked_neg().unwrap_or(libc::EIO)
        } else {
            libc::EIO
        };
        return Err(match errno {
            libc::EOPNOTSUPP => CryptError::Unsupported,
            libc::ELIBBAD => CryptError::SymbolNotFound(
                "C libcrypt loader rejected the required ABI".to_string(),
            ),
            _ => CryptError::DlopenFailed(format!("C loader failed with errno {errno}")),
        });
    }

    Ok(CryptSymbols {
        crypt_gensalt_ra: symbols.crypt_gensalt_ra.ok_or_else(|| {
            CryptError::SymbolNotFound("crypt_gensalt_ra function table entry".to_string())
        })?,
        crypt_preferred_method: symbols.crypt_preferred_method.ok_or_else(|| {
            CryptError::SymbolNotFound("crypt_preferred_method function table entry".to_string())
        })?,
        crypt_ra: symbols.crypt_ra.ok_or_else(|| {
            CryptError::SymbolNotFound("crypt_ra function table entry".to_string())
        })?,
    })
}

// ── Salt generation ────────────────────────────────────────────────────────

/// Generate a random salt for password hashing.
///
/// Uses `SYSTEMD_CRYPT_PREFIX` environment variable if set; otherwise falls
/// back to `crypt_preferred_method()` from libcrypt.
///
/// Returns the generated salt string on success.
pub fn make_salt() -> Result<String, CryptError> {
    let library = crypt_library()?;

    let prefix_c = match secure_crypt_prefix()? {
        // `secure_getenv()` distinguishes an unset variable from a present
        // empty one. Preserve that detail: C passes an explicitly empty
        // prefix to crypt_gensalt_ra() rather than selecting the default.
        Some(prefix) => prefix,
        None => {
            // SAFETY: C published the exact <crypt.h> function after retaining
            // its loader handle or selecting the static musl implementation.
            // A non-null return is a borrowed C string.
            let raw = unsafe { (library.crypt_preferred_method)() };
            if raw.is_null() {
                return Err(CryptError::CryptFailed(
                    "crypt_preferred_method() returned NULL".to_string(),
                ));
            }
            // SAFETY: `crypt_preferred_method()` promises a NUL-terminated
            // string that remains valid until the next libcrypt call. Copy it
            // before invoking crypt_gensalt_ra().
            unsafe { CStr::from_ptr(raw).to_owned() }
        }
    };

    // SAFETY: the loaded symbol has the <crypt.h> ABI validated above;
    // `prefix_c` is a live NUL-terminated input, and null/zero request
    // libcrypt-generated random bytes as in the C implementation.
    unsafe {
        let salt_ptr = (library.crypt_gensalt_ra)(prefix_c.as_ptr(), 0, std::ptr::null(), 0);
        if salt_ptr.is_null() {
            let errno_val = crate::ffi::errno();
            return Err(CryptError::CryptFailed(format!(
                "crypt_gensalt_ra failed (errno={})",
                errno_val
            )));
        }
        // SAFETY: a successful crypt_gensalt_ra() result is a live,
        // NUL-terminated allocation owned by this caller until freed below.
        let salt = CStr::from_ptr(salt_ptr).to_string_lossy().into_owned();
        // crypt_gensalt_ra allocates with malloc; free it.
        // SAFETY: `salt_ptr` is the allocation returned by crypt_gensalt_ra
        // and has not been freed or retained elsewhere.
        libc::free(salt_ptr as *mut c_void);
        Ok(salt)
    }
}

/// Return `SYSTEMD_CRYPT_PREFIX` with C `secure_getenv()` semantics.
///
/// Environment values are byte strings. Retaining their Unix bytes avoids
/// incorrectly rejecting a valid non-UTF-8 libcrypt prefix before passing it
/// through the same C-string boundary C uses.
fn secure_crypt_prefix() -> Result<Option<CString>, CryptError> {
    // SAFETY: getauxval() takes no pointers and transfers no ownership. AT_SECURE
    // is the kernel flag consulted by glibc's secure_getenv() implementation.
    if unsafe { libc::getauxval(libc::AT_SECURE) } != 0 {
        return Ok(None);
    }

    env::var_os(CRYPT_PREFIX_ENV)
        .map(|value| {
            CString::new(value.as_bytes())
                .map_err(|error| CryptError::InvalidPrefix(format!("NUL byte in prefix: {error}")))
        })
        .transpose()
}

// ── Password hashing ───────────────────────────────────────────────────────

/// Hash a password using the system's preferred method.
///
/// Generates a random salt via [`make_salt`], then hashes the password
/// with `crypt_ra()`.
///
/// Returns the full hash string (e.g. `$6$salt$hash`).
pub fn hash_password(password: &str) -> Result<String, CryptError> {
    let salt = make_salt()?;
    let library = crypt_library()?;

    let password_c = CString::new(password)
        .map_err(|e| CryptError::CryptFailed(format!("NUL byte in password: {}", e)))?;
    let salt_c = CString::new(salt.as_str())
        .map_err(|e| CryptError::CryptFailed(format!("NUL byte in salt: {}", e)))?;

    // SAFETY: both function inputs are live NUL-terminated strings. `data`
    // and `size` are writable local out-parameters; `CryptData` owns and
    // securely releases any allocation that libcrypt returns through `data`.
    unsafe {
        let mut cd_data = CryptData(std::ptr::null_mut());
        let mut cd_size: i32 = 0;

        let result_ptr = (library.crypt_ra)(
            password_c.as_ptr(),
            salt_c.as_ptr(),
            &mut cd_data.0,
            &mut cd_size,
        );

        if result_ptr.is_null() {
            let errno_val = crate::ffi::errno();
            return Err(CryptError::CryptFailed(format!(
                "crypt_ra failed (errno={})",
                errno_val
            )));
        }

        // SAFETY: a successful crypt_ra() result is a live NUL-terminated
        // string owned by the `cd_data` workspace until that guard drops.
        let hashed = CStr::from_ptr(result_ptr).to_string_lossy().into_owned();

        Ok(hashed)
    }
}

// ── Password verification ──────────────────────────────────────────────────

/// Verify a password against a single hashed password.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if it does not,
/// or an error on failure (e.g. libcrypt unavailable).
pub fn test_password(hashed_password: &str, password: &str) -> Result<bool, CryptError> {
    let library = crypt_library()?;

    let password_c = CString::new(password)
        .map_err(|_| CryptError::CryptFailed("NUL byte in password".to_string()))?;
    let hashed_c = CString::new(hashed_password)
        .map_err(|_| CryptError::CryptFailed("NUL byte in hashed password".to_string()))?;

    // SAFETY: both inputs are live NUL-terminated strings. The writable
    // out-parameters are local, and the `CryptData` guard erases and frees
    // any allocation returned by crypt_ra() on every exit path.
    unsafe {
        let mut cd_data = CryptData(std::ptr::null_mut());
        let mut cd_size: i32 = 0;

        let result_ptr = (library.crypt_ra)(
            password_c.as_ptr(),
            hashed_c.as_ptr(),
            &mut cd_data.0,
            &mut cd_size,
        );

        if result_ptr.is_null() {
            let errno_val = crate::ffi::errno();
            if errno_val == Errno::ENOMEM as i32 {
                return Err(CryptError::CryptFailed(
                    "crypt_ra: out of memory".to_string(),
                ));
            }
            // Unknown hashing method or string too short — not a match.
            return Ok(false);
        }

        // SAFETY: a successful crypt_ra() return is a live NUL-terminated
        // string within the workspace owned by `cd_data`.
        let result = CStr::from_ptr(result_ptr).to_string_lossy();
        let matches = result == hashed_password;

        Ok(matches)
    }
}

/// Verify a password against multiple hashed passwords.
///
/// Returns `Ok(true)` if the password matches any of the hashes,
/// `Ok(false)` if it matches none, or an error on failure.
pub fn test_password_many(hashed_passwords: &[&str], password: &str) -> Result<bool, CryptError> {
    for hashed in hashed_passwords {
        if test_password(hashed, password)? {
            return Ok(true);
        }
    }
    Ok(false)
}

// ── Heuristic: looks_like_hashed_password ───────────────────────────────────

/// Returns `true` if the string looks like a hashed UNIX password.
///
/// Rejects only strings documented in crypt(5) to have different meanings:
/// - `"x"` — indicates a shadow password entry
/// - `"*"` — indicates no valid login
/// - `NULL`
///
/// Locked passwords (strings starting with `"!"`, including just `"!"`) are
/// accepted, since the `"!"` prefix is a lock marker that wraps a real hash.
pub fn looks_like_hashed_password(s: Option<&str>) -> bool {
    let s = match s {
        Some(s) => s,
        None => return false,
    };

    // Skip (possibly duplicated) locking prefix.
    let stripped = s.trim_start_matches('!');

    // Reject known non-hash sentinel values.
    !matches!(stripped, "x" | "*")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── looks_like_hashed_password tests ─────────────────────────────────

    #[test]
    fn test_none_is_not_hashed() {
        assert!(!looks_like_hashed_password(None));
    }

    #[test]
    fn test_empty_string_is_hashed() {
        // Empty string is not "x" or "*", so it passes the heuristic.
        assert!(looks_like_hashed_password(Some("")));
    }

    #[test]
    fn test_x_is_not_hashed() {
        assert!(!looks_like_hashed_password(Some("x")));
    }

    #[test]
    fn test_asterisk_is_not_hashed() {
        assert!(!looks_like_hashed_password(Some("*")));
    }

    #[test]
    fn test_md5_hash_is_hashed() {
        assert!(looks_like_hashed_password(Some("$1$salt$hash")));
    }

    #[test]
    fn test_sha256_hash_is_hashed() {
        assert!(looks_like_hashed_password(Some("$5$salt$hash")));
    }

    #[test]
    fn test_sha512_hash_is_hashed() {
        assert!(looks_like_hashed_password(Some("$6$salt$hash")));
    }

    #[test]
    fn test_locked_password_is_hashed() {
        // "!" prefix (locked empty password) should be accepted.
        assert!(looks_like_hashed_password(Some("!")));
    }

    #[test]
    fn test_locked_with_hash_is_hashed() {
        // "!" followed by a real hash — locked account with password.
        assert!(looks_like_hashed_password(Some("!$6$salt$hash")));
    }

    #[test]
    fn test_double_locked_is_hashed() {
        // Multiple "!" prefixes should be stripped.
        assert!(looks_like_hashed_password(Some("!!")));
        assert!(looks_like_hashed_password(Some("!!!$6$salt$hash")));
    }

    #[test]
    fn test_des_hash_is_hashed() {
        // Traditional DES hash (no $ prefix).
        assert!(looks_like_hashed_password(Some("ab12345678")));
    }

    #[test]
    fn test_x_after_lock_prefix_is_not_hashed() {
        // "!x" should strip the "!" and then see "x" → not a hash.
        assert!(!looks_like_hashed_password(Some("!x")));
    }

    #[test]
    fn test_asterisk_after_lock_prefix_is_not_hashed() {
        assert!(!looks_like_hashed_password(Some("!*")));
    }

    // ── Error type tests ─────────────────────────────────────────────────

    #[test]
    fn test_crypt_error_display_unsupported() {
        let e = CryptError::Unsupported;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_crypt_error_display_dlopen_failed() {
        let e = CryptError::DlopenFailed("libcrypt.so.2 not found".to_string());
        assert!(e.to_string().contains("libcrypt.so.2 not found"));
    }

    #[test]
    fn test_crypt_error_display_symbol_not_found() {
        let e = CryptError::SymbolNotFound("crypt_ra".to_string());
        assert!(e.to_string().contains("crypt_ra"));
    }

    #[test]
    fn test_crypt_error_display_crypt_failed() {
        let e = CryptError::CryptFailed("EINVAL".to_string());
        assert!(e.to_string().contains("EINVAL"));
    }

    #[test]
    fn test_crypt_error_display_invalid_prefix() {
        let e = CryptError::InvalidPrefix("bad\0prefix".to_string());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_crypt_error_into_c_int_unsupported() {
        let val: i32 = CryptError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_crypt_error_into_c_int_dlopen() {
        let val: i32 = CryptError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_crypt_error_into_c_int_crypt_failed() {
        let val: i32 = CryptError::CryptFailed("x".into()).into();
        assert_eq!(val, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_crypt_error_into_c_int_invalid_prefix() {
        let val: i32 = CryptError::InvalidPrefix("x".into()).into();
        assert_eq!(val, Errno::EINVAL.to_neg_errno());
    }

    // ── Constants tests ──────────────────────────────────────────────────

    #[test]
    fn test_feature_description_not_empty() {
        assert!(!libcrypt_feature_description().is_empty());
        assert!(libcrypt_feature_description().contains("password"));
    }

    #[test]
    fn test_library_candidates() {
        let candidates = libcrypt_library_candidates();
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0], "libcrypt.so.2");
        assert_eq!(candidates[1], "libcrypt.so.1");
        assert_eq!(candidates[2], "libcrypt.so.1.1");
    }

    #[test]
    fn test_required_symbols() {
        let syms = libcrypt_required_symbols();
        assert_eq!(syms.len(), 3);
        assert!(syms.contains(&"crypt_gensalt_ra"));
        assert!(syms.contains(&"crypt_preferred_method"));
        assert!(syms.contains(&"crypt_ra"));
    }

    #[test]
    fn test_crypt_prefix_env() {
        assert_eq!(CRYPT_PREFIX_ENV, "SYSTEMD_CRYPT_PREFIX");
    }

    // ── dlopen caching test ──────────────────────────────────────────────

    #[test]
    fn test_dlopen_libcrypt_caching() {
        // Success and the exact initialization failure are both cached.
        let r1 = dlopen_libcrypt();
        let r2 = dlopen_libcrypt();
        assert_eq!(r1, r2);
    }

    // ── test_password_many tests ─────────────────────────────────────────

    #[test]
    fn test_test_password_many_empty_list() {
        // Empty list should return false (no match possible).
        let result = test_password_many(&[], "password");
        match result {
            Ok(false) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_test_password_many_single_entry() {
        // Single entry should behave like test_password.
        let result = test_password_many(&["$6$invalid"], "password");
        // A disabled configured feature or a bad crypt input may still fail.
        match result {
            Ok(_) => {}
            Err(CryptError::Unsupported) => {}
            Err(CryptError::CryptFailed(_)) => {}
            Err(CryptError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_test_password_many_multiple_entries() {
        let hashes = ["$6$a", "$5$b", "$1$c"];
        let result = test_password_many(&hashes, "test");
        match result {
            Ok(_) => {}
            Err(CryptError::Unsupported) => {}
            Err(CryptError::CryptFailed(_)) => {}
            Err(CryptError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }
}
