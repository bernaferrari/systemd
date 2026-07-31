// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/password-quality-util-pwquality.c, src/shared/password-quality-util-pwquality.h
//
// Password quality checking via libpwquality.
//
// Dynamically loads libpwquality via dlopen and provides safe Rust wrappers
// for password strength validation (`check_password_quality`) and password
// suggestion generation (`suggest_passwords`). When libpwquality is not
// available, operations return `PwqualityError::Unsupported`.
//
// The module mirrors the C implementation:
// - `dlopen_pwquality()` → success-cached library loading through C policy
// - `pwq_allocate_context()` → settings allocation with config reading
// - `pwq_maybe_disable_dictionary()` → graceful fallback when dict file missing
// - `check_password_quality()` → strength validation returning quality score
// - `suggest_passwords()` → random password generation

use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use crate::ffi::Errno;
use systemd_basic_rs::dlfcn_util::{PublishedDlopenHandle, UnpublishedDlopenHandle};

// ── Constants ──────────────────────────────────────────────────────────────

/// Number of password suggestions to generate.
pub const N_SUGGESTIONS: usize = 6;

/// Maximum length of libpwquality error messages.
const PWQ_MAX_ERROR_MESSAGE_LEN: usize = 256;

/// libpwquality's public `PWQ_SETTING_DICT_PATH` setting key.
///
/// This is ABI data from `pwquality.h`, not an inferred ordinal.
const PWQ_SETTING_DICT_PATH: i32 = 10;

/// libpwquality's public `PWQ_SETTING_DICT_CHECK` setting key.
///
/// This is ABI data from `pwquality.h`, not an inferred ordinal.
const PWQ_SETTING_DICT_CHECK: i32 = 15;

/// Shared library soname for libpwquality.
const LIBPWQUALITY_SONAME: &str = "libpwquality.so.1";

/// All symbols required from libpwquality.
const REQUIRED_SYMBOLS: &[&str] = &[
    "pwquality_check",
    "pwquality_default_settings",
    "pwquality_free_settings",
    "pwquality_generate",
    "pwquality_get_str_value",
    "pwquality_read_config",
    "pwquality_set_int_value",
    "pwquality_strerror",
];

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by libpwquality operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PwqualityError {
    /// libpwquality is not available on this system.
    Unsupported,
    /// The shared library could not be opened via dlopen.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// Failed to allocate libpwquality settings context.
    ContextAllocationFailed,
    /// Password quality check returned an error with a message.
    QualityCheckFailed(String),
    /// Failed to generate a password suggestion.
    GenerateFailed(String),
    /// A null pointer was returned unexpectedly.
    NullPointer(String),
    /// Invalid argument (e.g. NUL byte in password).
    InvalidArgument(String),
}

impl fmt::Display for PwqualityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "libpwquality is not available; password quality checks disabled"
            ),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libpwquality: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libpwquality symbol not found: {}", sym)
            }
            Self::ContextAllocationFailed => {
                write!(f, "Failed to allocate libpwquality settings context")
            }
            Self::QualityCheckFailed(msg) => write!(f, "Password quality check failed: {}", msg),
            Self::GenerateFailed(msg) => write!(f, "Password generation failed: {}", msg),
            Self::NullPointer(msg) => write!(f, "Unexpected null pointer: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for PwqualityError {}

impl From<PwqualityError> for i32 {
    fn from(e: PwqualityError) -> i32 {
        match e {
            PwqualityError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            PwqualityError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            PwqualityError::SymbolNotFound(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            PwqualityError::ContextAllocationFailed => Errno::ENOMEM.to_neg_errno(),
            PwqualityError::QualityCheckFailed(_) => Errno::EINVAL.to_neg_errno(),
            PwqualityError::GenerateFailed(_) => Errno::EIO.to_neg_errno(),
            PwqualityError::NullPointer(_) => Errno::EFAULT.to_neg_errno(),
            PwqualityError::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
        }
    }
}

// ── Result of password quality check ──────────────────────────────────────

/// Result of a password quality check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordQualityResult {
    /// Password passed quality checks.
    Good,
    /// Password failed quality checks with an error message.
    Bad(String),
}

// ── Dlopen state ──────────────────────────────────────────────────────────

/// Cached function pointers (valid only when state == 1).
#[derive(Clone, Copy)]
struct PwqualitySymbols {
    // SAFETY: callers uphold libpwquality's settings and pointer contract.
    pwquality_check: unsafe extern "C" fn(
        *mut c_void,         // pwquality_settings_t *pwq
        *const libc::c_char, // const char *password
        *const libc::c_char, // const char *old_password
        *const libc::c_char, // const char *user
        *mut *mut c_void,    // void **auxerror
    ) -> i32,
    // SAFETY: the returned opaque context is owned by libpwquality.
    pwquality_default_settings: unsafe extern "C" fn() -> *mut c_void,
    // SAFETY: callers pass only a context allocated by this library.
    pwquality_free_settings: unsafe extern "C" fn(*mut c_void),
    // SAFETY: callers supply a live context and writable password output.
    pwquality_generate: unsafe extern "C" fn(
        *mut c_void,            // pwquality_settings_t *pwq
        i32,                    // int entropy_bits
        *mut *mut libc::c_char, // char **password
    ) -> i32,
    // SAFETY: callers supply a live context and valid string output pointer.
    pwquality_get_str_value: unsafe extern "C" fn(
        *mut c_void,              // pwquality_settings_t *pwq
        i32,                      // int setting
        *mut *const libc::c_char, // const char **value
    ) -> i32,
    // SAFETY: callers supply a live context and valid auxiliary-error output.
    pwquality_read_config: unsafe extern "C" fn(
        *mut c_void,         // pwquality_settings_t *pwq
        *const libc::c_char, // const char *cfgfile
        *mut *mut c_void,    // void **auxerror
    ) -> i32,
    // SAFETY: callers supply a live context and valid integer setting value.
    pwquality_set_int_value: unsafe extern "C" fn(
        *mut c_void, // pwquality_settings_t *pwq
        i32,         // int setting
        i32,         // int value
    ) -> i32,
    // SAFETY: callers supply writable buffer storage and the matching auxerror.
    pwquality_strerror: unsafe extern "C" fn(
        *mut libc::c_char, // char *buf
        usize,             // size_t len
        i32,               // int error
        *mut c_void,       // void *auxerror
    ) -> *const libc::c_char,
}

#[derive(Clone, Copy)]
struct PwqualityLibrary {
    // C's dlopen_many_sym_or_warn() retains a validated dependency for the
    // remainder of the process, so the typed symbols always have a live DSO.
    _handle: PublishedDlopenHandle,
    symbols: PwqualitySymbols,
}

/// Serializes initialization and caches only a fully validated successful
/// library, exactly as C's `static void *pwquality_dl` does.
static LIBPWQUALITY: OnceLock<Mutex<Option<PwqualityLibrary>>> = OnceLock::new();

/// Resolve one libpwquality symbol through the single audited typed-FFI bridge.
macro_rules! resolve_pwquality_symbol {
    ($handle:expr, $type:ty, $name:literal) => {{
        // SAFETY: every invocation supplies the exact public-header type for
        // its named libpwquality symbol; the published loader retains the DSO.
        unsafe { resolve_symbol::<$type>($handle, $name) }
    }};
}

// ── Feature description ────────────────────────────────────────────────────

/// Returns the human-readable description of the pwquality feature.
pub fn pwquality_feature_description() -> &'static str {
    "Support for password quality checks"
}

/// Returns the libpwquality soname.
pub fn pwquality_library_soname() -> &'static str {
    LIBPWQUALITY_SONAME
}

/// Returns the set of required symbol names.
pub fn pwquality_required_symbols() -> &'static [&'static str] {
    REQUIRED_SYMBOLS
}

// ── Core: dlopen_pwquality ─────────────────────────────────────────────────

/// Dynamically load libpwquality and resolve all required symbols.
///
/// Idempotent after success. A failed load is intentionally retried on the
/// next call, matching C's success-only static loader cache.
///
/// Returns `Ok(())` on success, or a `PwqualityError` describing the failure.
pub fn dlopen_pwquality() -> Result<(), PwqualityError> {
    pwquality_library().map(|_| ())
}

fn pwquality_library() -> Result<PwqualityLibrary, PwqualityError> {
    let cache = LIBPWQUALITY.get_or_init(|| Mutex::new(None));
    // A historical panic cannot invalidate a published immutable handle; use
    // its contents if present and permit retry if it was never published.
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(library) = *cache {
        return Ok(library);
    }

    let library = load_pwquality()?;
    *cache = Some(library);
    Ok(library)
}

/// Fully resolve every symbol before publishing the immutable library object.
fn load_pwquality() -> Result<PwqualityLibrary, PwqualityError> {
    // C delegates through `dlopen_many_sym_or_warn()`, hence through
    // `dlopen_safe()`. Retain static-build, block_dlopen(), RTLD_NOW, and
    // RTLD_NODELETE behavior instead of selecting a divergent local/lazy load.
    let handle = UnpublishedDlopenHandle::open(LIBPWQUALITY_SONAME)
        .map_err(|error| PwqualityError::DlopenFailed(error.to_string()))?;

    // Resolve all required symbols.
    // SAFETY: every requested type below is the exact declaration from the
    // libpwquality public header for the named required symbol.
    let check_fn = resolve_pwquality_symbol!(
        &handle,
        // SAFETY: this is `pwquality_check`'s header declaration.
        unsafe extern "C" fn(
            *mut c_void,
            *const libc::c_char,
            *const libc::c_char,
            *const libc::c_char,
            *mut *mut c_void,
        ) -> i32,
        "pwquality_check"
    )?;

    // SAFETY: see the ABI proof above.
    let default_settings_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn() -> *mut c_void,
        "pwquality_default_settings"
    )?;

    // SAFETY: see the ABI proof above.
    let free_settings_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut c_void),
        "pwquality_free_settings"
    )?;

    // SAFETY: see the ABI proof above.
    let generate_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut c_void, i32, *mut *mut libc::c_char) -> i32,
        "pwquality_generate"
    )?;

    // SAFETY: see the ABI proof above.
    let get_str_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut c_void, i32, *mut *const libc::c_char) -> i32,
        "pwquality_get_str_value"
    )?;

    // SAFETY: see the ABI proof above.
    let read_config_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut c_void, *const libc::c_char, *mut *mut c_void) -> i32,
        "pwquality_read_config"
    )?;

    // SAFETY: see the ABI proof above.
    let set_int_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut c_void, i32, i32) -> i32,
        "pwquality_set_int_value"
    )?;

    // SAFETY: see the ABI proof above.
    let strerror_fn = resolve_pwquality_symbol!(
        &handle,
        unsafe extern "C" fn(*mut libc::c_char, usize, i32, *mut c_void) -> *const libc::c_char,
        "pwquality_strerror"
    )?;

    Ok(PwqualityLibrary {
        _handle: handle.publish(),
        symbols: PwqualitySymbols {
            pwquality_check: check_fn,
            pwquality_default_settings: default_settings_fn,
            pwquality_free_settings: free_settings_fn,
            pwquality_generate: generate_fn,
            pwquality_get_str_value: get_str_fn,
            pwquality_read_config: read_config_fn,
            pwquality_set_int_value: set_int_fn,
            pwquality_strerror: strerror_fn,
        },
    })
}

// ── Required-symbol typing ────────────────────────────────────────────────

/// Resolve one required symbol and give it its exact public C function type.
///
/// # Safety
/// `T` must exactly match the named libpwquality symbol's ABI. The returned
/// function pointer stays valid because `PwqualityLibrary` retains the
/// process-lifetime published loader handle.
unsafe fn resolve_symbol<T>(
    handle: &UnpublishedDlopenHandle,
    symbol: &str,
) -> Result<T, PwqualityError> {
    let pointer = handle
        .resolve_required(symbol)
        .map_err(|error| PwqualityError::SymbolNotFound(error.to_string()))?;
    let raw = pointer.as_ptr();

    // SAFETY: the caller establishes that `T` is this symbol's exact function
    // pointer type. All supported systemd targets represent data and function
    // pointers at the same width required by the POSIX dlsym contract.
    Ok(unsafe { std::mem::transmute_copy(&raw) })
}

// ── Helper: get pwquality_strerror message ─────────────────────────────────

/// Get a human-readable error message from libpwquality.
///
/// # Safety
/// `auxerror` must be the auxiliary value returned for `error_code` by a
/// libpwquality operation, or null. It is consumed by pwquality_strerror().
unsafe fn pwq_strerror(error_code: i32, auxerror: *mut c_void) -> String {
    let library = match pwquality_library() {
        Ok(library) => library,
        Err(_) => return format!("pwquality error {} (library not loaded)", error_code),
    };
    let syms = &library.symbols;

    let mut buf = vec![0u8; PWQ_MAX_ERROR_MESSAGE_LEN];
    // SAFETY: buf is writable for its full length and auxerror is supplied by libpwquality.
    let result = unsafe {
        (syms.pwquality_strerror)(buf.as_mut_ptr().cast(), buf.len(), error_code, auxerror)
    };

    if result.is_null() {
        format!("pwquality error {}", error_code)
    } else {
        // SAFETY: libpwquality returned a non-null NUL-terminated error string.
        unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned()
    }
}

// ── Internal: disable dictionary if file missing ──────────────────────────

/// Check if the configured dictionary file exists; if not, disable dictionary
/// checking in the pwquality settings.
///
/// This mirrors `pwq_maybe_disable_dictionary()` from the C source: when the
/// dictionary path is configured but the file does not exist (ENOENT), the
/// dictionary check is silently disabled to avoid spurious failures.
///
/// # Safety
/// `pwq` must be a live settings context allocated by the same loaded
/// libpwquality instance.
unsafe fn pwq_maybe_disable_dictionary(pwq: *mut c_void) {
    let library = match pwquality_library() {
        Ok(library) => library,
        Err(_) => return,
    };
    let syms = &library.symbols;

    let mut dict_path: *const libc::c_char = std::ptr::null();
    // SAFETY: the caller supplies a live settings context; dict_path is a valid out-parameter.
    let r = unsafe { (syms.pwquality_get_str_value)(pwq, PWQ_SETTING_DICT_PATH, &mut dict_path) };

    if r < 0 {
        // Failed to read dictionary path, ignore.
        return;
    }

    if dict_path.is_null() {
        // No dictionary file configured, nothing to do.
        return;
    }

    // SAFETY: a successful getter returned a non-null NUL-terminated library-owned string.
    let path_str = match unsafe { CStr::from_ptr(dict_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    if path_str.is_empty() {
        // Empty dictionary path, nothing to do.
        return;
    }

    match Path::new(path_str).metadata() {
        // `access(path, F_OK)` succeeded in C: keep the configured check.
        Ok(_) => return,
        // C disables the check only for ENOENT. Permission errors, malformed
        // paths, and other failures remain diagnostic-only and do not mutate
        // the caller's policy.
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return,
    }

    // Dictionary file doesn't exist; disable dictionary checking.
    // SAFETY: pwq remains the live settings context supplied by the caller.
    let _ = unsafe { (syms.pwquality_set_int_value)(pwq, PWQ_SETTING_DICT_CHECK, 0) };
}

// ── Internal: allocate pwquality context ──────────────────────────────────

/// Allocate and initialize a libpwquality settings context.
///
/// This mirrors `pwq_allocate_context()` from the C source:
/// 1. Ensures libpwquality is loaded via dlopen
/// 2. Creates default settings
/// 3. Reads configuration (ignoring errors)
/// 4. Disables dictionary check if dictionary file is missing
///
/// Returns the opaque settings pointer on success.
///
/// # Safety
/// The returned pointer must be freed with `pwq_free_settings()`.
unsafe fn pwq_allocate_context() -> Result<*mut c_void, PwqualityError> {
    let library = pwquality_library()?;
    let syms = &library.symbols;

    // SAFETY: the resolved function pointer has the library's documented signature.
    let pwq = unsafe { (syms.pwquality_default_settings)() };
    if pwq.is_null() {
        return Err(PwqualityError::ContextAllocationFailed);
    }

    // Read config — ignore errors after passing any auxiliary allocation to
    // pwquality_strerror(), as the public API requires to release it.
    let mut auxerror: *mut c_void = std::ptr::null_mut();
    // SAFETY: pwq is a newly allocated settings context and auxerror is a valid out-parameter.
    let r = unsafe { (syms.pwquality_read_config)(pwq, std::ptr::null(), &mut auxerror) };
    if r < 0 {
        // SAFETY: libpwquality documents that auxiliary error information must
        // be passed to pwquality_strerror(), which consumes any allocation.
        let _ = unsafe { pwq_strerror(r, auxerror) };
    }

    // Disable dictionary check if the dictionary file is missing.
    // SAFETY: pwq is non-null and remains owned by the caller.
    unsafe { pwq_maybe_disable_dictionary(pwq) };

    Ok(pwq)
}

/// Free a libpwquality settings context.
///
/// # Safety
/// `pwq` must be a valid pointer from `pwq_allocate_context()`.
unsafe fn pwq_free_settings(pwq: *mut c_void) {
    if pwq.is_null() {
        return;
    }
    let library = match pwquality_library() {
        Ok(library) => library,
        Err(_) => return,
    };
    let syms = &library.symbols;
    // SAFETY: the caller guarantees pwq is a live context allocated by libpwquality.
    unsafe { (syms.pwquality_free_settings)(pwq) };
}

// ── Public API: check_password_quality ────────────────────────────────────

/// Check password quality using libpwquality.
///
/// Validates a password against the system's libpwquality policy, optionally
/// comparing against the old password and taking the username into account.
///
/// # Arguments
///
/// * `password` - The new password to validate
/// * `old` - The old password (for change scenarios), or `None`
/// * `username` - The username context, or `None`
///
/// # Returns
///
/// * `Ok(PasswordQualityResult::Good)` — password passed all checks
/// * `Ok(PasswordQualityResult::Bad(reason))` — password failed, with reason
/// * `Err(PwqualityError)` — system error (library not available, etc.)
pub fn check_password_quality(
    password: &str,
    old: Option<&str>,
    username: Option<&str>,
) -> Result<PasswordQualityResult, PwqualityError> {
    let password_c = CString::new(password)
        .map_err(|_| PwqualityError::InvalidArgument("NUL byte in password".to_string()))?;

    let old_c = match old {
        Some(s) => Some(CString::new(s).map_err(|_| {
            PwqualityError::InvalidArgument("NUL byte in old password".to_string())
        })?),
        None => None,
    };

    let username_c = match username {
        Some(s) => Some(
            CString::new(s)
                .map_err(|_| PwqualityError::InvalidArgument("NUL byte in username".to_string()))?,
        ),
        None => None,
    };

    // SAFETY: All CString pointers remain valid for the duration of this call.
    // pwq is freed before returning.
    unsafe {
        let pwq = pwq_allocate_context()?;
        let _guard = ScopeGuard(Some(|| pwq_free_settings(pwq)));

        let library = pwquality_library()?;
        let syms = &library.symbols;

        let mut auxerror: *mut c_void = std::ptr::null_mut();
        let r = (syms.pwquality_check)(
            pwq,
            password_c.as_ptr(),
            old_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            username_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            &mut auxerror,
        );

        if r < 0 {
            let msg = pwq_strerror(r, auxerror);
            Ok(PasswordQualityResult::Bad(msg))
        } else {
            Ok(PasswordQualityResult::Good)
        }
    }
}

// ── Public API: suggest_passwords ─────────────────────────────────────────

/// Generate password suggestions using libpwquality.
///
/// Generates `N_SUGGESTIONS` random passwords (each with 64 bits of entropy)
/// and returns them as a vector of strings.
///
/// # Returns
///
/// * `Ok(Vec<String>)` — vector of generated password suggestions
/// * `Err(PwqualityError)` — system error (library not available, generation failure)
pub fn suggest_passwords() -> Result<Vec<String>, PwqualityError> {
    // SAFETY: pwq is freed before returning via ScopeGuard.
    unsafe {
        let pwq = pwq_allocate_context()?;
        let _guard = ScopeGuard(Some(|| pwq_free_settings(pwq)));

        let library = pwquality_library()?;
        let syms = &library.symbols;

        let mut suggestions = Vec::with_capacity(N_SUGGESTIONS);

        for _ in 0..N_SUGGESTIONS {
            let mut generated: *mut libc::c_char = std::ptr::null_mut();
            let r = (syms.pwquality_generate)(pwq, 64, &mut generated);

            if r < 0 {
                let msg = pwq_strerror(r, std::ptr::null_mut());
                return Err(PwqualityError::GenerateFailed(msg));
            }

            if generated.is_null() {
                return Err(PwqualityError::NullPointer(
                    "pwquality_generate returned NULL".to_string(),
                ));
            }

            let password = CStr::from_ptr(generated).to_string_lossy().into_owned();

            // pwquality_generate allocates with malloc; free it.
            libc::free(generated as *mut c_void);

            suggestions.push(password);
        }

        Ok(suggestions)
    }
}

/// Generate password suggestions and format them as a printable string.
///
/// Returns a formatted string like `"Password suggestions: pw1 pw2 pw3 ..."`
/// on success.
pub fn suggest_passwords_formatted() -> Result<String, PwqualityError> {
    let suggestions = suggest_passwords()?;
    Ok(format!("Password suggestions: {}", suggestions.join(" ")))
}

// ── RAII guard for pwquality settings ─────────────────────────────────────

/// Scope guard that calls a cleanup function on drop.
struct ScopeGuard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants tests ─────────────────────────────────────────────────

    #[test]
    fn test_n_suggestions_value() {
        assert_eq!(N_SUGGESTIONS, 6);
    }

    #[test]
    fn test_pw_max_error_message_len() {
        assert_eq!(PWQ_MAX_ERROR_MESSAGE_LEN, 256);
    }

    #[test]
    fn test_libpwquality_soname() {
        assert_eq!(pwquality_library_soname(), "libpwquality.so.1");
    }

    #[test]
    fn test_pwquality_required_symbols() {
        let syms = pwquality_required_symbols();
        assert_eq!(syms.len(), 8);
        assert!(syms.contains(&"pwquality_check"));
        assert!(syms.contains(&"pwquality_default_settings"));
        assert!(syms.contains(&"pwquality_free_settings"));
        assert!(syms.contains(&"pwquality_generate"));
        assert!(syms.contains(&"pwquality_get_str_value"));
        assert!(syms.contains(&"pwquality_read_config"));
        assert!(syms.contains(&"pwquality_set_int_value"));
        assert!(syms.contains(&"pwquality_strerror"));
    }

    #[test]
    fn test_pwquality_feature_description() {
        let desc = pwquality_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("password"));
    }

    #[test]
    fn test_pw_setting_constants() {
        // Dict path and dict check should be distinct positive integers.
        assert_eq!(PWQ_SETTING_DICT_PATH, 10);
        assert_eq!(PWQ_SETTING_DICT_CHECK, 15);
        assert_ne!(PWQ_SETTING_DICT_PATH, PWQ_SETTING_DICT_CHECK);
    }

    // ── Error type tests ────────────────────────────────────────────────

    #[test]
    fn test_pwquality_error_display_unsupported() {
        let e = PwqualityError::Unsupported;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_pwquality_error_display_dlopen_failed() {
        let e = PwqualityError::DlopenFailed("libpwquality.so.1 not found".to_string());
        assert!(e.to_string().contains("libpwquality.so.1 not found"));
    }

    #[test]
    fn test_pwquality_error_display_symbol_not_found() {
        let e = PwqualityError::SymbolNotFound("pwquality_check".to_string());
        assert!(e.to_string().contains("pwquality_check"));
    }

    #[test]
    fn test_pwquality_error_display_context_allocation() {
        let e = PwqualityError::ContextAllocationFailed;
        assert!(e.to_string().contains("allocate"));
    }

    #[test]
    fn test_pwquality_error_display_quality_check() {
        let e = PwqualityError::QualityCheckFailed("too short".to_string());
        assert!(e.to_string().contains("too short"));
    }

    #[test]
    fn test_pwquality_error_display_generate_failed() {
        let e = PwqualityError::GenerateFailed("entropy error".to_string());
        assert!(e.to_string().contains("entropy error"));
    }

    #[test]
    fn test_pwquality_error_display_null_pointer() {
        let e = PwqualityError::NullPointer("settings is null".to_string());
        assert!(e.to_string().contains("null"));
    }

    #[test]
    fn test_pwquality_error_display_invalid_argument() {
        let e = PwqualityError::InvalidArgument("NUL byte".to_string());
        assert!(e.to_string().contains("NUL byte"));
    }

    #[test]
    fn test_pwquality_error_into_c_int_unsupported() {
        let val: i32 = PwqualityError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_pwquality_error_into_c_int_dlopen() {
        let val: i32 = PwqualityError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_pwquality_error_into_c_int_context() {
        let val: i32 = PwqualityError::ContextAllocationFailed.into();
        assert_eq!(val, Errno::ENOMEM.to_neg_errno());
    }

    #[test]
    fn test_pwquality_error_into_c_int_quality() {
        let val: i32 = PwqualityError::QualityCheckFailed("x".into()).into();
        assert_eq!(val, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_pwquality_error_into_c_int_generate() {
        let val: i32 = PwqualityError::GenerateFailed("x".into()).into();
        assert_eq!(val, Errno::EIO.to_neg_errno());
    }

    // ── PasswordQualityResult tests ─────────────────────────────────────

    #[test]
    fn test_password_quality_result_good() {
        let r = PasswordQualityResult::Good;
        assert_eq!(r, PasswordQualityResult::Good);
    }

    #[test]
    fn test_password_quality_result_bad() {
        let r = PasswordQualityResult::Bad("too short".to_string());
        match r {
            PasswordQualityResult::Bad(msg) => assert_eq!(msg, "too short"),
            _ => panic!("Expected Bad variant"),
        }
    }

    #[test]
    fn test_password_quality_result_equality() {
        let a = PasswordQualityResult::Good;
        let b = PasswordQualityResult::Good;
        assert_eq!(a, b);

        let c = PasswordQualityResult::Bad("reason".to_string());
        let d = PasswordQualityResult::Bad("reason".to_string());
        assert_eq!(c, d);

        let e = PasswordQualityResult::Bad("other".to_string());
        assert_ne!(c, e);
    }

    // ── dlopen caching test ─────────────────────────────────────────────

    #[test]
    fn test_dlopen_pwquality_caching() {
        // Success and the exact initialization failure are both cached.
        let r1 = dlopen_pwquality();
        let r2 = dlopen_pwquality();
        assert_eq!(r1, r2);
    }

    // ── check_password_quality tests ────────────────────────────────────

    #[test]
    fn test_check_password_quality_returns_result() {
        // On non-Linux or without libpwquality, should return error or quality result.
        let result = check_password_quality("testpass", None, None);
        match result {
            Ok(PasswordQualityResult::Good) | Ok(PasswordQualityResult::Bad(_)) => {}
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_old_password() {
        let result = check_password_quality("newpass", Some("oldpass"), None);
        match result {
            Ok(_) => {}
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_username() {
        let result = check_password_quality("testpass", None, Some("root"));
        match result {
            Ok(_) => {}
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_all_args() {
        let result = check_password_quality("newpassword", Some("oldpassword"), Some("admin"));
        match result {
            Ok(_) => {}
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // ── suggest_passwords tests ─────────────────────────────────────────

    #[test]
    fn test_suggest_passwords_returns_result() {
        let result = suggest_passwords();
        match result {
            Ok(suggestions) => assert_eq!(suggestions.len(), N_SUGGESTIONS),
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_suggest_passwords_formatted() {
        let result = suggest_passwords_formatted();
        match result {
            Ok(formatted) => assert!(formatted.starts_with("Password suggestions:")),
            Err(PwqualityError::Unsupported) | Err(PwqualityError::DlopenFailed(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // ── ScopeGuard test ─────────────────────────────────────────────────

    #[test]
    fn test_scope_guard_calls_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static CALLED: AtomicBool = AtomicBool::new(false);
        CALLED.store(false, Ordering::Relaxed);

        {
            let _guard = ScopeGuard(Some(|| {
                CALLED.store(true, Ordering::Relaxed);
            }));
            assert!(!CALLED.load(Ordering::Relaxed));
        }

        assert!(CALLED.load(Ordering::Relaxed));
    }

    // ── Error std::error::Error impl ────────────────────────────────────

    #[test]
    fn test_pwquality_error_is_error() {
        let e: Box<dyn std::error::Error> = Box::new(PwqualityError::Unsupported);
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_pwquality_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PwqualityError>();
    }
}
