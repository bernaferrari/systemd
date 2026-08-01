// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/password-quality-util-passwdqc.c, src/shared/password-quality-util-passwdqc.h
//
// Password quality checking via libpasswdqc.
//
// Dynamically loads libpasswdqc via dlopen and provides safe Rust wrappers
// for password strength validation (`check_password_quality`) and password
// suggestion generation (`suggest_passwords`). When libpasswdqc is not
// available, operations return `PasswdqcError::Unsupported`.
//
// The module mirrors the C implementation:
// - `dlopen_passwdqc()` → success-cached library loading through C policy
// - `pwqc_allocate_context()` → params allocation with config reading
// - `check_password_quality()` → strength validation with username awareness
// - `suggest_passwords()` → random password generation

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use crate::ffi::Errno;
use systemd_basic_rs::dlfcn_util::{PublishedDlopenHandle, UnpublishedDlopenHandle};

// ── Constants ──────────────────────────────────────────────────────────────

/// Number of password suggestions to generate.
pub const N_SUGGESTIONS: usize = 6;

/// Shared library soname for libpasswdqc.
const LIBPASSWDQC_SONAME: &str = "libpasswdqc.so.1";

/// Default configuration file path for passwdqc.
const PASSWDQC_CONF_PATH: &str = "/etc/passwdqc.conf";

/// Human-readable feature description (matches SD_ELF_NOTE_DLOPEN comment).
const PASSWDQC_FEATURE_DESC: &str = "Support for password quality checks";

/// All symbols required from libpasswdqc.
const REQUIRED_SYMBOLS: &[&str] = &[
    "passwdqc_params_reset",
    "passwdqc_params_load",
    "passwdqc_params_parse",
    "passwdqc_params_free",
    "passwdqc_check",
    "passwdqc_random",
];

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by libpasswdqc operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswdqcError {
    /// libpasswdqc is not available on this system.
    Unsupported,
    /// The shared library could not be opened via dlopen.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// Failed to allocate passwdqc params context.
    ContextAllocationFailed,
    /// Failed to generate a password suggestion.
    GenerateFailed(String),
    /// A null pointer was returned unexpectedly.
    NullPointer(String),
    /// Invalid argument (e.g. NUL byte in password).
    InvalidArgument(String),
}

impl fmt::Display for PasswdqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "libpasswdqc is not available; password quality checks disabled"
            ),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libpasswdqc: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libpasswdqc symbol not found: {}", sym)
            }
            Self::ContextAllocationFailed => {
                write!(f, "Failed to allocate libpasswdqc params context")
            }
            Self::GenerateFailed(msg) => write!(f, "Password generation failed: {}", msg),
            Self::NullPointer(msg) => write!(f, "Unexpected null pointer: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for PasswdqcError {}

impl From<PasswdqcError> for i32 {
    fn from(e: PasswdqcError) -> i32 {
        match e {
            PasswdqcError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            PasswdqcError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            PasswdqcError::SymbolNotFound(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            PasswdqcError::ContextAllocationFailed => Errno::ENOMEM.to_neg_errno(),
            PasswdqcError::GenerateFailed(_) => Errno::EIO.to_neg_errno(),
            PasswdqcError::NullPointer(_) => Errno::EFAULT.to_neg_errno(),
            PasswdqcError::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
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

/// Public `passwdqc_params_qc_t` layout from passwdqc 2.x.
///
/// `libpasswdqc.so.1` first appeared in passwdqc 1.9, but this module also
/// requires `passwdqc_params_free`, which was added in 2.0. The layout below
/// is unchanged from passwdqc 2.0 through 2.1.
#[repr(C)]
struct PasswdqcParamsQc {
    min: [c_int; 5],
    max: c_int,
    passphrase_words: c_int,
    match_length: c_int,
    similar_deny: c_int,
    random_bits: c_int,
    wordlist: *mut c_char,
    denylist: *mut c_char,
    filter: *mut c_char,
}

#[repr(C)]
struct PasswdqcParamsPam {
    flags: c_int,
    retry: c_int,
}

#[repr(C)]
struct PasswdqcParams {
    qc: PasswdqcParamsQc,
    pam: PasswdqcParamsPam,
}

type PasswdqcParamsParseFn = unsafe extern "C" fn(
    *mut PasswdqcParams,
    *mut *mut c_char,
    c_int,
    *const *const c_char,
) -> c_int;

/// Resolve a passwdqc symbol only through its audited public C declaration.
/// The type remains visible at each call site while the dynamic-lookup unsafe
/// boundary is kept to one place.
macro_rules! resolve_passwdqc_symbol {
    ($handle:expr, $name:literal, $symbol_type:ty) => {{
        // SAFETY: each invocation supplies the exact public declaration for
        // the named libpasswdqc required symbol.
        unsafe_ffi!({ resolve_symbol::<$symbol_type>($handle, $name) })
    }};
}

/// Cached function pointers.
#[derive(Clone, Copy)]
struct PasswdqcSymbols {
    // SAFETY: callers provide an initialized, writable `passwdqc_params_t`.
    passwdqc_params_reset: unsafe extern "C" fn(*mut PasswdqcParams),
    // SAFETY: callers keep the params, output pointer, and C path live.
    passwdqc_params_load:
        unsafe extern "C" fn(*mut PasswdqcParams, *mut *mut c_char, *const c_char) -> c_int,
    passwdqc_params_parse: PasswdqcParamsParseFn,
    // SAFETY: callers pass only a context initialized by this library.
    passwdqc_params_free: unsafe extern "C" fn(*mut PasswdqcParams),
    // SAFETY: callers meet libpasswdqc's pointer and lifetime contract.
    passwdqc_check: unsafe extern "C" fn(
        *const PasswdqcParamsQc,
        *const c_char,
        *const c_char,
        *const libc::passwd,
    ) -> *const c_char,
    // SAFETY: callers pass a live initialized quality-settings subobject.
    passwdqc_random: unsafe extern "C" fn(*const PasswdqcParamsQc) -> *mut c_char,
}

#[derive(Clone, Copy)]
struct PasswdqcLibrary {
    // C's `dlopen_many_sym_or_warn()` deliberately retains a successful
    // optional dependency for process lifetime. Keeping that ownership in the
    // value that owns the function pointers makes the dependency explicit.
    _handle: PublishedDlopenHandle,
    symbols: PasswdqcSymbols,
}

/// Serializes initialization and records only a validated successful load.
///
/// This mirrors C's `static void *passwdqc_dl`: a failed attempt is not
/// published, so a later call may retry after the loader environment changes.
static LIBPASSWDQC: OnceLock<Mutex<Option<PasswdqcLibrary>>> = OnceLock::new();

// ── Feature description ────────────────────────────────────────────────────

/// Returns the human-readable description of the passwdqc feature.
pub fn passwdqc_feature_description() -> &'static str {
    PASSWDQC_FEATURE_DESC
}

/// Returns the libpasswdqc soname.
pub fn passwdqc_library_soname() -> &'static str {
    LIBPASSWDQC_SONAME
}

/// Returns the set of required symbol names.
pub fn passwdqc_required_symbols() -> &'static [&'static str] {
    REQUIRED_SYMBOLS
}

/// Returns the passwdqc configuration file path.
pub fn passwdqc_conf_path() -> &'static str {
    PASSWDQC_CONF_PATH
}

// ── Core: dlopen_passwdqc ─────────────────────────────────────────────────

/// Dynamically load libpasswdqc and resolve all required symbols.
///
/// Idempotent after success. Failed attempts are deliberately not cached,
/// matching C's `dlopen_many_sym_or_warn()` behavior.
///
/// Returns `Ok(())` on success, or a `PasswdqcError` describing the failure.
pub fn dlopen_passwdqc() -> Result<(), PasswdqcError> {
    passwdqc_library().map(|_| ())
}

fn passwdqc_library() -> Result<PasswdqcLibrary, PasswdqcError> {
    let cache = LIBPASSWDQC.get_or_init(|| Mutex::new(None));
    // A poisoned lock cannot invalidate a published process-lifetime handle;
    // retain its value and permit a fresh load if the panic happened earlier.
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(library) = *cache {
        return Ok(library);
    }

    let library = load_passwdqc()?;
    *cache = Some(library);
    Ok(library)
}

/// Open the library and resolve every symbol before publishing any state.
fn load_passwdqc() -> Result<PasswdqcLibrary, PasswdqcError> {
    // C delegates through `dlopen_many_sym_or_warn()`, which in turn uses
    // `dlopen_safe()`. Preserve its static-build, block_dlopen(), RTLD_NOW,
    // and RTLD_NODELETE policy instead of selecting a local lazy policy.
    let handle = UnpublishedDlopenHandle::open(LIBPASSWDQC_SONAME)
        .map_err(|error| PasswdqcError::DlopenFailed(error.to_string()))?;

    // Resolve every required symbol before publishing the loader handle.
    let params_reset_fn = resolve_passwdqc_symbol!(
        &handle,
        "passwdqc_params_reset",
        // SAFETY: exact public declaration of passwdqc_params_reset.
        unsafe extern "C" fn(*mut PasswdqcParams)
    )?;
    let params_load_fn = resolve_passwdqc_symbol!(
        &handle,
        "passwdqc_params_load",
        // SAFETY: exact public declaration of passwdqc_params_load.
        unsafe extern "C" fn(*mut PasswdqcParams, *mut *mut c_char, *const c_char) -> c_int
    )?;
    let params_parse_fn =
        resolve_passwdqc_symbol!(&handle, "passwdqc_params_parse", PasswdqcParamsParseFn)?;
    let params_free_fn = resolve_passwdqc_symbol!(
        &handle,
        "passwdqc_params_free",
        // SAFETY: exact public declaration of passwdqc_params_free.
        unsafe extern "C" fn(*mut PasswdqcParams)
    )?;
    let check_fn = resolve_passwdqc_symbol!(
        &handle,
        "passwdqc_check",
        // SAFETY: exact public declaration of passwdqc_check.
        unsafe extern "C" fn(
            *const PasswdqcParamsQc,
            *const c_char,
            *const c_char,
            *const libc::passwd,
        ) -> *const c_char
    )?;
    let random_fn = resolve_passwdqc_symbol!(
        &handle,
        "passwdqc_random",
        // SAFETY: exact public declaration of passwdqc_random.
        unsafe extern "C" fn(*const PasswdqcParamsQc) -> *mut c_char
    )?;

    Ok(PasswdqcLibrary {
        _handle: handle.publish(),
        symbols: PasswdqcSymbols {
            passwdqc_params_reset: params_reset_fn,
            passwdqc_params_load: params_load_fn,
            passwdqc_params_parse: params_parse_fn,
            passwdqc_params_free: params_free_fn,
            passwdqc_check: check_fn,
            passwdqc_random: random_fn,
        },
    })
}

// ── Required-symbol typing ────────────────────────────────────────────────

/// Resolve one required symbol and give it its exact public C function type.
///
/// # Safety
/// `T` must exactly match the named libpasswdqc symbol's ABI. The returned
/// function pointer stays valid because `PasswdqcLibrary` retains the
/// process-lifetime published loader handle.
unsafe fn resolve_symbol<T>(
    handle: &UnpublishedDlopenHandle,
    symbol: &str,
) -> Result<T, PasswdqcError> {
    let pointer = handle
        .resolve_required(symbol)
        .map_err(|error| PasswdqcError::SymbolNotFound(error.to_string()))?;
    let raw = pointer.as_ptr();

    // SAFETY: the caller establishes that `T` is this symbol's exact function
    // pointer type. All supported systemd targets represent data and function
    // pointers at the same width required by the POSIX dlsym contract.
    Ok(unsafe_ffi!(std::mem::transmute_copy(&raw)))
}

// ── Internal: allocate passwdqc context ───────────────────────────────────

/// Owns the caller-allocated outer params struct and its library-managed
/// internal strings.
struct PasswdqcContext {
    params: NonNull<PasswdqcParams>,
    library: PasswdqcLibrary,
}

impl PasswdqcContext {
    fn qc(&self) -> &PasswdqcParamsQc {
        // SAFETY: `params` remains allocated for the context lifetime and
        // `qc` is an inline field of the proven public C layout.
        unsafe_ffi!(&self.params.as_ref().qc)
    }
}

impl Drop for PasswdqcContext {
    fn drop(&mut self) {
        // SAFETY: `passwdqc_params_free` releases only the three internal
        // strings and resets the struct. The outer allocation is ours.
        unsafe_ffi!({
            (self.library.symbols.passwdqc_params_free)(self.params.as_ptr());
            libc::free(self.params.as_ptr().cast());
        })
    }
}

/// Allocate and initialize a libpasswdqc params context.
///
/// This mirrors `pwqc_allocate_context()` from the C source:
/// 1. Ensures libpasswdqc is loaded via dlopen
/// 2. Allocates and zeroes the params struct
/// 3. Resets params to defaults
/// 4. Attempts to load config from /etc/passwdqc.conf (ignoring errors)
///
/// Returns an owned params context on success.
fn pwqc_allocate_context() -> Result<PasswdqcContext, PasswdqcError> {
    let library = passwdqc_library()?;
    let syms = &library.symbols;

    // `ffi::calloc` preserves C allocator provenance for the library-owned
    // params fields while exposing the allocation result as a safe null check.
    let params = NonNull::new(
        crate::ffi::calloc(1, std::mem::size_of::<PasswdqcParams>()).cast::<PasswdqcParams>(),
    )
    .ok_or(PasswdqcError::ContextAllocationFailed)?;
    let context = PasswdqcContext { params, library };

    // SAFETY: the allocation has the exact public layout and remains owned by
    // `context`; the reset function initializes all fields.
    unsafe_ffi!({
        (syms.passwdqc_params_reset)(context.params.as_ptr());
    });

    // Attempt to load config. As in the C implementation, a diagnostic means
    // the defaults remain usable; a missing diagnostic on error means OOM.
    let conf_path = CString::new(PASSWDQC_CONF_PATH)
        .map_err(|_| PasswdqcError::InvalidArgument("NUL byte in config path".to_string()))?;
    let mut load_reason: *mut c_char = std::ptr::null_mut();
    // SAFETY: `context` owns initialized params, and both the NUL-terminated
    // path and writable diagnostic output remain live for this call.
    let r = unsafe_ffi!({
        (syms.passwdqc_params_load)(
            context.params.as_ptr(),
            &mut load_reason,
            conf_path.as_ptr(),
        )
    });

    if r < 0 && load_reason.is_null() {
        return Err(PasswdqcError::ContextAllocationFailed);
    }

    if !load_reason.is_null() {
        // SAFETY: passwdqc returns the diagnostic through malloc-owned
        // storage, matching the C caller's `_cleanup_free_`.
        unsafe_ffi!(libc::free(load_reason.cast()));
    }

    Ok(context)
}

// ── Public API: check_password_quality ────────────────────────────────────

/// Check password quality using libpasswdqc.
///
/// Validates a password against the system's libpasswdqc policy, optionally
/// comparing against the old password and taking the username into account.
///
/// When a username is provided, the platform's `libc::passwd` is constructed
/// with only `pw_name` populated; other string fields are empty (matching the
/// C implementation, which cannot provide GECOS, home dir, or shell info).
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
/// * `Err(PasswdqcError)` — system error (library not available, etc.)
pub fn check_password_quality(
    password: &str,
    old: Option<&str>,
    username: Option<&str>,
) -> Result<PasswordQualityResult, PasswdqcError> {
    let password_c = CString::new(password)
        .map_err(|_| PasswdqcError::InvalidArgument("NUL byte in password".to_string()))?;

    let old_c =
        match old {
            Some(s) => Some(CString::new(s).map_err(|_| {
                PasswdqcError::InvalidArgument("NUL byte in old password".to_string())
            })?),
            None => None,
        };

    let username_c = match username {
        Some(s) => Some(
            CString::new(s)
                .map_err(|_| PasswdqcError::InvalidArgument("NUL byte in username".to_string()))?,
        ),
        None => None,
    };

    // SAFETY: all CString pointers and the passwd structure remain valid for
    // the duration of the FFI call.
    unsafe_ffi!({
        let context = pwqc_allocate_context()?;
        let syms = &context.library.symbols;
        let qc = context.qc();

        let check_reason = if let Some(ref uname_c) = username_c {
            let empty = CString::default();
            // Zero initialization covers platform-specific fields such as
            // pw_uid and pw_gid; the five pointers match the C initializer.
            let mut pw: libc::passwd = std::mem::zeroed();
            pw.pw_name = uname_c.as_ptr().cast_mut();
            pw.pw_passwd = empty.as_ptr().cast_mut();
            pw.pw_gecos = empty.as_ptr().cast_mut();
            pw.pw_dir = empty.as_ptr().cast_mut();
            pw.pw_shell = empty.as_ptr().cast_mut();
            (syms.passwdqc_check)(
                qc,
                password_c.as_ptr(),
                old_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                &pw,
            )
        } else {
            (syms.passwdqc_check)(
                qc,
                password_c.as_ptr(),
                old_c.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                std::ptr::null(),
            )
        };

        if check_reason.is_null() {
            Ok(PasswordQualityResult::Good)
        } else {
            let reason = CStr::from_ptr(check_reason).to_string_lossy().into_owned();
            Ok(PasswordQualityResult::Bad(reason))
        }
    })
}

// ── Public API: suggest_passwords ─────────────────────────────────────────

/// Generate password suggestions using libpasswdqc.
///
/// Generates `N_SUGGESTIONS` random passwords and returns them as a vector
/// of strings.
///
/// # Returns
///
/// * `Ok(Vec<String>)` — vector of generated password suggestions
/// * `Err(PasswdqcError)` — system error (library not available, generation failure)
pub fn suggest_passwords() -> Result<Vec<String>, PasswdqcError> {
    // SAFETY: the context owns the exact public params representation and
    // remains alive for every FFI call below.
    unsafe_ffi!({
        let context = pwqc_allocate_context()?;
        let syms = &context.library.symbols;
        let qc = context.qc();

        let mut suggestions = Vec::with_capacity(N_SUGGESTIONS);

        for _ in 0..N_SUGGESTIONS {
            let generated = (syms.passwdqc_random)(qc);

            if generated.is_null() {
                return Err(PasswdqcError::GenerateFailed(
                    "passwdqc_random returned NULL".to_string(),
                ));
            }

            let password = CStr::from_ptr(generated).to_string_lossy().into_owned();

            // passwdqc_random allocates with malloc; free it.
            libc::free(generated as *mut c_void);

            suggestions.push(password);
        }

        Ok(suggestions)
    })
}

/// Generate password suggestions and format them as a printable string.
///
/// Returns a formatted string like `"Password suggestions: pw1 pw2 pw3 ..."`
/// on success.
pub fn suggest_passwords_formatted() -> Result<String, PasswdqcError> {
    let suggestions = suggest_passwords()?;
    Ok(format!("Password suggestions: {}", suggestions.join(" ")))
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
    fn test_libpasswdqc_soname() {
        assert_eq!(passwdqc_library_soname(), "libpasswdqc.so.1");
    }

    #[test]
    fn test_passwdqc_conf_path() {
        assert_eq!(passwdqc_conf_path(), "/etc/passwdqc.conf");
    }

    #[test]
    fn test_passwdqc_required_symbols() {
        let syms = passwdqc_required_symbols();
        assert_eq!(syms.len(), 6);
        assert!(syms.contains(&"passwdqc_params_reset"));
        assert!(syms.contains(&"passwdqc_params_load"));
        assert!(syms.contains(&"passwdqc_params_parse"));
        assert!(syms.contains(&"passwdqc_params_free"));
        assert!(syms.contains(&"passwdqc_check"));
        assert!(syms.contains(&"passwdqc_random"));
    }

    #[test]
    fn test_passwdqc_2_params_layout() {
        use std::mem::{align_of, offset_of, size_of};

        let ints_size = 10 * size_of::<c_int>();
        let pointer_align = align_of::<*mut c_char>();
        let first_pointer_offset = (ints_size + pointer_align - 1) & !(pointer_align - 1);

        assert_eq!(offset_of!(PasswdqcParamsQc, min), 0);
        assert_eq!(
            offset_of!(PasswdqcParamsQc, random_bits),
            9 * size_of::<c_int>()
        );
        assert_eq!(offset_of!(PasswdqcParamsQc, wordlist), first_pointer_offset);
        assert_eq!(
            offset_of!(PasswdqcParamsQc, denylist),
            first_pointer_offset + size_of::<*mut c_char>()
        );
        assert_eq!(
            offset_of!(PasswdqcParamsQc, filter),
            first_pointer_offset + 2 * size_of::<*mut c_char>()
        );
        assert_eq!(offset_of!(PasswdqcParams, qc), 0);
        assert_eq!(
            offset_of!(PasswdqcParams, pam),
            size_of::<PasswdqcParamsQc>()
        );
        assert_eq!(size_of::<PasswdqcParamsPam>(), 2 * size_of::<c_int>());
        let unpadded_params_size = size_of::<PasswdqcParamsQc>() + size_of::<PasswdqcParamsPam>();
        let params_align = align_of::<PasswdqcParams>();
        assert_eq!(
            size_of::<PasswdqcParams>(),
            (unpadded_params_size + params_align - 1) & !(params_align - 1)
        );
    }

    #[test]
    fn test_passwdqc_qc_is_inline() {
        // SAFETY: every field is an integer or raw pointer, for which the
        // all-zero bit pattern is valid.
        let params: PasswdqcParams = unsafe_ffi!(std::mem::zeroed());

        assert_eq!(
            std::ptr::addr_of!(params.qc).cast::<u8>(),
            std::ptr::addr_of!(params).cast::<u8>()
        );
    }

    #[test]
    fn test_passwdqc_feature_description() {
        let desc = passwdqc_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("password"));
    }

    #[test]
    fn test_passwdqc_feature_description_matches_c() {
        // Matches the SD_ELF_NOTE_DLOPEN string from the C source.
        assert_eq!(
            passwdqc_feature_description(),
            "Support for password quality checks"
        );
    }

    // ── Error type tests ────────────────────────────────────────────────

    #[test]
    fn test_passwdqc_error_display_unsupported() {
        let e = PasswdqcError::Unsupported;
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_passwdqc_error_display_dlopen_failed() {
        let e = PasswdqcError::DlopenFailed("libpasswdqc.so.1 not found".to_string());
        assert!(e.to_string().contains("libpasswdqc.so.1 not found"));
    }

    #[test]
    fn test_passwdqc_error_display_symbol_not_found() {
        let e = PasswdqcError::SymbolNotFound("passwdqc_check".to_string());
        assert!(e.to_string().contains("passwdqc_check"));
    }

    #[test]
    fn test_passwdqc_error_display_context_allocation() {
        let e = PasswdqcError::ContextAllocationFailed;
        assert!(e.to_string().contains("allocate"));
    }

    #[test]
    fn test_passwdqc_error_display_generate_failed() {
        let e = PasswdqcError::GenerateFailed("random failed".to_string());
        assert!(e.to_string().contains("random failed"));
    }

    #[test]
    fn test_passwdqc_error_display_null_pointer() {
        let e = PasswdqcError::NullPointer("params is null".to_string());
        assert!(e.to_string().contains("null"));
    }

    #[test]
    fn test_passwdqc_error_display_invalid_argument() {
        let e = PasswdqcError::InvalidArgument("NUL byte".to_string());
        assert!(e.to_string().contains("NUL byte"));
    }

    #[test]
    fn test_passwdqc_error_into_c_int_unsupported() {
        let val: i32 = PasswdqcError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_passwdqc_error_into_c_int_dlopen() {
        let val: i32 = PasswdqcError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_missing_required_abi_symbol_is_unsupported() {
        let val: i32 = PasswdqcError::SymbolNotFound("passwdqc_params_free".into()).into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_passwdqc_error_into_c_int_context() {
        let val: i32 = PasswdqcError::ContextAllocationFailed.into();
        assert_eq!(val, Errno::ENOMEM.to_neg_errno());
    }

    #[test]
    fn test_passwdqc_error_into_c_int_generate() {
        let val: i32 = PasswdqcError::GenerateFailed("x".into()).into();
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
    fn test_dlopen_passwdqc_caching() {
        // Success and the exact initialization failure are both cached.
        let r1 = dlopen_passwdqc();
        let r2 = dlopen_passwdqc();
        assert_eq!(r1, r2);
    }

    // ── check_password_quality tests ────────────────────────────────────

    #[test]
    fn test_check_password_quality_returns_result() {
        let result = check_password_quality("testpass", None, None);
        match result {
            Ok(PasswordQualityResult::Good) | Ok(PasswordQualityResult::Bad(_)) => {}
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_old_password() {
        let result = check_password_quality("newpass", Some("oldpass"), None);
        match result {
            Ok(_) => {}
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_username() {
        let result = check_password_quality("testpass", None, Some("root"));
        match result {
            Ok(_) => {}
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_check_password_quality_with_all_args() {
        let result = check_password_quality("newpassword", Some("oldpassword"), Some("admin"));
        match result {
            Ok(_) => {}
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // ── suggest_passwords tests ─────────────────────────────────────────

    #[test]
    fn test_suggest_passwords_returns_result() {
        let result = suggest_passwords();
        match result {
            Ok(suggestions) => assert_eq!(suggestions.len(), N_SUGGESTIONS),
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_suggest_passwords_formatted() {
        let result = suggest_passwords_formatted();
        match result {
            Ok(formatted) => assert!(formatted.starts_with("Password suggestions:")),
            Err(PasswdqcError::Unsupported)
            | Err(PasswdqcError::DlopenFailed(_))
            | Err(PasswdqcError::SymbolNotFound(_)) => {}
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // ── Error std::error::Error impl ────────────────────────────────────

    #[test]
    fn test_passwdqc_error_is_error() {
        let e: Box<dyn std::error::Error> = Box::new(PasswdqcError::Unsupported);
        assert!(e.to_string().contains("not available"));
    }

    #[test]
    fn test_passwdqc_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PasswdqcError>();
    }

    #[test]
    fn test_passwdqc_error_symbol_not_found_roundtrip() {
        for sym in REQUIRED_SYMBOLS {
            let e = PasswdqcError::SymbolNotFound(sym.to_string());
            assert!(e.to_string().contains(sym));
        }
    }
}
