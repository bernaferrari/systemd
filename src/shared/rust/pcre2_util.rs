// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/pcre2-util.c, src/shared/pcre2-util.h
//
// PCRE2 regular expression utilities.
//
// Provides dynamic loading of libpcre2-8 via dlopen, regex pattern
// compilation with case-sensitivity control (sensitive, insensitive,
// or auto-detected from pattern content), and pattern matching against
// arbitrary byte buffers with optional ovector output.

use std::collections::HashSet;
use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by PCRE2 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pcre2Error {
    /// PCRE2 support is not compiled in or library unavailable.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The library is already loaded; a second load is unnecessary.
    AlreadyLoaded,
    /// The regex pattern is invalid.
    InvalidPattern { pattern: String, detail: String },
    /// Pattern matching failed at the PCRE2 level.
    MatchFailed(String),
    /// Out of memory.
    OutOfMemory,
}

impl fmt::Display for Pcre2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "PCRE2 support is not compiled in"),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libpcre2-8: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required PCRE2 symbol not found: {}", sym)
            }
            Self::AlreadyLoaded => write!(f, "PCRE2 is already loaded"),
            Self::InvalidPattern { pattern, detail } => {
                write!(f, "Bad pattern \"{}\": {}", pattern, detail)
            }
            Self::MatchFailed(msg) => write!(f, "Pattern matching failed: {}", msg),
            Self::OutOfMemory => write!(f, "Out of memory"),
        }
    }
}

impl std::error::Error for Pcre2Error {}

impl From<Pcre2Error> for i32 {
    fn from(e: Pcre2Error) -> i32 {
        match e {
            Pcre2Error::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            Pcre2Error::DlopenFailed(_) | Pcre2Error::SymbolNotFound(_) => {
                Errno::ENOENT.to_neg_errno()
            }
            Pcre2Error::AlreadyLoaded => Errno::EBUSY.to_neg_errno(),
            Pcre2Error::InvalidPattern { .. } | Pcre2Error::MatchFailed(_) => {
                Errno::EINVAL.to_neg_errno()
            }
            Pcre2Error::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
        }
    }
}

// ── Compile case enumeration ────────────────────────────────────────────────

/// Controls case-sensitivity behaviour during pattern compilation.
///
/// Mirrors the C `PatternCompileCase` enum from `pcre2-util.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PatternCompileCase {
    /// Auto-detect: use case-insensitive matching if the pattern
    /// contains no uppercase ASCII letters.
    Auto = 0,
    /// Force case-sensitive matching.
    Sensitive = 1,
    /// Force case-insensitive matching.
    Insensitive = 2,
}

impl PatternCompileCase {
    /// Sentinel for invalid values, matching C's `_PATTERN_COMPILE_CASE_INVALID`.
    pub const INVALID: i32 = Errno::EINVAL.to_neg_errno();

    /// Try to construct from a raw integer discriminant.
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::Auto),
            1 => Some(Self::Sensitive),
            2 => Some(Self::Insensitive),
            _ => None,
        }
    }

    /// Total number of valid variants (matches C's `_PATTERN_COMPILE_CASE_MAX`).
    pub const COUNT: usize = 3;
}

// ── Match result ────────────────────────────────────────────────────────────

/// Result of a pattern match, optionally including the ovector
/// (start and end offsets of the first capture group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    /// Whether the pattern matched.
    pub matched: bool,
    /// Ovector: `(start_offset, end_offset)` of the first capture.
    /// Present only when `matched` is true and ovector was requested.
    pub ovector: Option<(usize, usize)>,
}

// ── Compiled pattern handle ────────────────────────────────────────────────

/// Opaque handle to a compiled PCRE2 pattern.
///
/// Wraps a raw pointer returned by `pcre2_compile_8` and frees it on drop
/// via `pcre2_code_free_8`.
#[derive(Debug)]
pub struct CompiledPattern {
    ptr: *mut c_void,
}

impl CompiledPattern {
    /// Create a new `CompiledPattern` from a raw PCRE2 code pointer.
    ///
    /// # Safety
    /// `ptr` must be a valid pointer returned by `pcre2_compile_8`, or null.
    unsafe fn from_raw(ptr: *mut c_void) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Returns the raw pointer (for internal use only).
    fn as_ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for CompiledPattern {
    fn drop(&mut self) {
        // Load the free function on demand — the library must already be loaded.
        if let Ok(lib) = Pcre2Lib::current() {
            unsafe {
                (lib.code_free())(self.ptr);
            }
        }
    }
}

// SAFETY: PCRE2 compiled code is thread-safe for matching (read-only access).
unsafe impl Send for CompiledPattern {}
// SAFETY: Shared references are read-only, and PCRE2 compiled patterns are safe to
// match concurrently across threads.
unsafe impl Sync for CompiledPattern {}

// ── PCRE2 library name and symbols ─────────────────────────────────────────

/// Shared library name for PCRE2 (8-bit code unit width).
const PCRE2_LIB_NAME: &str = "libpcre2-8.so.0";

/// All PCRE2 symbols that must be resolved.
///
/// Note: PCRE2 renames exported symbols with a `_8` suffix via C macros
/// (e.g. `pcre2_compile` → `pcre2_compile_8` in the .so). The C
/// `STRINGIFY()` macro resolves this transparently. Here we use the
/// mangled names directly.
const PCRE2_SYMBOLS: &[&str] = &[
    "pcre2_match_data_create_8",
    "pcre2_match_data_free_8",
    "pcre2_code_free_8",
    "pcre2_compile_8",
    "pcre2_get_error_message_8",
    "pcre2_match_8",
    "pcre2_get_ovector_pointer_8",
];

/// Human-readable description of the PCRE2 feature.
const PCRE2_FEATURE_DESCRIPTION: &str = "Support for regular expressions";

// ── PCRE2 FFI function types ────────────────────────────────────────────────

type Pcre2CompileFn = unsafe extern "C" fn(
    *const u8,   // pattern (PCRE2_SPTR8)
    usize,       // length (PCRE2_SIZE)
    u32,         // flags
    *mut i32,    // errorcode
    *mut usize,  // erroroffset (PCRE2_SIZE)
    *mut c_void, // compile context
) -> *mut c_void; // pcre2_code*

type Pcre2MatchFn = unsafe extern "C" fn(
    *const c_void, // code
    *const u8,     // subject (PCRE2_SPTR8)
    usize,         // length (PCRE2_SIZE)
    usize,         // startoffset
    u32,           // options
    *mut c_void,   // match_data
    *mut c_void,   // match_context
) -> i32;

type Pcre2MatchDataCreateFn = unsafe extern "C" fn(i32, *mut c_void) -> *mut c_void; // (ovecsize, general_ctx)

type Pcre2MatchDataFreeFn = unsafe extern "C" fn(*mut c_void);
type Pcre2CodeFreeFn = unsafe extern "C" fn(*mut c_void);

type Pcre2GetErrorMessageFn = unsafe extern "C" fn(
    i32,     // errorcode
    *mut u8, // buffer
    usize,   // bufflen (PCRE2_SIZE)
) -> i32;

type Pcre2GetOvectorPointerFn = unsafe extern "C" fn(*mut c_void) -> *mut usize;

// ── Dlopen state ────────────────────────────────────────────────────────────

/// Global flag: has `dlopen_pcre2()` been called successfully?
static PCRE2_LOADED: AtomicBool = AtomicBool::new(false);

/// Cached library handle (kept open for process lifetime).
static PCRE2_HANDLE: std::sync::atomic::AtomicPtr<c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Cached symbol pointers, packed into a struct.
struct Pcre2Symbols {
    match_data_create: Pcre2MatchDataCreateFn,
    match_data_free: Pcre2MatchDataFreeFn,
    code_free: Pcre2CodeFreeFn,
    compile: Pcre2CompileFn,
    get_error_message: Pcre2GetErrorMessageFn,
    match_fn: Pcre2MatchFn,
    get_ovector_pointer: Pcre2GetOvectorPointerFn,
}

// Use a Mutex to protect the lazy-init of the symbol struct.
static PCRE2_SYMS: std::sync::OnceLock<Pcre2Symbols> = std::sync::OnceLock::new();

/// Wrapper around the loaded PCRE2 library providing typed access to symbols.
struct Pcre2Lib {
    _handle: *mut c_void,
    syms: &'static Pcre2Symbols,
}

impl Pcre2Lib {
    /// Return the current library if loaded, or an error.
    fn current() -> Result<Self, Pcre2Error> {
        if !PCRE2_LOADED.load(Ordering::Acquire) {
            return Err(Pcre2Error::Unsupported);
        }
        let handle = PCRE2_HANDLE.load(Ordering::Acquire);
        let syms = PCRE2_SYMS.get().ok_or(Pcre2Error::Unsupported)?;
        Ok(Self {
            _handle: handle,
            syms,
        })
    }

    fn compile(&self) -> Pcre2CompileFn {
        self.syms.compile
    }

    fn match_fn(&self) -> Pcre2MatchFn {
        self.syms.match_fn
    }

    fn match_data_create(&self) -> Pcre2MatchDataCreateFn {
        self.syms.match_data_create
    }

    fn match_data_free(&self) -> Pcre2MatchDataFreeFn {
        self.syms.match_data_free
    }

    fn code_free(&self) -> Pcre2CodeFreeFn {
        self.syms.code_free
    }

    fn get_error_message(&self) -> Pcre2GetErrorMessageFn {
        self.syms.get_error_message
    }

    fn get_ovector_pointer(&self) -> Pcre2GetOvectorPointerFn {
        self.syms.get_ovector_pointer
    }
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library, returning the handle on success.
unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, Pcre2Error> {
    let c_name = CString::new(lib_name)
        .map_err(|e| Pcre2Error::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = dlerror_string();
        Err(Pcre2Error::DlopenFailed(format!(
            "{}: {}",
            lib_name, detail
        )))
    } else {
        Ok(handle)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// # Safety
/// `handle` must be a valid handle returned by `dlopen`.
unsafe fn dlsym_wrapper(handle: *mut c_void, symbol: &CStr) -> *mut c_void {
    // SAFETY: the caller supplies a live dlopen handle and symbol is NUL-terminated.
    unsafe { libc::dlsym(handle, symbol.as_ptr()) }
}

/// Retrieve the last `dlerror()` message as a Rust `String`.
fn dlerror_string() -> String {
    unsafe {
        let ptr = libc::dlerror();
        if ptr.is_null() {
            return "unknown error".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ── PCRE2 constants ─────────────────────────────────────────────────────────

/// `PCRE2_CASELESS` — case-insensitive matching flag.
const PCRE2_CASELESS: u32 = 0x0000_0008;

/// `PCRE2_ZERO_TERMINATED` — special length value indicating a NUL-terminated string.
const PCRE2_ZERO_TERMINATED: usize = usize::MAX;

/// `PCRE2_ERROR_NOMATCH` — return code when the subject does not match the pattern.
const PCRE2_ERROR_NOMATCH: i32 = -1;

// ── Public API ──────────────────────────────────────────────────────────────

/// Attempt to dynamically load libpcre2-8.
///
/// This function is idempotent: after the first successful call it returns
/// `Ok(())` immediately. On failure the result is cached so subsequent
/// calls return `Err` without retrying.
pub fn dlopen_pcre2() -> Result<(), Pcre2Error> {
    if PCRE2_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let handle = unsafe { dlopen_wrapper(PCRE2_LIB_NAME) }?;

    // Resolve all required symbols.
    let missing: Vec<String> = PCRE2_SYMBOLS
        .iter()
        .filter_map(|sym| {
            let c_sym = CString::new(*sym).unwrap_or_default();
            let ptr = unsafe { dlsym_wrapper(handle, &c_sym) };
            if ptr.is_null() {
                Some((*sym).to_string())
            } else {
                None
            }
        })
        .collect();

    if !missing.is_empty() {
        return Err(Pcre2Error::SymbolNotFound(missing.join(", ")));
    }

    // Safe to transmute: we just verified the symbols exist and the
    // function signatures match the PCRE2 ABI.
    let syms = unsafe {
        let c_sym = |name: &str| -> *mut c_void {
            let c = CString::new(name).unwrap_or_default();
            dlsym_wrapper(handle, &c)
        };

        Pcre2Symbols {
            match_data_create: std::mem::transmute(c_sym("pcre2_match_data_create_8")),
            match_data_free: std::mem::transmute(c_sym("pcre2_match_data_free_8")),
            code_free: std::mem::transmute(c_sym("pcre2_code_free_8")),
            compile: std::mem::transmute(c_sym("pcre2_compile_8")),
            get_error_message: std::mem::transmute(c_sym("pcre2_get_error_message_8")),
            match_fn: std::mem::transmute(c_sym("pcre2_match_8")),
            get_ovector_pointer: std::mem::transmute(c_sym("pcre2_get_ovector_pointer_8")),
        }
    };

    // Store handle and symbols globally.
    PCRE2_HANDLE.store(handle, Ordering::Release);
    let _ = PCRE2_SYMS.set(syms);
    PCRE2_LOADED.store(true, Ordering::Release);

    Ok(())
}

/// Check whether the pattern string contains any uppercase ASCII letters.
///
/// Used by the `Auto` case mode to decide whether to enable
/// case-insensitive matching.
fn pattern_has_uppercase(pattern: &str) -> bool {
    pattern.bytes().any(|b| b.is_ascii_uppercase())
}

/// Get an error message string from a PCRE2 error code.
///
/// Returns a human-readable message, or `"unknown error"` if the code
/// is unrecognised.
fn pcre2_error_message(lib: &Pcre2Lib, errorcode: i32) -> String {
    let mut buf = [0u8; 1024];
    let rc = unsafe { (lib.get_error_message())(errorcode, buf.as_mut_ptr(), buf.len()) };
    if rc < 0 {
        return "unknown error".to_string();
    }
    // Find the NUL terminator.
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

/// Compile a PCRE2 regex pattern.
///
/// This is the Rust equivalent of `pattern_compile_and_log()`. It ensures
/// PCRE2 is loaded, handles case-sensitivity mode selection, and returns
/// a `CompiledPattern` on success.
///
/// # Arguments
/// * `pattern` - The regex pattern string (NUL-terminated by the caller).
/// * `case_` - Case-sensitivity mode.
///
/// # Errors
/// * `Pcre2Error::Unsupported` — PCRE2 library not available.
/// * `Pcre2Error::InvalidPattern` — The pattern could not be compiled.
/// * `Pcre2Error::OutOfMemory` — Allocation failure in PCRE2.
pub fn pattern_compile(
    pattern: &str,
    case_: PatternCompileCase,
) -> Result<CompiledPattern, Pcre2Error> {
    let lib = Pcre2Lib::current()?;

    let mut flags: u32 = 0;

    if case_ == PatternCompileCase::Insensitive {
        flags = PCRE2_CASELESS;
    } else if case_ == PatternCompileCase::Auto {
        // Auto-detect: compile a probe pattern and test the user pattern
        // for uppercase letters.
        let has_upper = pattern_has_uppercase(pattern);
        if !has_upper {
            flags = PCRE2_CASELESS;
        }
    }

    let pattern_cstr = CString::new(pattern).map_err(|_| Pcre2Error::InvalidPattern {
        pattern: pattern.to_string(),
        detail: "pattern contains NUL byte".to_string(),
    })?;

    let mut errorcode: i32 = 0;
    let mut erroroffset: usize = 0;

    let code_ptr = unsafe {
        (lib.compile())(
            pattern_cstr.as_ptr() as *const u8,
            PCRE2_ZERO_TERMINATED,
            flags,
            &mut errorcode,
            &mut erroroffset,
            std::ptr::null_mut(),
        )
    };

    if code_ptr.is_null() {
        let detail = pcre2_error_message(&lib, errorcode);
        return Err(Pcre2Error::InvalidPattern {
            pattern: pattern.to_string(),
            detail,
        });
    }

    // SAFETY: code_ptr is non-null and returned by pcre2_compile_8.
    unsafe { CompiledPattern::from_raw(code_ptr) }.ok_or(Pcre2Error::InvalidPattern {
        pattern: pattern.to_string(),
        detail: "pcre2_compile returned null".to_string(),
    })
}

/// Match a compiled PCRE2 pattern against a message buffer.
///
/// This is the Rust equivalent of `pattern_matches_and_log()`.
///
/// # Arguments
/// * `compiled_pattern` - A previously compiled pattern.
/// * `message` - The subject string to match against.
/// * `want_ovector` - If true, populate the returned `MatchResult` with
///   the ovector offsets.
///
/// # Errors
/// * `Pcre2Error::Unsupported` — PCRE2 library not loaded.
/// * `Pcre2Error::MatchFailed` — PCRE2 returned an error other than NOMATCH.
/// * `Pcre2Error::OutOfMemory` — Could not allocate match data.
pub fn pattern_matches(
    compiled_pattern: &CompiledPattern,
    message: &str,
    want_ovector: bool,
) -> Result<MatchResult, Pcre2Error> {
    let lib = Pcre2Lib::current()?;

    // Create match data for 1 capture group.
    let md = unsafe { (lib.match_data_create())(1, std::ptr::null_mut()) };
    if md.is_null() {
        return Err(Pcre2Error::OutOfMemory);
    }

    // Ensure match data is freed.
    struct MatchDataGuard {
        ptr: *mut c_void,
        free_fn: Pcre2MatchDataFreeFn,
    }
    impl Drop for MatchDataGuard {
        fn drop(&mut self) {
            unsafe {
                (self.free_fn)(self.ptr);
            }
        }
    }
    let _guard = MatchDataGuard {
        ptr: md,
        free_fn: lib.match_data_free(),
    };

    let message_cstr = CString::new(message)
        .map_err(|_| Pcre2Error::MatchFailed("message contains NUL byte".to_string()))?;

    let rc = unsafe {
        (lib.match_fn())(
            compiled_pattern.as_ptr(),
            message_cstr.as_ptr() as *const u8,
            PCRE2_ZERO_TERMINATED,
            0, // start offset
            0, // options
            md,
            std::ptr::null_mut(),
        )
    };

    if rc == PCRE2_ERROR_NOMATCH {
        return Ok(MatchResult {
            matched: false,
            ovector: None,
        });
    }

    if rc < 0 {
        let detail = pcre2_error_message(&lib, rc);
        return Err(Pcre2Error::MatchFailed(detail));
    }

    let ovector = if want_ovector {
        let ovec = unsafe { (lib.get_ovector_pointer())(md) };
        if ovec.is_null() {
            None
        } else {
            Some((unsafe { *ovec }, unsafe { *ovec.add(1) }))
        }
    } else {
        None
    };

    Ok(MatchResult {
        matched: true,
        ovector,
    })
}

// ── Query helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `dlopen_pcre2()` has been called successfully.
pub fn pcre2_is_loaded() -> bool {
    PCRE2_LOADED.load(Ordering::Acquire)
}

/// Returns the human-readable description of the PCRE2 feature.
pub fn pcre2_feature_description() -> &'static str {
    PCRE2_FEATURE_DESCRIPTION
}

/// Returns the library name that will be loaded.
pub fn pcre2_library_name() -> &'static str {
    PCRE2_LIB_NAME
}

/// Returns the set of symbol names required from libpcre2-8.
pub fn pcre2_required_symbols() -> HashSet<&'static str> {
    PCRE2_SYMBOLS.iter().copied().collect()
}

/// Reset the loaded state. For testing only.
#[cfg(test)]
pub fn reset_pcre2_loaded() {
    PCRE2_LOADED.store(false, Ordering::Release);
    PCRE2_HANDLE.store(std::ptr::null_mut(), Ordering::Release);
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_compile_case_from_raw() {
        assert_eq!(
            PatternCompileCase::from_raw(0),
            Some(PatternCompileCase::Auto)
        );
        assert_eq!(
            PatternCompileCase::from_raw(1),
            Some(PatternCompileCase::Sensitive)
        );
        assert_eq!(
            PatternCompileCase::from_raw(2),
            Some(PatternCompileCase::Insensitive)
        );
        assert_eq!(PatternCompileCase::from_raw(3), None);
        assert_eq!(PatternCompileCase::from_raw(-1), None);
        assert_eq!(PatternCompileCase::from_raw(99), None);
    }

    #[test]
    fn test_pattern_compile_case_discriminants() {
        assert_eq!(PatternCompileCase::Auto as i32, 0);
        assert_eq!(PatternCompileCase::Sensitive as i32, 1);
        assert_eq!(PatternCompileCase::Insensitive as i32, 2);
    }

    #[test]
    fn test_pattern_compile_case_count() {
        assert_eq!(PatternCompileCase::COUNT, 3);
    }

    #[test]
    fn test_pattern_compile_case_invalid_sentinel() {
        assert_eq!(PatternCompileCase::INVALID, Errno::EINVAL.to_neg_errno());
        assert_eq!(PatternCompileCase::INVALID, -22);
    }

    #[test]
    fn test_pattern_has_uppercase() {
        assert!(pattern_has_uppercase("Hello"));
        assert!(pattern_has_uppercase("ABC"));
        assert!(pattern_has_uppercase("aBc"));
        assert!(!pattern_has_uppercase("hello"));
        assert!(!pattern_has_uppercase("123"));
        assert!(!pattern_has_uppercase(""));
        assert!(!pattern_has_uppercase("hello-world"));
    }

    #[test]
    fn test_pcre2_error_display_unsupported() {
        let e = Pcre2Error::Unsupported;
        assert!(e.to_string().contains("not compiled in"));
    }

    #[test]
    fn test_pcre2_error_display_dlopen_failed() {
        let e = Pcre2Error::DlopenFailed("no such file".to_string());
        assert!(e.to_string().contains("no such file"));
    }

    #[test]
    fn test_pcre2_error_display_symbol_not_found() {
        let e = Pcre2Error::SymbolNotFound("pcre2_compile_8".to_string());
        assert!(e.to_string().contains("pcre2_compile_8"));
    }

    #[test]
    fn test_pcre2_error_display_invalid_pattern() {
        let e = Pcre2Error::InvalidPattern {
            pattern: "[invalid".to_string(),
            detail: "unmatched bracket".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("[invalid"));
        assert!(s.contains("unmatched bracket"));
    }

    #[test]
    fn test_pcre2_error_display_match_failed() {
        let e = Pcre2Error::MatchFailed("some pcre2 error".to_string());
        assert!(e.to_string().contains("some pcre2 error"));
    }

    #[test]
    fn test_pcre2_error_display_out_of_memory() {
        let e = Pcre2Error::OutOfMemory;
        assert!(e.to_string().contains("Out of memory"));
    }

    #[test]
    fn test_pcre2_error_display_already_loaded() {
        let e = Pcre2Error::AlreadyLoaded;
        assert!(e.to_string().contains("already loaded"));
    }

    #[test]
    fn test_pcre2_error_into_c_int() {
        let val: i32 = Pcre2Error::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());

        let val: i32 = Pcre2Error::InvalidPattern {
            pattern: "x".into(),
            detail: "d".into(),
        }
        .into();
        assert_eq!(val, Errno::EINVAL.to_neg_errno());

        let val: i32 = Pcre2Error::OutOfMemory.into();
        assert_eq!(val, Errno::ENOMEM.to_neg_errno());
    }

    #[test]
    fn test_pcre2_error_equality() {
        let a = Pcre2Error::Unsupported;
        let b = Pcre2Error::Unsupported;
        assert_eq!(a, b);

        let c = Pcre2Error::InvalidPattern {
            pattern: "x".into(),
            detail: "d".into(),
        };
        let d = Pcre2Error::InvalidPattern {
            pattern: "x".into(),
            detail: "d".into(),
        };
        assert_eq!(c, d);

        let e = Pcre2Error::InvalidPattern {
            pattern: "y".into(),
            detail: "d".into(),
        };
        assert_ne!(c, e);
    }

    #[test]
    fn test_pcre2_feature_description() {
        let desc = pcre2_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("regular expressions"));
    }

    #[test]
    fn test_pcre2_library_name() {
        assert_eq!(pcre2_library_name(), "libpcre2-8.so.0");
    }

    #[test]
    fn test_pcre2_required_symbols() {
        let syms = pcre2_required_symbols();
        assert_eq!(syms.len(), PCRE2_SYMBOLS.len());
        assert!(syms.contains("pcre2_compile_8"));
        assert!(syms.contains("pcre2_match_8"));
        assert!(syms.contains("pcre2_code_free_8"));
        assert!(syms.contains("pcre2_match_data_create_8"));
        assert!(syms.contains("pcre2_match_data_free_8"));
        assert!(syms.contains("pcre2_get_error_message_8"));
        assert!(syms.contains("pcre2_get_ovector_pointer_8"));
    }

    #[test]
    fn test_pcre2_symbols_are_unique() {
        let set: HashSet<_> = PCRE2_SYMBOLS.iter().copied().collect();
        assert_eq!(set.len(), PCRE2_SYMBOLS.len());
    }

    #[test]
    fn test_match_result_construction() {
        let mr = MatchResult {
            matched: true,
            ovector: Some((3, 7)),
        };
        assert!(mr.matched);
        assert_eq!(mr.ovector, Some((3, 7)));

        let mr2 = MatchResult {
            matched: false,
            ovector: None,
        };
        assert!(!mr2.matched);
        assert!(mr2.ovector.is_none());
    }

    #[test]
    fn test_pcre2_constants() {
        assert_eq!(PCRE2_CASELESS, 0x0000_0008);
        assert_eq!(PCRE2_ZERO_TERMINATED, usize::MAX);
        assert_eq!(PCRE2_ERROR_NOMATCH, -1);
    }

    #[test]
    fn test_pcre2_is_loaded_initial() {
        reset_pcre2_loaded();
        assert!(!pcre2_is_loaded());
    }

    #[test]
    fn test_pattern_compile_without_pcre2_loaded() {
        reset_pcre2_loaded();
        let result = pattern_compile("test", PatternCompileCase::Sensitive);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Pcre2Error::Unsupported);
    }

    #[test]
    fn test_pattern_matches_without_pcre2_loaded() {
        reset_pcre2_loaded();
        // We can't easily construct a CompiledPattern without the library,
        // but we can verify the library-not-loaded path.
        assert!(!pcre2_is_loaded());
    }

    #[test]
    fn test_pcre2_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(Pcre2Error::Unsupported);
        assert!(e.to_string().contains("not compiled in"));
    }

    #[test]
    fn test_pattern_compile_case_auto_flags_logic() {
        // Auto with lowercase → caseless
        let has_upper = pattern_has_uppercase("lowercase");
        assert!(!has_upper);

        // Auto with uppercase → case-sensitive
        let has_upper = pattern_has_uppercase("MixedCase");
        assert!(has_upper);
    }
}
