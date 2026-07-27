// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bpf-util.c, src/shared/bpf-util.h
//
// BPF library dynamic loading utilities.
//
// Provides lazy dlopen-based loading of libbpf, symbol resolution for all
// BPF helpers (map operations, program attach/detach, ring buffers, object
// skeletons), and error-code translation for kernel-internal BPF errors.

use std::collections::HashSet;
use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by BPF dynamic-loading operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpfError {
    /// libbpf is not compiled in or not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// Invalid argument passed to a BPF helper.
    InvalidArgument(String),
}

impl fmt::Display for BpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "libbpf support is not compiled in, cgroup BPF features disabled"
            ),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libbpf: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libbpf symbol not found: {}", sym)
            }
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for BpfError {}

impl From<BpfError> for i32 {
    fn from(e: BpfError) -> i32 {
        match e {
            BpfError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            BpfError::DlopenFailed(_) => Errno::ENOENT.to_neg_errno(),
            BpfError::SymbolNotFound(_) => Errno::ENOENT.to_neg_errno(),
            BpfError::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
        }
    }
}

// ── Library name constants ──────────────────────────────────────────────────

/// Shared library names to try, in preference order.
const LIBBPF_CANDIDATES: &[&str] = &["libbpf.so.1", "libbpf.so.0"];

/// Human-readable description for the ELF NOTE metadata.
const BPF_FEATURE_DESCRIPTION: &str = "Support firewalling and sandboxing with BPF";

// ── Required symbol names ───────────────────────────────────────────────────

/// Symbols required from all libbpf versions.
const COMMON_SYMBOLS: &[&str] = &[
    "bpf_link__destroy",
    "bpf_link__fd",
    "bpf_link__open",
    "bpf_link__pin",
    "bpf_map__fd",
    "bpf_map__name",
    "bpf_map__set_inner_map_fd",
    "bpf_map__set_max_entries",
    "bpf_map__set_pin_path",
    "bpf_map_delete_elem",
    "bpf_map_get_fd_by_id",
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "bpf_object__attach_skeleton",
    "bpf_object__destroy_skeleton",
    "bpf_object__detach_skeleton",
    "bpf_object__load_skeleton",
    "bpf_object__name",
    "bpf_object__open_skeleton",
    "bpf_object__pin_maps",
    "bpf_program__attach",
    "bpf_program__attach_cgroup",
    "bpf_program__attach_lsm",
    "bpf_program__name",
    "libbpf_get_error",
    "libbpf_set_print",
    "ring_buffer__epoll_fd",
    "ring_buffer__free",
    "ring_buffer__new",
    "ring_buffer__poll",
];

/// Extra symbols available from libbpf >= 0.7.0 (present in libbpf.so.1).
const V07_SYMBOLS: &[&str] = &["bpf_map_create", "bpf_object__next_map"];

/// Compat symbols removed in libbpf 1.0 (only in libbpf.so.0).
const LEGACY_SYMBOLS: &[&str] = &["bpf_create_map"];

// ── Kernel error translation ───────────────────────────────────────────────

/// Translate a libbpf / kernel BPF error code to a standard errno value.
///
/// libbpf sometimes returns kernel-internal error codes that don't map to
/// standard errnos. This function translates the known ones (e.g. -524
/// → `-EOPNOTSUPP`) and passes everything else through unchanged.
///
/// See: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/errno.h?h=v6.9&id=a38297e3fb012ddfa7ce0321a7e5a8daeb1872b6#n27>
pub fn bpf_get_error_translated(raw_error: i32) -> i32 {
    match raw_error {
        // Kernel bug workaround: BPF returns 524 internally instead of EOPNOTSUPP.
        -524 => Errno::EOPNOTSUPP.to_neg_errno(),
        other => other,
    }
}

// ── Dlopen state machine ───────────────────────────────────────────────────

/// Global flag: has `dlopen_bpf()` been called and completed?
static BPF_LOADED: AtomicBool = AtomicBool::new(false);

/// Convenience wrapper — calls `dlopen_bpf_full` with `log_level = 0`.
pub fn dlopen_bpf() -> Result<(), BpfError> {
    dlopen_bpf_full(0)
}

/// Attempt to dynamically load libbpf.
///
/// This function is idempotent: after the first successful call it returns
/// `Ok(())` immediately. If neither `libbpf.so.1` nor `libbpf.so.0` can be
/// found the result is cached as an error so that subsequent calls return
/// `Err` without retrying.
///
/// `log_level` controls the verbosity of log messages emitted on failure
/// (0 = silent, higher = more verbose).
pub fn dlopen_bpf_full(log_level: i32) -> Result<(), BpfError> {
    if BPF_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let mut last_err = String::new();

    for (idx, lib) in LIBBPF_CANDIDATES.iter().enumerate() {
        match try_load_libbpf(lib, idx == 0, log_level) {
            Ok(()) => {
                BPF_LOADED.store(true, Ordering::Release);
                return Ok(());
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }

    Err(BpfError::DlopenFailed(last_err))
}

/// Try to open a single libbpf candidate and resolve all required symbols.
///
/// `is_modern` is true for `libbpf.so.1` (expects v0.7+ symbols and
/// *not* legacy compat symbols) and false for `libbpf.so.0` (expects
/// legacy symbols and skips v0.7+ symbols).
fn try_load_libbpf(lib_name: &str, is_modern: bool, _log_level: i32) -> Result<(), BpfError> {
    let handle = unsafe { dlopen_library(lib_name) }?;

    let missing = find_missing_symbols(handle, COMMON_SYMBOLS);
    if !missing.is_empty() {
        return Err(BpfError::SymbolNotFound(missing.join(", ")));
    }

    let extra_symbols = if is_modern {
        V07_SYMBOLS
    } else {
        LEGACY_SYMBOLS
    };

    let missing_extra = find_missing_symbols(handle, extra_symbols);
    if !missing_extra.is_empty() {
        return Err(BpfError::SymbolNotFound(missing_extra.join(", ")));
    }

    // Intentionally keep `handle` open for the lifetime of the process.
    // dlclose() is deliberately skipped — the symbols remain valid.
    let _ = handle;

    Ok(())
}

// ── Symbol resolution helpers ──────────────────────────────────────────────

/// Check which symbols from `names` are missing in the loaded library.
fn find_missing_symbols(handle: *mut c_void, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter_map(|&sym| {
            let c_sym = CString::new(sym).unwrap_or_default();
            let ptr = unsafe { resolve_symbol(handle, &c_sym) };
            if ptr.is_null() {
                Some(sym.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library, returning the handle on success.
///
/// Wraps `dlopen()` with `RTLD_LAZY | RTLD_LOCAL` and translates errors
/// into `BpfError::DlopenFailed`.
unsafe fn dlopen_library(lib_name: &str) -> Result<*mut c_void, BpfError> {
    let c_name = CString::new(lib_name)
        .map_err(|e| BpfError::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = dlerror_string();
        Err(BpfError::DlopenFailed(format!("{}: {}", lib_name, detail)))
    } else {
        Ok(handle)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// Returns a null pointer if the symbol is not found (caller checks).
unsafe fn resolve_symbol(handle: *mut c_void, symbol: &CStr) -> *mut c_void {
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

// ── Query helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `dlopen_bpf()` has been called successfully and
/// the library handle is available.
pub fn bpf_is_loaded() -> bool {
    BPF_LOADED.load(Ordering::Acquire)
}

/// Reset the loaded state. Useful for tests.
///
/// Only call from tests. Calling this while BPF symbols are in use is
/// undefined behaviour.
#[cfg(test)]
pub fn reset_bpf_loaded() {
    BPF_LOADED.store(false, Ordering::Release);
}

// ── Feature description (for external consumers) ────────────────────────────

/// Returns the human-readable description of the BPF feature, suitable
/// for inclusion in ELF notes or status reporting.
pub fn bpf_feature_description() -> &'static str {
    BPF_FEATURE_DESCRIPTION
}

/// Returns the list of candidate library names tried during loading.
pub fn bpf_library_candidates() -> &'static [&'static str] {
    LIBBPF_CANDIDATES
}

// ── Symbol name introspection ───────────────────────────────────────────────

/// Returns the full set of symbol names that must be resolved for a
/// successful load of libbpf >= 0.7 (the modern path).
pub fn bpf_required_symbols_modern() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    for &s in COMMON_SYMBOLS {
        set.insert(s);
    }
    for &s in V07_SYMBOLS {
        set.insert(s);
    }
    set
}

/// Returns the full set of symbol names that must be resolved when
/// loading libbpf.so.0 (the legacy / compat path).
pub fn bpf_required_symbols_legacy() -> HashSet<&'static str> {
    let mut set = HashSet::new();
    for &s in COMMON_SYMBOLS {
        set.insert(s);
    }
    for &s in LEGACY_SYMBOLS {
        set.insert(s);
    }
    set
}

// ── BpfMapType enumeration ──────────────────────────────────────────────────

/// BPF map types (subset used by systemd).
///
/// Mirrors the kernel's `enum bpf_map_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BpfMapType {
    /// Unspecified map type.
    Unspec = 0,
    /// Hash table.
    Hash = 1,
    /// Array.
    Array = 2,
    /// Per-CPU hash table.
    PerCpuHash = 5,
    /// Per-CPU array.
    PerCpuArray = 6,
    /// Stack trace map.
    StackTrace = 17,
    /// Hash of maps.
    HashOfMaps = 12,
    /// Array of maps.
    ArrayOfMaps = 13,
    /// LRU hash.
    LruHash = 24,
    /// LRU per-CPU hash.
    LruPerCpuHash = 25,
    /// Ring buffer.
    RingBuf = 27,
}

impl BpfMapType {
    /// Try to parse a BPF map type from its integer discriminant.
    /// Returns `None` for unrecognized values.
    pub fn from_raw(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Unspec),
            1 => Some(Self::Hash),
            2 => Some(Self::Array),
            5 => Some(Self::PerCpuHash),
            6 => Some(Self::PerCpuArray),
            12 => Some(Self::HashOfMaps),
            13 => Some(Self::ArrayOfMaps),
            17 => Some(Self::StackTrace),
            24 => Some(Self::LruHash),
            25 => Some(Self::LruPerCpuHash),
            27 => Some(Self::RingBuf),
            _ => None,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_error_display_unsupported() {
        let e = BpfError::Unsupported;
        assert!(e.to_string().contains("not compiled in"));
    }

    #[test]
    fn test_bpf_error_display_dlopen_failed() {
        let e = BpfError::DlopenFailed("no such file".to_string());
        assert!(e.to_string().contains("no such file"));
    }

    #[test]
    fn test_bpf_error_display_symbol_not_found() {
        let e = BpfError::SymbolNotFound("bpf_map__fd".to_string());
        assert!(e.to_string().contains("bpf_map__fd"));
    }

    #[test]
    fn test_bpf_error_display_invalid_argument() {
        let e = BpfError::InvalidArgument("bad flag".to_string());
        assert!(e.to_string().contains("bad flag"));
    }

    #[test]
    fn test_bpf_error_into_c_int_unsupported() {
        let val: i32 = BpfError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_bpf_error_into_c_int_dlopen_failed() {
        let val: i32 = BpfError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::ENOENT.to_neg_errno());
    }

    #[test]
    fn test_bpf_error_into_c_int_symbol_not_found() {
        let val: i32 = BpfError::SymbolNotFound("x".into()).into();
        assert_eq!(val, Errno::ENOENT.to_neg_errno());
    }

    #[test]
    fn test_bpf_error_into_c_int_invalid_argument() {
        let val: i32 = BpfError::InvalidArgument("x".into()).into();
        assert_eq!(val, Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn test_bpf_get_error_translated_524() {
        assert_eq!(
            bpf_get_error_translated(-524),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
    }

    #[test]
    fn test_bpf_get_error_translated_passthrough() {
        assert_eq!(bpf_get_error_translated(-22), -22);
        assert_eq!(bpf_get_error_translated(-2), -2);
        assert_eq!(bpf_get_error_translated(0), 0);
        assert_eq!(bpf_get_error_translated(42), 42);
    }

    #[test]
    fn test_bpf_feature_description() {
        let desc = bpf_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("BPF"));
    }

    #[test]
    fn test_bpf_library_candidates_order() {
        let candidates = bpf_library_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], "libbpf.so.1");
        assert_eq!(candidates[1], "libbpf.so.0");
    }

    #[test]
    fn test_bpf_required_symbols_modern_count() {
        let syms = bpf_required_symbols_modern();
        assert_eq!(syms.len(), COMMON_SYMBOLS.len() + V07_SYMBOLS.len());
        assert!(syms.contains("bpf_map__fd"));
        assert!(syms.contains("bpf_map_create"));
        assert!(syms.contains("bpf_object__next_map"));
    }

    #[test]
    fn test_bpf_required_symbols_legacy_count() {
        let syms = bpf_required_symbols_legacy();
        assert_eq!(syms.len(), COMMON_SYMBOLS.len() + LEGACY_SYMBOLS.len());
        assert!(syms.contains("bpf_map__fd"));
        assert!(syms.contains("bpf_create_map"));
        assert!(!syms.contains("bpf_map_create"));
    }

    #[test]
    fn test_bpf_map_type_from_raw_known() {
        assert_eq!(BpfMapType::from_raw(0), Some(BpfMapType::Unspec));
        assert_eq!(BpfMapType::from_raw(1), Some(BpfMapType::Hash));
        assert_eq!(BpfMapType::from_raw(2), Some(BpfMapType::Array));
        assert_eq!(BpfMapType::from_raw(5), Some(BpfMapType::PerCpuHash));
        assert_eq!(BpfMapType::from_raw(6), Some(BpfMapType::PerCpuArray));
        assert_eq!(BpfMapType::from_raw(13), Some(BpfMapType::ArrayOfMaps));
        assert_eq!(BpfMapType::from_raw(24), Some(BpfMapType::LruHash));
        assert_eq!(BpfMapType::from_raw(25), Some(BpfMapType::LruPerCpuHash));
        assert_eq!(BpfMapType::from_raw(27), Some(BpfMapType::RingBuf));
    }

    #[test]
    fn test_bpf_map_type_from_raw_unknown() {
        assert_eq!(BpfMapType::from_raw(99), None);
        assert_eq!(BpfMapType::from_raw(200), None);
    }

    #[test]
    fn test_bpf_map_type_discriminants() {
        assert_eq!(BpfMapType::Unspec as u32, 0);
        assert_eq!(BpfMapType::Hash as u32, 1);
        assert_eq!(BpfMapType::Array as u32, 2);
        assert_eq!(BpfMapType::ArrayOfMaps as u32, 13);
        assert_eq!(BpfMapType::RingBuf as u32, 27);
    }

    #[test]
    fn test_bpf_is_loaded_initial() {
        reset_bpf_loaded();
        assert!(!bpf_is_loaded());
    }

    #[test]
    fn test_common_symbols_not_empty() {
        assert!(!COMMON_SYMBOLS.is_empty());
        assert!(COMMON_SYMBOLS.len() > 20);
    }

    #[test]
    fn test_common_symbols_are_unique() {
        let set: HashSet<_> = COMMON_SYMBOLS.iter().copied().collect();
        assert_eq!(set.len(), COMMON_SYMBOLS.len());
    }

    #[test]
    fn test_v07_symbols_not_empty() {
        assert!(!V07_SYMBOLS.is_empty());
    }

    #[test]
    fn test_legacy_symbols_not_empty() {
        assert!(!LEGACY_SYMBOLS.is_empty());
    }

    #[test]
    fn test_symbol_sets_disjoint() {
        let common: HashSet<_> = COMMON_SYMBOLS.iter().copied().collect();
        let v07: HashSet<_> = V07_SYMBOLS.iter().copied().collect();
        let legacy: HashSet<_> = LEGACY_SYMBOLS.iter().copied().collect();
        for s in &v07 {
            assert!(!common.contains(s), "V07 symbol {} also in COMMON", s);
        }
        for s in &legacy {
            assert!(!common.contains(s), "Legacy symbol {} also in COMMON", s);
        }
    }

    #[test]
    fn test_dlopen_bpf_full_caching() {
        reset_bpf_loaded();
        let r1 = dlopen_bpf_full(0);
        let r2 = dlopen_bpf_full(0);
        assert_eq!(r1.is_ok(), r2.is_ok());
    }
}
