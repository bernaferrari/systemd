// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bpf-util.c, src/shared/bpf-util.h
//
// BPF library dynamic loading utilities.
//
// Provides a safe loader-state and symbol-presence model for libbpf. The
// authoritative C implementation owns the process-global typed function
// pointers, configures libbpf logging, and calls `libbpf_get_error()` on
// opaque libbpf pointers. This module deliberately does none of those things:
// it never turns a `dlsym()` address into a callable Rust function pointer.
//
// That boundary is intentional. A production Rust replacement must introduce
// a typed, lifetime-safe libbpf ABI table before it can replace C callers.

use std::collections::HashSet;
use std::fmt;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::ffi::Errno;
use systemd_basic_rs::dlfcn_util::UnpublishedDlopenHandle;

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
            BpfError::DlopenFailed(_) => Errno::EOPNOTSUPP.to_neg_errno(),
            BpfError::SymbolNotFound(_) => Errno::ELIBBAD.to_neg_errno(),
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
    "bpf_obj_get_info_by_fd",
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
    "bpf_program__set_autoload",
    "libbpf_get_error",
    "libbpf_set_print",
    "ring_buffer__epoll_fd",
    "ring_buffer__free",
    "ring_buffer__new",
    "ring_buffer__poll",
];

/// Optional compatibility/features symbol names from the C implementation.
///
/// Their absence does not reject an otherwise usable libbpf. C stores the
/// successfully resolved function pointers (or retains NULL / the
/// `bpf_token_create` `-ENOSYS` fallback). This safe model intentionally does
/// not expose callable optional symbols until it has a typed ABI table.
const OPTIONAL_SYMBOL_NAMES: &[&str] = &[
    "bpf_create_map",
    "bpf_map_create",
    "bpf_object__next_map",
    "bpf_token_create",
];

// ── Kernel error translation ───────────────────────────────────────────────

/// Translate an already-decoded libbpf error code to a standard errno value.
///
/// C's `bpf_get_error_translated(const void *)` first calls the dynamically
/// loaded `libbpf_get_error(ptr)`, then performs this translation. Passing an
/// opaque pointer across that ABI is deliberately out of scope for this safe
/// value model; callers must supply the resulting integer error code.
///
/// libbpf sometimes returns kernel-internal error codes that don't map to
/// standard errnos. This function translates the known one (`-524` to
/// `-EOPNOTSUPP`) and passes every other value through unchanged.
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

/// C's loader caches its first failed load attempt as well. Keep that
/// observable behavior while also serializing initialization so successful
/// racing callers cannot each leak a process-lifetime library reference.
static BPF_LOAD_STATE: Mutex<Option<BpfError>> = Mutex::new(None);

/// Convenience wrapper — calls `dlopen_bpf_full` with `log_level = 0`.
pub fn dlopen_bpf() -> Result<(), BpfError> {
    dlopen_bpf_full(0)
}

/// Attempt to dynamically load libbpf.
///
/// This function is idempotent: after the first successful call it returns
/// `Ok(())` immediately. It caches the final failure from C's soname order as
/// C's `dlopen_bpf()` does, so later calls return the same error without
/// retrying.
///
/// `log_level` is accepted for call-shape parity. C uses it only for process
/// logging; this safe state model neither installs C's libbpf print callback
/// nor emits process logs.
pub fn dlopen_bpf_full(log_level: i32) -> Result<(), BpfError> {
    if BPF_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    // A poisoned lock cannot invalidate dynamic-loader state. Recover the
    // stored result so an unrelated panic does not reopen the load race.
    let mut load_state = BPF_LOAD_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if BPF_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }
    if let Some(error) = &*load_state {
        return Err(error.clone());
    }

    let mut last_error = None;

    for lib in LIBBPF_CANDIDATES {
        match try_load_libbpf(lib, log_level) {
            Ok(()) => {
                BPF_LOADED.store(true, Ordering::Release);
                return Ok(());
            }
            Err(e) => {
                // Even after block_dlopen(), C tries the next soname: it may
                // already be resident and therefore accepted with RTLD_NOLOAD.
                last_error = Some(e);
            }
        }
    }

    let error = last_error
        .unwrap_or_else(|| BpfError::DlopenFailed("no libbpf loader candidates configured".into()));
    *load_state = Some(error.clone());
    Err(error)
}

/// Try to open a single libbpf candidate and resolve all required symbols.
///
fn try_load_libbpf(lib_name: &str, _log_level: i32) -> Result<(), BpfError> {
    let handle = dlopen_library(lib_name)?;

    if let Some(symbol) = find_first_missing_symbol(&handle, COMMON_SYMBOLS) {
        // `dlsym_many_or_warnv()` in src/basic/dlfcn-util.c resolves the
        // required entries in declaration order and returns `-ELIBBAD` at the
        // first missing one. Do the same rather than reporting a synthetic
        // aggregate that C never produces.
        return Err(BpfError::SymbolNotFound(symbol));
    }

    // The validated library reference is process-lifetime state, matching the
    // C loader. Unlike C, this module intentionally does not retain or call
    // individual libbpf symbol addresses.
    handle.publish();

    Ok(())
}

// ── Symbol resolution helpers ──────────────────────────────────────────────

/// Return the first required symbol missing from a loaded library.
///
/// This preserves the sequential failure behavior of C's
/// `dlsym_many_or_warnv()`. The detailed `dlerror()` text is intentionally
/// kept inside the shared loader diagnostic; C's public result is only
/// `-ELIBBAD` for this condition.
fn find_first_missing_symbol(handle: &UnpublishedDlopenHandle, names: &[&str]) -> Option<String> {
    first_missing_symbol(names, |symbol| handle.resolve_required(symbol).is_err())
        .map(str::to_owned)
}

/// Select the first missing entry from C's ordered required-symbol list.
///
/// Kept separate from the loader call so the C-visible first-failure rule is
/// directly testable without opening a host library.
fn first_missing_symbol<'a>(
    names: &'a [&'a str],
    mut is_missing: impl FnMut(&str) -> bool,
) -> Option<&'a str> {
    names.iter().copied().find(|symbol| is_missing(symbol))
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library through the C project's authoritative loader policy.
///
/// `dlopen_safe()` supplies `RTLD_NOW | RTLD_NODELETE`, rejects new loads
/// after `block_dlopen()`, and returns `EOPNOTSUPP` in static builds.
fn dlopen_library(lib_name: &str) -> Result<UnpublishedDlopenHandle, BpfError> {
    match UnpublishedDlopenHandle::open(lib_name) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            if error.errno() == libc::EOPNOTSUPP || error.errno() == libc::EPERM {
                return Err(BpfError::Unsupported);
            }

            Err(BpfError::DlopenFailed(error.to_string()))
        }
    }
}

// ── Query helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `dlopen_bpf()` has been called successfully and
/// the library handle is available.
pub fn bpf_is_loaded() -> bool {
    BPF_LOADED.load(Ordering::Acquire)
}

/// Reset the cached load result. Useful for tests.
///
/// Only call from tests. Calling this while BPF symbols are in use is
/// undefined behaviour.
#[cfg(test)]
pub fn reset_bpf_loaded() {
    BPF_LOADED.store(false, Ordering::Release);
    let mut state = BPF_LOAD_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *state = None;
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

/// Returns the set of symbols C requires from either supported libbpf soname.
///
/// The C `MODERN_LIBBPF` preprocessor branch changes only the C type-checking
/// macro used for three attach functions, not the symbol names. Compatibility
/// and newer feature entry points are optional in C.
pub fn bpf_required_symbols_modern() -> HashSet<&'static str> {
    COMMON_SYMBOLS.iter().copied().collect()
}

/// Returns the set of symbols C requires from a legacy libbpf.
///
/// See [`bpf_required_symbols_modern`] for why this has the same members.
pub fn bpf_required_symbols_legacy() -> HashSet<&'static str> {
    COMMON_SYMBOLS.iter().copied().collect()
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
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());
    }

    #[test]
    fn test_bpf_error_into_c_int_symbol_not_found() {
        let val: i32 = BpfError::SymbolNotFound("x".into()).into();
        assert_eq!(val, Errno::ELIBBAD.to_neg_errno());
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
    fn test_first_missing_symbol_preserves_c_resolution_order() {
        let names = ["first", "second", "third"];

        assert_eq!(
            first_missing_symbol(&names, |symbol| symbol == "second" || symbol == "third"),
            Some("second")
        );
        assert_eq!(first_missing_symbol(&names, |_| false), None);
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
        assert_eq!(syms.len(), COMMON_SYMBOLS.len());
        assert!(syms.contains("bpf_map__fd"));
        assert!(syms.contains("bpf_obj_get_info_by_fd"));
        assert!(syms.contains("bpf_program__set_autoload"));
        assert!(!syms.contains("bpf_map_create"));
    }

    #[test]
    fn test_bpf_required_symbols_legacy_count() {
        let syms = bpf_required_symbols_legacy();
        assert_eq!(syms.len(), COMMON_SYMBOLS.len());
        assert!(syms.contains("bpf_map__fd"));
        assert!(syms.contains("bpf_obj_get_info_by_fd"));
        assert!(syms.contains("bpf_program__set_autoload"));
        assert!(!syms.contains("bpf_create_map"));
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
    fn test_optional_symbols_are_not_required() {
        let common: HashSet<_> = COMMON_SYMBOLS.iter().copied().collect();
        assert!(!OPTIONAL_SYMBOL_NAMES.is_empty());
        for symbol in OPTIONAL_SYMBOL_NAMES {
            assert!(
                !common.contains(symbol),
                "optional symbol {symbol} also in COMMON"
            );
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
