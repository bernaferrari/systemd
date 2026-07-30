// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/module-util.c, src/shared/module-util.h
//
// Kernel module loading utilities.
//
// Provides safe helpers for kernel-module policy and state handling. Native
// libkmod loading is deliberately unavailable until its complete typed API and
// ownership model are implemented; attempts to load a module fail closed.

use std::collections::HashSet;
use std::fmt;

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by kernel-module operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleError {
    /// libkmod is not compiled in or not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The library is already loaded.
    AlreadyLoaded,
    /// Module alias lookup failed.
    LookupFailed { module: String, errno: i32 },
    /// The requested module was not found.
    ModuleNotFound { module: String },
    /// Module insertion failed.
    InsertFailed { module: String, errno: i32 },
    /// Memory allocation failure.
    OutOfMemory,
    /// Invalid argument.
    InvalidArgument(String),
    /// Deny-listed by kmod's built-in blacklist.
    DenyListedByKmod { module: String },
    /// Deny-listed via kernel command line.
    DenyListedByKernel { module: String },
    /// Module is built into the kernel.
    Builtin { module: String },
    /// Module is already loaded (live).
    AlreadyLive { module: String },
}

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => {
                write!(f, "libkmod support is not compiled in")
            }
            Self::DlopenFailed(msg) => write!(f, "Failed to open libkmod: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libkmod symbol not found: {}", sym)
            }
            Self::AlreadyLoaded => write!(f, "libkmod is already loaded"),
            Self::LookupFailed { module, errno } => {
                write!(
                    f,
                    "Failed to look up module alias '{}': errno {}",
                    module, errno
                )
            }
            Self::ModuleNotFound { module } => {
                write!(f, "Failed to find module '{}'", module)
            }
            Self::InsertFailed { module, errno } => {
                write!(f, "Failed to insert module '{}': errno {}", module, errno)
            }
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::DenyListedByKmod { module } => {
                write!(f, "Module '{}' is deny-listed (by kmod)", module)
            }
            Self::DenyListedByKernel { module } => {
                write!(f, "Module '{}' is deny-listed (by kernel)", module)
            }
            Self::Builtin { module } => {
                write!(f, "Module '{}' is built in", module)
            }
            Self::AlreadyLive { module } => {
                write!(f, "Module '{}' is already loaded", module)
            }
        }
    }
}

impl std::error::Error for ModuleError {}

impl From<ModuleError> for i32 {
    fn from(e: ModuleError) -> i32 {
        match &e {
            ModuleError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            ModuleError::DlopenFailed(_) | ModuleError::SymbolNotFound(_) => {
                Errno::ENOENT.to_neg_errno()
            }
            ModuleError::AlreadyLoaded => Errno::EBUSY.to_neg_errno(),
            ModuleError::LookupFailed { errno, .. } | ModuleError::InsertFailed { errno, .. } => {
                *errno
            }
            ModuleError::ModuleNotFound { .. } => Errno::ENOENT.to_neg_errno(),
            ModuleError::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
            ModuleError::InvalidArgument(_) => Errno::EINVAL.to_neg_errno(),
            ModuleError::DenyListedByKmod { .. }
            | ModuleError::DenyListedByKernel { .. }
            | ModuleError::Builtin { .. }
            | ModuleError::AlreadyLive { .. } => 0,
        }
    }
}

// ── Library constants ───────────────────────────────────────────────────────

/// Shared library names to try, in preference order.
const LIBKMOD_CANDIDATES: &[&str] = &["libkmod.so.2"];

/// Human-readable description for the ELF NOTE metadata.
const KMOD_FEATURE_DESCRIPTION: &str = "Support for loading kernel modules";

/// All libkmod symbols that must be resolved before the library is usable.
const REQUIRED_SYMBOLS: &[&str] = &[
    "kmod_list_next",
    "kmod_load_resources",
    "kmod_module_get_initstate",
    "kmod_module_get_module",
    "kmod_module_get_name",
    "kmod_module_new_from_lookup",
    "kmod_module_probe_insert_module",
    "kmod_module_unref",
    "kmod_module_unref_list",
    "kmod_new",
    "kmod_set_log_fn",
    "kmod_unref",
    "kmod_validate_resources",
];

/// Kernel command-line key for module deny-list entries.
const CMDLINE_BLACKLIST_KEY: &str = "module_blacklist";

/// Separator used in the kernel command-line deny-list value.
const CMDLINE_BLACKLIST_SEP: char = ',';

/// Sentinel errno returned by kmod when the module is deny-listed.
const KMOD_PROBE_APPLY_BLACKLIST: i32 = 0x08;

// ── Module init state ──────────────────────────────────────────────────────

/// Possible states of a kernel module as reported by kmod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleInitState {
    /// Module is built into the kernel image.
    Builtin,
    /// Module is currently loaded and live.
    Live,
    /// Module is coming down (unloading in progress).
    ComingDown,
    /// Module is going up (loading in progress).
    GoingUp,
    /// Module state is unknown or not yet initialized.
    Unknown,
}

impl From<i32> for ModuleInitState {
    fn from(state: i32) -> Self {
        match state {
            0 => ModuleInitState::Builtin,
            1 => ModuleInitState::Live,
            2 => ModuleInitState::ComingDown,
            3 => ModuleInitState::GoingUp,
            _ => ModuleInitState::Unknown,
        }
    }
}

impl std::fmt::Display for ModuleInitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleInitState::Builtin => write!(f, "builtin"),
            ModuleInitState::Live => write!(f, "live"),
            ModuleInitState::ComingDown => write!(f, "coming-down"),
            ModuleInitState::GoingUp => write!(f, "going-up"),
            ModuleInitState::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Module load result ─────────────────────────────────────────────────────

/// Result of loading a single kernel module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleLoadOutcome {
    /// Successfully inserted.
    Inserted(String),
    /// Already built into the kernel.
    Builtin(String),
    /// Already live (previously loaded).
    AlreadyLive(String),
    /// Deny-listed by kmod.
    DenyListedByKmod(String),
    /// Deny-listed via kernel command line.
    DenyListedByKernel(String),
}

/// Parse a kernel command-line string for `module_blacklist=mod1,mod2,...`
/// entries and return the set of deny-listed module names.
pub fn parse_cmdline_denylist(cmdline: &str) -> HashSet<String> {
    let mut denylist = HashSet::new();

    for item in cmdline.split_whitespace() {
        // Handle key=value pairs
        let (key, value) = match item.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };

        if key == CMDLINE_BLACKLIST_KEY {
            for name in value.split(CMDLINE_BLACKLIST_SEP) {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    denylist.insert(trimmed.to_string());
                }
            }
        }
    }

    denylist
}

/// Check whether a module name appears in a deny-list.
pub fn is_module_denylisted(module: &str, denylist: &HashSet<String>) -> bool {
    denylist.contains(module)
}

/// Parse a single kernel command-line key=value pair.
///
/// Returns `Some((key, value))` for entries matching `module_blacklist`,
/// `None` otherwise. When the key matches but no value is provided, returns
/// `Some((key, ""))` to indicate a missing value (caller should skip).
pub fn parse_proc_cmdline_item(entry: &str) -> Option<(&str, &str)> {
    let (key, value) = entry.split_once('=')?;
    if key == CMDLINE_BLACKLIST_KEY {
        Some((key, value))
    } else {
        None
    }
}

/// Report that native libkmod loading is not available in this Rust port.
///
/// The previous implementation opened a shared object, returned sentinel symbol
/// pointers instead of resolving its API, leaked the object handle, and then
/// reported success. A module loader is security-sensitive: until the complete
/// typed libkmod ownership and invocation layer exists, it must fail closed.
pub fn dlopen_libkmod() -> Result<HashSet<String>, ModuleError> {
    Err(ModuleError::Unsupported)
}

// ── Module load interface ──────────────────────────────────────────────────

/// Result type for `module_load_and_warn`.
#[derive(Debug, Clone)]
pub struct ModuleLoadResult {
    /// Outcomes for each module that was looked up and processed.
    pub outcomes: Vec<ModuleLoadOutcome>,
    /// The first non-recoverable error encountered, if any.
    pub first_error: Option<ModuleError>,
}

impl ModuleLoadResult {
    /// Returns `true` if at least one module was successfully inserted.
    pub fn has_success(&self) -> bool {
        self.outcomes
            .iter()
            .any(|o| matches!(o, ModuleLoadOutcome::Inserted(_)))
    }

    /// Returns `true` if no errors occurred and no modules were found.
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty() && self.first_error.is_none()
    }
}

/// Load a kernel module (possibly an alias) and report outcomes.
///
/// This mirrors `module_load_and_warn()` from module-util.c:
/// 1. Look up the module name/alias via kmod.
/// 2. Iterate over resolved modules.
/// 3. For each module, check its init state:
///    - **Builtin**: report as built-in.
///    - **Live**: report as already loaded.
///    - **Otherwise**: attempt insertion. If insertion fails with `-EPERM`,
///      check the kernel command-line deny-list.
///
/// `verbose` is reserved for the eventual libkmod-backed implementation.
///
/// `cmdline_denylist` is a pre-parsed set of module names from
/// `module_blacklist=` kernel command-line entries. Pass an empty set to skip
/// kernel-level deny-list checking.
pub fn module_load_and_warn(
    module: &str,
    verbose: bool,
    cmdline_denylist: &HashSet<String>,
) -> Result<ModuleLoadResult, ModuleError> {
    let module = module.trim();
    if module.is_empty() {
        return Err(ModuleError::InvalidArgument("module name is empty".into()));
    }

    // Check if the module is in the kernel command-line deny-list.
    if cmdline_denylist.contains(module) {
        return Ok(ModuleLoadResult {
            outcomes: vec![ModuleLoadOutcome::DenyListedByKernel(module.to_string())],
            first_error: None,
        });
    }

    let _ = verbose;
    Err(ModuleError::Unsupported)
}

/// Resolve an observed module insertion result.
///
/// `insert_errno = None` represents a completed successful insertion. Any
/// other insertion error is returned rather than being misreported as success.
pub fn resolve_module_outcome(
    name: &str,
    init_state: ModuleInitState,
    insert_errno: Option<i32>,
    cmdline_denylist: &HashSet<String>,
) -> Result<ModuleLoadOutcome, ModuleError> {
    match init_state {
        ModuleInitState::Builtin => Ok(ModuleLoadOutcome::Builtin(name.to_string())),
        ModuleInitState::Live => Ok(ModuleLoadOutcome::AlreadyLive(name.to_string())),
        _ => {
            if let Some(errno) = insert_errno {
                if errno == KMOD_PROBE_APPLY_BLACKLIST {
                    return Ok(ModuleLoadOutcome::DenyListedByKmod(name.to_string()));
                }
                if errno == Errno::EPERM.to_neg_errno() && cmdline_denylist.contains(name) {
                    return Ok(ModuleLoadOutcome::DenyListedByKernel(name.to_string()));
                }
                return Err(ModuleError::InsertFailed {
                    module: name.to_string(),
                    errno,
                });
            }
            Ok(ModuleLoadOutcome::Inserted(name.to_string()))
        }
    }
}

/// Determine the error severity from a module insertion errno.
///
/// Mirrors the C logic:
/// - `-ENODEV` → Notice
/// - `-ENOENT` → Warning
/// - Others    → Error
///
/// Returns a severity level as a string for caller-side log routing.
pub fn module_error_severity(errno: i32) -> &'static str {
    match errno {
        e if e == Errno::ENODEV.to_neg_errno() => "notice",
        e if e == Errno::ENOENT.to_neg_errno() => "warning",
        _ => "error",
    }
}

/// Check whether an insertion error is recoverable (i.e. should be
/// propagated as the overall result vs. silently swallowed).
///
/// Mirrors `IN_SET(err, -ENODEV, -ENOENT)` from the C source.
pub fn is_recoverable_insert_error(errno: i32) -> bool {
    errno == Errno::ENODEV.to_neg_errno() || errno == Errno::ENOENT.to_neg_errno()
}

/// Validate a module name string.
///
/// Returns `Ok(())` if the name is non-empty and contains only
/// alphanumeric characters, hyphens, and underscores.
pub fn validate_module_name(name: &str) -> Result<(), ModuleError> {
    if name.is_empty() {
        return Err(ModuleError::InvalidArgument("module name is empty".into()));
    }
    if name.len() > 255 {
        return Err(ModuleError::InvalidArgument(
            "module name exceeds maximum length".into(),
        ));
    }
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(ModuleError::InvalidArgument(format!(
                "module name contains invalid character '{}'",
                ch
            )));
        }
    }
    Ok(())
}

/// Build a module alias deny-list from a raw kernel command-line string.
///
/// Equivalent to calling `parse_cmdline_denylist` but with deduplication
/// guaranteed (HashSet handles this naturally).
pub fn build_denylist(cmdline: &str) -> HashSet<String> {
    parse_cmdline_denylist(cmdline)
}

/// Read the kernel command line from `/proc/cmdline`.
///
/// Returns the raw command-line string on success, or a `ModuleError` if
/// the file cannot be read.
pub fn read_kernel_cmdline() -> Result<String, ModuleError> {
    match std::fs::read_to_string("/proc/cmdline") {
        Ok(s) => Ok(s.trim_end().to_string()),
        Err(e) => Err(ModuleError::DlopenFailed(format!(
            "failed to read /proc/cmdline: {}",
            e
        ))),
    }
}

/// Parse `/proc/cmdline` and extract module deny-list entries.
///
/// Convenience wrapper that reads the file and parses it in one step.
pub fn parse_kernel_cmdline_denylist() -> Result<HashSet<String>, ModuleError> {
    let cmdline = read_kernel_cmdline()?;
    Ok(parse_cmdline_denylist(&cmdline))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_cmdline_denylist ──────────────────────────────────────────

    #[test]
    fn test_parse_cmdline_denylist_empty() {
        let dl = parse_cmdline_denylist("");
        assert!(dl.is_empty());
    }

    #[test]
    fn test_parse_cmdline_denylist_single() {
        let dl = parse_cmdline_denylist("module_blacklist=firewire_core");
        assert!(dl.contains("firewire_core"));
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn test_parse_cmdline_denylist_multiple() {
        let dl = parse_cmdline_denylist("module_blacklist=mod1,mod2,mod3");
        assert!(dl.contains("mod1"));
        assert!(dl.contains("mod2"));
        assert!(dl.contains("mod3"));
        assert_eq!(dl.len(), 3);
    }

    #[test]
    fn test_parse_cmdline_denylist_dedup() {
        let dl = parse_cmdline_denylist("module_blacklist=mod1,mod2,mod1");
        assert_eq!(dl.len(), 2);
    }

    #[test]
    fn test_parse_cmdline_denylist_ignores_other_keys() {
        let cmdline = "BOOT_IMAGE=/vmlinuz quiet module_blacklist=evil_module";
        let dl = parse_cmdline_denylist(cmdline);
        assert!(dl.contains("evil_module"));
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn test_parse_cmdline_denylist_no_value() {
        let dl = parse_cmdline_denylist("module_blacklist=");
        assert!(dl.is_empty());
    }

    #[test]
    fn test_parse_cmdline_denylist_whitespace() {
        let dl = parse_cmdline_denylist("module_blacklist=mod1,mod2");
        assert!(dl.contains("mod1"));
        assert!(dl.contains("mod2"));
    }

    // ── is_module_denylisted ────────────────────────────────────────────

    #[test]
    fn test_is_module_denylisted_true() {
        let mut dl = HashSet::new();
        dl.insert("evil".to_string());
        assert!(is_module_denylisted("evil", &dl));
    }

    #[test]
    fn test_is_module_denylisted_false() {
        let dl = HashSet::new();
        assert!(!is_module_denylisted("good", &dl));
    }

    // ── parse_proc_cmdline_item ─────────────────────────────────────────

    #[test]
    fn test_parse_proc_cmdline_item_blacklist() {
        let result = parse_proc_cmdline_item("module_blacklist=usb-storage");
        assert_eq!(result, Some(("module_blacklist", "usb-storage")));
    }

    #[test]
    fn test_parse_proc_cmdline_item_other_key() {
        let result = parse_proc_cmdline_item("root=/dev/sda1");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_proc_cmdline_item_no_equals() {
        let result = parse_proc_cmdline_item("nosplash");
        assert!(result.is_none());
    }

    // ── ModuleInitState ─────────────────────────────────────────────────

    #[test]
    fn test_module_init_state_from_i32() {
        assert_eq!(ModuleInitState::from(0), ModuleInitState::Builtin);
        assert_eq!(ModuleInitState::from(1), ModuleInitState::Live);
        assert_eq!(ModuleInitState::from(2), ModuleInitState::ComingDown);
        assert_eq!(ModuleInitState::from(3), ModuleInitState::GoingUp);
        assert_eq!(ModuleInitState::from(99), ModuleInitState::Unknown);
    }

    #[test]
    fn test_module_init_state_display() {
        assert_eq!(format!("{}", ModuleInitState::Builtin), "builtin");
        assert_eq!(format!("{}", ModuleInitState::Live), "live");
        assert_eq!(format!("{}", ModuleInitState::ComingDown), "coming-down");
        assert_eq!(format!("{}", ModuleInitState::GoingUp), "going-up");
        assert_eq!(format!("{}", ModuleInitState::Unknown), "unknown");
    }

    // ── resolve_module_outcome ──────────────────────────────────────────

    #[test]
    fn test_resolve_outcome_builtin() {
        let dl = HashSet::new();
        let outcome = resolve_module_outcome("kvm", ModuleInitState::Builtin, None, &dl).unwrap();
        assert_eq!(outcome, ModuleLoadOutcome::Builtin("kvm".into()));
    }

    #[test]
    fn test_resolve_outcome_live() {
        let dl = HashSet::new();
        let outcome = resolve_module_outcome("ext4", ModuleInitState::Live, None, &dl).unwrap();
        assert_eq!(outcome, ModuleLoadOutcome::AlreadyLive("ext4".into()));
    }

    #[test]
    fn test_resolve_outcome_inserted() {
        let dl = HashSet::new();
        let outcome = resolve_module_outcome("nfs", ModuleInitState::Unknown, None, &dl).unwrap();
        assert_eq!(outcome, ModuleLoadOutcome::Inserted("nfs".into()));
    }

    #[test]
    fn test_resolve_outcome_denylisted_by_kmod() {
        let dl = HashSet::new();
        let outcome = resolve_module_outcome(
            "bad",
            ModuleInitState::Unknown,
            Some(KMOD_PROBE_APPLY_BLACKLIST),
            &dl,
        )
        .unwrap();
        assert_eq!(outcome, ModuleLoadOutcome::DenyListedByKmod("bad".into()));
    }

    #[test]
    fn test_resolve_outcome_denylisted_by_kernel() {
        let mut dl = HashSet::new();
        dl.insert("usb-storage".to_string());
        let outcome = resolve_module_outcome(
            "usb-storage",
            ModuleInitState::Unknown,
            Some(Errno::EPERM.to_neg_errno()),
            &dl,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ModuleLoadOutcome::DenyListedByKernel("usb-storage".into())
        );
    }

    #[test]
    fn test_resolve_outcome_eperm_not_denylisted() {
        let dl = HashSet::new();
        let error = resolve_module_outcome(
            "nfs",
            ModuleInitState::Unknown,
            Some(Errno::EPERM.to_neg_errno()),
            &dl,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ModuleError::InsertFailed {
                module: "nfs".into(),
                errno: Errno::EPERM.to_neg_errno(),
            }
        );
    }

    // ── module_error_severity ───────────────────────────────────────────

    #[test]
    fn test_module_error_severity_enodev() {
        assert_eq!(
            module_error_severity(Errno::ENODEV.to_neg_errno()),
            "notice"
        );
    }

    #[test]
    fn test_module_error_severity_enoent() {
        assert_eq!(
            module_error_severity(Errno::ENOENT.to_neg_errno()),
            "warning"
        );
    }

    #[test]
    fn test_module_error_severity_other() {
        assert_eq!(module_error_severity(-5), "error");
    }

    // ── is_recoverable_insert_error ─────────────────────────────────────

    #[test]
    fn test_is_recoverable_enodev() {
        assert!(is_recoverable_insert_error(Errno::ENODEV.to_neg_errno()));
    }

    #[test]
    fn test_is_recoverable_enoent() {
        assert!(is_recoverable_insert_error(Errno::ENOENT.to_neg_errno()));
    }

    #[test]
    fn test_is_recoverable_eacces() {
        assert!(!is_recoverable_insert_error(Errno::EACCES.to_neg_errno()));
    }

    #[test]
    fn test_is_recoverable_eperm() {
        assert!(!is_recoverable_insert_error(Errno::EPERM.to_neg_errno()));
    }

    // ── validate_module_name ────────────────────────────────────────────

    #[test]
    fn test_validate_module_name_valid() {
        assert!(validate_module_name("ext4").is_ok());
        assert!(validate_module_name("nfsd").is_ok());
        assert!(validate_module_name("usb-storage").is_ok());
        assert!(validate_module_name("blk-mq").is_ok());
    }

    #[test]
    fn test_validate_module_name_empty() {
        assert!(validate_module_name("").is_err());
    }

    #[test]
    fn test_validate_module_name_too_long() {
        let name = "a".repeat(256);
        assert!(validate_module_name(&name).is_err());
    }

    #[test]
    fn test_validate_module_name_invalid_chars() {
        assert!(validate_module_name("mod.name").is_err());
        assert!(validate_module_name("mod name").is_err());
        assert!(validate_module_name("mod/name").is_err());
    }

    #[test]
    fn test_validate_module_name_max_length() {
        let name = "a".repeat(255);
        assert!(validate_module_name(&name).is_ok());
    }

    // ── build_denylist ──────────────────────────────────────────────────

    #[test]
    fn test_build_denylist() {
        let dl = build_denylist("quiet module_blacklist=mod1,mod2");
        assert_eq!(dl.len(), 2);
    }

    // ── ModuleLoadResult ────────────────────────────────────────────────

    #[test]
    fn test_module_load_result_has_success() {
        let mut r = ModuleLoadResult {
            outcomes: vec![
                ModuleLoadOutcome::Builtin("kvm".into()),
                ModuleLoadOutcome::Inserted("nfs".into()),
            ],
            first_error: None,
        };
        assert!(r.has_success());
        assert!(!r.is_empty());

        r.outcomes = vec![ModuleLoadOutcome::Builtin("kvm".into())];
        assert!(!r.has_success());
    }

    #[test]
    fn test_module_load_result_empty() {
        let r = ModuleLoadResult {
            outcomes: Vec::new(),
            first_error: None,
        };
        assert!(r.is_empty());
        assert!(!r.has_success());
    }

    // ── ModuleError → i32 ─────────────────────────────────────────────

    #[test]
    fn test_module_error_to_c_int() {
        assert_eq!(
            i32::from(ModuleError::Unsupported),
            Errno::EOPNOTSUPP.to_neg_errno()
        );
        assert_eq!(
            i32::from(ModuleError::ModuleNotFound { module: "x".into() }),
            Errno::ENOENT.to_neg_errno()
        );
        assert_eq!(
            i32::from(ModuleError::OutOfMemory),
            Errno::ENOMEM.to_neg_errno()
        );
        assert_eq!(
            i32::from(ModuleError::InvalidArgument("x".into())),
            Errno::EINVAL.to_neg_errno()
        );
        // Non-error outcomes map to 0
        assert_eq!(i32::from(ModuleError::Builtin { module: "x".into() }), 0);
        assert_eq!(
            i32::from(ModuleError::DenyListedByKmod { module: "x".into() }),
            0
        );
    }

    // ── module_load_and_warn ────────────────────────────────────────────

    #[test]
    fn test_module_load_and_warn_empty_name() {
        let dl = HashSet::new();
        let result = module_load_and_warn("", false, &dl);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModuleError::InvalidArgument(msg) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected InvalidArgument, got {:?}", other),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_module_load_and_warn_denylisted() {
        let mut dl = HashSet::new();
        dl.insert("evil".to_string());
        let result = module_load_and_warn("evil", false, &dl).unwrap();
        assert_eq!(result.outcomes.len(), 1);
        assert_eq!(
            result.outcomes[0],
            ModuleLoadOutcome::DenyListedByKernel("evil".into())
        );
    }

    // ── ModuleError Display ─────────────────────────────────────────────

    #[test]
    fn test_module_error_display() {
        let e = ModuleError::Unsupported;
        assert!(!e.to_string().is_empty());

        let e = ModuleError::LookupFailed {
            module: "foo".into(),
            errno: -2,
        };
        assert!(e.to_string().contains("foo"));

        let e = ModuleError::InsertFailed {
            module: "bar".into(),
            errno: -1,
        };
        assert!(e.to_string().contains("bar"));
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn test_required_symbols_nonempty() {
        assert!(!REQUIRED_SYMBOLS.is_empty());
        assert!(REQUIRED_SYMBOLS.contains(&"kmod_new"));
        assert!(REQUIRED_SYMBOLS.contains(&"kmod_unref"));
    }

    #[test]
    fn test_libkmod_candidates_nonempty() {
        assert!(!LIBKMOD_CANDIDATES.is_empty());
        assert!(LIBKMOD_CANDIDATES.contains(&"libkmod.so.2"));
    }

    #[test]
    fn test_kmod_probe_apply_blacklist_value() {
        assert_eq!(KMOD_PROBE_APPLY_BLACKLIST, 0x08);
    }

    #[test]
    fn test_dlopen_libkmod_fails_closed_without_typed_backend() {
        assert_eq!(dlopen_libkmod(), Err(ModuleError::Unsupported));
    }

    #[test]
    fn test_module_load_and_warn_fails_closed_without_typed_backend() {
        let denylist = HashSet::new();
        assert_eq!(
            module_load_and_warn("ext4", false, &denylist).unwrap_err(),
            ModuleError::Unsupported
        );
    }
}
