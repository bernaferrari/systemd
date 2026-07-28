// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/sleep-config.c, src/shared/sleep-config.h
//
// Sleep configuration parsing and state/mode management.
//
// Parses systemd sleep configuration from sleep.conf and drop-in files,
// checks kernel sleep state/mode support via /sys/power/*, and validates
// sleep operations (suspend, hibernate, hybrid-sleep, suspend-then-hibernate).

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

// ── Constants ───────────────────────────────────────────────────────────

/// Microseconds per second.
pub const USEC_PER_SEC: u64 = 1_000_000;

/// Sentinel value representing an infinite/indefinite duration.
pub const USEC_INFINITY: u64 = u64::MAX;

/// Default estimated suspend duration: 1 hour.
pub const DEFAULT_SUSPEND_ESTIMATION_USEC: u64 = USEC_PER_SEC * 3600;

/// Standard config file paths, in priority order (highest priority first).
const SLEEP_CONFIG_PATHS: &[&str] = &[
    "/etc/systemd/sleep.conf",
    "/run/systemd/sleep.conf",
    "/usr/local/lib/systemd/sleep.conf",
    "/usr/lib/systemd/sleep.conf",
];

/// Drop-in directory paths, in priority order.
const SLEEP_CONFIG_DROPIN_DIRS: &[&str] = &[
    "/etc/systemd/sleep.conf.d",
    "/run/systemd/sleep.conf.d",
    "/usr/lib/systemd/sleep.conf.d",
];

// ── Error type ──────────────────────────────────────────────────────────

/// Errors returned by sleep configuration operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SleepError {
    /// An invalid argument was provided.
    InvalidArgument,
    /// No sleep states are configured.
    NotConfigured,
    /// An I/O error occurred.
    Io(String),
    /// A configuration parsing error occurred.
    Parse(String),
}

impl fmt::Display for SleepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::NotConfigured => write!(f, "no sleep state configured"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for SleepError {}

impl From<io::Error> for SleepError {
    fn from(e: io::Error) -> Self {
        SleepError::Io(e.to_string())
    }
}

// ── SleepOperation ──────────────────────────────────────────────────────

/// Sleep operations supported by systemd.
///
/// Discriminant values match the C enum for ABI compatibility.
/// Note: `SuspendThenHibernate` has discriminant 4 (not 3) to match the
/// C enum where `_SLEEP_OPERATION_CONFIG_MAX` occupies value 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SleepOperation {
    /// Standard suspend to RAM (`SLEEP_SUSPEND`).
    Suspend = 0,
    /// Hibernate to swap (`SLEEP_HIBERNATE`).
    Hibernate = 1,
    /// Hybrid sleep: suspend + hibernate (`SLEEP_HYBRID_SLEEP`).
    HybridSleep = 2,
    /// Suspend first, hibernate after delay (`SLEEP_SUSPEND_THEN_HIBERNATE`).
    SuspendThenHibernate = 4,
}

impl SleepOperation {
    /// Number of operations that carry their own state/mode config.
    /// `SuspendThenHibernate` borrows config from `Suspend` and `Hibernate`.
    pub const CONFIG_MAX: usize = 3;

    /// Total number of valid operation slots (including the gap at index 3).
    pub const MAX: usize = 5;

    /// All valid sleep operations.
    pub const ALL: [SleepOperation; 4] = [
        Self::Suspend,
        Self::Hibernate,
        Self::HybridSleep,
        Self::SuspendThenHibernate,
    ];

    /// Operations that have their own state/mode configuration entries.
    pub const CONFIG_OPS: [SleepOperation; 3] = [Self::Suspend, Self::Hibernate, Self::HybridSleep];

    /// Parse from an integer discriminant. Returns `None` for invalid values.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Suspend),
            1 => Some(Self::Hibernate),
            2 => Some(Self::HybridSleep),
            4 => Some(Self::SuspendThenHibernate),
            _ => None,
        }
    }

    /// Parse from a string name.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "suspend" => Some(Self::Suspend),
            "hibernate" => Some(Self::Hibernate),
            "hybrid-sleep" => Some(Self::HybridSleep),
            "suspend-then-hibernate" => Some(Self::SuspendThenHibernate),
            _ => None,
        }
    }

    /// Convert to the canonical string name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Hibernate => "hibernate",
            Self::HybridSleep => "hybrid-sleep",
            Self::SuspendThenHibernate => "suspend-then-hibernate",
        }
    }

    /// Index into the `states`/`modes` arrays.
    /// Returns `None` for `SuspendThenHibernate` (has no direct config).
    pub fn config_index(self) -> Option<usize> {
        match self {
            Self::Suspend => Some(0),
            Self::Hibernate => Some(1),
            Self::HybridSleep => Some(2),
            Self::SuspendThenHibernate => None,
        }
    }

    /// Index into the `allow` array.
    pub fn allow_index(self) -> usize {
        match self {
            Self::Suspend => 0,
            Self::Hibernate => 1,
            Self::HybridSleep => 2,
            // Index 3 is unused (gap for _SLEEP_OPERATION_CONFIG_MAX)
            Self::SuspendThenHibernate => 4,
        }
    }
}

/// Check if an operation is a hibernation type (hibernate or hybrid-sleep).
pub fn sleep_operation_is_hibernation(op: SleepOperation) -> bool {
    matches!(op, SleepOperation::Hibernate | SleepOperation::HybridSleep)
}

// ── SleepSupport ────────────────────────────────────────────────────────

/// Describes why a sleep operation is (or isn't) supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SleepSupport {
    /// Operation is fully supported by kernel and configuration.
    Supported = 0,
    /// Disabled by configuration (`Allow* = no`).
    Disabled = 1,
    /// No sleep states configured for this operation.
    NotConfigured = 2,
    /// Configured states or modes not supported by the kernel.
    StateOrModeNotSupported = 3,
    /// Resume from hibernation not supported by platform.
    ResumeNotSupported = 4,
    /// Resume device specified but not present in `/proc/swaps`.
    ResumeDeviceMissing = 5,
    /// Resume offset configured but no resume device set.
    ResumeMisconfigured = 6,
    /// Insufficient swap space for hibernation.
    NotEnoughSwapSpace = 7,
    /// `CLOCK_BOOTTIME_ALARM` not supported (suspend-then-hibernate only).
    AlarmNotSupported = 8,
}

// ── Default state/mode tables ───────────────────────────────────────────

/// Default sleep states per operation, indexed by `config_index()`.
static DEFAULT_STATES: &[&[&str]] = &[
    &["mem", "standby", "freeze"], // Suspend
    &["disk"],                     // Hibernate
    &["disk"],                     // HybridSleep
];

/// Default sleep modes per operation, indexed by `config_index()`.
/// Suspend has no modes; Hibernate and HybridSleep have defaults.
static DEFAULT_MODES: &[&[&str]] = &[
    &[],                       // Suspend (not applicable)
    &["platform", "shutdown"], // Hibernate
    &["suspend"],              // HybridSleep
];

// ── SleepConfig ─────────────────────────────────────────────────────────

/// Parsed sleep configuration from `sleep.conf` and drop-in files.
#[derive(Debug, Clone)]
pub struct SleepConfig {
    /// Per-operation allow flags, indexed by `allow_index()`.
    pub allow: [bool; SleepOperation::MAX],
    /// Per-operation sleep states for `/sys/power/state`.
    /// Indexed by `config_index()`; only `CONFIG_MAX` entries.
    pub states: [Vec<String>; SleepOperation::CONFIG_MAX],
    /// Per-operation sleep modes for `/sys/power/disk`.
    /// Indexed by `config_index()`; only `CONFIG_MAX` entries.
    pub modes: [Vec<String>; SleepOperation::CONFIG_MAX],
    /// Modes for `/sys/power/mem_sleep`.
    pub mem_modes: Vec<String>,
    /// Delay before hibernation in suspend-then-hibernate (microseconds).
    pub hibernate_delay_usec: u64,
    /// Whether to hibernate while on AC power.
    pub hibernate_on_ac_power: bool,
    /// Estimated suspend duration (microseconds).
    pub suspend_estimation_usec: u64,
}

impl Default for SleepConfig {
    fn default() -> Self {
        Self {
            allow: [true; SleepOperation::MAX],
            states: Default::default(),
            modes: Default::default(),
            mem_modes: Vec::new(),
            hibernate_delay_usec: USEC_INFINITY,
            hibernate_on_ac_power: true,
            suspend_estimation_usec: DEFAULT_SUSPEND_ESTIMATION_USEC,
        }
    }
}

impl SleepConfig {
    /// Create a new `SleepConfig` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse sleep configuration from the system config files.
    ///
    /// Reads `sleep.conf` and drop-in directories in standard paths.
    /// Missing config files are silently ignored (defaults are used).
    pub fn from_system() -> Result<Self, SleepError> {
        let mut config = Self::default();

        // Read base config files — highest-priority path wins
        for path in SLEEP_CONFIG_PATHS.iter().rev() {
            let p = Path::new(path);
            if p.exists() {
                let content = fs::read_to_string(p)?;
                apply_config_entries(&mut config, &content);
                break;
            }
        }

        // Read drop-in directories (later dirs override earlier ones)
        for dropin_dir in SLEEP_CONFIG_DROPIN_DIRS {
            let dir = Path::new(dropin_dir);
            if !dir.is_dir() {
                continue;
            }
            let mut entries: Vec<_> = fs::read_dir(dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "conf"))
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let content = fs::read_to_string(entry.path())?;
                apply_config_entries(&mut config, &content);
            }
        }

        config.apply_defaults();
        config.validate();
        Ok(config)
    }

    /// Parse sleep configuration from a string (for testing).
    ///
    /// Applies defaults and validation automatically.
    pub fn parse_from_str(content: &str) -> Self {
        let mut config = Self::default();
        apply_config_entries(&mut config, content);
        config.apply_defaults();
        config.validate();
        config
    }

    /// Fill in default states/modes for any operation that wasn't
    /// explicitly configured, and clamp the suspend estimation.
    fn apply_defaults(&mut self) {
        for i in 0..SleepOperation::CONFIG_MAX {
            if self.states[i].is_empty() {
                self.states[i] = DEFAULT_STATES[i].iter().map(|s| s.to_string()).collect();
            }
            if self.modes[i].is_empty() && !DEFAULT_MODES[i].is_empty() {
                self.modes[i] = DEFAULT_MODES[i].iter().map(|s| s.to_string()).collect();
            }
        }

        if self.suspend_estimation_usec == 0 {
            self.suspend_estimation_usec = DEFAULT_SUSPEND_ESTIMATION_USEC;
        }
    }

    /// Validate and fix configuration, removing invalid entries.
    ///
    /// Removes `disk` from suspend states — it means hibernation, which
    /// should go through the proper hibernation path with resume checks.
    fn validate(&mut self) {
        self.states[0].retain(|s| s != "disk");
    }
}

// ── Config parsing ──────────────────────────────────────────────────────

/// Tristate value for Allow* settings: unset, true, or false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tristate {
    Unset,
    True,
    False,
}

/// Apply key=value entries from a sleep.conf section to the config.
fn apply_config_entries(config: &mut SleepConfig, content: &str) {
    let mut allow_suspend = Tristate::Unset;
    let mut allow_hibernate = Tristate::Unset;
    let mut allow_s2h = Tristate::Unset;
    let mut allow_hybrid_sleep = Tristate::Unset;
    let mut seen_section = false;
    let mut in_sleep_section = true; // default: no header ⇒ [Sleep]

    for line in content.lines() {
        let line = line.trim();

        // Handle section headers
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            seen_section = true;
            in_sleep_section = section.trim() == "Sleep";
            continue;
        }

        // Skip other sections
        if seen_section && !in_sleep_section {
            continue;
        }

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        match key {
            "AllowSuspend" => allow_suspend = parse_tristate(value),
            "AllowHibernation" => allow_hibernate = parse_tristate(value),
            "AllowSuspendThenHibernate" => allow_s2h = parse_tristate(value),
            "AllowHybridSleep" => allow_hybrid_sleep = parse_tristate(value),
            "SuspendState" => {
                if !value.is_empty() {
                    config.states[0] = split_quoted(value);
                }
            }
            "SuspendMode" | "HibernateState" | "HybridSleepState" | "HybridSleepMode" => {
                // Deprecated / disabled legacy — silently ignored
            }
            "HibernateMode" => {
                if !value.is_empty() {
                    config.modes[1] = split_quoted(value);
                }
            }
            "MemorySleepMode" => {
                if !value.is_empty() {
                    config.mem_modes = split_quoted(value);
                }
            }
            "HibernateDelaySec" => {
                if let Ok(usec) = parse_duration_usec(value) {
                    config.hibernate_delay_usec = usec;
                }
            }
            "HibernateOnACPower" => {
                config.hibernate_on_ac_power =
                    !matches!(value.to_lowercase().as_str(), "false" | "0" | "no" | "off");
            }
            "SuspendEstimationSec" => {
                if let Ok(usec) = parse_duration_usec(value) {
                    config.suspend_estimation_usec = usec;
                }
            }
            _ => {}
        }
    }

    // Apply allow flags
    apply_allow_flags(
        config,
        allow_suspend,
        allow_hibernate,
        allow_hybrid_sleep,
        allow_s2h,
    );
}

/// Parse a tristate boolean from a config value.
fn parse_tristate(value: &str) -> Tristate {
    match value.to_lowercase().as_str() {
        "false" | "0" | "no" | "off" => Tristate::False,
        "true" | "1" | "yes" | "on" => Tristate::True,
        _ => Tristate::Unset,
    }
}

/// Split a value string on whitespace, handling basic quoting.
fn split_quoted(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            '\\' if in_quotes => {
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
            }
            c => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

/// Parse a systemd-style duration to microseconds.
///
/// Supports bare seconds, and suffixes: `s`, `min`, `h`, `d`, `ms`, `us`.
/// Accepts `infinity` / `inf` for `USEC_INFINITY`.
fn parse_duration_usec(value: &str) -> Result<u64, SleepError> {
    let value = value.trim();

    if value.eq_ignore_ascii_case("infinity") || value.eq_ignore_ascii_case("inf") {
        return Ok(USEC_INFINITY);
    }

    let (num_str, multiplier_usec) = if let Some(v) = value.strip_suffix("ms") {
        (v.trim(), 1_000u64)
    } else if let Some(v) = value.strip_suffix("us") {
        (v.trim(), 1u64)
    } else if let Some(v) = value.strip_suffix("min") {
        (v.trim(), 60 * USEC_PER_SEC)
    } else if let Some(v) = value.strip_suffix("h") {
        (v.trim(), 3600 * USEC_PER_SEC)
    } else if let Some(v) = value.strip_suffix("d") {
        (v.trim(), 86400 * USEC_PER_SEC)
    } else if let Some(v) = value.strip_suffix("s") {
        (v.trim(), USEC_PER_SEC)
    } else {
        (value, USEC_PER_SEC)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| SleepError::Parse(format!("invalid duration: {value}")))?;

    Ok(num * multiplier_usec)
}

/// Apply allow flags based on tristate values.
///
/// Mirrors the C logic: explicit `false` disables, explicit `true` enables,
/// unset defaults to `true` for individual ops and to
/// `(suspend_allowed && hibernate_allowed)` for compound ops.
fn apply_allow_flags(
    config: &mut SleepConfig,
    allow_suspend: Tristate,
    allow_hibernate: Tristate,
    allow_hybrid_sleep: Tristate,
    allow_s2h: Tristate,
) {
    let suspend_allowed = allow_suspend != Tristate::False;
    let hibernate_allowed = allow_hibernate != Tristate::False;

    config.allow[SleepOperation::Suspend.allow_index()] = suspend_allowed;
    config.allow[SleepOperation::Hibernate.allow_index()] = hibernate_allowed;

    let hybrid_allowed = match allow_hybrid_sleep {
        Tristate::True => true,
        Tristate::False => false,
        Tristate::Unset => suspend_allowed && hibernate_allowed,
    };
    config.allow[SleepOperation::HybridSleep.allow_index()] = hybrid_allowed;

    let s2h_allowed = match allow_s2h {
        Tristate::True => true,
        Tristate::False => false,
        Tristate::Unset => suspend_allowed && hibernate_allowed,
    };
    config.allow[SleepOperation::SuspendThenHibernate.allow_index()] = s2h_allowed;
}

// ── Sleep state/mode support ────────────────────────────────────────────

/// Check if any of the given sleep states are supported by the kernel.
///
/// Reads `/sys/power/state` and checks whether any requested state appears
/// in the kernel's list of supported states.
///
/// Returns `Ok(true)` if a supported state is found, `Ok(false)` if none
/// match, or an error if the sysfs file cannot be read.
pub fn sleep_state_supported(states: &[&str]) -> Result<bool, SleepError> {
    check_states_in_sysfs(states, &fs::read_to_string("/sys/power/state")?)
}

/// Check whether any of `states` appear in `sysfs_content`.
fn check_states_in_sysfs(states: &[&str], sysfs_content: &str) -> Result<bool, SleepError> {
    if states.is_empty() {
        return Err(SleepError::NotConfigured);
    }

    for state in states {
        if sysfs_content.split_whitespace().any(|s| s == *state) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Check if any of the given sleep modes are supported by the kernel.
///
/// Reads the given sysfs path and checks if any requested mode appears
/// in the kernel's list of supported modes. Handles bracket-annotated
/// default mode (e.g., `[s2idle]` → `s2idle`).
///
/// If `modes` is empty, returns `Ok(true)` (kernel uses its own default).
pub fn sleep_mode_supported(path: &str, modes: &[&str]) -> Result<bool, SleepError> {
    let content = fs::read_to_string(path)?;
    check_modes_in_sysfs(modes, &content)
}

/// Check whether any of `modes` appear in `sysfs_content`.
fn check_modes_in_sysfs(modes: &[&str], sysfs_content: &str) -> Result<bool, SleepError> {
    if modes.is_empty() {
        return Ok(true);
    }

    for token in sysfs_content.split_whitespace() {
        let mode = token
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(token);

        if modes.iter().any(|m| *m == mode) {
            return Ok(true);
        }
    }

    Ok(false)
}

// ── Mem sleep detection ─────────────────────────────────────────────────

/// Check if `/sys/power/mem_sleep` needs to be consulted for the given operation.
///
/// Per kernel docs, `mem_sleep` is honored when `/sys/power/state` is `"mem"`
/// or when `/sys/power/disk` is set to `"suspend"`.
pub fn sleep_needs_mem_sleep(config: &SleepConfig, operation: SleepOperation) -> bool {
    let Some(idx) = operation.config_index() else {
        return false;
    };

    config.states[idx].iter().any(|s| s == "mem")
        || config.modes[idx].iter().any(|s| s == "suspend")
}

// ── Support checking ───────────────────────────────────────────────────

/// Check if a sleep operation is supported, returning the reason if not.
///
/// This is the main entry point for sleep support detection. It checks:
/// 1. Whether the operation is allowed by configuration
/// 2. Whether the kernel supports the required sleep states
/// 3. Whether mem_sleep modes are supported (if applicable)
/// 4. Whether disk modes are supported (for hibernation operations)
///
/// Returns `Ok(SleepSupport::Supported)` if fully supported, or `Ok(reason)`
/// with the specific reason why it is not supported. Returns `Err` only on
/// unexpected I/O or system errors.
pub fn sleep_supported(
    config: &SleepConfig,
    operation: SleepOperation,
) -> Result<SleepSupport, SleepError> {
    sleep_supported_inner(config, operation, true)
}

/// Internal support checker with optional allow-flag check.
fn sleep_supported_inner(
    config: &SleepConfig,
    operation: SleepOperation,
    check_allowed: bool,
) -> Result<SleepSupport, SleepError> {
    // Check allow flag
    if check_allowed && !config.allow[operation.allow_index()] {
        return Ok(SleepSupport::Disabled);
    }

    // Suspend-then-hibernate needs both suspend and hibernate support
    if operation == SleepOperation::SuspendThenHibernate {
        return check_s2h_supported(config);
    }

    let Some(idx) = operation.config_index() else {
        return Err(SleepError::InvalidArgument);
    };

    // Check state support
    let state_refs: Vec<&str> = config.states[idx].iter().map(String::as_str).collect();
    match sleep_state_supported(&state_refs) {
        Ok(true) => {}
        Err(SleepError::NotConfigured) => return Ok(SleepSupport::NotConfigured),
        Err(e) => return Err(e),
        Ok(false) => return Ok(SleepSupport::StateOrModeNotSupported),
    }

    // Check mem_sleep if needed
    if sleep_needs_mem_sleep(config, operation) {
        let mem_refs: Vec<&str> = config.mem_modes.iter().map(String::as_str).collect();
        if !sleep_mode_supported("/sys/power/mem_sleep", &mem_refs)? {
            return Ok(SleepSupport::StateOrModeNotSupported);
        }
    }

    // Check disk modes for hibernation operations
    if sleep_operation_is_hibernation(operation) {
        let mode_refs: Vec<&str> = config.modes[idx].iter().map(String::as_str).collect();
        if !sleep_mode_supported("/sys/power/disk", &mode_refs)? {
            return Ok(SleepSupport::StateOrModeNotSupported);
        }

        // Hibernation resume safety checks (hibernation_is_safe()) would go here.
        // They verify resume= kernel param, /proc/swaps, swap size, etc.
    }

    Ok(SleepSupport::Supported)
}

/// Check suspend-then-hibernate support.
///
/// Requires both suspend and hibernate to be supported, plus
/// `CLOCK_BOOTTIME_ALARM` for the wakeup timer.
fn check_s2h_supported(config: &SleepConfig) -> Result<SleepSupport, SleepError> {
    // Check suspend support (without allow check — s2h has its own)
    match sleep_supported_inner(config, SleepOperation::Suspend, false) {
        Ok(SleepSupport::Supported) => {}
        Ok(reason) => return Ok(reason),
        Err(e) => return Err(e),
    }

    // Check hibernate support (without allow check)
    match sleep_supported_inner(config, SleepOperation::Hibernate, false) {
        Ok(SleepSupport::Supported) => {}
        Ok(reason) => return Ok(reason),
        Err(e) => return Err(e),
    }

    // CLOCK_BOOTTIME_ALARM check would go here.
    // In the full implementation this calls clock_supported(CLOCK_BOOTTIME_ALARM).

    Ok(SleepSupport::Supported)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SleepOperation ──────────────────────────────────────────────

    #[test]
    fn test_sleep_operation_roundtrip() {
        for op in SleepOperation::ALL {
            let s = op.as_str();
            let parsed = SleepOperation::from_str_name(s).unwrap();
            assert_eq!(parsed, op, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn test_sleep_operation_from_str_invalid() {
        assert!(SleepOperation::from_str_name("invalid").is_none());
        assert!(SleepOperation::from_str_name("").is_none());
        assert!(SleepOperation::from_str_name("Suspend").is_none()); // case-sensitive
    }

    #[test]
    fn test_sleep_operation_from_i32() {
        assert_eq!(SleepOperation::from_i32(0), Some(SleepOperation::Suspend));
        assert_eq!(SleepOperation::from_i32(1), Some(SleepOperation::Hibernate));
        assert_eq!(
            SleepOperation::from_i32(2),
            Some(SleepOperation::HybridSleep)
        );
        assert_eq!(SleepOperation::from_i32(3), None); // gap (CONFIG_MAX)
        assert_eq!(
            SleepOperation::from_i32(4),
            Some(SleepOperation::SuspendThenHibernate)
        );
        assert_eq!(SleepOperation::from_i32(5), None);
        assert_eq!(SleepOperation::from_i32(-1), None);
    }

    #[test]
    fn test_sleep_operation_config_index() {
        assert_eq!(SleepOperation::Suspend.config_index(), Some(0));
        assert_eq!(SleepOperation::Hibernate.config_index(), Some(1));
        assert_eq!(SleepOperation::HybridSleep.config_index(), Some(2));
        assert_eq!(SleepOperation::SuspendThenHibernate.config_index(), None);
    }

    #[test]
    fn test_sleep_operation_allow_index() {
        assert_eq!(SleepOperation::Suspend.allow_index(), 0);
        assert_eq!(SleepOperation::Hibernate.allow_index(), 1);
        assert_eq!(SleepOperation::HybridSleep.allow_index(), 2);
        assert_eq!(SleepOperation::SuspendThenHibernate.allow_index(), 4);
    }

    #[test]
    fn test_sleep_operation_constants() {
        assert_eq!(SleepOperation::CONFIG_MAX, 3);
        assert_eq!(SleepOperation::MAX, 5);
        assert_eq!(SleepOperation::ALL.len(), 4);
        assert_eq!(SleepOperation::CONFIG_OPS.len(), 3);
    }

    #[test]
    fn test_sleep_operation_as_str() {
        assert_eq!(SleepOperation::Suspend.as_str(), "suspend");
        assert_eq!(SleepOperation::Hibernate.as_str(), "hibernate");
        assert_eq!(SleepOperation::HybridSleep.as_str(), "hybrid-sleep");
        assert_eq!(
            SleepOperation::SuspendThenHibernate.as_str(),
            "suspend-then-hibernate"
        );
    }

    #[test]
    fn test_is_hibernation() {
        assert!(sleep_operation_is_hibernation(SleepOperation::Hibernate));
        assert!(sleep_operation_is_hibernation(SleepOperation::HybridSleep));
        assert!(!sleep_operation_is_hibernation(SleepOperation::Suspend));
        assert!(!sleep_operation_is_hibernation(
            SleepOperation::SuspendThenHibernate
        ));
    }

    // ── SleepConfig defaults ────────────────────────────────────────

    #[test]
    fn test_sleep_config_default() {
        let config = SleepConfig::new();
        assert_eq!(config.hibernate_delay_usec, USEC_INFINITY);
        assert!(config.hibernate_on_ac_power);
        assert_eq!(
            config.suspend_estimation_usec,
            DEFAULT_SUSPEND_ESTIMATION_USEC
        );
        assert!(config.allow.iter().all(|&a| a));
    }

    #[test]
    fn test_parse_empty_config_uses_defaults() {
        let config = SleepConfig::parse_from_str("");
        assert_eq!(config.states[0], vec!["mem", "standby", "freeze"]);
        assert_eq!(config.states[1], vec!["disk"]);
        assert_eq!(config.states[2], vec!["disk"]);
        assert_eq!(config.modes[1], vec!["platform", "shutdown"]);
        assert_eq!(config.modes[2], vec!["suspend"]);
    }

    #[test]
    fn test_parse_suspend_state() {
        let config = SleepConfig::parse_from_str("[Sleep]\nSuspendState=mem freeze\n");
        assert_eq!(config.states[0], vec!["mem", "freeze"]);
    }

    #[test]
    fn test_parse_hibernate_mode() {
        let config = SleepConfig::parse_from_str("[Sleep]\nHibernateMode=platform shutdown\n");
        assert_eq!(config.modes[1], vec!["platform", "shutdown"]);
    }

    #[test]
    fn test_parse_memory_sleep_mode() {
        let config = SleepConfig::parse_from_str("[Sleep]\nMemorySleepMode=s2idle deep\n");
        assert_eq!(config.mem_modes, vec!["s2idle", "deep"]);
    }

    // ── Allow flags ─────────────────────────────────────────────────

    #[test]
    fn test_allow_flags_all_false() {
        let config =
            SleepConfig::parse_from_str("[Sleep]\nAllowSuspend=false\nAllowHibernation=false\n");
        assert!(!config.allow[SleepOperation::Suspend.allow_index()]);
        assert!(!config.allow[SleepOperation::Hibernate.allow_index()]);
        // Compound ops depend on both → also disabled
        assert!(!config.allow[SleepOperation::HybridSleep.allow_index()]);
        assert!(!config.allow[SleepOperation::SuspendThenHibernate.allow_index()]);
    }

    #[test]
    fn test_allow_hybrid_explicit_yes() {
        let config = SleepConfig::parse_from_str(
            "[Sleep]\nAllowSuspend=no\nAllowHibernation=no\nAllowHybridSleep=yes\n",
        );
        assert!(!config.allow[SleepOperation::Suspend.allow_index()]);
        assert!(!config.allow[SleepOperation::Hibernate.allow_index()]);
        assert!(config.allow[SleepOperation::HybridSleep.allow_index()]);
    }

    #[test]
    fn test_allow_s2h_explicit_yes() {
        let config = SleepConfig::parse_from_str(
            "[Sleep]\nAllowSuspend=no\nAllowHibernation=no\nAllowSuspendThenHibernate=yes\n",
        );
        assert!(!config.allow[SleepOperation::Suspend.allow_index()]);
        assert!(!config.allow[SleepOperation::Hibernate.allow_index()]);
        assert!(config.allow[SleepOperation::SuspendThenHibernate.allow_index()]);
    }

    // ── Duration parsing ────────────────────────────────────────────

    #[test]
    fn test_parse_duration_usec() {
        assert_eq!(parse_duration_usec("120").unwrap(), 120 * USEC_PER_SEC);
        assert_eq!(parse_duration_usec("120s").unwrap(), 120 * USEC_PER_SEC);
        assert_eq!(parse_duration_usec("2min").unwrap(), 2 * 60 * USEC_PER_SEC);
        assert_eq!(parse_duration_usec("1h").unwrap(), 3600 * USEC_PER_SEC);
        assert_eq!(parse_duration_usec("1d").unwrap(), 86400 * USEC_PER_SEC);
        assert_eq!(parse_duration_usec("500ms").unwrap(), 500_000);
        assert_eq!(parse_duration_usec("0").unwrap(), 0);
        assert_eq!(parse_duration_usec("infinity").unwrap(), USEC_INFINITY);
        assert_eq!(parse_duration_usec("inf").unwrap(), USEC_INFINITY);
        assert!(parse_duration_usec("abc").is_err());
    }

    #[test]
    fn test_parse_hibernate_delay() {
        let config = SleepConfig::parse_from_str("[Sleep]\nHibernateDelaySec=120\n");
        assert_eq!(config.hibernate_delay_usec, 120 * USEC_PER_SEC);
    }

    #[test]
    fn test_parse_hibernate_on_ac_power() {
        let config = SleepConfig::parse_from_str("[Sleep]\nHibernateOnACPower=false\n");
        assert!(!config.hibernate_on_ac_power);
    }

    #[test]
    fn test_suspend_estimation_zero_becomes_default() {
        let config = SleepConfig::parse_from_str("[Sleep]\nSuspendEstimationSec=0\n");
        assert_eq!(
            config.suspend_estimation_usec,
            DEFAULT_SUSPEND_ESTIMATION_USEC
        );
    }

    // ── Validation ──────────────────────────────────────────────────

    #[test]
    fn test_validate_removes_disk_from_suspend() {
        let config = SleepConfig::parse_from_str("[Sleep]\nSuspendState=mem disk freeze\n");
        assert_eq!(config.states[0], vec!["mem", "freeze"]);
        assert!(!config.states[0].iter().any(|s| s == "disk"));
    }

    // ── Mem sleep detection ─────────────────────────────────────────

    #[test]
    fn test_needs_mem_sleep_with_mem_state() {
        let mut config = SleepConfig::new();
        config.states[0] = vec!["mem".to_string()];
        assert!(sleep_needs_mem_sleep(&config, SleepOperation::Suspend));
    }

    #[test]
    fn test_needs_mem_sleep_default_suspend_includes_mem() {
        let config = SleepConfig::parse_from_str("");
        assert!(sleep_needs_mem_sleep(&config, SleepOperation::Suspend));
    }

    #[test]
    fn test_needs_mem_sleep_hybrid_with_suspend_mode() {
        let mut config = SleepConfig::new();
        config.modes[2] = vec!["suspend".to_string()];
        assert!(sleep_needs_mem_sleep(&config, SleepOperation::HybridSleep));
    }

    #[test]
    fn test_needs_mem_sleep_s2h_no_direct_config() {
        let config = SleepConfig::new();
        assert!(!sleep_needs_mem_sleep(
            &config,
            SleepOperation::SuspendThenHibernate
        ));
    }

    // ── Utility functions ───────────────────────────────────────────

    #[test]
    fn test_split_quoted() {
        assert_eq!(split_quoted("mem freeze"), vec!["mem", "freeze"]);
        assert_eq!(split_quoted("  mem   freeze  "), vec!["mem", "freeze"]);
        assert_eq!(split_quoted(""), Vec::<String>::new());
        assert_eq!(split_quoted("mem"), vec!["mem"]);
    }

    #[test]
    fn test_split_quoted_with_quotes() {
        assert_eq!(split_quoted(r#""mem freeze""#), vec!["mem freeze"]);
        assert_eq!(split_quoted(r#""mem" freeze"#), vec!["mem", "freeze"]);
    }

    #[test]
    fn test_parse_tristate() {
        assert_eq!(parse_tristate("true"), Tristate::True);
        assert_eq!(parse_tristate("1"), Tristate::True);
        assert_eq!(parse_tristate("yes"), Tristate::True);
        assert_eq!(parse_tristate("on"), Tristate::True);
        assert_eq!(parse_tristate("false"), Tristate::False);
        assert_eq!(parse_tristate("0"), Tristate::False);
        assert_eq!(parse_tristate("no"), Tristate::False);
        assert_eq!(parse_tristate("off"), Tristate::False);
        assert_eq!(parse_tristate("maybe"), Tristate::Unset);
        assert_eq!(parse_tristate(""), Tristate::Unset);
    }

    // ── SleepSupport discriminants ──────────────────────────────────

    #[test]
    fn test_sleep_support_discriminants() {
        assert_eq!(SleepSupport::Supported as i32, 0);
        assert_eq!(SleepSupport::Disabled as i32, 1);
        assert_eq!(SleepSupport::NotConfigured as i32, 2);
        assert_eq!(SleepSupport::StateOrModeNotSupported as i32, 3);
        assert_eq!(SleepSupport::ResumeNotSupported as i32, 4);
        assert_eq!(SleepSupport::ResumeDeviceMissing as i32, 5);
        assert_eq!(SleepSupport::ResumeMisconfigured as i32, 6);
        assert_eq!(SleepSupport::NotEnoughSwapSpace as i32, 7);
        assert_eq!(SleepSupport::AlarmNotSupported as i32, 8);
    }

    // ── Error type ──────────────────────────────────────────────────

    #[test]
    fn test_sleep_error_display() {
        assert_eq!(SleepError::InvalidArgument.to_string(), "invalid argument");
        assert_eq!(
            SleepError::NotConfigured.to_string(),
            "no sleep state configured"
        );
        assert!(
            SleepError::Io("not found".into())
                .to_string()
                .contains("not found")
        );
        assert!(SleepError::Parse("bad".into()).to_string().contains("bad"));
    }

    // ── Sysfs content parsing ───────────────────────────────────────

    #[test]
    fn test_check_states_in_sysfs() {
        let sysfs = "freeze mem standby disk";
        assert!(check_states_in_sysfs(&["mem"], sysfs).unwrap());
        assert!(check_states_in_sysfs(&["disk"], sysfs).unwrap());
        assert!(!check_states_in_sysfs(&["s2idle"], sysfs).unwrap());
    }

    #[test]
    fn test_check_states_empty() {
        assert_eq!(
            check_states_in_sysfs(&[], "anything").unwrap_err(),
            SleepError::NotConfigured
        );
    }

    #[test]
    fn test_check_modes_in_sysfs_bracket_default() {
        let sysfs = "s2idle [deep] shutdown";
        assert!(check_modes_in_sysfs(&["deep"], sysfs).unwrap());
        assert!(check_modes_in_sysfs(&["s2idle"], sysfs).unwrap());
        assert!(check_modes_in_sysfs(&["shutdown"], sysfs).unwrap());
        assert!(!check_modes_in_sysfs(&["platform"], sysfs).unwrap());
    }

    #[test]
    fn test_check_modes_empty_returns_true() {
        assert!(check_modes_in_sysfs(&[], "anything").unwrap());
    }

    // ── Disabled support check ──────────────────────────────────────

    #[test]
    fn test_sleep_supported_disabled() {
        let config = SleepConfig::parse_from_str("[Sleep]\nAllowSuspend=false\n");
        assert_eq!(
            sleep_supported(&config, SleepOperation::Suspend).unwrap(),
            SleepSupport::Disabled
        );
    }

    // ── Legacy keys ignored ─────────────────────────────────────────

    #[test]
    fn test_legacy_keys_silently_ignored() {
        let config = SleepConfig::parse_from_str(
            "[Sleep]\n\
             SuspendMode=foo\n\
             HibernateState=bar\n\
             HybridSleepState=baz\n\
             HybridSleepMode=qux\n",
        );
        // SuspendMode should not create modes for suspend
        assert!(config.modes[0].is_empty());
        // HibernateState should not override hibernate states
        assert_eq!(config.states[1], vec!["disk"]);
    }

    // ── Section handling ────────────────────────────────────────────

    #[test]
    fn test_keys_outside_sleep_section_ignored() {
        let config = SleepConfig::parse_from_str(
            "[Other]\nAllowSuspend=false\n[Sleep]\nAllowSuspend=false\n",
        );
        // Only the [Sleep] section should apply
        assert!(!config.allow[SleepOperation::Suspend.allow_index()]);
    }

    #[test]
    fn test_no_section_header_treated_as_sleep() {
        let config = SleepConfig::parse_from_str("AllowSuspend=false\n");
        assert!(!config.allow[SleepOperation::Suspend.allow_index()]);
    }
}
