// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/install.c, src/shared/install.h
//
// Unit file install state management, change tracking, preset rule parsing,
// and path classification utilities.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum symlink chase depth when traversing unit file aliases/links.
use crate::ffi::*;
pub const UNIT_FILE_FOLLOW_SYMLINK_MAX: u32 = 64;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by install operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// An entity already exists where one was not expected.
    Exists,
    /// The unit file is masked (symlinked to `/dev/null`).
    Masked,
    /// The unit file is transient or generated at runtime.
    Generated,
    /// The file is within the systemd unit hierarchy already.
    BadPath,
    /// Invalid specifier in the unit name.
    BadUnitSetting,
    /// Template/non-template mismatch between source and destination.
    TemplateMismatch,
    /// The unit name is syntactically invalid.
    InvalidName,
    /// The unit is a linked file that cannot be operated on.
    Linked,
    /// Cross-device link or invalid alias.
    CrossDevice,
    /// The requested unit does not exist.
    NotFound,
    /// An alias target cannot be resolved.
    UnresolvableAlias,
    /// Specifiers in the unit name could not be resolved.
    UnresolvableSpecifier,
    /// A generic I/O or system error occurred.
    Io(i32),
    /// The unit name is empty or not valid for any category.
    InvalidUnitName,
}

impl InstallError {
    /// Convert to a negative errno value (systemd convention).
    pub fn to_errno(&self) -> i32 {
        match self {
            InstallError::Exists => libc::EEXIST,
            InstallError::Masked => ERFKILL,
            InstallError::Generated => libc::EADDRNOTAVAIL,
            InstallError::BadPath => libc::ETXTBSY,
            InstallError::BadUnitSetting => EBADSLT,
            InstallError::TemplateMismatch => libc::EIDRM,
            InstallError::InvalidName => EUCLEAN,
            InstallError::Linked => libc::ELOOP,
            InstallError::CrossDevice => libc::EXDEV,
            InstallError::NotFound => libc::ENOENT,
            InstallError::UnresolvableAlias => libc::ENOLINK,
            InstallError::UnresolvableSpecifier => EUNATCH,
            InstallError::Io(e) => *e,
            InstallError::InvalidUnitName => libc::EINVAL,
        }
    }

    /// Build from a negative errno value, if it is a recognised unit-issue code.
    pub fn from_errno(e: i32) -> Option<Self> {
        match -e {
            libc::EEXIST => Some(InstallError::Exists),
            ERFKILL => Some(InstallError::Masked),
            libc::EADDRNOTAVAIL => Some(InstallError::Generated),
            libc::ETXTBSY => Some(InstallError::BadPath),
            EBADSLT => Some(InstallError::BadUnitSetting),
            libc::EIDRM => Some(InstallError::TemplateMismatch),
            EUCLEAN => Some(InstallError::InvalidName),
            libc::ELOOP => Some(InstallError::Linked),
            libc::EXDEV => Some(InstallError::CrossDevice),
            libc::ENOENT => Some(InstallError::NotFound),
            libc::ENOLINK => Some(InstallError::UnresolvableAlias),
            EUNATCH => Some(InstallError::UnresolvableSpecifier),
            _ => None,
        }
    }

    /// Human-readable error message for the change (mirrors `install_change_dump_error`).
    pub fn error_message(&self, path: &str, source: Option<&str>) -> String {
        match self {
            InstallError::Exists => {
                let mut m = format!("File '{}' already exists", path);
                if let Some(s) = source {
                    m.push_str(&format!(" and is a symlink to {}", s));
                }
                m
            }
            InstallError::Masked => format!("Unit {} is masked", path),
            InstallError::Generated => format!("Unit {} is transient or generated", path),
            InstallError::BadPath => {
                format!(
                    "File '{}' is under the systemd unit hierarchy already",
                    path
                )
            }
            InstallError::BadUnitSetting => format!("Invalid specifier in unit {}", path),
            InstallError::TemplateMismatch => format!(
                "Refusing to operate on template unit {} when destination unit {} is a non-template unit",
                source.unwrap_or("?"),
                path
            ),
            InstallError::InvalidName => format!("Invalid unit name {}", path),
            InstallError::Linked => format!("Refusing to operate on linked unit file {}", path),
            InstallError::CrossDevice => {
                if let Some(s) = source {
                    format!("Cannot alias {} as {}", s, path)
                } else {
                    format!("Invalid unit reference {}", path)
                }
            }
            InstallError::NotFound => format!("Unit {} does not exist", path),
            InstallError::UnresolvableAlias => format!("Unit {} is an unresolvable alias", path),
            InstallError::UnresolvableSpecifier => {
                format!("Cannot resolve specifiers in unit {}", path)
            }
            InstallError::Io(_) => format!("I/O error on {}", path),
            InstallError::InvalidUnitName => format!("Invalid unit name {}", path),
        }
    }
}

/// Check whether a negative return code is one of the "unit issue" errors
/// generated/transient/missing/invalid units when applying presets.
pub fn errno_is_unit_issue(r: i32) -> bool {
    matches!(
        -r,
        libc::EEXIST
            | ERFKILL
            | libc::EADDRNOTAVAIL
            | libc::ETXTBSY
            | EBADSLT
            | libc::EIDRM
            | EUCLEAN
            | libc::ELOOP
            | libc::EXDEV
            | libc::ENOENT
            | libc::ENOLINK
            | EUNATCH
    )
}

// ── Enums ─────────────────────────────────────────────────────────────────

/// The type of change recorded during an install operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChangeType {
    Symlink,
    Unlink,
    IsMasked,
    IsMaskedGenerator,
    IsDangling,
    DestinationNotPresent,
    AuxiliaryFailed,
}

impl InstallChangeType {
    /// All valid variants in table order.
    pub const ALL: [InstallChangeType; 7] = [
        InstallChangeType::Symlink,
        InstallChangeType::Unlink,
        InstallChangeType::IsMasked,
        InstallChangeType::IsMaskedGenerator,
        InstallChangeType::IsDangling,
        InstallChangeType::DestinationNotPresent,
        InstallChangeType::AuxiliaryFailed,
    ];

    /// Human-readable name (mirrors `install_change_type_table`).
    pub fn to_str(self) -> &'static str {
        match self {
            InstallChangeType::Symlink => "symlink",
            InstallChangeType::Unlink => "unlink",
            InstallChangeType::IsMasked => "masked",
            InstallChangeType::IsMaskedGenerator => "masked by generator",
            InstallChangeType::IsDangling => "dangling",
            InstallChangeType::DestinationNotPresent => "destination not present",
            InstallChangeType::AuxiliaryFailed => "auxiliary unit failed",
        }
    }

    /// Parse from string (mirrors `install_change_type_from_string`).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "symlink" => Some(InstallChangeType::Symlink),
            "unlink" => Some(InstallChangeType::Unlink),
            "masked" => Some(InstallChangeType::IsMasked),
            "masked by generator" => Some(InstallChangeType::IsMaskedGenerator),
            "dangling" => Some(InstallChangeType::IsDangling),
            "destination not present" => Some(InstallChangeType::DestinationNotPresent),
            "auxiliary unit failed" => Some(InstallChangeType::AuxiliaryFailed),
            _ => None,
        }
    }
}

/// How the unit file was discovered (mirrors `InstallMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Regular,
    Linked,
    Alias,
    Masked,
}

/// Preset actions read from `.preset` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetAction {
    Unknown,
    Enable,
    Disable,
    Ignore,
}

impl PresetAction {
    /// Human-readable past-tense (mirrors `preset_action_past_tense_table`).
    pub fn past_tense(self) -> &'static str {
        match self {
            PresetAction::Unknown => "unknown",
            PresetAction::Enable => "enabled",
            PresetAction::Disable => "disabled",
            PresetAction::Ignore => "ignored",
        }
    }
}

/// Preset mode for `unit_file_preset` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetMode {
    Full,
    EnableOnly,
    DisableOnly,
}

impl PresetMode {
    pub fn to_str(self) -> &'static str {
        match self {
            PresetMode::Full => "full",
            PresetMode::EnableOnly => "enable-only",
            PresetMode::DisableOnly => "disable-only",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "full" => Some(PresetMode::Full),
            "enable-only" => Some(PresetMode::EnableOnly),
            "disable-only" => Some(PresetMode::DisableOnly),
            _ => None,
        }
    }
}

bitflags::bitflags! {
    /// Flags controlling unit file operations (mirrors `UnitFileFlags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UnitFileFlags: u32 {
        const RUNTIME = 1 << 0;
        const FORCE = 1 << 1;
        const PORTABLE = 1 << 2;
        const DRY_RUN = 1 << 3;
        const IGNORE_AUXILIARY_FAILURE = 1 << 4;
    }
}

bitflags::bitflags! {
    /// Flags controlling search/load behaviour (mirrors `SearchFlags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SearchFlags: u32 {
        const LOAD = 1 << 0;
        const FOLLOW_CONFIG_SYMLINKS = 1 << 1;
        const DROPIN = 1 << 2;
        const IGNORE_TEMPLATE = 1 << 3;
    }
}

/// Unit file state returned by `unit_file_get_state` (mirrors `UnitFileState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitFileState {
    Enabled,
    EnabledRuntime,
    Linked,
    LinkedRuntime,
    Alias,
    Masked,
    MaskedRuntime,
    Static,
    Disabled,
    Indirect,
    Generated,
    Transient,
    Bad,
}

impl UnitFileState {
    /// String table (mirrors `unit_file_state_table`).
    pub fn to_str(self) -> &'static str {
        match self {
            UnitFileState::Enabled => "enabled",
            UnitFileState::EnabledRuntime => "enabled-runtime",
            UnitFileState::Linked => "linked",
            UnitFileState::LinkedRuntime => "linked-runtime",
            UnitFileState::Alias => "alias",
            UnitFileState::Masked => "masked",
            UnitFileState::MaskedRuntime => "masked-runtime",
            UnitFileState::Static => "static",
            UnitFileState::Disabled => "disabled",
            UnitFileState::Indirect => "indirect",
            UnitFileState::Generated => "generated",
            UnitFileState::Transient => "transient",
            UnitFileState::Bad => "bad",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "enabled" => Some(UnitFileState::Enabled),
            "enabled-runtime" => Some(UnitFileState::EnabledRuntime),
            "linked" => Some(UnitFileState::Linked),
            "linked-runtime" => Some(UnitFileState::LinkedRuntime),
            "alias" => Some(UnitFileState::Alias),
            "masked" => Some(UnitFileState::Masked),
            "masked-runtime" => Some(UnitFileState::MaskedRuntime),
            "static" => Some(UnitFileState::Static),
            "disabled" => Some(UnitFileState::Disabled),
            "indirect" => Some(UnitFileState::Indirect),
            "generated" => Some(UnitFileState::Generated),
            "transient" => Some(UnitFileState::Transient),
            "bad" => Some(UnitFileState::Bad),
            _ => None,
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────

/// A single recorded change from an install operation.
#[derive(Debug, Clone)]
pub struct InstallChange {
    /// The change type (success variant) or error.
    pub change_type: ChangeOrError,
    /// Path affected by the change.
    pub path: String,
    /// Symlink source, if applicable.
    pub source: Option<String>,
}

/// Union of success change types and error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeOrError {
    Ok(InstallChangeType),
    Err(i32), // negative errno
}

impl ChangeOrError {
    pub fn is_modification(&self) -> bool {
        matches!(
            self,
            ChangeOrError::Ok(InstallChangeType::Symlink)
                | ChangeOrError::Ok(InstallChangeType::Unlink)
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, ChangeOrError::Ok(_))
    }

    pub fn is_error(&self) -> bool {
        matches!(self, ChangeOrError::Err(_))
    }
}

impl InstallChange {
    /// Create a new change entry with simplified path.
    pub fn new(change_type: ChangeOrError, path: &str, source: Option<&str>) -> Self {
        InstallChange {
            change_type,
            path: simplify_path(path),
            source: source.map(|s| simplify_path(s)),
        }
    }
}

/// Check if any change in the list is a modification (symlink or unlink).
/// Mirrors `install_changes_have_modification`.
pub fn install_changes_have_modification(changes: &[InstallChange]) -> bool {
    changes.iter().any(|c| c.change_type.is_modification())
}

/// Installation info for a unit (mirrors `InstallInfo`).
#[derive(Debug, Clone, Default)]
pub struct InstallInfo {
    pub name: String,
    pub path: Option<String>,
    pub root: Option<String>,
    pub aliases: Vec<String>,
    pub wanted_by: Vec<String>,
    pub required_by: Vec<String>,
    pub upheld_by: Vec<String>,
    pub also: Vec<String>,
    pub default_instance: Option<String>,
    pub symlink_target: Option<String>,
    pub install_mode: Option<InstallMode>,
    pub auxiliary: bool,
}

impl InstallInfo {
    /// Returns `true` if the unit has any [Install] section rules
    /// (Alias, WantedBy, RequiredBy, UpheldBy).
    /// Mirrors `install_info_has_rules`.
    pub fn has_rules(&self) -> bool {
        !self.aliases.is_empty()
            || !self.wanted_by.is_empty()
            || !self.required_by.is_empty()
            || !self.upheld_by.is_empty()
    }

    /// Returns `true` if the unit has `Also=` entries.
    /// Mirrors `install_info_has_also`.
    pub fn has_also(&self) -> bool {
        !self.also.is_empty()
    }
}

/// A single preset rule parsed from a `.preset` file.
#[derive(Debug, Clone)]
pub struct PresetRule {
    pub pattern: String,
    pub action: PresetAction,
    pub instances: Vec<String>,
}

/// Collection of preset rules loaded from configuration files.
#[derive(Debug, Clone, Default)]
pub struct UnitFilePresets {
    pub rules: Vec<PresetRule>,
    pub initialized: bool,
}

// ── Path utilities ────────────────────────────────────────────────────────

/// Simplify a path by collapsing duplicate slashes and resolving `.`/`..`
/// components where possible without filesystem access.
fn simplify_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut components: Vec<&str> = Vec::new();
    let starts_with_slash = p.starts_with('/');

    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = components.last() {
                    if *last != ".." {
                        components.pop();
                        continue;
                    }
                }
                components.push("..");
            }
            _ => components.push(part),
        }
    }

    if starts_with_slash {
        out.push('/');
    }
    out.push_str(&components.join("/"));
    if out.is_empty() { ".".to_string() } else { out }
}

/// Strip a root directory prefix from `path`.
/// Mirrors the C `skip_root` function: the result always starts with `/` on success.
///
/// Returns `Some(suffix)` when `path` starts with `root_dir` (with a `/` boundary),
/// or `None` otherwise.
pub fn skip_root<'a>(root_dir: Option<&'a str>, path: &'a str) -> Option<&'a str> {
    let root = root_dir?;
    // Strip trailing slashes so that "/etc/" matches "/etc/systemd".
    let root = if root == "/" {
        root
    } else {
        root.trim_end_matches('/')
    };
    if path == root {
        // Exact match → treat as root itself.
        return Some("/");
    }
    let suffix = path.strip_prefix(root)?;
    if suffix.starts_with('/') {
        Some(suffix)
    } else if suffix.is_empty() {
        // path equals root_dir exactly, but we didn't match above
        // because of trailing slash differences.
        Some("/")
    } else {
        None
    }
}

/// Check if `change_type` (as a raw i32) is a modification change
/// (symlink creation or removal). Mirrors the C helper.
pub fn is_modification_raw(change_type: i32) -> bool {
    matches!(change_type, 0 | 1)
}

/// Return the config path appropriate for the given flags.
/// When `portable` is set, returns the attached-* path; otherwise the
/// config-* path. When `runtime` is set, returns the runtime variant.
///
/// Mirrors `config_path_from_flags`.
pub fn config_path_from_flags<'a>(
    persistent_config: Option<&'a str>,
    runtime_config: Option<&'a str>,
    persistent_attached: Option<&'a str>,
    runtime_attached: Option<&'a str>,
    flags: UnitFileFlags,
) -> Option<&'a str> {
    if flags.contains(UnitFileFlags::PORTABLE) {
        if flags.contains(UnitFileFlags::RUNTIME) {
            runtime_attached
        } else {
            persistent_attached
        }
    } else if flags.contains(UnitFileFlags::RUNTIME) {
        runtime_config
    } else {
        persistent_config
    }
}

// ── Preset file parsing ──────────────────────────────────────────────────

/// Parse a single line from a `.preset` file into an optional rule.
/// Returns `None` for blank lines and comments.
pub fn parse_preset_line(line: &str) -> Option<PresetRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    if let Some(rest) = line.strip_prefix("enable ") {
        let rest = rest.trim();
        let mut words = rest.split_whitespace();
        let pattern = words.next().unwrap_or("").to_string();
        let instances: Vec<String> = words.map(String::from).collect();
        Some(PresetRule {
            pattern,
            action: PresetAction::Enable,
            instances,
        })
    } else if let Some(rest) = line.strip_prefix("disable ") {
        Some(PresetRule {
            pattern: rest.trim().to_string(),
            action: PresetAction::Disable,
            instances: Vec::new(),
        })
    } else if let Some(rest) = line.strip_prefix("ignore ") {
        Some(PresetRule {
            pattern: rest.trim().to_string(),
            action: PresetAction::Ignore,
            instances: Vec::new(),
        })
    } else {
        None
    }
}

/// Query the preset action for a unit name against a loaded set of rules.
/// If no rule matches, defaults to `PresetAction::Enable` (mirrors systemd
/// behaviour: "Preset files don't specify rule for X. Enabling.").
pub fn query_preset(name: &str, presets: &UnitFilePresets) -> Result<PresetAction, InstallError> {
    if name.is_empty() {
        return Err(InstallError::InvalidUnitName);
    }

    for rule in &presets.rules {
        if glob_match(&rule.pattern, name) {
            return Ok(rule.action);
        }
    }

    // Default: enable (matches C behaviour).
    Ok(PresetAction::Enable)
}

/// Parse all preset rules from a string (representing the contents of a
/// `.preset` file).
pub fn parse_preset_file(contents: &str) -> Vec<PresetRule> {
    contents.lines().filter_map(parse_preset_line).collect()
}

// ── Glob matching ─────────────────────────────────────────────────────────

/// Simple glob matching (replaces `fnmatch` for basic patterns used in preset files).
/// Supports `*`, `?`, `[abc]`, `[!abc]`, `[a-z]`.
pub fn glob_match(pattern: &str, string: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let string: Vec<char> = string.chars().collect();
    glob_match_impl(&pattern, &string)
}

fn glob_match_impl(pattern: &[char], string: &[char]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < string.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '*' => {
                    star_pi = pi;
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                '[' => {
                    if let Some(result) = match_char_class(&pattern[pi..], string[si]) {
                        pi = result.0;
                        if result.1 {
                            si += 1;
                            continue;
                        }
                    } else if pattern[pi] == string[si] {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                c if c == string[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }

        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Match a character class `[abc]` or `[!abc]` or `[a-z]`.
/// Returns `Some((new_pattern_index, matched))` or `None` if malformed.
fn match_char_class(pattern: &[char], c: char) -> Option<(usize, bool)> {
    if pattern.is_empty() || pattern[0] != '[' {
        return None;
    }

    let mut i = 1;
    let negate = if i < pattern.len() && pattern[i] == '!' {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    while i < pattern.len() && pattern[i] != ']' {
        if i + 2 < pattern.len() && pattern[i + 1] == '-' {
            let start = pattern[i];
            let end = pattern[i + 2];
            if c >= start && c <= end {
                matched = true;
            }
            i += 3;
        } else {
            if pattern[i] == c {
                matched = true;
            }
            i += 1;
        }
    }

    if i < pattern.len() && pattern[i] == ']' {
        i += 1;
        Some((i, matched != negate))
    } else {
        None
    }
}

// ── Success message formatting ────────────────────────────────────────────

/// Format a success message for a change entry.
/// Mirrors `install_change_dump_success`.
pub fn format_success_message(change: &InstallChange) -> Option<String> {
    match &change.change_type {
        ChangeOrError::Ok(t) => Some(match t {
            InstallChangeType::Symlink => {
                let arrow = "\u{2192}"; // →
                format!(
                    "Created symlink '{}' {} '{}'.",
                    change.path,
                    arrow,
                    change.source.as_deref().unwrap_or("?")
                )
            }
            InstallChangeType::Unlink => format!("Removed '{}'.", change.path),
            InstallChangeType::IsMasked => {
                format!("Unit {} is masked, ignoring.", change.path)
            }
            InstallChangeType::IsMaskedGenerator => {
                format!(
                    "Unit {} is masked via a generator and cannot be unmasked, skipping.",
                    change.path
                )
            }
            InstallChangeType::IsDangling => {
                format!(
                    "Unit {} is an alias to a non-existent unit, ignoring.",
                    change.path
                )
            }
            InstallChangeType::DestinationNotPresent => {
                format!(
                    "Unit {} is added as a dependency to a non-existent unit {}.",
                    change.source.as_deref().unwrap_or("?"),
                    change.path
                )
            }
            InstallChangeType::AuxiliaryFailed => {
                format!("Failed to enable auxiliary unit {}, ignoring.", change.path)
            }
        }),
        ChangeOrError::Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── skip_root ──────────────────────────────────────────────────────

    #[test]
    fn test_skip_root_basic() {
        assert_eq!(
            skip_root(Some("/etc"), "/etc/systemd/system"),
            Some("/systemd/system")
        );
    }

    #[test]
    fn test_skip_root_no_boundary() {
        assert_eq!(skip_root(Some("/etc"), "/etccfg"), None);
    }

    #[test]
    fn test_skip_root_none_root() {
        // When root_dir is None, skip_root returns None (no prefix to strip).
        assert_eq!(skip_root(None, "/etc/systemd/system"), None);
    }

    #[test]
    fn test_skip_root_exact_match() {
        assert_eq!(skip_root(Some("/etc"), "/etc"), Some("/"));
    }

    #[test]
    fn test_skip_root_trailing_slash() {
        assert_eq!(skip_root(Some("/etc/"), "/etc/systemd"), Some("/systemd"));
    }

    // ── InstallInfo helpers ────────────────────────────────────────────

    #[test]
    fn test_install_info_has_rules() {
        let info = InstallInfo {
            wanted_by: vec!["multi-user.target".to_string()],
            ..Default::default()
        };
        assert!(info.has_rules());
        assert!(!info.has_also());
    }

    #[test]
    fn test_install_info_has_also() {
        let info = InstallInfo {
            also: vec!["other.service".to_string()],
            ..Default::default()
        };
        assert!(!info.has_rules());
        assert!(info.has_also());
    }

    #[test]
    fn test_install_info_no_rules() {
        let info = InstallInfo::default();
        assert!(!info.has_rules());
        assert!(!info.has_also());
    }

    #[test]
    fn test_install_info_all_rules() {
        let info = InstallInfo {
            aliases: vec!["a".to_string()],
            wanted_by: vec!["b".to_string()],
            required_by: vec!["c".to_string()],
            upheld_by: vec!["d".to_string()],
            also: vec!["e".to_string()],
            ..Default::default()
        };
        assert!(info.has_rules());
        assert!(info.has_also());
    }

    // ── errno_is_unit_issue ────────────────────────────────────────────

    #[test]
    fn test_errno_is_unit_issue() {
        assert!(errno_is_unit_issue(-libc::EEXIST));
        assert!(errno_is_unit_issue(-ERFKILL));
        assert!(errno_is_unit_issue(-libc::ENOENT));
        assert!(errno_is_unit_issue(-libc::ELOOP));
        assert!(errno_is_unit_issue(-libc::EXDEV));
        assert!(!errno_is_unit_issue(-libc::EPERM));
        assert!(!errno_is_unit_issue(0));
    }

    // ── InstallChangeType string table ─────────────────────────────────

    #[test]
    fn test_change_type_round_trip() {
        for ct in InstallChangeType::ALL {
            assert_eq!(InstallChangeType::from_str(ct.to_str()), Some(ct));
        }
        assert_eq!(InstallChangeType::from_str("nope"), None);
    }

    // ── PresetMode round-trip ──────────────────────────────────────────

    #[test]
    fn test_preset_mode_round_trip() {
        for m in [
            PresetMode::Full,
            PresetMode::EnableOnly,
            PresetMode::DisableOnly,
        ] {
            assert_eq!(PresetMode::from_str(m.to_str()), Some(m));
        }
        assert_eq!(PresetMode::from_str("nope"), None);
    }

    // ── UnitFileState round-trip ───────────────────────────────────────

    #[test]
    fn test_unit_file_state_round_trip() {
        let all = [
            UnitFileState::Enabled,
            UnitFileState::EnabledRuntime,
            UnitFileState::Linked,
            UnitFileState::LinkedRuntime,
            UnitFileState::Alias,
            UnitFileState::Masked,
            UnitFileState::MaskedRuntime,
            UnitFileState::Static,
            UnitFileState::Disabled,
            UnitFileState::Indirect,
            UnitFileState::Generated,
            UnitFileState::Transient,
            UnitFileState::Bad,
        ];
        for s in all {
            assert_eq!(UnitFileState::from_str(s.to_str()), Some(s));
        }
        assert_eq!(UnitFileState::from_str("nope"), None);
    }

    // ── PresetAction past tense ────────────────────────────────────────

    #[test]
    fn test_preset_action_past_tense() {
        assert_eq!(PresetAction::Unknown.past_tense(), "unknown");
        assert_eq!(PresetAction::Enable.past_tense(), "enabled");
        assert_eq!(PresetAction::Disable.past_tense(), "disabled");
        assert_eq!(PresetAction::Ignore.past_tense(), "ignored");
    }

    // ── config_path_from_flags ─────────────────────────────────────────

    #[test]
    fn test_config_path_from_flags_persistent() {
        assert_eq!(
            config_path_from_flags(
                Some("/etc/systemd/system"),
                Some("/run/systemd/system"),
                Some("/etc/systemd/attached"),
                Some("/run/systemd/attached"),
                UnitFileFlags::empty(),
            ),
            Some("/etc/systemd/system")
        );
    }

    #[test]
    fn test_config_path_from_flags_runtime() {
        assert_eq!(
            config_path_from_flags(
                Some("/etc/systemd/system"),
                Some("/run/systemd/system"),
                Some("/etc/systemd/attached"),
                Some("/run/systemd/attached"),
                UnitFileFlags::RUNTIME,
            ),
            Some("/run/systemd/system")
        );
    }

    #[test]
    fn test_config_path_from_flags_portable_runtime() {
        assert_eq!(
            config_path_from_flags(
                Some("/etc/systemd/system"),
                Some("/run/systemd/system"),
                Some("/etc/systemd/attached"),
                Some("/run/systemd/attached"),
                UnitFileFlags::RUNTIME | UnitFileFlags::PORTABLE,
            ),
            Some("/run/systemd/attached")
        );
    }

    // ── parse_preset_line ──────────────────────────────────────────────

    #[test]
    fn test_parse_preset_line() {
        let rule = parse_preset_line("enable foo.service").unwrap();
        assert_eq!(rule.pattern, "foo.service");
        assert_eq!(rule.action, PresetAction::Enable);
        assert!(rule.instances.is_empty());

        let rule = parse_preset_line("disable *.service").unwrap();
        assert_eq!(rule.pattern, "*.service");
        assert_eq!(rule.action, PresetAction::Disable);

        let rule = parse_preset_line("ignore foo@.service").unwrap();
        assert_eq!(rule.pattern, "foo@.service");
        assert_eq!(rule.action, PresetAction::Ignore);

        assert!(parse_preset_line("# comment").is_none());
        assert!(parse_preset_line("").is_none());
        assert!(parse_preset_line("unknown foo").is_none());
    }

    #[test]
    fn test_parse_preset_line_with_instances() {
        let rule = parse_preset_line("enable foo@.service a b c").unwrap();
        assert_eq!(rule.pattern, "foo@.service");
        assert_eq!(rule.instances, vec!["a", "b", "c"]);
    }

    // ── parse_preset_file ──────────────────────────────────────────────

    #[test]
    fn test_parse_preset_file() {
        let contents = "\
# This is a comment
enable foo.service
disable bar.service

enable baz@.service x y
";
        let rules = parse_preset_file(contents);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].action, PresetAction::Enable);
        assert_eq!(rules[0].pattern, "foo.service");
        assert_eq!(rules[1].action, PresetAction::Disable);
        assert_eq!(rules[1].pattern, "bar.service");
        assert_eq!(rules[2].instances, vec!["x", "y"]);
    }

    // ── query_preset ───────────────────────────────────────────────────

    #[test]
    fn test_query_preset_matching() {
        let presets = UnitFilePresets {
            rules: vec![
                PresetRule {
                    pattern: "foo.service".to_string(),
                    action: PresetAction::Enable,
                    instances: vec![],
                },
                PresetRule {
                    pattern: "bar.service".to_string(),
                    action: PresetAction::Disable,
                    instances: vec![],
                },
            ],
            initialized: true,
        };
        assert_eq!(
            query_preset("foo.service", &presets).unwrap(),
            PresetAction::Enable
        );
        assert_eq!(
            query_preset("bar.service", &presets).unwrap(),
            PresetAction::Disable
        );
    }

    #[test]
    fn test_query_preset_default_enable() {
        let presets = UnitFilePresets {
            rules: vec![],
            initialized: true,
        };
        assert_eq!(
            query_preset("anything.service", &presets).unwrap(),
            PresetAction::Enable
        );
    }

    #[test]
    fn test_query_preset_glob_pattern() {
        let presets = UnitFilePresets {
            rules: vec![PresetRule {
                pattern: "*.service".to_string(),
                action: PresetAction::Disable,
                instances: vec![],
            }],
            initialized: true,
        };
        assert_eq!(
            query_preset("foo.service", &presets).unwrap(),
            PresetAction::Disable
        );
        assert_eq!(
            query_preset("foo.socket", &presets).unwrap(),
            PresetAction::Enable // doesn't match *.service
        );
    }

    #[test]
    fn test_query_preset_empty_name() {
        let presets = UnitFilePresets::default();
        assert!(query_preset("", &presets).is_err());
    }

    // ── install_changes_have_modification ───────────────────────────────

    #[test]
    fn test_changes_have_modification() {
        let changes = vec![InstallChange {
            change_type: ChangeOrError::Ok(InstallChangeType::Symlink),
            path: "/a".to_string(),
            source: None,
        }];
        assert!(install_changes_have_modification(&changes));

        let changes = vec![InstallChange {
            change_type: ChangeOrError::Ok(InstallChangeType::IsMasked),
            path: "/a".to_string(),
            source: None,
        }];
        assert!(!install_changes_have_modification(&changes));

        assert!(!install_changes_have_modification(&[]));
    }

    // ── ChangeOrError helpers ──────────────────────────────────────────

    #[test]
    fn test_change_or_error() {
        let ok = ChangeOrError::Ok(InstallChangeType::Symlink);
        assert!(ok.is_success());
        assert!(!ok.is_error());
        assert!(ok.is_modification());

        let err = ChangeOrError::Err(-libc::ENOENT);
        assert!(!err.is_success());
        assert!(err.is_error());
        assert!(!err.is_modification());

        let non_mod = ChangeOrError::Ok(InstallChangeType::IsMasked);
        assert!(!non_mod.is_modification());
    }

    // ── is_modification_raw ────────────────────────────────────────────

    #[test]
    fn test_is_modification_raw() {
        assert!(is_modification_raw(0)); // Symlink
        assert!(is_modification_raw(1)); // Unlink
        assert!(!is_modification_raw(2)); // IsMasked
        assert!(!is_modification_raw(-2)); // error
    }

    // ── InstallError ───────────────────────────────────────────────────

    #[test]
    fn test_install_error_round_trip() {
        let errors = [
            InstallError::Exists,
            InstallError::Masked,
            InstallError::Generated,
            InstallError::BadPath,
            InstallError::BadUnitSetting,
            InstallError::TemplateMismatch,
            InstallError::InvalidName,
            InstallError::Linked,
            InstallError::CrossDevice,
            InstallError::NotFound,
            InstallError::UnresolvableAlias,
            InstallError::UnresolvableSpecifier,
        ];
        for e in &errors {
            let errno = e.to_errno();
            assert_eq!(InstallError::from_errno(-errno), Some(e.clone()));
        }
    }

    #[test]
    fn test_install_error_message() {
        assert_eq!(
            InstallError::Masked.error_message("foo.service", None),
            "Unit foo.service is masked"
        );
        assert_eq!(
            InstallError::Exists.error_message("/etc/foo", Some("/usr/lib/foo")),
            "File '/etc/foo' already exists and is a symlink to /usr/lib/foo"
        );
    }

    // ── simplify_path ──────────────────────────────────────────────────

    #[test]
    fn test_simplify_path() {
        assert_eq!(simplify_path("/a/b/../c"), "/a/c");
        assert_eq!(simplify_path("/a/./b"), "/a/b");
        assert_eq!(simplify_path("/a//b"), "/a/b");
        assert_eq!(simplify_path("a/b"), "a/b");
    }

    // ── format_success_message ─────────────────────────────────────────

    #[test]
    fn test_format_success_message() {
        let change = InstallChange {
            change_type: ChangeOrError::Ok(InstallChangeType::Symlink),
            path: "/etc/foo".to_string(),
            source: Some("/usr/lib/foo".to_string()),
        };
        let msg = format_success_message(&change).unwrap();
        assert!(msg.contains("Created symlink"));
        assert!(msg.contains("/etc/foo"));

        let change = InstallChange {
            change_type: ChangeOrError::Ok(InstallChangeType::Unlink),
            path: "/etc/foo".to_string(),
            source: None,
        };
        let msg = format_success_message(&change).unwrap();
        assert!(msg.contains("Removed"));

        // Error type should return None
        let change = InstallChange {
            change_type: ChangeOrError::Err(-libc::ENOENT),
            path: "/etc/foo".to_string(),
            source: None,
        };
        assert!(format_success_message(&change).is_none());
    }

    // ── glob_match ─────────────────────────────────────────────────────

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*.service", "foo.service"));
        assert!(!glob_match("*.service", "foo.socket"));
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", "ab"));
        assert!(glob_match("[abc]", "a"));
        assert!(!glob_match("[abc]", "d"));
        assert!(glob_match("[!abc]", "d"));
        assert!(!glob_match("[!abc]", "a"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("foo*", "foo"));
        assert!(glob_match("foo*", "foobar"));
        assert!(!glob_match("foo*", "barfoo"));
    }

    // ── InstallChange::new ─────────────────────────────────────────────

    #[test]
    fn test_install_change_new_simplifies() {
        let change = InstallChange::new(
            ChangeOrError::Ok(InstallChangeType::Symlink),
            "/a//b/../c",
            Some("/x/./y"),
        );
        assert_eq!(change.path, "/a/c");
        assert_eq!(change.source.as_deref(), Some("/x/y"));
    }
}
