// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/boot.c
//
// Boot loader entry management and configuration for systemd-boot.
//
// Handles boot entry types (type #1 loader spec entries, type #2 UKI entries),
// configuration loading, entry selection, reboot behavior, and the main
// boot menu loop.

// ── Constants ─────────────────────────────────────────────────────────────

/// Magic string for recognizing systemd-boot binaries.
pub const SD_MAGIC_PREFIX: &str = "#### LoaderInfo: systemd-boot ";

/// Maximum filename length for type #1 entries.
pub const MAX_TYPE1_FILENAME_LEN: usize = 255;

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderType {
    Undefined,
    Auto,
    Efi,
    Linux,
    Uki,
    UkiUrl,
    Type2Uki,
    SecureBootKeys,
    Bad,
    Ignore,
}

impl Default for LoaderType {
    fn default() -> Self {
        LoaderType::Undefined
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootOnError {
    No,
    Yes,
    Auto,
}

impl RebootOnError {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no" => Some(RebootOnError::No),
            "yes" => Some(RebootOnError::Yes),
            "auto" => Some(RebootOnError::Auto),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            RebootOnError::No => "no",
            RebootOnError::Yes => "yes",
            RebootOnError::Auto => "auto",
        }
    }
}

// ── Loader type queries ───────────────────────────────────────────────────

pub fn loader_type_allow_editor(t: LoaderType) -> bool {
    matches!(
        t,
        LoaderType::Efi
            | LoaderType::Linux
            | LoaderType::Uki
            | LoaderType::UkiUrl
            | LoaderType::Type2Uki
    )
}

pub fn loader_type_allow_editor_in_sb(t: LoaderType) -> bool {
    matches!(t, LoaderType::Efi | LoaderType::Linux)
}

pub fn loader_type_may_auto_select(t: LoaderType) -> bool {
    matches!(
        t,
        LoaderType::Efi
            | LoaderType::Linux
            | LoaderType::Uki
            | LoaderType::UkiUrl
            | LoaderType::Type2Uki
    )
}

pub fn loader_type_bump_counters(t: LoaderType) -> bool {
    matches!(
        t,
        LoaderType::Linux | LoaderType::Uki | LoaderType::Type2Uki
    )
}

pub fn loader_type_process_random_seed(t: LoaderType) -> bool {
    matches!(
        t,
        LoaderType::Linux | LoaderType::Uki | LoaderType::Type2Uki
    )
}

pub fn loader_type_save_entry(t: LoaderType) -> bool {
    matches!(
        t,
        LoaderType::Auto
            | LoaderType::Efi
            | LoaderType::Linux
            | LoaderType::Uki
            | LoaderType::UkiUrl
            | LoaderType::Type2Uki
    )
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    NotFound,
    InvalidParameter,
    LoadError,
    OutOfResources,
    DeviceError,
    Unsupported,
    NoEntry,
    ConfigLoadFailed,
    Timeout,
    NotImplemented,
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::NotFound => write!(f, "not found"),
            BootError::InvalidParameter => write!(f, "invalid parameter"),
            BootError::LoadError => write!(f, "load error"),
            BootError::OutOfResources => write!(f, "out of resources"),
            BootError::DeviceError => write!(f, "device error"),
            BootError::Unsupported => write!(f, "unsupported"),
            BootError::NoEntry => write!(f, "no entry"),
            BootError::ConfigLoadFailed => write!(f, "config load failed"),
            BootError::Timeout => write!(f, "timeout"),
            BootError::NotImplemented => write!(f, "not implemented"),
        }
    }
}

impl std::error::Error for BootError {}

// ── Data structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct BootEntry {
    pub loader_type: LoaderType,
    pub id: String,
    pub title: Option<String>,
    pub version: Option<String>,
    pub machine_id: Option<String>,
    pub efi: Option<String>,
    pub linux: Option<String>,
    pub initrd: Vec<String>,
    pub options: Vec<String>,
    pub devicetree: Option<String>,
    pub architecture: Option<String>,
}

impl BootEntry {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            ..Default::default()
        }
    }
}

// ── Config timeout parsing ────────────────────────────────────────────────

pub fn config_timeout_sec_from_string(s: &str) -> Result<u64, BootError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(BootError::InvalidParameter);
    }

    let timeout: u64 = s.parse().map_err(|_| BootError::InvalidParameter)?;

    if timeout > u32::MAX as u64 {
        return Err(BootError::InvalidParameter);
    }

    Ok(timeout)
}

// ── Entry comparison ──────────────────────────────────────────────────────

pub fn boot_entry_compare(a: &BootEntry, b: &BootEntry) -> std::cmp::Ordering {
    let a_title = a.title.as_deref().unwrap_or(&a.id);
    let b_title = b.title.as_deref().unwrap_or(&b.id);

    match a_title.cmp(b_title) {
        std::cmp::Ordering::Equal => a.id.cmp(&b.id),
        other => other,
    }
}

// ── Type 1 filename validation ────────────────────────────────────────────

pub fn valid_type1_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_TYPE1_FILENAME_LEN {
        return false;
    }
    if name.starts_with('.') {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii()) {
        return false;
    }

    let lower = name.to_ascii_lowercase();
    lower.ends_with(".conf") || lower.ends_with(".loader")
}

// ── Entry uniqueness ──────────────────────────────────────────────────────

pub fn entries_unique(entries: &[BootEntry]) -> bool {
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            if entries[i].id == entries[j].id {
                return false;
            }
        }
    }
    true
}

// ── Entry lookup ──────────────────────────────────────────────────────────

pub fn entry_lookup_key(entries: &[BootEntry], id: &str) -> Option<usize> {
    entries.iter().position(|e| e.id == id)
}

// ── Boot entry tries parsing ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootTries {
    pub tries_left: u32,
    pub tries_done: u32,
}

pub fn boot_entry_parse_tries(id: &str) -> Option<BootTries> {
    let mut parts: Vec<&str> = id.rsplitn(2, '+').collect();
    parts.reverse();

    if parts.len() != 2 {
        return None;
    }

    let tries_done: u32 = parts[1].parse().ok()?;
    let mut left_parts: Vec<&str> = parts[0].rsplitn(2, '-').collect();
    left_parts.reverse();

    if left_parts.len() != 2 {
        return None;
    }

    let tries_left: u32 = left_parts[1].parse().ok()?;
    Some(BootTries {
        tries_left,
        tries_done,
    })
}

// ── sd-boot detection ─────────────────────────────────────────────────────

pub fn is_sd_boot(loader_info: &str) -> bool {
    loader_info.starts_with("systemd-boot") || loader_info.starts_with("sd-boot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reboot_on_error_from_str() {
        assert_eq!(RebootOnError::from_str("no"), Some(RebootOnError::No));
        assert_eq!(RebootOnError::from_str("yes"), Some(RebootOnError::Yes));
        assert_eq!(RebootOnError::from_str("auto"), Some(RebootOnError::Auto));
        assert_eq!(RebootOnError::from_str("maybe"), None);
    }

    #[test]
    fn test_reboot_on_error_to_str() {
        assert_eq!(RebootOnError::No.to_str(), "no");
        assert_eq!(RebootOnError::Yes.to_str(), "yes");
        assert_eq!(RebootOnError::Auto.to_str(), "auto");
    }

    #[test]
    fn test_loader_type_allow_editor() {
        assert!(loader_type_allow_editor(LoaderType::Efi));
        assert!(loader_type_allow_editor(LoaderType::Linux));
        assert!(!loader_type_allow_editor(LoaderType::Auto));
        assert!(!loader_type_allow_editor(LoaderType::SecureBootKeys));
    }

    #[test]
    fn test_loader_type_allow_editor_in_sb() {
        assert!(loader_type_allow_editor_in_sb(LoaderType::Efi));
        assert!(loader_type_allow_editor_in_sb(LoaderType::Linux));
        assert!(!loader_type_allow_editor_in_sb(LoaderType::Uki));
    }

    #[test]
    fn test_loader_type_may_auto_select() {
        assert!(loader_type_may_auto_select(LoaderType::Type2Uki));
        assert!(!loader_type_may_auto_select(LoaderType::SecureBootKeys));
    }

    #[test]
    fn test_loader_type_bump_counters() {
        assert!(loader_type_bump_counters(LoaderType::Linux));
        assert!(loader_type_bump_counters(LoaderType::Uki));
        assert!(!loader_type_bump_counters(LoaderType::Efi));
    }

    #[test]
    fn test_config_timeout_valid() {
        assert_eq!(config_timeout_sec_from_string("10"), Ok(10));
        assert_eq!(config_timeout_sec_from_string("0"), Ok(0));
        assert_eq!(config_timeout_sec_from_string("  30  "), Ok(30));
    }

    #[test]
    fn test_config_timeout_invalid() {
        assert!(config_timeout_sec_from_string("").is_err());
        assert!(config_timeout_sec_from_string("abc").is_err());
        assert!(config_timeout_sec_from_string("-1").is_err());
    }

    #[test]
    fn test_valid_type1_filename() {
        assert!(valid_type1_filename("test.conf"));
        assert!(valid_type1_filename("my-entry.loader"));
        assert!(!valid_type1_filename(".hidden.conf"));
        assert!(!valid_type1_filename(""));
        assert!(!valid_type1_filename("no_extension"));
    }

    #[test]
    fn test_boot_entry_compare() {
        let a = BootEntry {
            id: "a".into(),
            title: Some("Alpha".into()),
            ..Default::default()
        };
        let b = BootEntry {
            id: "b".into(),
            title: Some("Beta".into()),
            ..Default::default()
        };
        assert_eq!(boot_entry_compare(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_entries_unique() {
        let entries = vec![BootEntry::new("entry1"), BootEntry::new("entry2")];
        assert!(entries_unique(&entries));

        let dupes = vec![BootEntry::new("entry1"), BootEntry::new("entry1")];
        assert!(!entries_unique(&dupes));
    }

    #[test]
    fn test_entry_lookup_key() {
        let entries = vec![BootEntry::new("a"), BootEntry::new("b")];
        assert_eq!(entry_lookup_key(&entries, "a"), Some(0));
        assert_eq!(entry_lookup_key(&entries, "b"), Some(1));
        assert_eq!(entry_lookup_key(&entries, "c"), None);
    }

    #[test]
    fn test_is_sd_boot() {
        assert!(is_sd_boot("systemd-boot 256"));
        assert!(is_sd_boot("sd-boot"));
        assert!(!is_sd_boot("GRUB"));
        assert!(!is_sd_boot("Windows Boot Manager"));
    }

    #[test]
    fn test_boot_entry_parse_tries() {
        let result = boot_entry_parse_tries("kernel-3+2");
        assert_eq!(
            result,
            Some(BootTries {
                tries_left: 3,
                tries_done: 2
            })
        );
    }

    #[test]
    fn test_boot_entry_parse_tries_no_plus() {
        assert_eq!(boot_entry_parse_tries("kernel"), None);
        assert_eq!(boot_entry_parse_tries("kernel+"), None);
    }
}
