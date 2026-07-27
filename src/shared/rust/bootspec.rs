// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bootspec.c, src/shared/bootspec.h
//
// Boot Loader Specification parsing and management.
//
// Implements parsing of Type #1 (.conf) and Type #2 (.efi UKI) boot entries,
// boot configuration loading, default/selected entry selection, entry
// comparison/sorting, uniquification of display titles, and loader.conf
// parsing. Also handles try-count extraction from filenames (e.g.
// `linux+3-2.efi` → 3 tries left, 2 done).

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value indicating "not set" for tries/profile counters.
pub const TRIES_NOT_SET: u32 = u32::MAX;

/// Maximum number of unified kernel profiles per PE image.
pub const UNIFIED_PROFILES_MAX: u32 = 16;

/// Standard boot entry search directories relative to partition root.
pub const LOADER_ENTRIES_DIR: &str = "/loader/entries";
pub const EFI_LINUX_DIR: &str = "/EFI/Linux/";
pub const LOADER_ADDONS_DIR: &str = "/loader/addons/";
pub const LOADER_CONF_PATH: &str = "/loader/loader.conf";

/// Known loader.conf keys that are valid but not parsed in userspace.
const LOADER_CONF_SKIP_KEYS: &[&str] = &[
    "timeout",
    "editor",
    "auto-entries",
    "auto-firmware",
    "auto-poweroff",
    "auto-reboot",
    "beep",
    "reboot-for-bitlocker",
    "reboot-on-error",
    "secure-boot-enroll",
    "secure-boot-enroll-action",
    "secure-boot-enroll-timeout-sec",
    "console-mode",
    "log-level",
];

/// Pretty-print names for well-known automatic boot entries.
const AUTO_ENTRY_TITLES: &[(&str, &str)] = &[
    ("auto-osx", "macOS"),
    ("auto-windows", "Windows Boot Manager"),
    ("auto-efi-shell", "EFI Shell"),
    ("auto-efi-default", "EFI Default Loader"),
    ("auto-poweroff", "Power Off The System"),
    ("auto-reboot", "Reboot The System"),
    (
        "auto-reboot-to-firmware-setup",
        "Reboot Into Firmware Interface",
    ),
];

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by bootspec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootspecError {
    /// Invalid argument or malformed input.
    InvalidInput(String),
    /// I/O error with context.
    Io(String),
    /// Entry not found.
    NotFound(String),
    /// Memory allocation failure (OOM).
    OutOfMemory,
    /// Parse error in boot entry or loader.conf.
    ParseError {
        path: String,
        line: u32,
        message: String,
    },
}

impl std::fmt::Display for BootspecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootspecError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            BootspecError::Io(msg) => write!(f, "I/O error: {msg}"),
            BootspecError::NotFound(msg) => write!(f, "Not found: {msg}"),
            BootspecError::OutOfMemory => write!(f, "Out of memory"),
            BootspecError::ParseError {
                path,
                line,
                message,
            } => write!(f, "Parse error at {path}:{line}: {message}"),
        }
    }
}

impl std::error::Error for BootspecError {}

/// Result alias for bootspec operations.
pub type BootResult<T> = Result<T, BootspecError>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Boot entry types as defined by the Boot Loader Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootEntryType {
    /// Type #1: *.conf text files describing kernel/initrd/options.
    Type1,
    /// Type #2: *.efi Unified Kernel Image (UKI) files.
    Type2,
    /// Entry reported by the boot loader via LoaderEntries EFI variable.
    Loader,
    /// Automatically discovered entry (prefixed with "auto-").
    Auto,
}

impl BootEntryType {
    /// Short identifier string for the entry type.
    pub fn as_str(self) -> &'static str {
        match self {
            BootEntryType::Type1 => "type1",
            BootEntryType::Type2 => "type2",
            BootEntryType::Loader => "loader",
            BootEntryType::Auto => "auto",
        }
    }

    /// Human-readable description of the entry type.
    pub fn description(self) -> &'static str {
        match self {
            BootEntryType::Type1 => "Boot Loader Specification Type #1 (.conf)",
            BootEntryType::Type2 => "Boot Loader Specification Type #2 (UKI, .efi)",
            BootEntryType::Loader => "Reported by Boot Loader",
            BootEntryType::Auto => "Automatic",
        }
    }

    /// Parse from a short identifier string (case-insensitive).
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "type1" => Some(BootEntryType::Type1),
            "type2" => Some(BootEntryType::Type2),
            "loader" => Some(BootEntryType::Loader),
            "auto" => Some(BootEntryType::Auto),
            _ => None,
        }
    }
}

/// Where a boot entry was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootEntrySource {
    /// EFI System Partition.
    Esp,
    /// Extended Boot Loader Partition.
    Xbootldr,
}

impl BootEntrySource {
    /// Short identifier string.
    pub fn as_str(self) -> &'static str {
        match self {
            BootEntrySource::Esp => "esp",
            BootEntrySource::Xbootldr => "xbootldr",
        }
    }

    /// Human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            BootEntrySource::Esp => "EFI System Partition",
            BootEntrySource::Xbootldr => "Extended Boot Loader Partition",
        }
    }

    /// Parse from a short identifier string.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "esp" => Some(BootEntrySource::Esp),
            "xbootldr" => Some(BootEntrySource::Xbootldr),
            _ => None,
        }
    }
}

// ── Data Structures ──────────────────────────────────────────────────────

/// A boot entry addon (`.addon.efi` file providing extra cmdline options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEntryAddon {
    /// Path to the addon file.
    pub location: PathBuf,
    /// Extra kernel command line options contributed by this addon.
    pub cmdline: String,
}

/// Collection of boot entry addons.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootEntryAddons {
    /// Individual addon entries.
    pub items: Vec<BootEntryAddon>,
}

/// A single boot entry (Type #1, Type #2, Loader, or Auto).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEntry {
    /// The type of this boot entry.
    pub entry_type: BootEntryType,
    /// Where this entry was discovered.
    pub source: BootEntrySource,
    /// Whether this entry was reported by the boot loader.
    pub reported_by_loader: bool,

    /// File basename including extension (e.g. "fedora.conf").
    pub id: String,
    /// Old-style ID without `.conf` suffix, for deduplication.
    pub id_old: Option<String>,
    /// ID without profile suffix (e.g. "linux" from "linux@debug").
    pub id_without_profile: Option<String>,
    /// Full path to the drop-in config file or EFI binary.
    pub path: Option<PathBuf>,
    /// Root path under which kernel/initrd/etc. are found.
    pub root: Option<String>,

    /// Human-readable title shown in boot menu.
    pub title: Option<String>,
    /// Display title after uniquification (may include version/machine-id).
    pub show_title: Option<String>,
    /// Sort key for ordering entries.
    pub sort_key: Option<String>,
    /// Version string from os-release or entry file.
    pub version: Option<String>,
    /// Machine ID associated with this entry.
    pub machine_id: Option<String>,
    /// Architecture string.
    pub architecture: Option<String>,

    /// Kernel command line options (from `options` field or UKI .cmdline).
    pub options: Vec<String>,
    /// Addons local to this entry's `.extra.d` directory.
    pub local_addons: BootEntryAddons,

    /// Path to the linux kernel image (Type #1 only).
    pub kernel: Option<String>,
    /// Path to an EFI binary (Type #1 only).
    pub efi: Option<String>,
    /// Path to a UKI (Type #1 only, when overriding).
    pub uki: Option<String>,
    /// URL for remote UKI.
    pub uki_url: Option<String>,
    /// Initrd paths.
    pub initrd: Vec<String>,
    /// Device tree path.
    pub device_tree: Option<String>,
    /// Device tree overlay paths.
    pub device_tree_overlay: Vec<String>,

    /// Number of boot tries remaining (TRIES_NOT_SET if not applicable).
    pub tries_left: u32,
    /// Number of boot tries completed.
    pub tries_done: u32,
    /// Profile index for unified kernel images.
    pub profile: u32,
}

impl BootEntry {
    /// Create a new boot entry with default values.
    pub fn new(entry_type: BootEntryType, source: BootEntrySource) -> Self {
        Self {
            entry_type,
            source,
            reported_by_loader: false,
            id: String::new(),
            id_old: None,
            id_without_profile: None,
            path: None,
            root: None,
            title: None,
            show_title: None,
            sort_key: None,
            version: None,
            machine_id: None,
            architecture: None,
            options: Vec::new(),
            local_addons: BootEntryAddons::default(),
            kernel: None,
            efi: None,
            uki: None,
            uki_url: None,
            initrd: Vec::new(),
            device_tree: None,
            device_tree_overlay: Vec::new(),
            tries_left: TRIES_NOT_SET,
            tries_done: TRIES_NOT_SET,
            profile: TRIES_NOT_SET,
        }
    }

    /// Get the display title: show_title → title → id.
    pub fn display_title(&self) -> &str {
        self.show_title
            .as_deref()
            .or(self.title.as_deref())
            .or_else(|| {
                if self.id.is_empty() {
                    None
                } else {
                    Some(self.id.as_str())
                }
            })
            .unwrap_or("(unnamed)")
    }
}

/// Complete boot configuration holding all discovered entries and settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootConfig {
    /// Whether loader.conf was loaded.
    pub loader_conf_status: Option<Result<(), BootspecError>>,

    /// Pattern for selecting preferred boot entry (from loader.conf).
    pub preferred_pattern: Option<String>,
    /// Pattern for selecting default boot entry (from loader.conf).
    pub default_pattern: Option<String>,

    /// LoaderEntryOneShot EFI variable value.
    pub entry_oneshot: Option<String>,
    /// LoaderEntryPreferred EFI variable value.
    pub entry_preferred: Option<String>,
    /// LoaderEntryDefault EFI variable value.
    pub entry_default: Option<String>,
    /// LoaderEntrySelected EFI variable value.
    pub entry_selected: Option<String>,
    /// LoaderEntrySysFail EFI variable value.
    pub entry_sysfail: Option<String>,

    /// All discovered boot entries.
    pub entries: Vec<BootEntry>,

    /// Global addons per source (index 0 = ESP, 1 = XBOOTLDR).
    pub global_addons: [BootEntryAddons; 2],

    /// Index of the default entry (-1 if none).
    pub default_entry: isize,
    /// Index of the selected entry (-1 if none).
    pub selected_entry: isize,
}

// ── Path Utilities ───────────────────────────────────────────────────────

/// Normalize a path relative to "/": prepend "/" if not absolute, simplify,
/// reject trailing slashes and ".." or "." components.
pub fn mangle_path(field: &str, p: &str) -> BootResult<String> {
    let normalized = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };

    if normalized.ends_with('/') {
        return Ok(String::new()); // Signal to ignore
    }

    let simplified = Path::new(&normalized);
    let components: Vec<_> = simplified.components().collect();

    // Reject any "." or ".." components
    for comp in &components {
        match comp {
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Ok(String::new()); // Signal to ignore
            }
            _ => {}
        }
    }

    // Rebuild clean path
    let mut result = String::from("/");
    let mut first = true;
    for comp in &components {
        if let std::path::Component::Normal(s) = comp {
            if !first {
                result.push('/');
            }
            result.push_str(&s.to_string_lossy());
            first = false;
        }
    }

    Ok(result)
}

/// Parse a single path value and return the normalized path, or None if the
/// path should be ignored (trailing slash, not normalized).
pub fn parse_path_one(field: &str, p: &str) -> BootResult<Option<String>> {
    let c = mangle_path(field, p)?;
    if c.is_empty() {
        Ok(None)
    } else {
        Ok(Some(c))
    }
}

/// Parse multiple whitespace-separated paths and return all valid normalized paths.
pub fn parse_path_many(field: &str, p: &str) -> BootResult<Vec<String>> {
    let mut result = Vec::new();
    for token in p.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        let c = mangle_path(field, token)?;
        if !c.is_empty() {
            result.push(c);
        }
    }
    Ok(result)
}

// ── Filename Try-Count Extraction ────────────────────────────────────────

/// Result of extracting try-count information from a boot entry filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriesInfo {
    /// Filename with the `+N-M` suffix removed.
    pub stripped: String,
    /// Number of tries remaining (TRIES_NOT_SET if no info in filename).
    pub tries_left: u32,
    /// Number of tries completed.
    pub tries_done: u32,
}

/// Extract try-count information from a boot entry filename.
///
/// Parses the `+N-M` pattern before the file extension. For example,
/// `linux+3-2.efi` yields `stripped="linux.efi"`, `tries_left=3`, `tries_done=2`.
/// If no pattern is found, returns the original filename with `TRIES_NOT_SET` values.
pub fn boot_filename_extract_tries(fname: &str) -> TriesInfo {
    // Find the last dot (suffix separator)
    let suffix_pos = match fname.rfind('.') {
        Some(pos) => pos,
        None => {
            return TriesInfo {
                stripped: fname.to_owned(),
                tries_left: TRIES_NOT_SET,
                tries_done: TRIES_NOT_SET,
            }
        }
    };

    let base = &fname[..suffix_pos];
    let ext = &fname[suffix_pos..];

    // Find the last '+' before the suffix
    let plus_pos = match base.rfind('+') {
        Some(pos) => pos,
        None => {
            return TriesInfo {
                stripped: fname.to_owned(),
                tries_left: TRIES_NOT_SET,
                tries_done: TRIES_NOT_SET,
            }
        }
    };

    let after_plus = &base[plus_pos + 1..];

    // Parse tries_left: leading digits
    let digits_end = after_plus
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_plus.len());
    if digits_end == 0 {
        return TriesInfo {
            stripped: fname.to_owned(),
            tries_left: TRIES_NOT_SET,
            tries_done: TRIES_NOT_SET,
        };
    }

    let left_str = &after_plus[..digits_end];
    let tries_left: u32 = match left_str.parse() {
        Ok(v) if v <= i32::MAX as u32 => v,
        _ => {
            return TriesInfo {
                stripped: fname.to_owned(),
                tries_left: TRIES_NOT_SET,
                tries_done: TRIES_NOT_SET,
            }
        }
    };

    let rest = &after_plus[digits_end..];

    // Parse optional tries_done after '-'
    let (tries_done, remaining) = if rest.starts_with('-') {
        let after_dash = &rest[1..];
        let done_digits_end = after_dash
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_dash.len());
        if done_digits_end == 0 {
            return TriesInfo {
                stripped: fname.to_owned(),
                tries_left: TRIES_NOT_SET,
                tries_done: TRIES_NOT_SET,
            };
        }
        let done_str = &after_dash[..done_digits_end];
        match done_str.parse::<u32>() {
            Ok(v) if v <= i32::MAX as u32 => (v, &after_dash[done_digits_end..]),
            _ => {
                return TriesInfo {
                    stripped: fname.to_owned(),
                    tries_left: TRIES_NOT_SET,
                    tries_done: TRIES_NOT_SET,
                }
            }
        }
    } else {
        (TRIES_NOT_SET, rest)
    };

    // Remaining must be empty (right up to the suffix)
    if !remaining.is_empty() {
        return TriesInfo {
            stripped: fname.to_owned(),
            tries_left: TRIES_NOT_SET,
            tries_done: TRIES_NOT_SET,
        };
    }

    // Both tries_left and tries_done must be present for a valid extraction
    if tries_done == TRIES_NOT_SET {
        return TriesInfo {
            stripped: fname.to_owned(),
            tries_left: TRIES_NOT_SET,
            tries_done: TRIES_NOT_SET,
        };
    }

    TriesInfo {
        stripped: format!("{}{}", &fname[..plus_pos], ext),
        tries_left,
        tries_done,
    }
}

// ── Loader Entry Name Validation ─────────────────────────────────────────

/// Check if a loader entry name is valid.
///
/// Valid names: non-empty, no NUL bytes, no path separators, no ".." components.
pub fn efi_loader_entry_name_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.contains('\0') {
        return false;
    }
    if name.contains('/') || name.contains('\\') {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    if name.starts_with('.') {
        return false;
    }
    true
}

// ── Type #1 Entry Parsing ────────────────────────────────────────────────

/// A parsed key-value pair from a boot entry config line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLine {
    pub field: String,
    pub value: String,
}

/// Parse a single line from a Type #1 boot entry config file.
/// Returns None for comments, blank lines, or lines with no field.
pub fn parse_config_line(line: &str) -> Option<ConfigLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());
    let field = parts.next()?.to_owned();
    let value = parts.next()?.trim().to_owned();

    if field.is_empty() {
        return None;
    }

    Some(ConfigLine { field, value })
}

/// Parse a Type #1 boot entry from config line data.
///
/// Takes the filename, root path, and parsed config lines, and produces a
/// fully populated `BootEntry`.
pub fn boot_entry_load_type1(
    filename: &str,
    root: &str,
    source: BootEntrySource,
    dir: &str,
    lines: &[&str],
) -> BootResult<BootEntry> {
    let tries_info = boot_filename_extract_tries(filename);
    let id = tries_info.stripped;

    if !efi_loader_entry_name_valid(&id) {
        return Err(BootspecError::InvalidInput(format!(
            "Invalid loader entry name: {filename}"
        )));
    }

    if !id.to_ascii_lowercase().ends_with(".conf") {
        return Err(BootspecError::InvalidInput(format!(
            "Invalid loader entry file suffix: {filename}"
        )));
    }

    let id_old = Some(id[..id.len() - 5].to_owned()); // strip .conf
    let path = PathBuf::from(dir).join(filename);

    let mut entry = BootEntry::new(BootEntryType::Type1, source);
    entry.id = id;
    entry.id_old = id_old;
    entry.path = Some(path);
    entry.root = Some(root.to_owned());
    entry.tries_left = tries_info.tries_left;
    entry.tries_done = tries_info.tries_done;

    for _line_num in 0..lines.len() {
        let config = match parse_config_line(lines[_line_num]) {
            Some(c) => c,
            None => continue,
        };

        match config.field.as_str() {
            "title" => entry.title = Some(config.value),
            "sort-key" => entry.sort_key = Some(config.value),
            "version" => entry.version = Some(config.value),
            "machine-id" => entry.machine_id = Some(config.value),
            "architecture" => entry.architecture = Some(config.value),
            "options" => {
                if !config.value.is_empty() {
                    entry.options.push(config.value);
                }
            }
            "linux" => {
                if let Some(p) = parse_path_one("linux", &config.value)? {
                    entry.kernel = Some(p);
                }
            }
            "efi" => {
                if let Some(p) = parse_path_one("efi", &config.value)? {
                    entry.efi = Some(p);
                }
            }
            "uki" => {
                if let Some(p) = parse_path_one("uki", &config.value)? {
                    entry.uki = Some(p);
                }
            }
            "uki-url" => entry.uki_url = Some(config.value),
            "profile" => {
                if let Ok(p) = config.value.parse::<u32>() {
                    entry.profile = p;
                }
            }
            "initrd" => {
                if let Ok(paths) = parse_path_many("initrd", &config.value) {
                    entry.initrd.extend(paths);
                }
            }
            "devicetree" => {
                if let Some(p) = parse_path_one("devicetree", &config.value)? {
                    entry.device_tree = Some(p);
                }
            }
            "devicetree-overlay" => {
                if let Ok(paths) = parse_path_many("devicetree-overlay", &config.value) {
                    entry.device_tree_overlay.extend(paths);
                }
            }
            _ => {} // Unknown field, silently ignore
        }
    }

    Ok(entry)
}

// ── Loader.conf Parsing ─────────────────────────────────────────────────

/// Parse a loader.conf file and update the boot configuration.
///
/// Recognized keys: `default`, `preferred`, plus several keys that are valid
/// but ignored in userspace (timeout, editor, etc.).
pub fn boot_loader_read_conf(config: &mut BootConfig, lines: &[&str]) -> BootResult<()> {
    for raw_line in lines {
        let config_line = match parse_config_line(raw_line) {
            Some(c) => c,
            None => continue,
        };

        if config_line.value.is_empty() {
            continue;
        }

        match config_line.field.as_str() {
            "default" => config.default_pattern = Some(config_line.value),
            "preferred" => config.preferred_pattern = Some(config_line.value),
            key if LOADER_CONF_SKIP_KEYS.contains(&key) => {
                // Valid key, not parsed in userspace
            }
            _ => {
                // Unknown key, ignore
            }
        }
    }

    Ok(())
}

// ── Entry Comparison ─────────────────────────────────────────────────────

/// Compare two boot entries for sorting.
///
/// This mimics the ordering used by sd-boot:
/// 1. Entries with tries_left == 0 are sorted last
/// 2. Entries with sort_key come before those without
/// 3. Within sort_key groups: sort_key → machine_id → version (descending)
/// 4. Then by id (descending version comparison)
/// 5. Within same id+profile: tries_left (ascending), tries_done (ascending)
pub fn boot_entry_compare(a: &BootEntry, b: &BootEntry) -> Ordering {
    // Entries with no tries left go last
    let a_exhausted = a.tries_left == 0;
    let b_exhausted = b.tries_left == 0;
    match a_exhausted.cmp(&b_exhausted) {
        Ordering::Equal => {}
        other => return other,
    }

    // Entries with sort_key come first
    let a_has_key = a.sort_key.is_some();
    let b_has_key = b.sort_key.is_some();
    match a_has_key.cmp(&b_has_key) {
        Ordering::Equal => {}
        other => return other,
    }

    // If both have sort keys, compare by sort_key, then machine_id, then version (desc)
    if a_has_key && b_has_key {
        match version_cmp(a.sort_key.as_deref(), b.sort_key.as_deref()) {
            Ordering::Equal => {}
            other => return other,
        }
        match a.machine_id.cmp(&b.machine_id) {
            Ordering::Equal => {}
            other => return other,
        }
        // Version comparison is inverted (newer = higher priority)
        match version_cmp(a.version.as_deref(), b.version.as_deref()) {
            Ordering::Equal => {}
            other => return other.reverse(),
        }
    }

    // Compare by id (version comparison)
    let a_id = a.id_without_profile.as_deref().unwrap_or(&a.id);
    let b_id = b.id_without_profile.as_deref().unwrap_or(&b.id);
    match version_cmp(Some(a_id), Some(b_id)) {
        Ordering::Equal => {}
        other => return other,
    }

    // If same id and both have profile, compare by profile
    if a.id_without_profile.is_some() && b.id_without_profile.is_some() {
        match a.profile.cmp(&b.profile) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    // Compare tries (entries with tries info come first, ascending)
    if a.tries_left != TRIES_NOT_SET || b.tries_left != TRIES_NOT_SET {
        if a.tries_left == TRIES_NOT_SET {
            return Ordering::Greater;
        }
        if b.tries_left == TRIES_NOT_SET {
            return Ordering::Less;
        }
        match a.tries_left.cmp(&b.tries_left) {
            Ordering::Equal => {}
            other => return other.reverse(),
        }
        return b.tries_done.cmp(&a.tries_done);
    }

    Ordering::Equal
}

/// Simple version-string comparison (strverscmp-like).
///
/// Compares version strings by treating runs of digits numerically
/// (longer digit runs are larger), then character-by-character for
/// non-digit portions.
pub fn version_cmp(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a_val), Some(b_val)) => strverscmp(a_val, b_val),
    }
}

/// Version string comparison function.
///
/// Implements strverscmp-like ordering: digit sequences are compared
/// numerically (not lexicographically), longer digit sequences are
/// considered larger versions.
pub fn strverscmp(a: &str, b: &str) -> Ordering {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut ai = 0usize;
    let mut bi = 0usize;

    loop {
        // Skip leading zeros
        while ai < a_chars.len() && a_chars[ai] == '0' {
            ai += 1;
        }
        while bi < b_chars.len() && b_chars[bi] == '0' {
            bi += 1;
        }

        // Count consecutive digits
        let mut a_digits = 0usize;
        while ai + a_digits < a_chars.len() && a_chars[ai + a_digits].is_ascii_digit() {
            a_digits += 1;
        }
        let mut b_digits = 0usize;
        while bi + b_digits < b_chars.len() && b_chars[bi + b_digits].is_ascii_digit() {
            b_digits += 1;
        }

        // More digits = larger version
        match a_digits.cmp(&b_digits) {
            Ordering::Equal => {}
            other => return other,
        }

        // Compare digit by digit
        for j in 0..a_digits {
            let a_d = a_chars[ai + j];
            let b_d = if bi + j < b_chars.len() {
                b_chars[bi + j]
            } else {
                return Ordering::Greater;
            };
            match a_d.cmp(&b_d) {
                Ordering::Equal => {}
                other => return other,
            }
        }

        ai += a_digits;
        bi += b_digits;

        // End of either string
        if ai >= a_chars.len() && bi >= b_chars.len() {
            return Ordering::Equal;
        }
        if ai >= a_chars.len() {
            return Ordering::Less;
        }
        if bi >= b_chars.len() {
            return Ordering::Greater;
        }

        // Compare non-digit characters
        match a_chars[ai].cmp(&b_chars[bi]) {
            Ordering::Equal => {
                ai += 1;
                bi += 1;
            }
            other => return other,
        }
    }
}

// ── Title Uniquification ─────────────────────────────────────────────────

/// Make boot entry display titles unique by appending disambiguators.
///
/// Three rounds of uniquification are attempted:
/// 1. Append version to non-unique titles
/// 2. Append machine-id to still-non-unique titles
/// 3. Append filename to still-non-unique titles
pub fn boot_entries_uniquify(entries: &mut [BootEntry]) -> BootResult<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut nonunique = vec![false; entries.len()];

    // Round 1: Find non-unique titles
    if !find_nonunique(entries, &mut nonunique) {
        return Ok(());
    }

    // Append version
    for (i, entry) in entries.iter_mut().enumerate() {
        if nonunique[i] {
            if let Some(ref ver) = entry.version {
                entry.show_title = Some(format!("{} ({ver})", entry.display_title()));
            }
        }
    }

    if !find_nonunique(entries, &mut nonunique) {
        return Ok(());
    }

    // Append machine-id
    for (i, entry) in entries.iter_mut().enumerate() {
        if nonunique[i] {
            if let Some(ref mid) = entry.machine_id {
                entry.show_title = Some(format!("{} ({mid})", entry.display_title()));
            }
        }
    }

    if !find_nonunique(entries, &mut nonunique) {
        return Ok(());
    }

    // Append filename as last resort
    for (i, entry) in entries.iter_mut().enumerate() {
        if nonunique[i] {
            entry.show_title = Some(format!("{} ({})", entry.display_title(), entry.id));
        }
    }

    Ok(())
}

/// Find all entries with non-unique display titles.
/// Returns true if any non-unique titles exist, updating `arr` in place.
fn find_nonunique(entries: &[BootEntry], arr: &mut [bool]) -> bool {
    for v in arr.iter_mut() {
        *v = false;
    }

    let mut any = false;
    for i in 0..entries.len() {
        for j in 0..entries.len() {
            if i != j && entries[i].display_title() == entries[j].display_title() {
                arr[i] = true;
                arr[j] = true;
                any = true;
            }
        }
    }

    any
}

// ── Entry Lookup ─────────────────────────────────────────────────────────

/// Find a boot entry by ID (case-insensitive exact match or fnmatch glob).
///
/// If `id` is "@saved", looks up `config.entry_selected` instead.
pub fn boot_config_find(config: &BootConfig, id: &str) -> Option<usize> {
    let effective_id = if id == "@saved" {
        config.entry_selected.as_deref()?
    } else {
        id
    };

    for (i, entry) in config.entries.iter().enumerate() {
        if pattern_matches(effective_id, &entry.id) {
            return Some(i);
        }
        if let Some(ref old) = entry.id_old {
            if effective_id.eq_ignore_ascii_case(old) {
                return Some(i);
            }
        }
    }

    None
}

/// Find a boot entry by exact ID match (case-insensitive, no globbing).
pub fn boot_config_find_entry(config: &BootConfig, id: &str) -> Option<usize> {
    for (i, entry) in config.entries.iter().enumerate() {
        if entry.id.eq_ignore_ascii_case(id) {
            return Some(i);
        }
        if let Some(ref old) = entry.id_old {
            if old.eq_ignore_ascii_case(id) {
                return Some(i);
            }
        }
    }
    None
}

/// Simple glob matching for boot entry IDs (case-insensitive).
/// Supports `*` (match anything) and `?` (match single char).
pub fn pattern_matches(pattern: &str, text: &str) -> bool {
    glob_match_impl(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
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
                c => {
                    if c == '?' || c.eq_ignore_ascii_case(&string[si]) {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
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

// ── Default / Selected Entry Selection ───────────────────────────────────

/// Select the default boot entry.
///
/// Priority order:
/// 1. LoaderEntryOneShot
/// 2. LoaderEntryPreferred
/// 3. LoaderEntryDefault
/// 4. preferred pattern from loader.conf
/// 5. default pattern from loader.conf
/// 6. First entry
pub fn boot_entries_select_default(config: &BootConfig) -> isize {
    if config.entries.is_empty() {
        return -1;
    }

    if let Some(ref oneshot) = config.entry_oneshot {
        if let Some(idx) = boot_config_find(config, oneshot) {
            return idx as isize;
        }
    }

    if let Some(ref preferred) = config.entry_preferred {
        if let Some(idx) = boot_config_find(config, preferred) {
            return idx as isize;
        }
    }

    if let Some(ref default) = config.entry_default {
        if let Some(idx) = boot_config_find(config, default) {
            return idx as isize;
        }
    }

    if let Some(ref pattern) = config.preferred_pattern {
        if let Some(idx) = boot_config_find(config, pattern) {
            return idx as isize;
        }
    }

    if let Some(ref pattern) = config.default_pattern {
        if let Some(idx) = boot_config_find(config, pattern) {
            return idx as isize;
        }
    }

    0
}

/// Select the entry indicated by LoaderEntrySelected.
pub fn boot_entries_select_selected(config: &BootConfig) -> isize {
    if config.entries.is_empty() {
        return -1;
    }

    match &config.entry_selected {
        Some(sel) => boot_config_find(config, sel)
            .map(|i| i as isize)
            .unwrap_or(-1),
        None => -1,
    }
}

/// Finalize the boot configuration: sort entries and uniquify titles.
pub fn boot_config_finalize(config: &mut BootConfig) -> BootResult<()> {
    config.entries.sort_by(boot_entry_compare);
    boot_entries_uniquify(&mut config.entries)?;
    Ok(())
}

/// Select special entries (default, selected) based on EFI variables.
pub fn boot_config_select_special_entries(config: &mut BootConfig) -> BootResult<()> {
    config.default_entry = boot_entries_select_default(config);
    config.selected_entry = boot_entries_select_selected(config);
    Ok(())
}

// ── Augment from Loader ──────────────────────────────────────────────────

/// Augment boot config with entries reported by the boot loader.
///
/// Adds entries from `found_by_loader` that are not already in the config.
/// If `auto_only` is true, only "auto-*" entries are added.
pub fn boot_config_augment_from_loader(
    config: &mut BootConfig,
    found_by_loader: &[&str],
    auto_only: bool,
) -> BootResult<()> {
    for id in found_by_loader {
        if let Some(idx) = boot_config_find_entry(config, id) {
            config.entries[idx].reported_by_loader = true;
            continue;
        }

        if auto_only && !id.starts_with("auto-") {
            continue;
        }

        let entry_type = if id.starts_with("auto-") {
            BootEntryType::Auto
        } else {
            BootEntryType::Loader
        };

        let title = AUTO_ENTRY_TITLES
            .iter()
            .find(|(auto_id, _)| *auto_id == *id)
            .map(|(_, title)| title.to_string());

        let mut entry = BootEntry::new(entry_type, BootEntrySource::Esp);
        entry.id = (*id).to_owned();
        entry.title = title;
        entry.reported_by_loader = true;

        config.entries.push(entry);
    }

    Ok(())
}

// ── os-release Name/Version/SortKey Selection ────────────────────────────

/// Select the best name, version, and sort key from os-release fields.
///
/// Returns owned strings. Prefers PRETTY_NAME for title, IMAGE_ID for sort
/// key, VERSION for version display.
pub fn bootspec_pick_name_version_sort_key(
    os_pretty_name: Option<&str>,
    os_image_id: Option<&str>,
    os_name: Option<&str>,
    os_id: Option<&str>,
    os_image_version: Option<&str>,
    os_version: Option<&str>,
    os_version_id: Option<&str>,
    os_build_id: Option<&str>,
) -> Option<(String, String, String)> {
    let name = os_pretty_name.or(os_name)?;

    let version = os_version
        .or(os_image_version)
        .or(os_version_id)
        .or(os_build_id)
        .unwrap_or("");

    let sort_key = os_image_id.or(os_id).unwrap_or("");

    if sort_key.is_empty() {
        return None;
    }

    Some((name.to_owned(), version.to_owned(), sort_key.to_owned()))
}

// ── Default Instance ─────────────────────────────────────────────────────

impl Default for BootConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BootConfig {
    /// Create a new empty boot configuration.
    pub fn new() -> Self {
        Self {
            loader_conf_status: None,
            preferred_pattern: None,
            default_pattern: None,
            entry_oneshot: None,
            entry_preferred: None,
            entry_default: None,
            entry_selected: None,
            entry_sysfail: None,
            entries: Vec::new(),
            global_addons: [BootEntryAddons::default(), BootEntryAddons::default()],
            default_entry: -1,
            selected_entry: -1,
        }
    }

    /// Get a reference to the default entry, if one is set.
    pub fn default_entry_ref(&self) -> Option<&BootEntry> {
        if self.default_entry >= 0 {
            self.entries.get(self.default_entry as usize)
        } else {
            None
        }
    }

    /// Get a mutable reference to the default entry, if one is set.
    pub fn default_entry_mut(&mut self) -> Option<&mut BootEntry> {
        if self.default_entry >= 0 {
            self.entries.get_mut(self.default_entry as usize)
        } else {
            None
        }
    }

    /// Get a reference to the selected entry, if one is set.
    pub fn selected_entry_ref(&self) -> Option<&BootEntry> {
        if self.selected_entry >= 0 {
            self.entries.get(self.selected_entry as usize)
        } else {
            None
        }
    }

    /// Load a Type #1 entry from config lines and add it to the config.
    pub fn load_type1_entry(
        &mut self,
        filename: &str,
        root: &str,
        source: BootEntrySource,
        dir: &str,
        lines: &[&str],
    ) -> BootResult<()> {
        let entry = boot_entry_load_type1(filename, root, source, dir, lines)?;
        self.entries.push(entry);
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_entry_type_roundtrip() {
        assert_eq!(
            BootEntryType::from_str_lossy("type1"),
            Some(BootEntryType::Type1)
        );
        assert_eq!(
            BootEntryType::from_str_lossy("Type2"),
            Some(BootEntryType::Type2)
        );
        assert_eq!(
            BootEntryType::from_str_lossy("LOADER"),
            Some(BootEntryType::Loader)
        );
        assert_eq!(
            BootEntryType::from_str_lossy("auto"),
            Some(BootEntryType::Auto)
        );
        assert_eq!(BootEntryType::from_str_lossy("invalid"), None);
        assert_eq!(BootEntryType::from_str_lossy(""), None);

        assert_eq!(BootEntryType::Type1.as_str(), "type1");
        assert_eq!(
            BootEntryType::Type2.description(),
            "Boot Loader Specification Type #2 (UKI, .efi)"
        );
    }

    #[test]
    fn test_boot_entry_source_roundtrip() {
        assert_eq!(
            BootEntrySource::from_str_lossy("esp"),
            Some(BootEntrySource::Esp)
        );
        assert_eq!(
            BootEntrySource::from_str_lossy("XBOOTLDR"),
            Some(BootEntrySource::Xbootldr)
        );
        assert_eq!(BootEntrySource::from_str_lossy("invalid"), None);

        assert_eq!(BootEntrySource::Esp.as_str(), "esp");
        assert_eq!(
            BootEntrySource::Xbootldr.description(),
            "Extended Boot Loader Partition"
        );
    }

    #[test]
    fn test_boot_filename_extract_tries_basic() {
        let info = boot_filename_extract_tries("linux+3-2.efi");
        assert_eq!(info.stripped, "linux.efi");
        assert_eq!(info.tries_left, 3);
        assert_eq!(info.tries_done, 2);
    }

    #[test]
    fn test_boot_filename_extract_tries_no_tries() {
        let info = boot_filename_extract_tries("linux.efi");
        assert_eq!(info.stripped, "linux.efi");
        assert_eq!(info.tries_left, TRIES_NOT_SET);
        assert_eq!(info.tries_done, TRIES_NOT_SET);
    }

    #[test]
    fn test_boot_filename_extract_tries_left_only() {
        let info = boot_filename_extract_tries("linux+5.conf");
        assert_eq!(info.stripped, "linux+5.conf");
        assert_eq!(info.tries_left, TRIES_NOT_SET);
        assert_eq!(info.tries_done, TRIES_NOT_SET);
    }

    #[test]
    fn test_boot_filename_extract_tries_no_extension() {
        let info = boot_filename_extract_tries("linux+3-2");
        assert_eq!(info.stripped, "linux+3-2");
        assert_eq!(info.tries_left, TRIES_NOT_SET);
        assert_eq!(info.tries_done, TRIES_NOT_SET);
    }

    #[test]
    fn test_boot_filename_extract_tries_zero() {
        let info = boot_filename_extract_tries("kernel+0-1.efi");
        assert_eq!(info.stripped, "kernel.efi");
        assert_eq!(info.tries_left, 0);
        assert_eq!(info.tries_done, 1);
    }

    #[test]
    fn test_efi_loader_entry_name_valid() {
        assert!(efi_loader_entry_name_valid("fedora.conf"));
        assert!(efi_loader_entry_name_valid("MyEntry.efi"));
        assert!(efi_loader_entry_name_valid("a"));
        assert!(!efi_loader_entry_name_valid(""));
        assert!(!efi_loader_entry_name_valid("../etc/passwd"));
        assert!(!efi_loader_entry_name_valid("foo/bar"));
        assert!(!efi_loader_entry_name_valid(".hidden"));
        assert!(!efi_loader_entry_name_valid(".."));
        assert!(!efi_loader_entry_name_valid("foo\0bar"));
    }

    #[test]
    fn test_parse_config_line() {
        assert_eq!(
            parse_config_line("title Fedora Linux"),
            Some(ConfigLine {
                field: "title".into(),
                value: "Fedora Linux".into(),
            })
        );
        assert_eq!(parse_config_line("# comment"), None);
        assert_eq!(parse_config_line(""), None);
        assert_eq!(parse_config_line("   "), None);
        assert_eq!(parse_config_line("novalue"), None);
    }

    #[test]
    fn test_boot_entry_load_type1_basic() {
        let lines = [
            "title Fedora Linux 40",
            "version 40.1",
            "machine-id 1234567890abcdef",
            "options root=/dev/sda1",
            "linux /vmlinuz",
            "initrd /initramfs",
        ];

        let entry = boot_entry_load_type1(
            "fedora.conf",
            "/boot",
            BootEntrySource::Esp,
            "/boot/loader/entries",
            &lines,
        )
        .unwrap();

        assert_eq!(entry.entry_type, BootEntryType::Type1);
        assert_eq!(entry.source, BootEntrySource::Esp);
        assert_eq!(entry.id, "fedora.conf");
        assert_eq!(entry.id_old.as_deref(), Some("fedora"));
        assert_eq!(entry.title.as_deref(), Some("Fedora Linux 40"));
        assert_eq!(entry.version.as_deref(), Some("40.1"));
        assert_eq!(entry.machine_id.as_deref(), Some("1234567890abcdef"));
        assert_eq!(entry.options, vec!["root=/dev/sda1"]);
        assert_eq!(entry.kernel.as_deref(), Some("/vmlinuz"));
        assert_eq!(entry.initrd, vec!["/initramfs"]);
        assert_eq!(entry.tries_left, TRIES_NOT_SET);
    }

    #[test]
    fn test_boot_entry_load_type1_with_tries() {
        let lines = ["title Test Kernel"];

        let entry = boot_entry_load_type1(
            "test+2-1.conf",
            "/boot",
            BootEntrySource::Esp,
            "/boot/loader/entries",
            &lines,
        )
        .unwrap();

        assert_eq!(entry.id, "test.conf");
        assert_eq!(entry.tries_left, 2);
        assert_eq!(entry.tries_done, 1);
    }

    #[test]
    fn test_boot_entry_load_type1_invalid_suffix() {
        let lines = ["title Test"];
        let result = boot_entry_load_type1(
            "test.txt",
            "/boot",
            BootEntrySource::Esp,
            "/boot/loader/entries",
            &lines,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mangle_path() {
        assert_eq!(mangle_path("linux", "vmlinuz").unwrap(), "/vmlinuz");
        assert_eq!(mangle_path("linux", "/vmlinuz").unwrap(), "/vmlinuz");
        // Trailing slash → ignored (empty string)
        assert_eq!(mangle_path("initrd", "/initrd/").unwrap(), "");
        // Path with ".." → ignored
        assert_eq!(mangle_path("linux", "../vmlinuz").unwrap(), "");
    }

    #[test]
    fn test_boot_entry_compare_sorting() {
        let mut a = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        a.id = "a.conf".into();
        a.sort_key = Some("10".into());
        a.version = Some("1.0".into());

        let mut b = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        b.id = "b.conf".into();
        b.sort_key = Some("5".into());
        b.version = Some("2.0".into());

        // Lower sort_key comes first
        assert_eq!(boot_entry_compare(&b, &a), Ordering::Less);
    }

    #[test]
    fn test_boot_entry_compare_exhausted() {
        let mut a = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        a.id = "a.conf".into();
        a.tries_left = 0;

        let mut b = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        b.id = "b.conf".into();

        // Entry with 0 tries goes last
        assert_eq!(boot_entry_compare(&a, &b), Ordering::Greater);
    }

    #[test]
    fn test_strverscmp() {
        assert_eq!(strverscmp("1", "2"), Ordering::Less);
        assert_eq!(strverscmp("2", "1"), Ordering::Greater);
        assert_eq!(strverscmp("1", "1"), Ordering::Equal);
        assert_eq!(strverscmp("1.0", "1.1"), Ordering::Less);
        assert_eq!(strverscmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(strverscmp("1.10", "1.2"), Ordering::Greater);
        assert_eq!(strverscmp("abc", "abd"), Ordering::Less);
        assert_eq!(strverscmp("", ""), Ordering::Equal);
        assert_eq!(strverscmp("a", "ab"), Ordering::Less);
    }

    #[test]
    fn test_boot_entries_uniquify() {
        let mut entries = vec![];

        let mut e1 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e1.id = "fedora.conf".into();
        e1.title = Some("Fedora".into());
        e1.version = Some("40".into());

        let mut e2 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e2.id = "ubuntu.conf".into();
        e2.title = Some("Fedora".into());
        e2.version = Some("41".into());

        entries.push(e1);
        entries.push(e2);

        boot_entries_uniquify(&mut entries).unwrap();

        assert_eq!(entries[0].show_title.as_deref(), Some("Fedora (40)"));
        assert_eq!(entries[1].show_title.as_deref(), Some("Fedora (41)"));
    }

    #[test]
    fn test_boot_entries_uniquify_empty() {
        let mut entries: Vec<BootEntry> = vec![];
        boot_entries_uniquify(&mut entries).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_boot_config_find() {
        let mut config = BootConfig::new();
        let mut e = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e.id = "fedora.conf".into();
        config.entries.push(e);

        assert_eq!(boot_config_find(&config, "fedora.conf"), Some(0));
        assert_eq!(boot_config_find(&config, "FEDORA.CONF"), Some(0));
        assert_eq!(boot_config_find(&config, "ubuntu.conf"), None);
    }

    #[test]
    fn test_boot_config_find_saved() {
        let mut config = BootConfig::new();
        config.entry_selected = Some("fedora.conf".into());
        let mut e = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e.id = "fedora.conf".into();
        config.entries.push(e);

        assert_eq!(boot_config_find(&config, "@saved"), Some(0));
    }

    #[test]
    fn test_boot_entries_select_default() {
        let mut config = BootConfig::new();

        let mut e1 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e1.id = "first.conf".into();
        let mut e2 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e2.id = "second.conf".into();
        config.entries.push(e1);
        config.entries.push(e2);

        // No patterns set → first entry
        assert_eq!(boot_entries_select_default(&config), 0);

        config.default_pattern = Some("second*".into());
        assert_eq!(boot_entries_select_default(&config), 1);
    }

    #[test]
    fn test_boot_entries_select_default_empty() {
        let config = BootConfig::new();
        assert_eq!(boot_entries_select_default(&config), -1);
    }

    #[test]
    fn test_boot_loader_read_conf() {
        let mut config = BootConfig::new();
        let lines = [
            "default fedora*",
            "preferred arch*",
            "timeout 5",
            "editor yes",
            "unknown-field value",
        ];

        boot_loader_read_conf(&mut config, &lines).unwrap();

        assert_eq!(config.default_pattern.as_deref(), Some("fedora*"));
        assert_eq!(config.preferred_pattern.as_deref(), Some("arch*"));
    }

    #[test]
    fn test_boot_config_finalize_sorts() {
        let mut config = BootConfig::new();

        let mut e1 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e1.id = "z.conf".into();
        let mut e2 = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e2.id = "a.conf".into();
        config.entries.push(e1);
        config.entries.push(e2);

        boot_config_finalize(&mut config).unwrap();

        // Should be sorted (descending version comparison means "a" > "z")
        assert_eq!(config.entries[0].id, "a.conf");
        assert_eq!(config.entries[1].id, "z.conf");
    }

    #[test]
    fn test_boot_config_augment_from_loader() {
        let mut config = BootConfig::new();
        let mut e = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        e.id = "existing.conf".into();
        config.entries.push(e);

        let found = ["existing.conf", "auto-windows", "auto-osx"];

        boot_config_augment_from_loader(&mut config, &found, false).unwrap();

        assert_eq!(config.entries.len(), 3);
        assert!(config.entries[0].reported_by_loader);
        assert_eq!(
            config.entries[1].title.as_deref(),
            Some("Windows Boot Manager")
        );
        assert_eq!(config.entries[2].title.as_deref(), Some("macOS"));
    }

    #[test]
    fn test_boot_config_augment_auto_only() {
        let mut config = BootConfig::new();

        let found = ["auto-windows", "custom-entry"];

        boot_config_augment_from_loader(&mut config, &found, true).unwrap();

        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.entries[0].id, "auto-windows");
    }

    #[test]
    fn test_bootspec_pick_name_version_sort_key() {
        let (name, version, sort_key) = bootspec_pick_name_version_sort_key(
            Some("Fedora Linux 40"),
            Some("fedora"),
            Some("Fedora"),
            Some("fedora"),
            Some("40"),
            Some("40 (Workstation Edition)"),
            Some("40"),
            Some("20240415"),
        )
        .unwrap();

        assert_eq!(name, "Fedora Linux 40");
        assert_eq!(version, "40 (Workstation Edition)");
        assert_eq!(sort_key, "fedora");
    }

    #[test]
    fn test_bootspec_pick_name_version_sort_key_minimal() {
        let (name, version, sort_key) = bootspec_pick_name_version_sort_key(
            None,
            None,
            Some("MyOS"),
            Some("myos"),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(name, "MyOS");
        assert_eq!(version, "");
        assert_eq!(sort_key, "myos");
    }

    #[test]
    fn test_bootspec_pick_name_version_sort_key_none() {
        assert!(bootspec_pick_name_version_sort_key(
            None, None, None, None, None, None, None, None,
        )
        .is_none());
    }

    #[test]
    fn test_pattern_matches() {
        assert!(pattern_matches("fedora*", "fedora.conf"));
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("f?dora*", "fedora.conf"));
        assert!(!pattern_matches("ubuntu*", "fedora.conf"));
        assert!(pattern_matches("", ""));
        assert!(!pattern_matches("a", ""));
    }

    #[test]
    fn test_boot_entry_display_title() {
        let mut entry = BootEntry::new(BootEntryType::Type1, BootEntrySource::Esp);
        entry.id = "test.conf".into();
        assert_eq!(entry.display_title(), "test.conf");

        entry.show_title = Some("Custom Title".into());
        assert_eq!(entry.display_title(), "Custom Title");

        entry.show_title = None;
        entry.title = Some("Real Title".into());
        assert_eq!(entry.display_title(), "Real Title");
    }

    #[test]
    fn test_boot_config_new() {
        let config = BootConfig::new();
        assert!(config.entries.is_empty());
        assert_eq!(config.default_entry, -1);
        assert!(config.default_pattern.is_none());
        assert!(config.entry_selected.is_none());
    }

    #[test]
    fn test_boot_config_load_type1_entry() {
        let mut config = BootConfig::new();
        let lines = ["title Test", "version 1.0"];

        config
            .load_type1_entry(
                "test.conf",
                "/boot",
                BootEntrySource::Esp,
                "/boot/loader/entries",
                &lines,
            )
            .unwrap();

        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.entries[0].title.as_deref(), Some("Test"));
    }

    #[test]
    fn test_parse_path_many() {
        let paths = parse_path_many("initrd", "/initrd1 /initrd2").unwrap();
        assert_eq!(paths, vec!["/initrd1", "/initrd2"]);
    }

    #[test]
    fn test_parse_path_many_with_bad_paths() {
        let paths = parse_path_many("initrd", "/good ../bad /trailing/").unwrap();
        assert_eq!(paths, vec!["/good"]);
    }

    #[test]
    fn test_constants() {
        assert_eq!(TRIES_NOT_SET, u32::MAX);
        assert!(!LOADER_ENTRIES_DIR.is_empty());
        assert!(!EFI_LINUX_DIR.is_empty());
        assert!(!LOADER_CONF_PATH.is_empty());
        assert!(UNIFIED_PROFILES_MAX > 0);
    }
}
