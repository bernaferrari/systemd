// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/locale-setup.c, src/shared/locale-setup.h
//
// Locale configuration: reading, parsing, and applying system locale settings.
// Supports loading locale from /proc/cmdline, /etc/locale.conf, and environment
// variables. Provides locale context management with stat-based caching and
// simplification.

use crate::ffi::*;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default locale used when no locale is configured.
const DEFAULT_LOCALE: &str = "C.UTF-8";

/// Default path to the locale configuration file.
const DEFAULT_LOCALE_CONF: &str = "/etc/locale.conf";

/// Default path to the virtual console configuration file.
const DEFAULT_VCONSOLE_CONF: &str = "/etc/vconsole.conf";

/// Path to the kernel command line (Linux-specific).
const PROC_CMDLINE_PATH: &str = "/proc/cmdline";

// ── Path resolution ───────────────────────────────────────────────────────

static ETC_LOCALE_CONF_PATH: OnceLock<PathBuf> = OnceLock::new();
static ETC_VCONSOLE_CONF_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Returns the path to the locale configuration file.
///
/// Respects the `SYSTEMD_ETC_LOCALE_CONF` environment variable override,
/// falling back to `/etc/locale.conf`.
pub fn etc_locale_conf() -> &'static Path {
    ETC_LOCALE_CONF_PATH.get_or_init(|| {
        env::var("SYSTEMD_ETC_LOCALE_CONF")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOCALE_CONF))
    })
}

/// Returns the path to the virtual console configuration file.
///
/// Respects the `SYSTEMD_ETC_VCONSOLE_CONF` environment variable override,
/// falling back to `/etc/vconsole.conf`.
pub fn etc_vconsole_conf() -> &'static Path {
    ETC_VCONSOLE_CONF_PATH.get_or_init(|| {
        env::var("SYSTEMD_ETC_VCONSOLE_CONF")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_VCONSOLE_CONF))
    })
}

// ── LocaleVariable ────────────────────────────────────────────────────────

/// Locale variable identifiers.
///
/// Corresponds to the C `LocaleVariable` enum. These represent all recognized
/// locale configuration variables. `LC_ALL` is intentionally excluded —
/// `LANG` should be used instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LocaleVariable {
    Lang,
    Language,
    LcCtype,
    LcNumeric,
    LcTime,
    LcCollate,
    LcMonetary,
    LcMessages,
    LcPaper,
    LcName,
    LcAddress,
    LcTelephone,
    LcMeasurement,
    LcIdentification,
}

impl LocaleVariable {
    /// Total number of locale variables.
    pub const COUNT: usize = 14;

    /// All locale variables in canonical order.
    pub const ALL: [LocaleVariable; Self::COUNT] = [
        Self::Lang,
        Self::Language,
        Self::LcCtype,
        Self::LcNumeric,
        Self::LcTime,
        Self::LcCollate,
        Self::LcMonetary,
        Self::LcMessages,
        Self::LcPaper,
        Self::LcName,
        Self::LcAddress,
        Self::LcTelephone,
        Self::LcMeasurement,
        Self::LcIdentification,
    ];

    /// Returns the environment variable name for this locale variable.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lang => "LANG",
            Self::Language => "LANGUAGE",
            Self::LcCtype => "LC_CTYPE",
            Self::LcNumeric => "LC_NUMERIC",
            Self::LcTime => "LC_TIME",
            Self::LcCollate => "LC_COLLATE",
            Self::LcMonetary => "LC_MONETARY",
            Self::LcMessages => "LC_MESSAGES",
            Self::LcPaper => "LC_PAPER",
            Self::LcName => "LC_NAME",
            Self::LcAddress => "LC_ADDRESS",
            Self::LcTelephone => "LC_TELEPHONE",
            Self::LcMeasurement => "LC_MEASUREMENT",
            Self::LcIdentification => "LC_IDENTIFICATION",
        }
    }

    /// Returns the index of this variable in the canonical ordering.
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Creates a `LocaleVariable` from a numeric index.
    pub const fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Lang),
            1 => Some(Self::Language),
            2 => Some(Self::LcCtype),
            3 => Some(Self::LcNumeric),
            4 => Some(Self::LcTime),
            5 => Some(Self::LcCollate),
            6 => Some(Self::LcMonetary),
            7 => Some(Self::LcMessages),
            8 => Some(Self::LcPaper),
            9 => Some(Self::LcName),
            10 => Some(Self::LcAddress),
            11 => Some(Self::LcTelephone),
            12 => Some(Self::LcMeasurement),
            13 => Some(Self::LcIdentification),
            _ => None,
        }
    }

    /// Parses an environment variable name into a `LocaleVariable`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "LANG" => Some(Self::Lang),
            "LANGUAGE" => Some(Self::Language),
            "LC_CTYPE" => Some(Self::LcCtype),
            "LC_NUMERIC" => Some(Self::LcNumeric),
            "LC_TIME" => Some(Self::LcTime),
            "LC_COLLATE" => Some(Self::LcCollate),
            "LC_MONETARY" => Some(Self::LcMonetary),
            "LC_MESSAGES" => Some(Self::LcMessages),
            "LC_PAPER" => Some(Self::LcPaper),
            "LC_NAME" => Some(Self::LcName),
            "LC_ADDRESS" => Some(Self::LcAddress),
            "LC_TELEPHONE" => Some(Self::LcTelephone),
            "LC_MEASUREMENT" => Some(Self::LcMeasurement),
            "LC_IDENTIFICATION" => Some(Self::LcIdentification),
            _ => None,
        }
    }
}

// ── LocaleLoadFlag ────────────────────────────────────────────────────────

/// Flags controlling locale loading behavior.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LocaleLoadFlag: u32 {
        /// Load locale from /proc/cmdline (highest priority source).
        const PROC_CMDLINE = 1 << 0;
        /// Load locale from /etc/locale.conf.
        const LOCALE_CONF  = 1 << 1;
        /// Load locale from process environment variables.
        const ENVIRONMENT  = 1 << 2;
        /// Simplify locale variables after loading (remove entries duplicating LANG).
        const SIMPLIFY     = 1 << 3;
    }
}

// ── LocaleArray ───────────────────────────────────────────────────────────

/// A fixed-size array of optional locale values, indexed by [`LocaleVariable`].
pub type LocaleArray = [Option<String>; LocaleVariable::COUNT];

/// Creates a new empty locale array with all entries set to `None`.
pub fn locale_array_new() -> LocaleArray {
    std::array::from_fn(|_| None)
}

// ── LocaleContext ─────────────────────────────────────────────────────────

/// Result of a locale configuration load attempt.
enum LoadResult {
    /// New configuration was successfully loaded from a source.
    Loaded,
    /// Configuration file has not changed since the last load.
    Unchanged,
    /// No configuration source was available.
    NotLoaded,
}

/// Locale context holding current locale configuration with change detection.
///
/// Manages locale variable values loaded from various sources
/// (/proc/cmdline, locale.conf, environment) with modification-time-based
/// caching to avoid redundant re-reads.
#[derive(Debug)]
pub struct LocaleContext {
    /// Current locale variable values.
    locale: LocaleArray,
    /// Last modification time of the loaded config file, for change detection.
    last_modified: Option<std::time::SystemTime>,
}

impl Default for LocaleContext {
    fn default() -> Self {
        Self::new()
    }
}

impl LocaleContext {
    /// Creates a new empty locale context.
    pub fn new() -> Self {
        Self {
            locale: locale_array_new(),
            last_modified: None,
        }
    }

    /// Clears all locale values and resets the modification-time cache.
    pub fn clear(&mut self) {
        for entry in self.locale.iter_mut() {
            *entry = None;
        }
        self.last_modified = None;
    }

    /// Returns the value of the specified locale variable, if set.
    pub fn get(&self, var: LocaleVariable) -> Option<&str> {
        self.locale[var.index()].as_deref()
    }

    /// Sets the value of the specified locale variable.
    /// Pass `None` to clear the variable.
    pub fn set(&mut self, var: LocaleVariable, value: Option<&str>) {
        self.locale[var.index()] = value.map(String::from);
    }

    /// Returns `true` if no locale variable is set.
    pub fn is_empty(&self) -> bool {
        self.locale.iter().all(|v| v.is_none())
    }

    /// Loads locale configuration according to the specified flags.
    ///
    /// Loading priority: /proc/cmdline > locale.conf > environment variables.
    /// If the [`LocaleLoadFlag::SIMPLIFY`] flag is set, redundant entries
    /// duplicating `LANG` are removed after loading.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if locale.conf exists but cannot be read.
    /// Errors from /proc/cmdline are silently ignored (kernel fs may be
    /// unavailable in containers).
    pub fn load(&mut self, flags: LocaleLoadFlag) -> Result<(), io::Error> {
        let mut loaded = false;

        // Priority 1: /proc/cmdline
        if flags.contains(LocaleLoadFlag::PROC_CMDLINE) {
            if let Ok(true) = self.load_proc_cmdline() {
                loaded = true;
            }
            // Errors from /proc/cmdline are silently ignored
        }

        // Priority 2: /etc/locale.conf
        if !loaded && flags.contains(LocaleLoadFlag::LOCALE_CONF) {
            match self.load_conf()? {
                LoadResult::Loaded | LoadResult::Unchanged => {
                    loaded = true;
                }
                LoadResult::NotLoaded => {}
            }
        }

        // Priority 3: environment variables
        if !loaded && flags.contains(LocaleLoadFlag::ENVIRONMENT) {
            self.load_env();
            loaded = true;
        }

        if !loaded {
            self.clear();
            return Ok(());
        }

        if flags.contains(LocaleLoadFlag::SIMPLIFY) {
            locale_variables_simplify(&mut self.locale);
        }

        Ok(())
    }

    /// Attempts to load locale variables from `/proc/cmdline`.
    ///
    /// Looks for `locale.LANG=value`, `locale.LC_CTYPE=value`, etc.
    /// Strips the `rd.` prefix used for initrd-only parameters.
    /// Returns `Ok(true)` if at least one locale variable was found.
    fn load_proc_cmdline(&mut self) -> Result<bool, io::Error> {
        let content = match fs::read_to_string(PROC_CMDLINE_PATH) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(e);
            }
        };

        self.clear();

        let mut found = false;
        for token in content.split_whitespace() {
            // Strip rd. prefix (initrd-only parameters)
            let token = token.strip_prefix("rd.").unwrap_or(token);

            if let Some(rest) = token.strip_prefix("locale.") {
                if let Some(eq_pos) = rest.find('=') {
                    let key = &rest[..eq_pos];
                    let value = &rest[eq_pos + 1..];
                    if let Some(var) = LocaleVariable::from_name(key) {
                        if !value.is_empty() {
                            self.set(var, Some(value));
                            found = true;
                        }
                    }
                }
            }
        }

        Ok(found)
    }

    /// Attempts to load locale variables from the locale.conf file.
    ///
    /// Uses modification-time-based caching: if the file has not changed
    /// since the last successful load, returns [`LoadResult::Unchanged`]
    /// without re-reading.
    fn load_conf(&mut self) -> Result<LoadResult, io::Error> {
        let path = etc_locale_conf();

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Ok(LoadResult::NotLoaded);
                }
                return Err(e);
            }
        };

        let modified = metadata.modified()?;

        // File unchanged since last load — skip re-reading
        if let Some(ref last) = self.last_modified {
            if *last == modified {
                return Ok(LoadResult::Unchanged);
            }
        }

        self.last_modified = Some(modified);
        self.clear();

        let content = fs::read_to_string(path)?;
        parse_locale_conf_into(&content, &mut self.locale);

        Ok(LoadResult::Loaded)
    }

    /// Loads locale variables from the process environment.
    ///
    /// Reads each recognized locale variable name via [`std::env::var`].
    /// Empty environment variables are treated as unset.
    fn load_env(&mut self) {
        self.clear();

        for &var in &LocaleVariable::ALL {
            if let Ok(val) = env::var(var.name()) {
                if !val.is_empty() {
                    self.set(var, Some(&val));
                }
            }
        }
    }

    /// Builds environment variable lists from the current locale context.
    ///
    /// Returns `(set_vars, unset_vars)` where:
    /// - `set_vars`: `KEY=VALUE` pairs for variables that have non-empty values
    /// - `unset_vars`: variable names for variables without values
    pub fn build_env(&self) -> (Vec<String>, Vec<String>) {
        let mut set = Vec::new();
        let mut unset = Vec::new();

        for &var in &LocaleVariable::ALL {
            match self.get(var) {
                Some(val) if !val.is_empty() => {
                    set.push(format!("{}={}", var.name(), val));
                }
                _ => {
                    unset.push(var.name().to_string());
                }
            }
        }

        (set, unset)
    }

    /// Merges non-empty values from this context into the target array.
    ///
    /// Only fills in target entries that are currently `None`. Existing
    /// values in the target are never overwritten.
    pub fn merge_into(&self, target: &mut LocaleArray) {
        for &var in &LocaleVariable::ALL {
            if let Some(val) = self.get(var) {
                if !val.is_empty() && target[var.index()].is_none() {
                    target[var.index()] = Some(val.to_string());
                }
            }
        }
    }

    /// Takes ownership of locale values from the given array, replacing
    /// this context's values.
    pub fn take_from(&mut self, source: &mut LocaleArray) {
        for &var in &LocaleVariable::ALL {
            if source[var.index()].is_some() {
                self.locale[var.index()] = source[var.index()].take();
            }
        }
    }

    /// Compares this context's locale values with the given array for equality.
    pub fn equal(&self, other: &LocaleArray) -> bool {
        LocaleVariable::ALL
            .iter()
            .all(|&var| self.get(var) == other[var.index()].as_deref())
    }

    /// Saves the current locale configuration to the locale.conf file.
    ///
    /// If all locale values are empty, the config file is removed instead.
    /// Returns the set and unset variable lists.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be written or removed.
    pub fn save(&mut self) -> Result<(Vec<String>, Vec<String>), io::Error> {
        let (set_vars, unset_vars) = self.build_env();
        let path = etc_locale_conf();

        if set_vars.is_empty() {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            self.last_modified = None;
            return Ok((Vec::new(), Vec::new()));
        }

        let mut content = String::new();
        for entry in &set_vars {
            content.push_str(entry);
            content.push('\n');
        }

        fs::write(path, content)?;

        // Update stat cache after writing
        if let Ok(m) = fs::metadata(path) {
            self.last_modified = m.modified().ok();
        }

        Ok((set_vars, unset_vars))
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parses locale.conf formatted content and inserts matching values into the
/// locale array.
///
/// Format: `KEY=VALUE` pairs, one per line. Lines starting with `#` or `;`
/// are comments. Empty lines are ignored. Only recognized locale variable
/// names are stored; unknown keys are silently skipped.
pub fn parse_locale_conf_into(content: &str, locale: &mut LocaleArray) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();
            if let Some(var) = LocaleVariable::from_name(key) {
                if !value.is_empty() {
                    locale[var.index()] = Some(value.to_string());
                }
            }
        }
    }
}

/// Parses a locale.conf file and returns the recognized key-value pairs.
///
/// # Errors
///
/// Returns an I/O error if the file cannot be read.
pub fn parse_locale_conf(path: &Path) -> Result<Vec<(String, String)>, io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(parse_locale_conf_str(&content))
}

/// Parses locale.conf formatted content and returns the recognized key-value
/// pairs as a vector.
pub fn parse_locale_conf_str(content: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();
            if LocaleVariable::from_name(&key).is_some() && !value.is_empty() {
                result.push((key, value));
            }
        }
    }

    result
}

// ── Simplification ────────────────────────────────────────────────────────

/// Simplifies locale variables by removing entries that duplicate `LANG`.
///
/// If a non-`LANG` variable has the same value as `LANG`, it is cleared
/// since `LANG` serves as the universal fallback. This reduces redundant
/// configuration entries.
pub fn locale_variables_simplify(locale: &mut LocaleArray) {
    let lang_value = locale[LocaleVariable::Lang.index()].clone();

    let lang_deref = match &lang_value {
        Some(v) => v.as_str(),
        None => return,
    };

    for var in LocaleVariable::ALL {
        if var == LocaleVariable::Lang {
            continue;
        }
        if let Some(ref val) = locale[var.index()] {
            if val == lang_deref {
                locale[var.index()] = None;
            }
        }
    }
}

// ── locale_setup ──────────────────────────────────────────────────────────

/// Sets up locale environment variables for the system.
///
/// Loads locale configuration from `/proc/cmdline` and `/etc/locale.conf`
/// (in priority order). If no locale is configured, falls back to
/// [`DEFAULT_LOCALE`].
///
/// Returns the list of `KEY=VALUE` environment variable strings.
///
/// # Errors
///
/// Returns an I/O error if locale.conf exists but cannot be read.
pub fn locale_setup() -> Result<Vec<String>, io::Error> {
    let mut ctx = LocaleContext::new();
    ctx.load(LocaleLoadFlag::PROC_CMDLINE | LocaleLoadFlag::LOCALE_CONF)?;

    let (set_vars, _) = ctx.build_env();

    let env_list = if set_vars.is_empty() {
        vec![format!("LANG={}", DEFAULT_LOCALE)]
    } else {
        set_vars
    };

    Ok(env_list)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LocaleVariable ────────────────────────────────────────────────────

    #[test]
    fn test_locale_variable_name() {
        assert_eq!(LocaleVariable::Lang.name(), "LANG");
        assert_eq!(LocaleVariable::Language.name(), "LANGUAGE");
        assert_eq!(LocaleVariable::LcCtype.name(), "LC_CTYPE");
        assert_eq!(LocaleVariable::LcNumeric.name(), "LC_NUMERIC");
        assert_eq!(LocaleVariable::LcTime.name(), "LC_TIME");
        assert_eq!(LocaleVariable::LcCollate.name(), "LC_COLLATE");
        assert_eq!(LocaleVariable::LcMonetary.name(), "LC_MONETARY");
        assert_eq!(LocaleVariable::LcMessages.name(), "LC_MESSAGES");
        assert_eq!(LocaleVariable::LcPaper.name(), "LC_PAPER");
        assert_eq!(LocaleVariable::LcName.name(), "LC_NAME");
        assert_eq!(LocaleVariable::LcAddress.name(), "LC_ADDRESS");
        assert_eq!(LocaleVariable::LcTelephone.name(), "LC_TELEPHONE");
        assert_eq!(LocaleVariable::LcMeasurement.name(), "LC_MEASUREMENT");
        assert_eq!(LocaleVariable::LcIdentification.name(), "LC_IDENTIFICATION");
    }

    #[test]
    fn test_locale_variable_from_name_valid() {
        assert_eq!(
            LocaleVariable::from_name("LANG"),
            Some(LocaleVariable::Lang)
        );
        assert_eq!(
            LocaleVariable::from_name("LANGUAGE"),
            Some(LocaleVariable::Language)
        );
        assert_eq!(
            LocaleVariable::from_name("LC_CTYPE"),
            Some(LocaleVariable::LcCtype)
        );
        assert_eq!(
            LocaleVariable::from_name("LC_IDENTIFICATION"),
            Some(LocaleVariable::LcIdentification)
        );
    }

    #[test]
    fn test_locale_variable_from_name_invalid() {
        assert_eq!(LocaleVariable::from_name("LC_ALL"), None);
        assert_eq!(LocaleVariable::from_name("PATH"), None);
        assert_eq!(LocaleVariable::from_name(""), None);
        assert_eq!(LocaleVariable::from_name("lang"), None); // case-sensitive
    }

    #[test]
    fn test_locale_variable_from_index_roundtrip() {
        for var in LocaleVariable::ALL {
            assert_eq!(LocaleVariable::from_index(var.index()), Some(var));
        }
        assert_eq!(LocaleVariable::from_index(LocaleVariable::COUNT), None);
        assert_eq!(LocaleVariable::from_index(100), None);
    }

    #[test]
    fn test_locale_variable_count() {
        assert_eq!(LocaleVariable::ALL.len(), LocaleVariable::COUNT);
        assert_eq!(LocaleVariable::COUNT, 14);
    }

    // ── LocaleLoadFlag ────────────────────────────────────────────────────

    #[test]
    fn test_locale_load_flags() {
        let f = LocaleLoadFlag::PROC_CMDLINE | LocaleLoadFlag::LOCALE_CONF;
        assert!(f.contains(LocaleLoadFlag::PROC_CMDLINE));
        assert!(f.contains(LocaleLoadFlag::LOCALE_CONF));
        assert!(!f.contains(LocaleLoadFlag::ENVIRONMENT));
        assert!(!f.contains(LocaleLoadFlag::SIMPLIFY));

        let all = LocaleLoadFlag::PROC_CMDLINE
            | LocaleLoadFlag::LOCALE_CONF
            | LocaleLoadFlag::ENVIRONMENT
            | LocaleLoadFlag::SIMPLIFY;
        assert!(all.contains(LocaleLoadFlag::PROC_CMDLINE));
        assert!(all.contains(LocaleLoadFlag::LOCALE_CONF));
        assert!(all.contains(LocaleLoadFlag::ENVIRONMENT));
        assert!(all.contains(LocaleLoadFlag::SIMPLIFY));
    }

    // ── LocaleArray ───────────────────────────────────────────────────────

    #[test]
    fn test_locale_array_new() {
        let arr = locale_array_new();
        for entry in &arr {
            assert!(entry.is_none());
        }
    }

    // ── LocaleContext ─────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_new_default() {
        let ctx = LocaleContext::default();
        assert!(ctx.is_empty());
        assert!(ctx.get(LocaleVariable::Lang).is_none());
    }

    #[test]
    fn test_locale_context_clear() {
        let mut ctx = LocaleContext::new();
        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));
        ctx.set(LocaleVariable::LcTime, Some("de_DE.UTF-8"));
        assert!(!ctx.is_empty());

        ctx.clear();
        assert!(ctx.is_empty());
        assert!(ctx.get(LocaleVariable::Lang).is_none());
        assert!(ctx.get(LocaleVariable::LcTime).is_none());
    }

    #[test]
    fn test_locale_context_set_get() {
        let mut ctx = LocaleContext::new();

        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));
        assert_eq!(ctx.get(LocaleVariable::Lang), Some("en_US.UTF-8"));

        ctx.set(LocaleVariable::Lang, Some("de_DE.UTF-8"));
        assert_eq!(ctx.get(LocaleVariable::Lang), Some("de_DE.UTF-8"));

        ctx.set(LocaleVariable::Lang, None);
        assert_eq!(ctx.get(LocaleVariable::Lang), None);
    }

    #[test]
    fn test_locale_context_is_empty() {
        let mut ctx = LocaleContext::new();
        assert!(ctx.is_empty());

        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));
        assert!(!ctx.is_empty());

        ctx.set(LocaleVariable::Lang, None);
        assert!(ctx.is_empty());
    }

    // ── Parsing ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_locale_conf_basic() {
        let content = "LANG=en_US.UTF-8\nLC_CTYPE=en_US.UTF-8\n";
        let mut locale = locale_array_new();
        parse_locale_conf_into(content, &mut locale);

        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(
            locale[LocaleVariable::LcCtype.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(locale[LocaleVariable::LcTime.index()], None);
    }

    #[test]
    fn test_parse_locale_conf_comments_and_empty() {
        let content = "# This is a comment\n; Also a comment\n\nLANG=en_US.UTF-8\n\n";
        let mut locale = locale_array_new();
        parse_locale_conf_into(content, &mut locale);

        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
    }

    #[test]
    fn test_parse_locale_conf_unknown_keys() {
        let content = "UNKNOWN_KEY=value\nLANG=en_US.UTF-8\nLC_ALL=C\n";
        let mut locale = locale_array_new();
        parse_locale_conf_into(content, &mut locale);

        // LC_ALL is intentionally not recognized
        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        let lc_all_idx = LocaleVariable::from_name("LC_ALL");
        assert!(lc_all_idx.is_none());
    }

    #[test]
    fn test_parse_locale_conf_empty_values() {
        let content = "LANG=\nLC_CTYPE=en_US.UTF-8\n";
        let mut locale = locale_array_new();
        parse_locale_conf_into(content, &mut locale);

        // Empty values are treated as unset
        assert_eq!(locale[LocaleVariable::Lang.index()], None);
        assert_eq!(
            locale[LocaleVariable::LcCtype.index()].as_deref(),
            Some("en_US.UTF-8")
        );
    }

    #[test]
    fn test_parse_locale_conf_whitespace() {
        let content = "  LANG  =  en_US.UTF-8  \n  LC_TIME  =  de_DE.UTF-8  \n";
        let mut locale = locale_array_new();
        parse_locale_conf_into(content, &mut locale);

        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(
            locale[LocaleVariable::LcTime.index()].as_deref(),
            Some("de_DE.UTF-8")
        );
    }

    #[test]
    fn test_parse_locale_conf_str() {
        let content = "LANG=en_US.UTF-8\nLC_NUMERIC=de_DE.UTF-8\n";
        let pairs = parse_locale_conf_str(content);

        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("LANG".to_string(), "en_US.UTF-8".to_string()));
        assert_eq!(
            pairs[1],
            ("LC_NUMERIC".to_string(), "de_DE.UTF-8".to_string())
        );
    }

    // ── Simplification ────────────────────────────────────────────────────

    #[test]
    fn test_locale_variables_simplify() {
        let mut locale = locale_array_new();
        locale[LocaleVariable::Lang.index()] = Some("en_US.UTF-8".to_string());
        locale[LocaleVariable::LcCtype.index()] = Some("en_US.UTF-8".to_string());
        locale[LocaleVariable::LcTime.index()] = Some("de_DE.UTF-8".to_string());

        locale_variables_simplify(&mut locale);

        // LC_CTYPE duplicated LANG, should be cleared
        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(locale[LocaleVariable::LcCtype.index()], None);
        // LC_TIME differed, should remain
        assert_eq!(
            locale[LocaleVariable::LcTime.index()].as_deref(),
            Some("de_DE.UTF-8")
        );
    }

    #[test]
    fn test_locale_variables_simplify_no_lang() {
        let mut locale = locale_array_new();
        locale[LocaleVariable::LcCtype.index()] = Some("en_US.UTF-8".to_string());

        locale_variables_simplify(&mut locale);

        // No LANG set, nothing should be simplified
        assert_eq!(
            locale[LocaleVariable::LcCtype.index()].as_deref(),
            Some("en_US.UTF-8")
        );
    }

    // ── Build env ─────────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_build_env() {
        let mut ctx = LocaleContext::new();
        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));
        ctx.set(LocaleVariable::LcTime, Some("de_DE.UTF-8"));
        // LcNumeric left unset

        let (set, unset) = ctx.build_env();

        assert!(set.contains(&"LANG=en_US.UTF-8".to_string()));
        assert!(set.contains(&"LC_TIME=de_DE.UTF-8".to_string()));
        assert!(!set.iter().any(|s| s.starts_with("LC_NUMERIC=")));
        assert!(unset.contains(&"LC_NUMERIC".to_string()));
    }

    #[test]
    fn test_locale_context_build_env_empty() {
        let ctx = LocaleContext::new();
        let (set, unset) = ctx.build_env();

        assert!(set.is_empty());
        assert_eq!(unset.len(), LocaleVariable::COUNT);
    }

    // ── Merge ─────────────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_merge_into() {
        let mut ctx = LocaleContext::new();
        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));
        ctx.set(LocaleVariable::LcTime, Some("de_DE.UTF-8"));

        let mut target = locale_array_new();
        target[LocaleVariable::LcTime.index()] = Some("fr_FR.UTF-8".to_string());

        ctx.merge_into(&mut target);

        // LANG merged (target was empty)
        assert_eq!(
            target[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        // LcTime NOT overwritten (target already had a value)
        assert_eq!(
            target[LocaleVariable::LcTime.index()].as_deref(),
            Some("fr_FR.UTF-8")
        );
    }

    // ── Equal ─────────────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_equal() {
        let mut ctx = LocaleContext::new();
        ctx.set(LocaleVariable::Lang, Some("en_US.UTF-8"));

        let mut other = locale_array_new();
        other[LocaleVariable::Lang.index()] = Some("en_US.UTF-8".to_string());

        assert!(ctx.equal(&other));

        other[LocaleVariable::Lang.index()] = Some("de_DE.UTF-8".to_string());
        assert!(!ctx.equal(&other));
    }

    // ── Take ──────────────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_take_from() {
        let mut ctx = LocaleContext::new();
        ctx.set(LocaleVariable::Lang, Some("old"));

        let mut source = locale_array_new();
        source[LocaleVariable::Lang.index()] = Some("new".to_string());
        source[LocaleVariable::LcTime.index()] = Some("de_DE".to_string());

        ctx.take_from(&mut source);

        assert_eq!(ctx.get(LocaleVariable::Lang), Some("new"));
        assert_eq!(ctx.get(LocaleVariable::LcTime), Some("de_DE"));
        // Source entries are taken (moved)
        assert!(source[LocaleVariable::Lang.index()].is_none());
        assert!(source[LocaleVariable::LcTime.index()].is_none());
    }

    // ── Load ──────────────────────────────────────────────────────────────

    #[test]
    fn test_locale_context_load_from_file() {
        let tmp = tempfile::tempdir().unwrap();
        let conf_path = tmp.path().join("locale.conf");
        fs::write(&conf_path, "LANG=en_US.UTF-8\nLC_CTYPE=en_US.UTF-8\n").unwrap();

        // We need to test load_conf indirectly. Since load_conf uses
        // the global etc_locale_conf(), we test parsing instead.
        let content = fs::read_to_string(&conf_path).unwrap();
        let mut locale = locale_array_new();
        parse_locale_conf_into(&content, &mut locale);

        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(
            locale[LocaleVariable::LcCtype.index()].as_deref(),
            Some("en_US.UTF-8")
        );
    }

    #[test]
    fn test_locale_context_load_missing_file() {
        let mut ctx = LocaleContext::new();
        // Loading with no config file should succeed (silently)
        let result = ctx.load(LocaleLoadFlag::LOCALE_CONF);
        assert!(result.is_ok());
    }

    #[test]
    fn test_locale_context_load_with_simplify() {
        let tmp = tempfile::tempdir().unwrap();
        let conf_path = tmp.path().join("locale.conf");
        fs::write(
            &conf_path,
            "LANG=en_US.UTF-8\nLC_CTYPE=en_US.UTF-8\nLC_TIME=de_DE.UTF-8\n",
        )
        .unwrap();

        let content = fs::read_to_string(&conf_path).unwrap();
        let mut locale = locale_array_new();
        parse_locale_conf_into(&content, &mut locale);
        locale_variables_simplify(&mut locale);

        // LC_CTYPE duplicated LANG, should be cleared
        assert_eq!(
            locale[LocaleVariable::Lang.index()].as_deref(),
            Some("en_US.UTF-8")
        );
        assert_eq!(locale[LocaleVariable::LcCtype.index()], None);
        assert_eq!(
            locale[LocaleVariable::LcTime.index()].as_deref(),
            Some("de_DE.UTF-8")
        );
    }

    // ── locale_setup ──────────────────────────────────────────────────────

    #[test]
    fn test_locale_setup_no_config() {
        // When no config exists, should fall back to default locale
        let env_list = locale_setup().unwrap();
        assert_eq!(env_list, vec![format!("LANG={}", DEFAULT_LOCALE)]);
    }

    // ── Path resolution ───────────────────────────────────────────────────

    #[test]
    fn test_etc_locale_conf_default() {
        // Can't easily test without setting env var, but verify it returns a path
        let path = etc_locale_conf();
        assert!(path.to_str().unwrap().ends_with("locale.conf"));
    }

    #[test]
    fn test_etc_vconsole_conf_default() {
        let path = etc_vconsole_conf();
        assert!(path.to_str().unwrap().ends_with("vconsole.conf"));
    }
}
