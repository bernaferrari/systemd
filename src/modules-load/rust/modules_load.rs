// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/modules-load/modules-load.c
//
// Kernel module loading from configuration files.
//
// Parses module names from modules-load.d configuration files and the
// kernel command line (`modules_load=`), normalising `.ko` / `.ko.zst`
// suffixes and replacing dashes with underscores to deduplicate names.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum module name length, matching `MODULE_NAME_MAX_LEN` in the C code.
pub const MODULE_NAME_MAX_LEN: usize = 4096;

/// Standard configuration file search directories for modules-load.d.
///
/// Mirrors `conf_file_dirs[] = CONF_PATHS_NULSTR("modules-load.d")`.
pub const CONF_FILE_DIRS: &[&str] = &[
    "/etc/modules-load.d",
    "/run/modules-load.d",
    "/usr/local/lib/modules-load.d",
    "/usr/lib/modules-load.d",
];

/// Kernel command-line parameter key for specifying modules to load.
pub const PROC_CMDLINE_KEY: &str = "modules_load";

// ── Module set ────────────────────────────────────────────────────────────

use std::collections::HashSet;

/// An ordered set of deduplicated, normalised module names.
///
/// Mirrors the `OrderedSet` used in the C source.
#[derive(Debug, Clone, Default)]
pub struct ModuleSet {
    modules: HashSet<String>,
}

impl ModuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a raw module name, returning `true` if it was new.
    pub fn insert(&mut self, module: String) -> bool {
        self.modules.insert(module)
    }

    pub fn contains(&self, module: &str) -> bool {
        self.modules.contains(module)
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Return all module names as a sorted vector for deterministic output.
    pub fn to_sorted_vec(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.modules.iter().map(|s| s.as_str()).collect();
        v.sort();
        v
    }

    /// Append a module name, stripping `.ko` / `.ko.zst` suffixes and
    /// normalising dashes to underscores — just like
    /// `modules_list_append_suffix()` in the C code.
    pub fn append_suffix(&mut self, mod_with_suffix: &str) -> Result<()> {
        let module = mod_with_suffix.trim();
        if module.is_empty() {
            return Ok(());
        }
        let cleaned = module
            .strip_suffix(".ko.zst")
            .or_else(|| module.strip_suffix(".ko"))
            .unwrap_or(module);
        let normalised = normalise_module_name(cleaned);
        self.modules.insert(normalised);
        Ok(())
    }

    /// Append a bare module name (no suffix stripping).
    pub fn append(&mut self, module: &str) -> Result<()> {
        if module.is_empty() {
            return Ok(());
        }
        self.modules.insert(module.to_string());
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Normalise a module name by replacing dashes with underscores.
///
/// Mirrors `string_replace_char(mod, '-', '_')` in the C code.
pub fn normalise_module_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Validate a module name: non-empty, not too long, safe characters only.
///
/// Mirrors the length check in `modules_list_append_suffix()` plus a
/// reasonable character set validation.
pub fn is_module_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < MODULE_NAME_MAX_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse the `modules_load=` kernel command-line value.
///
/// Splits on commas and adds each trimmed module name to the set.
/// Corresponds to `parse_proc_cmdline_item()` handling `"modules_load"`.
pub fn parse_proc_cmdline_modules(
    key: &str,
    value: Option<&str>,
    module_set: &mut ModuleSet,
) -> Result<()> {
    if key == PROC_CMDLINE_KEY {
        if let Some(v) = value {
            for module in v.split(',') {
                module_set.append(module.trim())?;
            }
        }
    }
    Ok(())
}

/// Return the standard configuration file directories.
pub fn conf_file_dirs() -> &'static [&'static str] {
    CONF_FILE_DIRS
}

#[cfg(target_os = "linux")]
pub fn load_module(module: &str) -> Result<()> {
    use std::ffi::CString;
    use std::ptr;

    let c_name = CString::new(module).map_err(|_| Errno(22))?;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_init_module,
            ptr::null::<u8>(),
            0_usize,
            c_name.as_ptr(),
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::EEXIST {
        return Ok(());
    }
    Err(Errno(errno))
}

#[cfg(target_os = "linux")]
pub fn load_module_via_modprobe(module: &str) -> Result<()> {
    let status = std::process::Command::new("/sbin/modprobe")
        .arg(module)
        .status()
        .map_err(|_| Errno(2))?;
    if status.success() {
        Ok(())
    } else {
        Err(Errno(status.code().unwrap_or(1)))
    }
}

#[cfg(target_os = "linux")]
pub fn load_module_best_effort(module: &str) -> Result<()> {
    if load_module(module).is_ok() {
        return Ok(());
    }
    load_module_via_modprobe(module)
}

#[cfg(not(target_os = "linux"))]
pub fn load_module_best_effort(_module: &str) -> Result<()> {
    Ok(())
}

pub fn read_proc_cmdline() -> Option<String> {
    std::fs::read_to_string("/proc/cmdline").ok()
}

pub fn parse_proc_cmdline_value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    for token in cmdline.split_whitespace() {
        if let Some(rest) = token.strip_prefix(key) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val);
            }
        }
    }
    None
}

pub fn load_modules_from_conf_dirs(set: &mut ModuleSet) -> Result<()> {
    for dir in CONF_FILE_DIRS {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut conf_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "conf")
                    .unwrap_or(false)
            })
            .collect();
        conf_files.sort_by_key(|e| e.file_name());

        for entry in conf_files {
            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                for name in line.split_whitespace() {
                    let normalized = normalise_module_name(name);
                    if is_module_name_valid(&normalized) {
                        set.append_suffix(name)?;
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_set_insert_and_contains() {
        let mut set = ModuleSet::new();
        assert!(set.is_empty());
        assert!(set.insert("ext4".into()));
        assert!(!set.insert("ext4".into())); // duplicate
        assert!(set.contains("ext4"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn module_set_append_suffix_strips_ko() {
        let mut set = ModuleSet::new();
        set.append_suffix("ext4.ko").unwrap();
        assert!(set.contains("ext4"));
    }

    #[test]
    fn module_set_append_suffix_strips_ko_zst() {
        let mut set = ModuleSet::new();
        set.append_suffix("nfs.ko.zst").unwrap();
        assert!(set.contains("nfs"));
    }

    #[test]
    fn module_set_append_suffix_no_suffix() {
        let mut set = ModuleSet::new();
        set.append_suffix("btrfs").unwrap();
        assert!(set.contains("btrfs"));
    }

    #[test]
    fn module_set_append_suffix_empty() {
        let mut set = ModuleSet::new();
        set.append_suffix("").unwrap();
        assert!(set.is_empty());
        set.append_suffix("   ").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn module_set_deduplication() {
        let mut set = ModuleSet::new();
        set.append_suffix("ext4.ko").unwrap();
        set.append_suffix("ext4").unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn parse_proc_cmdline_modules_basic() {
        let mut set = ModuleSet::new();
        parse_proc_cmdline_modules("modules_load", Some("ext4,nfs,btrfs"), &mut set).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains("ext4"));
        assert!(set.contains("nfs"));
        assert!(set.contains("btrfs"));
    }

    #[test]
    fn parse_proc_cmdline_modules_wrong_key() {
        let mut set = ModuleSet::new();
        parse_proc_cmdline_modules("other_key", Some("ext4"), &mut set).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_proc_cmdline_modules_no_value() {
        let mut set = ModuleSet::new();
        parse_proc_cmdline_modules("modules_load", None, &mut set).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn is_module_name_valid_cases() {
        assert!(is_module_name_valid("ext4"));
        assert!(is_module_name_valid("nfs-client"));
        assert!(is_module_name_valid("drm_kms_helper"));
        assert!(!is_module_name_valid(""));
        assert!(!is_module_name_valid("a b"));
        assert!(!is_module_name_valid("a/b"));
    }

    #[test]
    fn normalise_module_name_dashes() {
        assert_eq!(normalise_module_name("nfs-client"), "nfs_client");
        assert_eq!(
            normalise_module_name("already_underscore"),
            "already_underscore"
        );
        assert_eq!(normalise_module_name("mix-ed_name"), "mix_ed_name");
    }

    #[test]
    fn conf_file_dirs_nonempty() {
        assert!(!conf_file_dirs().is_empty());
    }

    #[test]
    fn module_set_to_sorted_vec() {
        let mut set = ModuleSet::new();
        set.insert("zfs".into());
        set.insert("ext4".into());
        set.insert("btrfs".into());
        assert_eq!(set.to_sorted_vec(), vec!["btrfs", "ext4", "zfs"]);
    }
}
