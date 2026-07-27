// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/modules-load/modules-load.c
//
// Loads statically configured kernel modules.
//
// Reads module names from /etc/modules-load.d/*.conf, the kernel
// command line (modules_load=), and optional CLI arguments.
// Module names are normalized: dashes become underscores and
// duplicates are removed.

use std::collections::HashSet;

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum module name length, matching MODULE_NAME_MAX_LEN in C.
pub const MODULE_NAME_MAX_LEN: usize = 4096;

/// Standard configuration file search directories.
pub const CONF_FILE_DIRS: &[&str] = &[
    "/etc/modules-load.d",
    "/run/modules-load.d",
    "/usr/local/lib/modules-load.d",
    "/usr/lib/modules-load.d",
];

// ── ModuleSet ─────────────────────────────────────────────────────────────

/// An ordered, deduplicated set of kernel module names.
pub struct ModuleSet {
    modules: HashSet<String>,
}

impl Default for ModuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleSet {
    pub fn new() -> Self {
        Self {
            modules: HashSet::new(),
        }
    }

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

    pub fn to_vec(&self) -> Vec<&str> {
        self.modules.iter().map(|s| s.as_str()).collect()
    }

    /// Add a module name, stripping .ko / .ko.zst suffixes and
    /// normalizing dashes to underscores.
    pub fn append_suffix(&mut self, mod_with_suffix: &str) -> Result<()> {
        let module = mod_with_suffix.trim();
        if module.is_empty() {
            return Ok(());
        }
        let cleaned = module
            .strip_suffix(".ko")
            .or_else(|| module.strip_suffix(".ko.zst"));
        let name = cleaned.unwrap_or(module);
        self.modules.insert(name.to_string());
        Ok(())
    }

    pub fn append(&mut self, module: &str) -> Result<()> {
        if module.is_empty() {
            return Ok(());
        }
        self.modules.insert(module.to_string());
        Ok(())
    }
}

// ── Module name normalization ─────────────────────────────────────────────

/// Normalize a module name: replace '-' with '_' for deduplication.
/// kmod treats these interchangeably.
pub fn normalize_module_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Validate a module name: non-empty, <256 chars, ASCII alphanumeric/dash/underscore.
pub fn is_module_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── Config file parsing ───────────────────────────────────────────────────

/// Check if a line is a comment (starts with # or ;).
pub fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('#') || trimmed.starts_with(';')
}

/// Parse a single config file line into a module name.
/// Returns None for empty lines and comments.
pub fn parse_config_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || is_comment_line(trimmed) {
        return None;
    }
    Some(normalize_module_name(trimmed))
}

/// Parse a full config file content into module names.
pub fn parse_config_content(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| parse_config_line(line))
        .collect()
}

// ── Kernel command line parsing ───────────────────────────────────────────

/// Parse the modules_load= kernel command line value.
/// Splits on commas and adds each module to the set.
pub fn parse_proc_cmdline_modules(
    key: &str,
    value: Option<&str>,
    module_set: &mut ModuleSet,
) -> Result<()> {
    if key == "modules_load" {
        if let Some(v) = value {
            for module in v.split(',') {
                let normalized = normalize_module_name(module.trim());
                module_set.append(&normalized)?;
            }
        }
    }
    Ok(())
}

// ── Worker thread helpers ─────────────────────────────────────────────────

/// Determine the number of worker threads for parallel module loading.
/// Uses min(online_cpus, max_threads) and ensures at least 1.
pub fn determine_num_worker_threads(
    n_modules: usize,
    online_cpus: usize,
    max_threads: usize,
) -> usize {
    if n_modules == 0 {
        return 0;
    }
    let base = online_cpus.clamp(1, max_threads);
    let actual = base.clamp(1, n_modules);
    actual.saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_set_insert_dedup() {
        let mut set = ModuleSet::new();
        assert!(set.is_empty());
        assert!(set.insert("ext4".into()));
        assert!(!set.insert("ext4".into()));
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
    fn module_set_empty_suffix_noop() {
        let mut set = ModuleSet::new();
        set.append_suffix("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn normalize_module_names() {
        assert_eq!(normalize_module_name("drm-kms"), "drm_kms");
        assert_eq!(normalize_module_name("ext4"), "ext4");
        assert_eq!(normalize_module_name("a-b-c"), "a_b_c");
    }

    #[test]
    fn module_name_validation() {
        assert!(is_module_name_valid("ext4"));
        assert!(is_module_name_valid("nfs-client"));
        assert!(is_module_name_valid("drm_kms_helper"));
        assert!(!is_module_name_valid(""));
        assert!(!is_module_name_valid("a b"));
    }

    #[test]
    fn comment_line_detection() {
        assert!(is_comment_line("# comment"));
        assert!(is_comment_line("; comment"));
        assert!(!is_comment_line("ext4"));
        assert!(!is_comment_line(""));
    }

    #[test]
    fn parse_config_lines() {
        let content = "# comment\next4\n\nnfs\nbtrfs";
        let modules = parse_config_content(content);
        assert_eq!(modules, vec!["ext4", "nfs", "btrfs"]);
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
    fn worker_thread_count() {
        assert_eq!(determine_num_worker_threads(0, 4, 16), 0);
        assert_eq!(determine_num_worker_threads(10, 4, 16), 3);
        assert_eq!(determine_num_worker_threads(2, 16, 16), 1);
        assert_eq!(determine_num_worker_threads(1, 4, 16), 0);
    }

    #[test]
    fn to_sorted_vec_returns_sorted() {
        let mut set = ModuleSet::new();
        set.insert("zfs".into());
        set.insert("ext4".into());
        set.insert("btrfs".into());
        assert_eq!(set.to_sorted_vec(), vec!["btrfs", "ext4", "zfs"]);
    }
}

impl ModuleSet {
    pub fn to_sorted_vec(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.modules.iter().map(|s| s.as_str()).collect();
        v.sort();
        v
    }
}

pub fn read_proc_cmdline() -> Option<String> {
    std::fs::read_to_string("/proc/cmdline").ok()
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
            for name in parse_config_content(&content) {
                let normalized = normalize_module_name(&name);
                if is_module_name_valid(&normalized) {
                    let _ = set.append(&normalized);
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn load_module_best_effort(module: &str) -> Result<()> {
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

#[cfg(not(target_os = "linux"))]
pub fn load_module_best_effort(_module: &str) -> Result<()> {
    Ok(())
}
