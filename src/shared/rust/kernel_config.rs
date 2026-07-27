// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/kernel-config.c
//
// Kernel install configuration file parser.
//
// Parses kernel/install.conf files which define machine ID, boot root,
// layout, and generator settings for kernel installation.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default configuration file path relative to the system prefix.
pub const KERNEL_INSTALL_CONF: &str = "kernel/install.conf";

/// Valid configuration keys recognized in install.conf.
pub const VALID_KEYS: &[&str] = &[
    "MACHINE_ID",
    "BOOT_ROOT",
    "layout",
    "initrd_generator",
    "uki_generator",
];

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during kernel install configuration parsing.
#[derive(Debug)]
pub enum KernelConfigError {
    /// An I/O error occurred reading the configuration file.
    Io(io::Error),
    /// The configuration file was not found.
    NotFound(PathBuf),
}

impl fmt::Display for KernelConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelConfigError::Io(e) => write!(f, "I/O error: {}", e),
            KernelConfigError::NotFound(p) => {
                write!(f, "Configuration file not found: {}", p.display())
            }
        }
    }
}

impl std::error::Error for KernelConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KernelConfigError::Io(e) => Some(e),
            KernelConfigError::NotFound(_) => None,
        }
    }
}

impl From<io::Error> for KernelConfigError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => {
                KernelConfigError::NotFound(PathBuf::new()) // caller should set path
            }
            _ => KernelConfigError::Io(e),
        }
    }
}

// ── Data structures ───────────────────────────────────────────────────────

/// Parsed kernel install configuration.
///
/// All fields are optional; missing keys yield `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelInstallConfig {
    /// Machine ID for the kernel installation.
    pub machine_id: Option<String>,
    /// Boot root directory path.
    pub boot_root: Option<String>,
    /// Installation layout (e.g. "bls").
    pub layout: Option<String>,
    /// Initrd generator command.
    pub initrd_generator: Option<String>,
    /// UKI (Unified Kernel Image) generator command.
    pub uki_generator: Option<String>,
}

impl KernelInstallConfig {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if no fields are set.
    pub fn is_empty(&self) -> bool {
        self.machine_id.is_none()
            && self.boot_root.is_none()
            && self.layout.is_none()
            && self.initrd_generator.is_none()
            && self.uki_generator.is_none()
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse a single configuration line into a (key, value) pair.
///
/// Handles:
/// - Leading/trailing whitespace trimming
/// - `#` and `;` comment lines (returns `None`)
/// - Empty/whitespace-only lines (returns `None`)
/// - `KEY=VALUE` format with optional whitespace around `=`
/// - Lines without `=` or with an empty key (returns `None`)
///
/// Unknown keys are returned; callers decide whether to accept them.
pub fn parse_install_conf_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value.trim()))
}

/// Check whether a key is a recognized install.conf key.
pub fn is_valid_key(key: &str) -> bool {
    VALID_KEYS.contains(&key)
}

/// Parse a configuration string (full file contents) into a [`KernelInstallConfig`].
///
/// Unknown keys are silently ignored, matching the C implementation behavior.
pub fn parse_install_conf(contents: &str) -> KernelInstallConfig {
    let mut config = KernelInstallConfig::default();
    for line in contents.lines() {
        if let Some((key, value)) = parse_install_conf_line(line) {
            match key {
                "MACHINE_ID" => config.machine_id = Some(value.to_string()),
                "BOOT_ROOT" => config.boot_root = Some(value.to_string()),
                "layout" => config.layout = Some(value.to_string()),
                "initrd_generator" => config.initrd_generator = Some(value.to_string()),
                "uki_generator" => config.uki_generator = Some(value.to_string()),
                _ => {} // ignore unknown keys
            }
        }
    }
    config
}

/// Parse a kernel install configuration file from disk.
///
/// Returns the parsed [`KernelInstallConfig`] on success, or a
/// [`KernelConfigError`] on failure.
pub fn load_kernel_install_conf(path: &Path) -> Result<KernelInstallConfig, KernelConfigError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            KernelConfigError::NotFound(path.to_path_buf())
        } else {
            KernelConfigError::Io(e)
        }
    })?;
    Ok(parse_install_conf(&contents))
}

/// Resolve the configuration file path and load it.
///
/// If `root` is `Some`, prepends it to the path. If `conf_root` is `Some`,
/// uses `<conf_root>/install.conf` instead of the default path.
pub fn load_kernel_install_conf_at(
    root: Option<&Path>,
    conf_root: Option<&Path>,
) -> Result<KernelInstallConfig, KernelConfigError> {
    let conf_path = match conf_root {
        Some(cr) => cr.join("install.conf"),
        None => PathBuf::from(KERNEL_INSTALL_CONF),
    };

    let full_path = match root {
        Some(r) => r.join(&conf_path),
        None => conf_path,
    };

    load_kernel_install_conf(&full_path)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::Write;

    // ── parse_install_conf_line tests ──

    #[test]
    fn test_parse_line_simple_key_value() {
        assert_eq!(
            parse_install_conf_line("MACHINE_ID=abc123"),
            Some(("MACHINE_ID", "abc123"))
        );
    }

    #[test]
    fn test_parse_line_whitespace_around_equals() {
        assert_eq!(
            parse_install_conf_line("  BOOT_ROOT = /boot  "),
            Some(("BOOT_ROOT", "/boot"))
        );
    }

    #[test]
    fn test_parse_line_hash_comment() {
        assert_eq!(parse_install_conf_line("# this is a comment"), None);
    }

    #[test]
    fn test_parse_line_semicolon_comment() {
        assert_eq!(parse_install_conf_line("; this is a comment"), None);
    }

    #[test]
    fn test_parse_line_empty() {
        assert_eq!(parse_install_conf_line(""), None);
        assert_eq!(parse_install_conf_line("   "), None);
    }

    #[test]
    fn test_parse_line_no_equals() {
        assert_eq!(parse_install_conf_line("JUST_A_WORD"), None);
    }

    #[test]
    fn test_parse_line_empty_key() {
        assert_eq!(parse_install_conf_line("=value"), None);
        assert_eq!(parse_install_conf_line("  =value"), None);
    }

    #[test]
    fn test_parse_line_empty_value() {
        assert_eq!(
            parse_install_conf_line("MACHINE_ID="),
            Some(("MACHINE_ID", ""))
        );
    }

    #[test]
    fn test_parse_line_value_with_spaces() {
        assert_eq!(
            parse_install_conf_line("layout=bls layout"),
            Some(("layout", "bls layout"))
        );
    }

    #[test]
    fn test_parse_line_value_with_equals() {
        // Only the first '=' separates key from value
        assert_eq!(
            parse_install_conf_line("initrd_generator=foo=bar"),
            Some(("initrd_generator", "foo=bar"))
        );
    }

    // ── is_valid_key tests ──

    #[test]
    fn test_is_valid_key_known() {
        for key in VALID_KEYS {
            assert!(is_valid_key(key), "expected {} to be valid", key);
        }
    }

    #[test]
    fn test_is_valid_key_unknown() {
        assert!(!is_valid_key("UNKNOWN_KEY"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("machine_id")); // case-sensitive
    }

    // ── parse_install_conf tests ──

    #[test]
    fn test_parse_empty_contents() {
        let config = parse_install_conf("");
        assert!(config.is_empty());
    }

    #[test]
    fn test_parse_all_keys() {
        let contents = "\
MACHINE_ID=deadbeef
BOOT_ROOT=/boot
layout=bls
initrd_generator=dracut
uki_generator=ukify
";
        let config = parse_install_conf(contents);
        assert_eq!(config.machine_id.as_deref(), Some("deadbeef"));
        assert_eq!(config.boot_root.as_deref(), Some("/boot"));
        assert_eq!(config.layout.as_deref(), Some("bls"));
        assert_eq!(config.initrd_generator.as_deref(), Some("dracut"));
        assert_eq!(config.uki_generator.as_deref(), Some("ukify"));
        assert!(!config.is_empty());
    }

    #[test]
    fn test_parse_with_comments_and_blank_lines() {
        let contents = "\
# Top comment
MACHINE_ID=abc123

; Another comment
BOOT_ROOT=/boot
";
        let config = parse_install_conf(contents);
        assert_eq!(config.machine_id.as_deref(), Some("abc123"));
        assert_eq!(config.boot_root.as_deref(), Some("/boot"));
        assert!(config.layout.is_none());
    }

    #[test]
    fn test_parse_unknown_keys_ignored() {
        let contents = "UNKNOWN=something\nMACHINE_ID=123\nALSO_UNKNOWN=foo";
        let config = parse_install_conf(contents);
        assert_eq!(config.machine_id.as_deref(), Some("123"));
        assert!(config.boot_root.is_none());
    }

    #[test]
    fn test_parse_last_key_wins() {
        let contents = "MACHINE_ID=first\nMACHINE_ID=second";
        let config = parse_install_conf(contents);
        assert_eq!(config.machine_id.as_deref(), Some("second"));
    }

    // ── KernelInstallConfig tests ──

    #[test]
    fn test_config_default_is_empty() {
        let config = KernelInstallConfig::default();
        assert!(config.is_empty());
    }

    #[test]
    fn test_config_new_is_empty() {
        let config = KernelInstallConfig::new();
        assert!(config.is_empty());
    }

    #[test]
    fn test_config_equality() {
        let a = KernelInstallConfig {
            machine_id: Some("abc".into()),
            boot_root: None,
            layout: None,
            initrd_generator: None,
            uki_generator: None,
        };
        let b = KernelInstallConfig {
            machine_id: Some("abc".into()),
            boot_root: None,
            layout: None,
            initrd_generator: None,
            uki_generator: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_config_clone() {
        let config = parse_install_conf("MACHINE_ID=abc");
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    // ── load_kernel_install_conf tests (file I/O) ──

    #[test]
    fn test_load_conf_not_found() {
        let result = load_kernel_install_conf(Path::new("/nonexistent/path/install.conf"));
        match result {
            Err(KernelConfigError::NotFound(p)) => {
                assert!(p.to_str().unwrap().contains("nonexistent"));
            }
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_load_conf_valid_file() {

        let conf_path = std::env::temp_dir().join("systemd_kc_test_install.conf");
        std::fs::write(&conf_path, "MACHINE_ID=abc123
BOOT_ROOT=/boot
layout=bls
").unwrap();

        let config = load_kernel_install_conf(&conf_path).unwrap();
        assert_eq!(config.machine_id.as_deref(), Some("abc123"));
        assert_eq!(config.boot_root.as_deref(), Some("/boot"));
        assert_eq!(config.layout.as_deref(), Some("bls"));
    }

    #[test]
    fn test_load_conf_valid_file_from_dir() {
        let dir = std::env::temp_dir().join("systemd_kernel_config_test_valid");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("install.conf");
        let mut f = fs::File::create(&file_path).unwrap();
        write!(f, "MACHINE_ID=abc123\nBOOT_ROOT=/boot\nlayout=bls\n").unwrap();
        drop(f);

        let config = load_kernel_install_conf(&file_path).unwrap();
        assert_eq!(config.machine_id.as_deref(), Some("abc123"));
        assert_eq!(config.boot_root.as_deref(), Some("/boot"));
        assert_eq!(config.layout.as_deref(), Some("bls"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_conf_empty_file() {
        let dir = std::env::temp_dir().join("systemd_kernel_config_test_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("install.conf");
        fs::write(&file_path, "").unwrap();

        let config = load_kernel_install_conf(&file_path).unwrap();
        assert!(config.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    // ── load_kernel_install_conf_at tests ──

    #[test]
    fn test_load_conf_at_no_root_no_conf_root() {
        // Should look for kernel/install.conf which likely doesn't exist
        let result = load_kernel_install_conf_at(None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_conf_at_with_root() {
        let dir = std::env::temp_dir().join("systemd_kernel_config_at_root");
        let _ = fs::remove_dir_all(&dir);
        let conf_dir = dir.join("kernel");
        fs::create_dir_all(&conf_dir).unwrap();
        fs::write(conf_dir.join("install.conf"), "MACHINE_ID=xyz\n").unwrap();

        let config = load_kernel_install_conf_at(Some(&dir), None).unwrap();
        assert_eq!(config.machine_id.as_deref(), Some("xyz"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_conf_at_with_conf_root() {
        let dir = std::env::temp_dir().join("systemd_kernel_config_at_conf_root");
        let _ = fs::remove_dir_all(&dir);
        let conf_root = dir.join("etc");
        fs::create_dir_all(&conf_root).unwrap();
        fs::write(conf_root.join("install.conf"), "BOOT_ROOT=/myboot\n").unwrap();

        let config = load_kernel_install_conf_at(None, Some(conf_root.as_path())).unwrap();
        assert_eq!(config.boot_root.as_deref(), Some("/myboot"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_conf_at_with_root_and_conf_root() {
        let root_dir = std::env::temp_dir().join("systemd_kernel_config_at_both");
        let _ = fs::remove_dir_all(&root_dir);
        let conf_root = PathBuf::from("custom");
        let full_conf_root = root_dir.join(&conf_root);
        fs::create_dir_all(&full_conf_root).unwrap();
        fs::write(
            full_conf_root.join("install.conf"),
            "layout=custom_layout\n",
        )
        .unwrap();

        let config =
            load_kernel_install_conf_at(Some(&root_dir), Some(conf_root.as_path())).unwrap();
        assert_eq!(config.layout.as_deref(), Some("custom_layout"));

        let _ = fs::remove_dir_all(&root_dir);
    }

    // ── KernelConfigError tests ──

    #[test]
    fn test_error_display_not_found() {
        let err = KernelConfigError::NotFound(PathBuf::from("/missing/file"));
        let msg = format!("{}", err);
        assert!(msg.contains("/missing/file"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_error_display_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = KernelConfigError::Io(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("access denied"));
    }

    #[test]
    fn test_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = KernelConfigError::Io(io_err);
        assert!(err.source().is_some());

        let err = KernelConfigError::NotFound(PathBuf::from("/x"));
        assert!(err.source().is_none());
    }
}
