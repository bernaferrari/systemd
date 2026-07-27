// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-cat.c
//
// udevadm cat — display udev rules or configuration files.
//
// Provides option parsing and validation for the `udevadm cat` subcommand,
// which concatenates and displays udev rules files or the udev.conf file.

// ── Option constants ─────────────────────────────────────────────────────

/// Long-option values that don't map to a short character.
pub const ARG_ROOT: i32 = 0x100;
pub const ARG_TLDR: i32 = 0x101;
pub const ARG_CONFIG: i32 = 0x102;

// ── Cat flags ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatFlags(u32);

impl CatFlags {
    pub const NONE: CatFlags = CatFlags(0);
    pub const TLDR: CatFlags = CatFlags(1);

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, other: CatFlags) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn empty() -> Self {
        CatFlags(0)
    }
}

impl Default for CatFlags {
    fn default() -> Self {
        CatFlags::empty()
    }
}

// ── Parsed arguments ──────────────────────────────────────────────────────

/// Parsed command-line arguments for `udevadm cat`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatArgs {
    pub root: Option<String>,
    pub cat_flags: CatFlags,
    pub show_config: bool,
    pub files: Vec<String>,
}

impl CatArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Errors from argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatParseError {
    HelpRequested,
    VersionRequested,
    ConfigWithFiles,
    InvalidOption(String),
}

impl std::fmt::Display for CatParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatParseError::HelpRequested => write!(f, "help requested"),
            CatParseError::VersionRequested => write!(f, "version requested"),
            CatParseError::ConfigWithFiles => {
                write!(f, "Combination of --config and FILEs is not supported.")
            }
            CatParseError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
        }
    }
}

impl std::error::Error for CatParseError {}

/// Long option definition for getopt-style parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongOption {
    pub name: &'static str,
    pub has_arg: bool,
    pub val: i32,
}

/// Returns the supported long options for `udevadm cat`.
pub fn long_options() -> Vec<LongOption> {
    vec![
        LongOption {
            name: "help",
            has_arg: false,
            val: 'h' as i32,
        },
        LongOption {
            name: "version",
            has_arg: false,
            val: 'V' as i32,
        },
        LongOption {
            name: "root",
            has_arg: true,
            val: ARG_ROOT,
        },
        LongOption {
            name: "tldr",
            has_arg: false,
            val: ARG_TLDR,
        },
        LongOption {
            name: "config",
            has_arg: false,
            val: ARG_CONFIG,
        },
    ]
}

/// The short options string accepted by `udevadm cat`.
pub const SHORT_OPTS: &str = "hV";

/// Validate parsed arguments for consistency.
/// Returns an error if `--config` is combined with positional file arguments.
pub fn validate_args(args: &CatArgs) -> Result<(), CatParseError> {
    if args.show_config && !args.files.is_empty() {
        return Err(CatParseError::ConfigWithFiles);
    }
    Ok(())
}

/// Determine the config file path when --config is specified.
pub fn config_file_path(root: Option<&str>) -> String {
    match root {
        Some(r) => format!("{r}/udev/udev.conf"),
        None => "udev/udev.conf".to_string(),
    }
}

// ── Help text ─────────────────────────────────────────────────────────────

/// Returns the help text for `udevadm cat`.
pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} cat [OPTIONS] [FILE...]\n\
         \nShow udev rules files.\n\n\
         -h --help            Show this help\n\
         -V --version         Show package version\n\
            --root=PATH       Operate on an alternate filesystem root\n\
            --tldr            Skip comments and empty lines\n\
            --config          Show udev.conf rather than udev rules files\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cat_flags_default() {
        assert_eq!(CatFlags::NONE, CatFlags::empty());
        assert!(CatFlags::NONE.is_empty());
    }

    #[test]
    fn test_cat_flags_tldr() {
        assert!(!CatFlags::TLDR.is_empty());
        assert!(CatFlags::TLDR.contains(CatFlags::TLDR));
    }

    #[test]
    fn test_cat_args_default() {
        let args = CatArgs::new();
        assert!(args.root.is_none());
        assert!(args.cat_flags.is_empty());
        assert!(!args.show_config);
        assert!(args.files.is_empty());
    }

    #[test]
    fn test_validate_args_config_no_files() {
        let args = CatArgs {
            show_config: true,
            files: vec![],
            ..Default::default()
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_validate_args_config_with_files_rejected() {
        let args = CatArgs {
            show_config: true,
            files: vec!["/etc/udev/rules.d/99-test.rules".to_string()],
            ..Default::default()
        };
        let result = validate_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CatParseError::ConfigWithFiles);
    }

    #[test]
    fn test_validate_args_no_config_with_files_ok() {
        let args = CatArgs {
            show_config: false,
            files: vec!["99-test.rules".to_string()],
            ..Default::default()
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_config_file_path_no_root() {
        assert_eq!(config_file_path(None), "udev/udev.conf");
    }

    #[test]
    fn test_config_file_path_with_root() {
        assert_eq!(
            config_file_path(Some("/mnt/sysroot")),
            "/mnt/sysroot/udev/udev.conf"
        );
    }

    #[test]
    fn test_help_text_contains_key_options() {
        let help = help_text("udevadm");
        assert!(help.contains("--help"));
        assert!(help.contains("--version"));
        assert!(help.contains("--root"));
        assert!(help.contains("--tldr"));
        assert!(help.contains("--config"));
    }

    #[test]
    fn test_long_options_table() {
        let opts = long_options();
        assert_eq!(opts.len(), 5);
        assert!(opts.iter().any(|o| o.name == "root" && o.has_arg));
        assert!(opts.iter().any(|o| o.name == "tldr" && !o.has_arg));
        assert!(opts.iter().any(|o| o.name == "config" && !o.has_arg));
    }

    #[test]
    fn test_short_opts_string() {
        assert_eq!(SHORT_OPTS, "hV");
    }
}
