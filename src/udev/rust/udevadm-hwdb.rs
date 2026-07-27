// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udevadm-hwdb.c
//
// udevadm hwdb — hardware database management (deprecated).
//
// Provides option definitions, validation, and deprecation notice
// for the hwdb subcommand. Users should use systemd-hwdb instead.

// ── Constants ─────────────────────────────────────────────────────────────

pub const ARG_USR: i32 = 0x100;

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HwdbArgs {
    pub test: Option<String>,
    pub root: Option<String>,
    pub hwdb_bin_dir: Option<String>,
    pub update: bool,
    pub strict: bool,
}

impl HwdbArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── Validation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwdbParseError {
    HelpRequested,
    VersionRequested,
    NeitherUpdateNorTest,
    InvalidOption(String),
}

impl std::fmt::Display for HwdbParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HwdbParseError::HelpRequested => write!(f, "help requested"),
            HwdbParseError::VersionRequested => write!(f, "version requested"),
            HwdbParseError::NeitherUpdateNorTest => {
                write!(f, "Either --update or --test must be used.")
            }
            HwdbParseError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
        }
    }
}

impl std::error::Error for HwdbParseError {}

/// Validate that at least one of --update or --test is specified.
pub fn validate_args(args: &HwdbArgs) -> Result<(), HwdbParseError> {
    if !args.update && args.test.is_none() {
        return Err(HwdbParseError::NeitherUpdateNorTest);
    }
    Ok(())
}

/// Returns the deprecation notice text.
pub fn deprecation_notice() -> &'static str {
    "udevadm hwdb is deprecated. Use systemd-hwdb instead."
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} hwdb [OPTIONS]\n\n\
         -h --help            Print this message\n\
         -V --version         Print version of the program\n\
         -u --update          Update the hardware database\n\
         -s --strict          When updating, return non-zero exit value on any parsing error\n\
            --usr             Generate in /usr/lib/udev instead of /etc/udev\n\
         -t --test=MODALIAS   Query database and print result\n\
         -r --root=PATH       Alternative root path in the filesystem\n\n\
         NOTE:\n\
         The sub-command 'hwdb' is deprecated, and is left for backwards compatibility.\n\
         Please use systemd-hwdb instead.\n"
    )
}

// ── Option table ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwdbOption {
    pub name: &'static str,
    pub has_arg: bool,
    pub val: i32,
}

pub fn long_options() -> Vec<HwdbOption> {
    vec![
        HwdbOption {
            name: "update",
            has_arg: false,
            val: 'u' as i32,
        },
        HwdbOption {
            name: "usr",
            has_arg: false,
            val: ARG_USR,
        },
        HwdbOption {
            name: "strict",
            has_arg: false,
            val: 's' as i32,
        },
        HwdbOption {
            name: "test",
            has_arg: true,
            val: 't' as i32,
        },
        HwdbOption {
            name: "root",
            has_arg: true,
            val: 'r' as i32,
        },
        HwdbOption {
            name: "version",
            has_arg: false,
            val: 'V' as i32,
        },
        HwdbOption {
            name: "help",
            has_arg: false,
            val: 'h' as i32,
        },
    ]
}

pub const SHORT_OPTS: &str = "ust:r:Vh";

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hwdb_args_default() {
        let args = HwdbArgs::new();
        assert!(args.test.is_none());
        assert!(args.root.is_none());
        assert!(args.hwdb_bin_dir.is_none());
        assert!(!args.update);
        assert!(!args.strict);
    }

    #[test]
    fn test_validate_args_update() {
        let args = HwdbArgs {
            update: true,
            ..Default::default()
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_validate_args_test() {
        let args = HwdbArgs {
            test: Some("usb:v*p*".to_string()),
            ..Default::default()
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_validate_args_both() {
        let args = HwdbArgs {
            update: true,
            test: Some("usb:v*p*".to_string()),
            ..Default::default()
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_validate_args_neither() {
        let args = HwdbArgs::new();
        let result = validate_args(&args);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HwdbParseError::NeitherUpdateNorTest);
    }

    #[test]
    fn test_deprecation_notice() {
        let notice = deprecation_notice();
        assert!(notice.contains("deprecated"));
        assert!(notice.contains("systemd-hwdb"));
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--update"));
        assert!(help.contains("--test"));
        assert!(help.contains("--strict"));
        assert!(help.contains("--root"));
        assert!(help.contains("deprecated"));
    }

    #[test]
    fn test_long_options() {
        let opts = long_options();
        assert_eq!(opts.len(), 7);
        assert!(opts.iter().any(|o| o.name == "update" && !o.has_arg));
        assert!(opts.iter().any(|o| o.name == "test" && o.has_arg));
        assert!(opts.iter().any(|o| o.name == "usr" && o.val == ARG_USR));
    }

    #[test]
    fn test_short_opts() {
        assert_eq!(SHORT_OPTS, "ust:r:Vh");
    }
}
