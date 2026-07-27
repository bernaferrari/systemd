// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-test-builtin.c
//
// udevadm test-builtin — test a built-in udev command against a device.
//
// Defines argument parsing, device-action resolution, and validation
// logic for the test-builtin subcommand.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default device action when none is specified on the command line.
pub const DEFAULT_ACTION: DeviceAction = DeviceAction::Add;

// ── Device action ─────────────────────────────────────────────────────────

/// Device actions recognised by the kernel and udev.
/// Mirrors `sd_device_action_t` from sd-device.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

impl DeviceAction {
    /// Parse a device action from a string.
    /// Returns `None` for unrecognised strings.
    pub fn from_str(s: &str) -> Option<DeviceAction> {
        match s {
            "add" => Some(DeviceAction::Add),
            "remove" => Some(DeviceAction::Remove),
            "change" => Some(DeviceAction::Change),
            "move" => Some(DeviceAction::Move),
            "online" => Some(DeviceAction::Online),
            "offline" => Some(DeviceAction::Offline),
            "bind" => Some(DeviceAction::Bind),
            "unbind" => Some(DeviceAction::Unbind),
            _ => None,
        }
    }

    /// Convert to the string the kernel understands.
    pub fn to_str(self) -> &'static str {
        match self {
            DeviceAction::Add => "add",
            DeviceAction::Remove => "remove",
            DeviceAction::Change => "change",
            DeviceAction::Move => "move",
            DeviceAction::Online => "online",
            DeviceAction::Offline => "offline",
            DeviceAction::Bind => "bind",
            DeviceAction::Unbind => "unbind",
        }
    }

    /// All action variants, for help / listing.
    pub fn all() -> &'static [DeviceAction] {
        &[
            DeviceAction::Add,
            DeviceAction::Remove,
            DeviceAction::Change,
            DeviceAction::Move,
            DeviceAction::Online,
            DeviceAction::Offline,
            DeviceAction::Bind,
            DeviceAction::Unbind,
        ]
    }
}

// ── Builtin command lookup ────────────────────────────────────────────────

/// Names of the built-in commands, as registered via `udev_builtin_list()`.
/// Mirrors the dispatch table in udev-builtin.c.
pub const BUILTIN_COMMANDS: &[&str] = &[
    "blkid",
    "btrfs",
    "dmsetup",
    "firmware",
    "hwdb",
    "input_id",
    "keyboard",
    "kmod",
    "net_driver",
    "net_id",
    "net_setup_link",
    "path_id",
    "tpm2_id",
    "usb_id",
    "uaccess",
];

/// Look up a builtin command by name.
/// Returns the command string if found, or an error.
pub fn lookup_builtin(name: &str) -> Result<&'static str, BuiltinError> {
    BUILTIN_COMMANDS
        .iter()
        .find(|&&cmd| cmd == name)
        .copied()
        .ok_or_else(|| BuiltinError::UnknownCommand(name.to_string()))
}

// ── Parsed arguments ──────────────────────────────────────────────────────

/// Holds the result of parsing argv for `test-builtin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBuiltinArgs {
    /// Device action (defaults to ADD).
    pub action: DeviceAction,
    /// Built-in command to invoke.
    pub command: String,
    /// Syspath of the target device.
    pub syspath: String,
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinError {
    /// The user asked for --help.
    HelpRequested,
    /// The user asked for --version.
    VersionRequested,
    /// Unrecognised option.
    InvalidOption(String),
    /// The device action string could not be parsed.
    InvalidAction(String),
    /// Wrong number of positional arguments.
    WrongArgumentCount { expected: usize, got: usize },
    /// The specified builtin command does not exist.
    UnknownCommand(String),
}

impl std::fmt::Display for BuiltinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuiltinError::HelpRequested => write!(f, "help requested"),
            BuiltinError::VersionRequested => write!(f, "version requested"),
            BuiltinError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            BuiltinError::InvalidAction(s) => write!(f, "Invalid action '{s}'"),
            BuiltinError::WrongArgumentCount { expected, got } => {
                write!(f, "Expected {expected} positional arguments, got {got}")
            }
            BuiltinError::UnknownCommand(cmd) => {
                write!(f, "Unknown command '{cmd}'")
            }
        }
    }
}

impl std::error::Error for BuiltinError {}

// ── Argument validation ───────────────────────────────────────────────────

/// Validate that exactly two positional arguments (command, syspath) are present.
pub fn validate_positional_args<'a>(
    args: &'a [&'a str],
) -> Result<(&'a str, &'a str), BuiltinError> {
    if args.len() != 2 {
        return Err(BuiltinError::WrongArgumentCount {
            expected: 2,
            got: args.len(),
        });
    }
    Ok((args[0], args[1]))
}

/// Fully validate and build a `TestBuiltinArgs` from the parsed components.
pub fn build_args(
    action: DeviceAction,
    positional: &[&str],
) -> Result<TestBuiltinArgs, BuiltinError> {
    let (cmd, syspath) = validate_positional_args(positional)?;
    lookup_builtin(cmd)?;
    Ok(TestBuiltinArgs {
        action,
        command: cmd.to_string(),
        syspath: syspath.to_string(),
    })
}

// ── Help text ─────────────────────────────────────────────────────────────

/// Build the help string for the test-builtin subcommand.
/// Mirrors the C `help()` function.
pub fn help_text(program_name: &str) -> String {
    let mut out = format!(
        "{program_name} test-builtin [OPTIONS] COMMAND DEVPATH\n\n\
         Test a built-in command.\n\n\
          -h --help               Print this message\n\
         -V --version            Print version of the program\n\
         -a --action=ACTION|help Set action string\n\
         \nCommands:\n"
    );
    for cmd in BUILTIN_COMMANDS {
        out.push_str(&format!("  {cmd}\n"));
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_action_roundtrip() {
        for action in DeviceAction::all() {
            assert_eq!(DeviceAction::from_str(action.to_str()), Some(*action));
        }
    }

    #[test]
    fn test_device_action_unknown() {
        assert_eq!(DeviceAction::from_str("unknown"), None);
        assert_eq!(DeviceAction::from_str(""), None);
    }

    #[test]
    fn test_device_action_default() {
        assert_eq!(DEFAULT_ACTION, DeviceAction::Add);
    }

    #[test]
    fn test_lookup_builtin_found() {
        assert_eq!(lookup_builtin("blkid"), Ok("blkid"));
        assert_eq!(lookup_builtin("hwdb"), Ok("hwdb"));
        assert_eq!(lookup_builtin("usb_id"), Ok("usb_id"));
    }

    #[test]
    fn test_lookup_builtin_unknown() {
        assert!(matches!(
            lookup_builtin("nonexistent"),
            Err(BuiltinError::UnknownCommand(_))
        ));
    }

    #[test]
    fn test_validate_positional_args_ok() {
        let result = validate_positional_args(&["blkid", "/sys/devices/test"]);
        assert_eq!(result.unwrap(), ("blkid", "/sys/devices/test"));
    }

    #[test]
    fn test_validate_positional_args_wrong_count() {
        assert!(matches!(
            validate_positional_args(&["onlyone"]),
            Err(BuiltinError::WrongArgumentCount {
                expected: 2,
                got: 1
            })
        ));
        assert!(matches!(
            validate_positional_args(&["a", "b", "c"]),
            Err(BuiltinError::WrongArgumentCount {
                expected: 2,
                got: 3
            })
        ));
        assert!(matches!(
            validate_positional_args(&[]),
            Err(BuiltinError::WrongArgumentCount {
                expected: 2,
                got: 0
            })
        ));
    }

    #[test]
    fn test_build_args_success() {
        let args = build_args(DeviceAction::Add, &["blkid", "/sys/dev/test"]).unwrap();
        assert_eq!(args.action, DeviceAction::Add);
        assert_eq!(args.command, "blkid");
        assert_eq!(args.syspath, "/sys/dev/test");
    }

    #[test]
    fn test_build_args_unknown_command() {
        let result = build_args(DeviceAction::Add, &["badcmd", "/sys/dev/test"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_help_text_contains_commands() {
        let help = help_text("udevadm");
        assert!(help.contains("blkid"));
        assert!(help.contains("hwdb"));
        assert!(help.contains("--help"));
        assert!(help.contains("--action"));
    }

    #[test]
    fn test_error_display() {
        let err = BuiltinError::InvalidAction("bogus".to_string());
        assert!(err.to_string().contains("bogus"));

        let err = BuiltinError::WrongArgumentCount {
            expected: 2,
            got: 0,
        };
        assert!(err.to_string().contains("2"));
        assert!(err.to_string().contains("0"));
    }
}
