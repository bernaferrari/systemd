// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-trigger.c
//
// udevadm trigger — request device events from the kernel.
//
// Defines scan-type enumeration, match-filter collection, argument
// validation, and device-list execution logic for the trigger subcommand.

// ── Scan type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Devices,
    Subsystems,
    All,
}

impl ScanType {
    pub fn from_str(s: &str) -> Option<ScanType> {
        match s {
            "devices" => Some(ScanType::Devices),
            "subsystems" => Some(ScanType::Subsystems),
            "all" => Some(ScanType::All),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            ScanType::Devices => "devices",
            ScanType::Subsystems => "subsystems",
            ScanType::All => "all",
        }
    }
}

// ── Initialized match ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializedMatch {
    Any,
    Yes,
    No,
}

impl Default for InitializedMatch {
    fn default() -> Self {
        InitializedMatch::Any
    }
}

// ── Match filters ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchFilters {
    pub devices: Vec<String>,
    pub subsystem_match: Vec<String>,
    pub subsystem_nomatch: Vec<String>,
    pub attr_match: Vec<String>,
    pub attr_nomatch: Vec<String>,
    pub property_match: Vec<String>,
    pub tag_match: Vec<String>,
    pub sysname_match: Vec<String>,
    pub name_match: Vec<String>,
    pub parent_match: Vec<String>,
    pub prioritized_subsystems: Vec<String>,
    pub initialized_match: InitializedMatch,
    pub include_parents: bool,
}

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerArgs {
    pub verbose: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub uuid: bool,
    pub settle: bool,
    pub ping: bool,
    pub ping_timeout_usec: u64,
    pub scan_type: ScanType,
    pub action: String,
    pub filters: MatchFilters,
}

impl Default for TriggerArgs {
    fn default() -> Self {
        Self {
            verbose: false,
            dry_run: false,
            quiet: false,
            uuid: false,
            settle: false,
            ping: false,
            ping_timeout_usec: 5_000_000,
            scan_type: ScanType::Devices,
            action: "change".to_string(),
            filters: MatchFilters::default(),
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
    UnknownScanType(String),
    InvalidAction(String),
    InvalidTimeout(String),
    InvalidKeyValue(String),
    BuildArgListFailed(String),
}

impl std::fmt::Display for TriggerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriggerError::HelpRequested => write!(f, "help requested"),
            TriggerError::VersionRequested => write!(f, "version requested"),
            TriggerError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            TriggerError::UnknownScanType(s) => {
                write!(f, "Unknown type --type={s}")
            }
            TriggerError::InvalidAction(s) => write!(f, "Invalid action '{s}'"),
            TriggerError::InvalidTimeout(s) => {
                write!(f, "Failed to parse timeout value '{s}'")
            }
            TriggerError::InvalidKeyValue(s) => {
                write!(f, "Failed to parse key/value pair '{s}'")
            }
            TriggerError::BuildArgListFailed(s) => {
                write!(f, "Failed to build argument list: {s}")
            }
        }
    }
}

impl std::error::Error for TriggerError {}

// ── Validation ────────────────────────────────────────────────────────────

pub fn validate_scan_type(s: &str) -> Result<ScanType, TriggerError> {
    ScanType::from_str(s).ok_or_else(|| TriggerError::UnknownScanType(s.to_string()))
}

pub fn validate_action(action: &str) -> Result<String, TriggerError> {
    let valid = [
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
    ];
    if valid.contains(&action) {
        Ok(action.to_string())
    } else {
        Err(TriggerError::InvalidAction(action.to_string()))
    }
}

/// Parse a key=value argument. Returns (key, value) where value may be empty.
pub fn parse_key_value(s: &str) -> Result<(String, String), TriggerError> {
    if let Some(eq_pos) = s.find('=') {
        let key = &s[..eq_pos];
        let value = &s[eq_pos + 1..];
        Ok((key.to_string(), value.to_string()))
    } else if !s.is_empty() {
        Ok((s.to_string(), String::new()))
    } else {
        Err(TriggerError::InvalidKeyValue(String::new()))
    }
}

/// Parse a comma-separated list of subsystem names.
pub fn parse_subsystem_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

// ── Execution result ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    /// All devices triggered successfully.
    Ok,
    /// One or more non-fatal errors occurred; the first error code is stored.
    PartialFailure(i32),
    /// A fatal error (EROFS) was encountered.
    FatalError(i32),
}

/// Classify an error returned when triggering a single device.
/// Mirrors the error-handling logic in C `exec_list()`.
pub fn classify_trigger_error(err: i32, quiet: bool) -> (ExecStatus, i32) {
    let ignore = err == -2 || err == -19; // -ENOENT, -ENODEV
    let level = if quiet {
        7 // LOG_DEBUG
    } else if err == -2 {
        7
    } else if err == -19 {
        4 // LOG_WARNING
    } else {
        3 // LOG_ERR
    };
    if err == -30 {
        // -EROFS: read-only filesystem
        (ExecStatus::FatalError(err), level)
    } else if ignore {
        (ExecStatus::Ok, level)
    } else {
        (ExecStatus::PartialFailure(err), level)
    }
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} trigger [OPTIONS] DEVPATH\n\n\
         Request events from the kernel.\n\n\
         -h --help                         Show this help\n\
         -V --version                      Show package version\n\
         -v --verbose                      Print the list of devices while running\n\
         -n --dry-run                      Do not actually trigger the events\n\
         -q --quiet                        Suppress error logging in triggering events\n\
         -t --type=                        Type of events to trigger\n\
                 devices                     sysfs devices (default)\n\
                 subsystems                  sysfs subsystems and drivers\n\
                 all                         sysfs devices, subsystems, and drivers\n\
         -c --action=ACTION|help           Event action value, default is \"change\"\n\
         -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n\
         -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n\
         -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n\
         -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n\
         -p --property-match=KEY=VALUE     Trigger devices with a matching property\n\
         -g --tag-match=TAG                Trigger devices with a matching tag\n\
         -y --sysname-match=NAME           Trigger devices with this /sys path\n\
            --name-match=NAME              Trigger devices with this /dev name\n\
         -b --parent-match=NAME            Trigger devices with that parent device\n\
            --include-parents              Trigger parent devices of found devices\n\
            --initialized-match            Trigger devices that are already initialized\n\
            --initialized-nomatch          Trigger devices that are not initialized yet\n\
         -w --settle                       Wait for the triggered events to complete\n\
            --wait-daemon[=SECONDS]        Wait for udevd daemon to be initialized\n\
            --uuid                         Print synthetic uevent UUID\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_type_roundtrip() {
        assert_eq!(ScanType::from_str("devices"), Some(ScanType::Devices));
        assert_eq!(ScanType::from_str("subsystems"), Some(ScanType::Subsystems));
        assert_eq!(ScanType::from_str("all"), Some(ScanType::All));
        assert_eq!(ScanType::from_str("unknown"), None);
    }

    #[test]
    fn test_scan_type_to_str() {
        assert_eq!(ScanType::Devices.to_str(), "devices");
        assert_eq!(ScanType::Subsystems.to_str(), "subsystems");
        assert_eq!(ScanType::All.to_str(), "all");
    }

    #[test]
    fn test_validate_scan_type_ok() {
        assert_eq!(validate_scan_type("devices"), Ok(ScanType::Devices));
        assert_eq!(validate_scan_type("subsystems"), Ok(ScanType::Subsystems));
        assert_eq!(validate_scan_type("all"), Ok(ScanType::All));
    }

    #[test]
    fn test_validate_scan_type_err() {
        assert!(validate_scan_type("bad").is_err());
    }

    #[test]
    fn test_validate_action_ok() {
        assert!(validate_action("change").is_ok());
        assert!(validate_action("add").is_ok());
    }

    #[test]
    fn test_validate_action_err() {
        assert!(validate_action("explode").is_err());
        assert!(validate_action("").is_err());
    }

    #[test]
    fn test_parse_key_value_with_eq() {
        let (k, v) = parse_key_value("foo=bar").unwrap();
        assert_eq!(k, "foo");
        assert_eq!(v, "bar");
    }

    #[test]
    fn test_parse_key_value_no_eq() {
        let (k, _v) = parse_key_value("foo").unwrap();
        assert_eq!(k, "foo");
    }

    #[test]
    fn test_parse_key_value_empty() {
        assert!(parse_key_value("").is_err());
    }

    #[test]
    fn test_parse_key_value_eq_only() {
        let (k, v) = parse_key_value("=bar").unwrap();
        assert_eq!(k, "");
        assert!(parse_key_value("").is_err());
    }

    #[test]
    fn test_parse_subsystem_list() {
        let list = parse_subsystem_list("net,block,usb");
        assert_eq!(list, vec!["net", "block", "usb"]);
    }

    #[test]
    fn test_parse_subsystem_list_trailing_comma() {
        let list = parse_subsystem_list("net,");
        assert_eq!(list, vec!["net"]);
    }

    #[test]
    fn test_parse_subsystem_list_empty() {
        let list = parse_subsystem_list("");
        assert!(list.is_empty());
    }

    #[test]
    fn test_classify_trigger_error_enoent() {
        let (status, _) = classify_trigger_error(-2, false);
        assert_eq!(status, ExecStatus::Ok);
    }

    #[test]
    fn test_classify_trigger_error_erofs() {
        let (status, _) = classify_trigger_error(-30, false);
        assert_eq!(status, ExecStatus::FatalError(-30));
    }

    #[test]
    fn test_classify_trigger_error_other() {
        let (status, _) = classify_trigger_error(-5, false);
        assert_eq!(status, ExecStatus::PartialFailure(-5));
    }

    #[test]
    fn test_default_trigger_args() {
        let args = TriggerArgs::default();
        assert!(!args.verbose);
        assert!(!args.dry_run);
        assert!(!args.quiet);
        assert_eq!(args.scan_type, ScanType::Devices);
        assert_eq!(args.action, "change");
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--type="));
        assert!(help.contains("--settle"));
        assert!(help.contains("--uuid"));
    }
}
