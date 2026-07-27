// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-monitor.c
//
// udevadm monitor — listen to kernel and udev events.
//
// Defines the monitor group types, subsystem filter parsing, tag filter
// management, event formatting, and argument validation for the monitor
// subcommand.

// ── Monitor group ─────────────────────────────────────────────────────────

/// Netlink groups for device monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorNetlinkGroup {
    /// Kernel uevents (raw).
    Kernel,
    /// Udev events (after rule processing).
    Udev,
}

impl MonitorNetlinkGroup {
    pub fn label(self) -> &'static str {
        match self {
            MonitorNetlinkGroup::Kernel => "KERNEL",
            MonitorNetlinkGroup::Udev => "UDEV",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            MonitorNetlinkGroup::Kernel => "kernel",
            MonitorNetlinkGroup::Udev => "udev",
        }
    }
}

// ── Subsystem filter ──────────────────────────────────────────────────────

/// A subsystem filter entry, optionally with a devtype constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemFilter {
    pub subsystem: String,
    pub devtype: Option<String>,
}

/// Parse a subsystem/devtype filter string in the form "SUBSYSTEM[/DEVTYPE]".
/// Mirrors the -s option parsing in the C parse_argv().
pub fn parse_subsystem_filter(s: &str) -> SubsystemFilter {
    match s.split_once('/') {
        Some((subsystem, devtype)) => SubsystemFilter {
            subsystem: subsystem.to_string(),
            devtype: Some(devtype.to_string()),
        },
        None => SubsystemFilter {
            subsystem: s.to_string(),
            devtype: None,
        },
    }
}

// ── Event formatting ──────────────────────────────────────────────────────

/// Device action types for event display.
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
    Unknown,
}

impl DeviceAction {
    pub fn from_string(s: &str) -> DeviceAction {
        match s {
            "add" => DeviceAction::Add,
            "remove" => DeviceAction::Remove,
            "change" => DeviceAction::Change,
            "move" => DeviceAction::Move,
            "online" => DeviceAction::Online,
            "offline" => DeviceAction::Offline,
            "bind" => DeviceAction::Bind,
            "unbind" => DeviceAction::Unbind,
            _ => DeviceAction::Unknown,
        }
    }

    pub fn to_string_val(self) -> &'static str {
        match self {
            DeviceAction::Add => "add",
            DeviceAction::Remove => "remove",
            DeviceAction::Change => "change",
            DeviceAction::Move => "move",
            DeviceAction::Online => "online",
            DeviceAction::Offline => "offline",
            DeviceAction::Bind => "bind",
            DeviceAction::Unbind => "unbind",
            DeviceAction::Unknown => "unknown",
        }
    }
}

/// Format a monitor event line.
/// Mirrors the printf in device_monitor_handler().
pub fn format_event_line(
    group: MonitorNetlinkGroup,
    timestamp_sec: u64,
    timestamp_usec: u64,
    action: DeviceAction,
    devpath: &str,
    subsystem: &str,
) -> String {
    format!(
        "{:<6}[{}.{:06}] {:<8} {} ({})",
        group.label(),
        timestamp_sec,
        timestamp_usec,
        action.to_string_val(),
        devpath,
        subsystem,
    )
}

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MonitorArgs {
    pub show_property: bool,
    pub print_kernel: bool,
    pub print_udev: bool,
    pub tag_filters: Vec<String>,
    pub subsystem_filters: Vec<SubsystemFilter>,
}

impl MonitorArgs {
    pub fn new() -> Self {
        Self::default()
    }

    /// If neither --kernel nor --udev was specified, enable both.
    /// Mirrors the post-processing in C parse_argv().
    pub fn apply_defaults(&mut self) {
        if !self.print_kernel && !self.print_udev {
            self.print_kernel = true;
            self.print_udev = true;
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorParseError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
}

impl std::fmt::Display for MonitorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitorParseError::HelpRequested => write!(f, "help requested"),
            MonitorParseError::VersionRequested => write!(f, "version requested"),
            MonitorParseError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
        }
    }
}

impl std::error::Error for MonitorParseError {}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} monitor [OPTIONS]\n\n\
         Listen to kernel and udev events.\n\n\
         -h --help                                Show this help\n\
         -V --version                             Show package version\n\
         -p --property                            Print the event properties\n\
         -k --kernel                              Print kernel uevents\n\
         -u --udev                                Print udev events\n\
         -s --subsystem-match=SUBSYSTEM[/DEVTYPE] Filter events by subsystem\n\
         -t --tag-match=TAG                       Filter events by tag\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_group_labels() {
        assert_eq!(MonitorNetlinkGroup::Kernel.label(), "KERNEL");
        assert_eq!(MonitorNetlinkGroup::Udev.label(), "UDEV");
    }

    #[test]
    fn test_monitor_group_descriptions() {
        assert_eq!(MonitorNetlinkGroup::Kernel.description(), "kernel");
        assert_eq!(MonitorNetlinkGroup::Udev.description(), "udev");
    }

    #[test]
    fn test_parse_subsystem_filter_no_devtype() {
        let f = parse_subsystem_filter("net");
        assert_eq!(f.subsystem, "net");
        assert_eq!(f.devtype, None);
    }

    #[test]
    fn test_parse_subsystem_filter_with_devtype() {
        let f = parse_subsystem_filter("net/wlan");
        assert_eq!(f.subsystem, "net");
        assert_eq!(f.devtype, Some("wlan".to_string()));
    }

    #[test]
    fn test_device_action_roundtrip() {
        let actions = [
            DeviceAction::Add,
            DeviceAction::Remove,
            DeviceAction::Change,
            DeviceAction::Move,
            DeviceAction::Online,
            DeviceAction::Offline,
            DeviceAction::Bind,
            DeviceAction::Unbind,
        ];
        for a in &actions {
            assert_eq!(DeviceAction::from_string(a.to_string_val()), *a);
        }
    }

    #[test]
    fn test_format_event_line() {
        let line = format_event_line(
            MonitorNetlinkGroup::Udev,
            12345,
            678901,
            DeviceAction::Add,
            "/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda",
            "block",
        );
        assert!(line.starts_with("UDEV "));
        assert!(line.contains("add"));
        assert!(line.contains("block"));
        assert!(line.contains("12345"));
    }

    #[test]
    fn test_monitor_args_defaults() {
        let mut args = MonitorArgs::new();
        assert!(!args.print_kernel);
        assert!(!args.print_udev);
        args.apply_defaults();
        assert!(args.print_kernel);
        assert!(args.print_udev);
    }

    #[test]
    fn test_monitor_args_no_override() {
        let mut args = MonitorArgs {
            print_kernel: true,
            ..Default::default()
        };
        args.apply_defaults();
        assert!(args.print_kernel);
        assert!(!args.print_udev);
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--kernel"));
        assert!(help.contains("--udev"));
        assert!(help.contains("--property"));
        assert!(help.contains("--subsystem-match"));
        assert!(help.contains("--tag-match"));
    }
}
