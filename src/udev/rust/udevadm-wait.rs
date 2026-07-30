// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-wait.c
//
// udevadm wait — wait for devices or device symlinks to be created.
//
// Defines wait-until enumeration, device-check logic, argument parsing,
// timeout and settle handling for the wait subcommand.

// ── Wait-until enumeration ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitUntil {
    Initialized,
    Added,
    Removed,
}

impl std::str::FromStr for WaitUntil {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "initialized" => Ok(WaitUntil::Initialized),
            "added" => Ok(WaitUntil::Added),
            "removed" => Ok(WaitUntil::Removed),
            _ => Err(()),
        }
    }
}

impl WaitUntil {
    pub fn to_str(self) -> &'static str {
        match self {
            WaitUntil::Initialized => "initialized",
            WaitUntil::Added => "added",
            WaitUntil::Removed => "removed",
        }
    }
}

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitArgs {
    pub wait_until: WaitUntil,
    pub timeout_usec: u64,
    pub settle: bool,
    pub devices: Vec<String>,
}

impl Default for WaitArgs {
    fn default() -> Self {
        Self {
            wait_until: WaitUntil::Initialized,
            timeout_usec: u64::MAX,
            settle: false,
            devices: Vec::new(),
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
    InvalidTimeout(String),
    InvalidInitialized(String),
    TooFewArguments,
    DevicePathNotSafe(String),
    NotADevicePath(String),
    EventLoopFailed(String),
    TimedOut(String),
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WaitError::HelpRequested => write!(f, "help requested"),
            WaitError::VersionRequested => write!(f, "version requested"),
            WaitError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            WaitError::InvalidTimeout(s) => {
                write!(f, "Failed to parse -t/--timeout= parameter: {s}")
            }
            WaitError::InvalidInitialized(s) => {
                write!(f, "Failed to parse --initialized= parameter: {s}")
            }
            WaitError::TooFewArguments => {
                write!(
                    f,
                    "Too few arguments, expected at least one device path or device symlink."
                )
            }
            WaitError::DevicePathNotSafe(p) => {
                write!(f, "Device path cannot contain \"..\": {p}")
            }
            WaitError::NotADevicePath(p) => {
                write!(
                    f,
                    "Specified path \"{p}\" does not start with \"/dev/\" or \"/sys/\"."
                )
            }
            WaitError::EventLoopFailed(msg) => write!(f, "Event loop failed: {msg}"),
            WaitError::TimedOut(state) => {
                write!(f, "Timed out for waiting devices being {state}.")
            }
        }
    }
}

impl std::error::Error for WaitError {}

// ── Device check logic ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCheckResult {
    /// The condition is satisfied.
    Satisfied,
    /// The condition is not yet satisfied.
    NotSatisfied,
    /// The device/path does not exist (relevant for "removed" check).
    NotFound,
}

/// Evaluate whether a device satisfies the wait condition.
/// Mirrors `check_device()` in the C source.
pub fn check_device_condition(
    wait_until: WaitUntil,
    device_exists: bool,
    device_processed: bool,
) -> DeviceCheckResult {
    match wait_until {
        WaitUntil::Removed => {
            if !device_exists {
                DeviceCheckResult::Satisfied
            } else {
                DeviceCheckResult::NotSatisfied
            }
        }
        WaitUntil::Initialized => {
            if !device_exists {
                DeviceCheckResult::NotFound
            } else if device_processed {
                DeviceCheckResult::Satisfied
            } else {
                DeviceCheckResult::NotSatisfied
            }
        }
        WaitUntil::Added => {
            if device_exists {
                DeviceCheckResult::Satisfied
            } else {
                DeviceCheckResult::NotSatisfied
            }
        }
    }
}

/// Check whether all devices satisfy their conditions.
/// Mirrors `check()` in the C source.
pub fn check_all_devices(
    wait_until: WaitUntil,
    settle: bool,
    queue_empty: Option<bool>,
    devices: &[(bool, bool)],
) -> bool {
    if settle && queue_empty == Some(false) {
        return false;
    }
    devices.iter().all(|&(exists, processed)| {
        check_device_condition(wait_until, exists, processed) == DeviceCheckResult::Satisfied
    })
}

// ── Path validation ───────────────────────────────────────────────────────

pub fn is_device_path(p: &str) -> bool {
    p.starts_with("/dev/") || p.starts_with("/sys/")
}

pub fn is_path_safe(p: &str) -> bool {
    let components: Vec<&str> = p.split('/').collect();
    !components.contains(&"..")
}

pub fn simplify_path(p: &str) -> String {
    let mut result = String::new();
    let mut parts: Vec<&str> = Vec::new();
    for component in p.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(component),
        }
    }
    if parts.is_empty() {
        return "/".to_string();
    }
    for part in parts {
        result.push('/');
        result.push_str(part);
    }
    result
}

pub fn validate_device_paths(paths: &[&str]) -> Result<(), WaitError> {
    for p in paths {
        let simplified = simplify_path(p);
        if !is_path_safe(&simplified) {
            return Err(WaitError::DevicePathNotSafe(p.to_string()));
        }
        if !is_device_path(&simplified) {
            return Err(WaitError::NotADevicePath(p.to_string()));
        }
    }
    Ok(())
}

// ── Periodic timer ────────────────────────────────────────────────────────

pub const PERIODIC_TIMER_INTERVAL_MSEC: u64 = 250;
pub const PERIODIC_TIMER_THRESHOLD: u32 = 2;

/// Determine whether the periodic timer should trigger an early exit.
/// Mirrors `on_periodic_timer()` counter logic.
pub fn periodic_check(all_satisfied: bool, consecutive_count: u32) -> (bool, u32) {
    let new_count = if all_satisfied {
        consecutive_count + 1
    } else {
        0
    };
    let should_exit = new_count >= PERIODIC_TIMER_THRESHOLD;
    (should_exit, new_count)
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} wait [OPTIONS] DEVICE [DEVICE…]\n\n\
         Wait for devices or device symlinks being created.\n\n\
         -h --help             Print this message\n\
         -V --version          Print version of the program\n\
         -t --timeout=SEC      Maximum time to wait for the device\n\
            --initialized=BOOL Wait for devices being initialized by systemd-udevd\n\
            --removed          Wait for devices being removed\n\
            --settle           Also wait for all queued events being processed\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_until_roundtrip() {
        for s in &["initialized", "added", "removed"] {
            assert_eq!(s.parse::<WaitUntil>().unwrap().to_str(), *s);
        }
        assert!("bad".parse::<WaitUntil>().is_err());
    }

    #[test]
    fn test_check_device_removed() {
        assert_eq!(
            check_device_condition(WaitUntil::Removed, false, false),
            DeviceCheckResult::Satisfied
        );
        assert_eq!(
            check_device_condition(WaitUntil::Removed, true, false),
            DeviceCheckResult::NotSatisfied
        );
    }

    #[test]
    fn test_check_device_initialized() {
        assert_eq!(
            check_device_condition(WaitUntil::Initialized, false, false),
            DeviceCheckResult::NotFound
        );
        assert_eq!(
            check_device_condition(WaitUntil::Initialized, true, true),
            DeviceCheckResult::Satisfied
        );
        assert_eq!(
            check_device_condition(WaitUntil::Initialized, true, false),
            DeviceCheckResult::NotSatisfied
        );
    }

    #[test]
    fn test_check_device_added() {
        assert_eq!(
            check_device_condition(WaitUntil::Added, true, false),
            DeviceCheckResult::Satisfied
        );
        assert_eq!(
            check_device_condition(WaitUntil::Added, false, false),
            DeviceCheckResult::NotSatisfied
        );
    }

    #[test]
    fn test_check_all_devices_initialized() {
        let devices = vec![(true, true), (true, true)];
        assert!(check_all_devices(
            WaitUntil::Initialized,
            false,
            None,
            &devices
        ));
        let devices = vec![(true, false)];
        assert!(!check_all_devices(
            WaitUntil::Initialized,
            false,
            None,
            &devices
        ));
    }

    #[test]
    fn test_check_all_devices_with_settle() {
        let devices = vec![(true, true)];
        assert!(check_all_devices(
            WaitUntil::Initialized,
            true,
            Some(true),
            &devices
        ));
        assert!(!check_all_devices(
            WaitUntil::Initialized,
            true,
            Some(false),
            &devices
        ));
    }

    #[test]
    fn test_is_device_path() {
        assert!(is_device_path("/dev/sda"));
        assert!(is_device_path("/sys/block/sda"));
        assert!(!is_device_path("/run/udev"));
        assert!(!is_device_path("sda"));
    }

    #[test]
    fn test_is_path_safe() {
        assert!(is_path_safe("/dev/sda"));
        assert!(is_path_safe("/sys/block/sda/part1"));
        assert!(!is_path_safe("/dev/../etc/passwd"));
    }

    #[test]
    fn test_simplify_path() {
        assert_eq!(simplify_path("/dev/sda"), "/dev/sda");
        assert_eq!(simplify_path("/dev/../etc/passwd"), "/etc/passwd");
        assert_eq!(simplify_path("/"), "/");
    }

    #[test]
    fn test_validate_device_paths_ok() {
        assert!(validate_device_paths(&["/dev/sda", "/sys/block/sda"]).is_ok());
    }

    #[test]
    fn test_validate_device_paths_unsafe() {
        assert!(validate_device_paths(&["/dev/../etc/passwd"]).is_err());
    }

    #[test]
    fn test_validate_device_paths_not_device() {
        assert!(validate_device_paths(&["/run/udev"]).is_err());
    }

    #[test]
    fn test_periodic_check_not_satisfied() {
        let (exit, count) = periodic_check(false, 5);
        assert!(!exit);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_periodic_check_satisfied_threshold() {
        let (exit, count) = periodic_check(true, 0);
        assert!(!exit);
        assert_eq!(count, 1);
        let (exit, count) = periodic_check(true, 1);
        assert!(exit);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_default_args() {
        let args = WaitArgs::default();
        assert_eq!(args.wait_until, WaitUntil::Initialized);
        assert_eq!(args.timeout_usec, u64::MAX);
        assert!(!args.settle);
        assert!(args.devices.is_empty());
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--timeout"));
        assert!(help.contains("--initialized"));
        assert!(help.contains("--removed"));
    }
}
