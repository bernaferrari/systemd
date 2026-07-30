// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/battery-check/battery-check.c
//
// Check battery level to see whether there's enough charge.
// Warns via plymouth and console if battery is critically low.

// ── Constants ─────────────────────────────────────────────────────────────

/// Message shown when battery is critically low.
pub const BATTERY_LOW_MESSAGE: &str = "Battery level critically low. Please connect your charger or the system will power off in 10 seconds.";

/// Message shown when AC power is restored.
pub const BATTERY_RESTORED_MESSAGE: &str = "A.C. power restored, continuing.";

/// How long to wait (in seconds) before rechecking battery status.
pub const BATTERY_CHECK_WAIT_SECS: u64 = 10;

// ── Types ─────────────────────────────────────────────────────────────────

/// Parsed command-line arguments for `systemd-battery-check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatteryCheckArgs {
    /// Whether the check should be performed (controlled by kernel cmdline).
    pub doit: bool,
}

impl Default for BatteryCheckArgs {
    fn default() -> Self {
        Self { doit: true }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse command-line arguments for `systemd-battery-check`.
///
/// Accepts `-h`/`--help` and `--version`; no positional arguments are allowed.
pub fn parse_battery_check_args(args: &[&str]) -> Result<BatteryCheckArgs, i32> {
    match args.first().copied() {
        None => Ok(BatteryCheckArgs::default()),
        Some("--help" | "-h" | "--version") => Err(0),
        Some(_) => Err(-libc::EINVAL),
    }
}

// ── Plymouth message ──────────────────────────────────────────────────────

/// Build a plymouth protocol message with mode and text.
///
/// The format follows the plymouth socket protocol:
/// - `C\x02<len+1><mode>\x00`
/// - `M\x02<len+1><text>\x00`
pub fn build_plymouth_message(mode: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // Command: change mode
    buf.push(b'C');
    buf.push(0x02);
    buf.push((mode.len() + 1) as u8);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0x00);

    // Command: display message
    buf.push(b'M');
    buf.push(0x02);
    buf.push((message.len() + 1) as u8);
    buf.extend_from_slice(message.as_bytes());
    buf.push(0x00);

    buf
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Battery check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatteryCheckResult {
    /// Battery is fine (not low or on AC power).
    Ok,
    /// Battery is critically low and discharging.
    CriticallyLow,
    /// Unable to determine battery status (treated as non-critical).
    Unknown,
}

/// Run the battery check logic.
///
/// This function takes two callback results:
/// 1. First battery check result
/// 2. Second battery check result (after waiting)
///
/// Returns the appropriate exit code (0 = continue, positive = power off).
pub fn run_battery_check(
    first_check: BatteryCheckResult,
    second_check: BatteryCheckResult,
    doit: bool,
) -> i32 {
    if !doit {
        return 0;
    }

    match first_check {
        BatteryCheckResult::Ok | BatteryCheckResult::Unknown => 0,
        BatteryCheckResult::CriticallyLow => match second_check {
            BatteryCheckResult::CriticallyLow => 1, // still low → power off
            _ => 0,                                 // restored or unknown → continue
        },
    }
}

/// Parse the kernel command line boolean value for `systemd.battery_check`.
///
/// Returns `true` if the check should be performed, `false` if disabled.
pub fn parse_cmdline_doit(value: Option<&str>) -> bool {
    match value {
        None => true, // default: perform the check
        Some("0" | "no" | "false" | "off") => false,
        Some("1" | "yes" | "true" | "on") => true,
        Some("") => true,
        _ => true, // unknown values → perform the check
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = BatteryCheckArgs::default();
        assert!(args.doit);
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_battery_check_args(&[]).unwrap();
        assert!(args.doit);
    }

    #[test]
    fn test_parse_help() {
        assert!(parse_battery_check_args(&["--help"]).is_err());
    }

    #[test]
    fn test_parse_version() {
        assert!(parse_battery_check_args(&["--version"]).is_err());
    }

    #[test]
    fn test_parse_positional_rejected() {
        assert!(parse_battery_check_args(&["extra"]).is_err());
    }

    #[test]
    fn test_parse_unknown_flag() {
        assert!(parse_battery_check_args(&["--bogus"]).is_err());
    }

    #[test]
    fn test_run_battery_check_not_doit() {
        assert_eq!(
            run_battery_check(
                BatteryCheckResult::CriticallyLow,
                BatteryCheckResult::CriticallyLow,
                false
            ),
            0
        );
    }

    #[test]
    fn test_run_battery_check_ok() {
        assert_eq!(
            run_battery_check(BatteryCheckResult::Ok, BatteryCheckResult::Ok, true),
            0
        );
    }

    #[test]
    fn test_run_battery_check_unknown() {
        assert_eq!(
            run_battery_check(
                BatteryCheckResult::Unknown,
                BatteryCheckResult::Unknown,
                true
            ),
            0
        );
    }

    #[test]
    fn test_run_battery_check_low_then_ok() {
        assert_eq!(
            run_battery_check(
                BatteryCheckResult::CriticallyLow,
                BatteryCheckResult::Ok,
                true
            ),
            0
        );
    }

    #[test]
    fn test_run_battery_check_still_low() {
        assert_eq!(
            run_battery_check(
                BatteryCheckResult::CriticallyLow,
                BatteryCheckResult::CriticallyLow,
                true
            ),
            1
        );
    }

    #[test]
    fn test_run_battery_check_low_then_unknown() {
        assert_eq!(
            run_battery_check(
                BatteryCheckResult::CriticallyLow,
                BatteryCheckResult::Unknown,
                true
            ),
            0
        );
    }

    #[test]
    fn test_parse_cmdline_doit_default() {
        assert!(parse_cmdline_doit(None));
    }

    #[test]
    fn test_parse_cmdline_doit_disabled() {
        assert!(!parse_cmdline_doit(Some("0")));
        assert!(!parse_cmdline_doit(Some("no")));
        assert!(!parse_cmdline_doit(Some("false")));
        assert!(!parse_cmdline_doit(Some("off")));
    }

    #[test]
    fn test_parse_cmdline_doit_enabled() {
        assert!(parse_cmdline_doit(Some("1")));
        assert!(parse_cmdline_doit(Some("yes")));
        assert!(parse_cmdline_doit(Some("true")));
        assert!(parse_cmdline_doit(Some("on")));
    }

    #[test]
    fn test_build_plymouth_message() {
        let msg = build_plymouth_message("shutdown", "Hello");
        assert_eq!(msg[0], b'C');
        assert_eq!(msg[1], 0x02);
        assert_eq!(msg[2], 9);
        assert_eq!(&msg[3..11], b"shutdown");
        assert_eq!(msg[11], 0x00);
        assert_eq!(msg[12], b'M');
        assert_eq!(msg[13], 0x02);
        assert_eq!(msg[14], 6);
        assert_eq!(&msg[15..20], b"Hello");
        assert_eq!(msg[20], 0x00);
    }

    #[test]
    fn test_battery_messages_not_empty() {
        assert!(!BATTERY_LOW_MESSAGE.is_empty());
        assert!(!BATTERY_RESTORED_MESSAGE.is_empty());
    }
}
