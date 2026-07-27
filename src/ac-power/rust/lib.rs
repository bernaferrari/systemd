// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/ac-power/ac-power.c
//
// Report whether the system is connected to an external power source.
// Supports checking AC power status and low battery detection.

// ── Types ─────────────────────────────────────────────────────────────────

/// Action to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcPowerAction {
    /// Check if on AC power (default).
    AcPower,
    /// Check if battery is discharging and low.
    Low,
}

/// Parsed command-line arguments for `systemd-ac-power`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcPowerArgs {
    /// Show state as text.
    pub verbose: bool,
    /// Which action to perform.
    pub action: AcPowerAction,
}

impl Default for AcPowerArgs {
    fn default() -> Self {
        Self {
            verbose: false,
            action: AcPowerAction::AcPower,
        }
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parse command-line arguments for `systemd-ac-power`.
///
/// Accepts a slice of string arguments and returns the parsed args or an error.
/// Recognized flags: `--verbose` / `-v`, `--low`.
pub fn parse_ac_power_args(args: &[&str]) -> Result<AcPowerArgs, i32> {
    let mut result = AcPowerArgs::default();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--verbose" | "-v" => {
                result.verbose = true;
            }
            "--low" => {
                result.action = AcPowerAction::Low;
            }
            "--help" | "-h" => {
                return Err(0); // help requested, not an error per se
            }
            "--version" => {
                return Err(0);
            }
            s if s.starts_with('-') => {
                return Err(-libc::EINVAL);
            }
            _ => {
                // Positional argument not allowed
                return Err(-libc::EINVAL);
            }
        }
        i += 1;
    }

    Ok(result)
}

// ── Core logic ────────────────────────────────────────────────────────────

/// Power status result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerStatus {
    /// System is on AC power / battery is fine.
    OnPower,
    /// System is on battery (not on AC) / battery is discharging and low.
    OnBattery,
}

/// Determine the exit code from a boolean power check result.
///
/// The C code returns `r == 0` (i.e., 0 becomes 1/true, nonzero becomes 0/false).
/// When `verbose` is true, a human-readable string should be printed.
///
/// Returns the exit code (0 = success/on AC, 1 = not on AC).
pub fn compute_exit_code(on_ac: bool) -> i32 {
    if on_ac {
        0
    } else {
        1
    }
}

/// Determine the result text for verbose output.
pub fn yes_no(flag: bool) -> &'static str {
    if flag {
        "yes"
    } else {
        "no"
    }
}

/// Run the ac-power check given the parsed arguments.
///
/// The actual power-status check is delegated to a caller-provided function,
/// since reading sysfs/procfs is not available in pure Rust tests.
///
/// Returns the exit code.
pub fn run_ac_power<F>(args: &AcPowerArgs, check_power: F) -> Result<i32, i32>
where
    F: FnOnce() -> Result<bool, i32>,
{
    let on_power = check_power()?;
    if args.verbose {
        println!("{}", yes_no(on_power));
    }
    Ok(compute_exit_code(on_power))
}

/// Run the low-battery check given the parsed arguments.
///
/// The actual battery-status check is delegated to a caller-provided function.
/// Returns the exit code.
pub fn run_low_battery<F>(args: &AcPowerArgs, check_low: F) -> Result<i32, i32>
where
    F: FnOnce() -> Result<bool, i32>,
{
    let low = check_low()?;
    if args.verbose {
        println!("{}", yes_no(low));
    }
    // The C code returns `r == 0` for both actions
    Ok(if low { 1 } else { 0 })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = AcPowerArgs::default();
        assert!(!args.verbose);
        assert_eq!(args.action, AcPowerAction::AcPower);
    }

    #[test]
    fn test_parse_empty_args() {
        let args = parse_ac_power_args(&[]).unwrap();
        assert!(!args.verbose);
        assert_eq!(args.action, AcPowerAction::AcPower);
    }

    #[test]
    fn test_parse_verbose() {
        let args = parse_ac_power_args(&["--verbose"]).unwrap();
        assert!(args.verbose);
        assert_eq!(args.action, AcPowerAction::AcPower);
    }

    #[test]
    fn test_parse_verbose_short() {
        let args = parse_ac_power_args(&["-v"]).unwrap();
        assert!(args.verbose);
    }

    #[test]
    fn test_parse_low() {
        let args = parse_ac_power_args(&["--low"]).unwrap();
        assert_eq!(args.action, AcPowerAction::Low);
    }

    #[test]
    fn test_parse_verbose_and_low() {
        let args = parse_ac_power_args(&["--verbose", "--low"]).unwrap();
        assert!(args.verbose);
        assert_eq!(args.action, AcPowerAction::Low);
    }

    #[test]
    fn test_parse_unknown_flag() {
        assert!(parse_ac_power_args(&["--bogus"]).is_err());
    }

    #[test]
    fn test_parse_positional_rejected() {
        assert!(parse_ac_power_args(&["extra"]).is_err());
    }

    #[test]
    fn test_compute_exit_code() {
        assert_eq!(compute_exit_code(true), 0);
        assert_eq!(compute_exit_code(false), 1);
    }

    #[test]
    fn test_yes_no() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn test_run_ac_power_on_ac() {
        let args = AcPowerArgs {
            verbose: false,
            action: AcPowerAction::AcPower,
        };
        let result = run_ac_power(&args, || Ok(true)).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_run_ac_power_on_battery() {
        let args = AcPowerArgs {
            verbose: false,
            action: AcPowerAction::AcPower,
        };
        let result = run_ac_power(&args, || Ok(false)).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_run_ac_power_error() {
        let args = AcPowerArgs::default();
        let result = run_ac_power(&args, || Err(-libc::EIO));
        assert!(result.is_err());
    }
}
