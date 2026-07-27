// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/sulogin-shell/sulogin-shell.c
//
// Sulogin shell wrapper.
//
// Runs sulogin in a loop and attempts to start the default target
// after each invocation via D-Bus. Falls back to looping if the
// target cannot be started.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default target used outside of initrd.
pub const SPECIAL_DEFAULT_TARGET: &str = "default.target";

/// Target used in initrd.
pub const SPECIAL_INITRD_TARGET: &str = "initrd.target";

/// Environment variable name for forcing sulogin.
pub const ENV_SULOGIN_FORCE: &str = "SYSTEMD_SULOGIN_FORCE";

/// Kernel command line key for forcing sulogin.
pub const CMDLINE_SULOGIN_FORCE: &str = "SYSTEMD_SULOGIN_FORCE";

/// Default sulogin binary path.
pub const SULOGIN_PATH: &str = "/usr/sbin/sulogin";

/// The --force flag for sulogin.
pub const SULOGIN_FORCE_FLAG: &str = "--force";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Result of the sulogin shell run loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuloginResult {
    /// Successfully started the target.
    TargetStarted,
    /// Fallback: target could not be started, looping.
    Fallback,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from sulogin shell operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuloginError {
    /// Failed to connect to D-Bus.
    BusConnectionFailed(String),
    /// Failed to reload the daemon.
    DaemonReloadFailed(String),
    /// Failed to check target state.
    TargetStateQueryFailed(String),
    /// Failed to start the target.
    TargetStartFailed(String),
    /// Failed to execute sulogin.
    SuloginExecFailed(String),
}

impl std::fmt::Display for SuloginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuloginError::BusConnectionFailed(msg) => {
                write!(f, "Failed to get D-Bus connection: {}", msg)
            }
            SuloginError::DaemonReloadFailed(msg) => {
                write!(f, "Failed to reload daemon: {}", msg)
            }
            SuloginError::TargetStateQueryFailed(msg) => {
                write!(f, "Failed to retrieve unit state: {}", msg)
            }
            SuloginError::TargetStartFailed(msg) => {
                write!(f, "Failed to start target: {}", msg)
            }
            SuloginError::SuloginExecFailed(msg) => {
                write!(f, "Failed to execute sulogin: {}", msg)
            }
        }
    }
}

impl std::error::Error for SuloginError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Build the sulogin command line, optionally with --force.
pub fn build_sulogin_cmdline(force: bool) -> Vec<&'static str> {
    if force {
        vec![SULOGIN_PATH, SULOGIN_FORCE_FLAG]
    } else {
        vec![SULOGIN_PATH]
    }
}

/// Determine the target to start based on whether we are in initrd.
pub fn determine_target(in_initrd: bool) -> &'static str {
    if in_initrd {
        SPECIAL_INITRD_TARGET
    } else {
        SPECIAL_DEFAULT_TARGET
    }
}

/// Parse a boolean value from an environment variable string.
/// Returns true for "1", "true", "yes", "on".
pub fn parse_env_bool(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower == "1" || lower == "true" || lower == "yes" || lower == "on"
}

/// Generate the mode message printed to the user.
pub fn format_mode_message(mode: &str) -> String {
    format!(
        "You are in {} mode. After logging in, type \"journalctl -xb\" to view\n\
         system logs, \"systemctl reboot\" to reboot, or \"exit\"\n\
         to continue bootup.",
        mode
    )
}

/// Determine whether to force sulogin based on env and cmdline.
/// The environment variable takes precedence over the kernel command line.
pub fn should_force_sulogin(env_value: Option<&str>, cmdline_value: Option<bool>) -> bool {
    // Environment variable takes precedence
    if let Some(v) = env_value {
        return parse_env_bool(v);
    }
    cmdline_value.unwrap_or(false)
}

/// Represents the state of a D-Bus check for whether a target is inactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Inactive,
    Active,
    Unknown,
}

impl TargetState {
    /// Parse from a D-Bus property string.
    pub fn from_active_state(state: &str) -> Self {
        match state {
            "inactive" => TargetState::Inactive,
            "active" | "reloading" | "activating" | "deactivating" => TargetState::Active,
            _ => TargetState::Unknown,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sulogin_cmdline_no_force() {
        let cmd = build_sulogin_cmdline(false);
        assert_eq!(cmd, vec![SULOGIN_PATH]);
    }

    #[test]
    fn test_build_sulogin_cmdline_force() {
        let cmd = build_sulogin_cmdline(true);
        assert_eq!(cmd, vec![SULOGIN_PATH, SULOGIN_FORCE_FLAG]);
    }

    #[test]
    fn test_determine_target_normal() {
        assert_eq!(determine_target(false), SPECIAL_DEFAULT_TARGET);
    }

    #[test]
    fn test_determine_target_initrd() {
        assert_eq!(determine_target(true), SPECIAL_INITRD_TARGET);
    }

    #[test]
    fn test_parse_env_bool_true_values() {
        assert!(parse_env_bool("1"));
        assert!(parse_env_bool("true"));
        assert!(parse_env_bool("yes"));
        assert!(parse_env_bool("on"));
        assert!(parse_env_bool("True"));
        assert!(parse_env_bool("YES"));
    }

    #[test]
    fn test_parse_env_bool_false_values() {
        assert!(!parse_env_bool("0"));
        assert!(!parse_env_bool("false"));
        assert!(!parse_env_bool("no"));
        assert!(!parse_env_bool(""));
    }

    #[test]
    fn test_should_force_sulogin_env_set() {
        assert!(should_force_sulogin(Some("1"), Some(false)));
        assert!(!should_force_sulogin(Some("0"), Some(true)));
    }

    #[test]
    fn test_should_force_sulogin_env_unset_cmdline_true() {
        assert!(should_force_sulogin(None, Some(true)));
    }

    #[test]
    fn test_should_force_sulogin_env_unset_cmdline_false() {
        assert!(!should_force_sulogin(None, Some(false)));
    }

    #[test]
    fn test_should_force_sulogin_both_unset() {
        assert!(!should_force_sulogin(None, None));
    }

    #[test]
    fn test_format_mode_message() {
        let msg = format_mode_message("emergency");
        assert!(msg.contains("emergency"));
        assert!(msg.contains("journalctl -xb"));
    }

    #[test]
    fn test_target_state_from_active_state() {
        assert_eq!(
            TargetState::from_active_state("inactive"),
            TargetState::Inactive
        );
        assert_eq!(
            TargetState::from_active_state("active"),
            TargetState::Active
        );
        assert_eq!(
            TargetState::from_active_state("failed"),
            TargetState::Unknown
        );
    }

    #[test]
    fn test_error_display() {
        let err = SuloginError::BusConnectionFailed("timeout".to_string());
        assert!(format!("{}", err).contains("D-Bus"));
    }
}
