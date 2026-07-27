// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/sulogin-shell/sulogin-shell.c
//
pub const SPECIAL_DEFAULT_TARGET: &str = "default.target";
pub const SPECIAL_INITRD_TARGET: &str = "initrd.target";
pub const ENV_FORCE: &str = "SYSTEMD_SULOGIN_FORCE";
pub const SULOGIN: &str = "/usr/sbin/sulogin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuloginError {
    TargetActive,
    CommandFailed,
}

impl std::fmt::Display for SuloginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SuloginError {}

pub fn format_mode_message(mode: &str) -> String {
    format!(
        "You are in {mode} mode. After logging in, type \"journalctl -xb\" to view\nsystem logs, \"systemctl reboot\" to reboot, or \"exit\"\nto continue bootup."
    )
}

pub fn parse_bool(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

pub fn should_force(env_value: Option<&str>, cmdline_value: Option<&str>) -> bool {
    env_value.and_then(parse_bool).unwrap_or(false)
        || cmdline_value.and_then(parse_bool).unwrap_or(false)
}

pub fn sulogin_cmdline(force: bool) -> Vec<&'static str> {
    if force {
        vec![SULOGIN, "--force"]
    } else {
        vec![SULOGIN]
    }
}

pub fn target_for(in_initrd: bool) -> &'static str {
    if in_initrd {
        SPECIAL_INITRD_TARGET
    } else {
        SPECIAL_DEFAULT_TARGET
    }
}

pub fn can_start_target(is_inactive: bool) -> Result<(), SuloginError> {
    if is_inactive {
        Ok(())
    } else {
        Err(SuloginError::TargetActive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_mode_message() {
        assert!(format_mode_message("rescue").contains("rescue"));
    }

    #[test]
    fn parses_true_bool() {
        assert_eq!(parse_bool("yes"), Some(true));
    }

    #[test]
    fn parses_false_bool() {
        assert_eq!(parse_bool("off"), Some(false));
    }

    #[test]
    fn invalid_bool_returns_none() {
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn env_force_wins() {
        assert!(should_force(Some("1"), None));
    }

    #[test]
    fn cmdline_force_used() {
        assert!(should_force(None, Some("true")));
    }

    #[test]
    fn target_switches_in_initrd() {
        assert_eq!(target_for(true), SPECIAL_INITRD_TARGET);
    }

    #[test]
    fn start_requires_inactive_target() {
        assert_eq!(
            can_start_target(false).unwrap_err(),
            SuloginError::TargetActive
        );
    }
}
