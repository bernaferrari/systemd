// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/crash-handler.c, src/core/crash-handler.h

use crate::crash_action::CrashAction;
use crate::ffi::Errno;

pub const EXIT_EXCEPTION: i32 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashDisposition {
    Exit { status: i32 },
    Reboot { delay_seconds: u64 },
    Poweroff,
    Freeze,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashHandlerInstall {
    pub installed_signals: Vec<i32>,
    pub ignored_error: Option<Errno>,
}

/// A C-accepted crash startup setting that the experimental PID 1 cannot own
/// safely. The parser is kept next to the crash handler because C wires these
/// settings through `parse_proc_cmdline_item()` in `src/core/main.c:312-366`
/// and later consumes them in `initialize_coredump()`,
/// `initialize_core_pattern()`, and `install_crash_handler()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedCrashStartupPolicy {
    EarlyCorePattern,
    CrashShell,
    CrashChangeVirtualTerminal,
    CrashAction(String),
}

impl std::fmt::Display for UnsupportedCrashStartupPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let option = match self {
            Self::EarlyCorePattern => "systemd.early_core_pattern",
            Self::CrashShell => "systemd.crash_shell",
            Self::CrashChangeVirtualTerminal => "systemd.crash_chvt",
            Self::CrashAction(_) => "systemd.crash_action",
        };
        write!(
            formatter,
            "{option} was explicitly requested, but this experimental Rust PID 1 cannot yet apply its C-compatible runtime policy"
        )
    }
}

pub type Result<T> = std::result::Result<T, Errno>;

pub fn freeze_or_exit_or_reboot(
    in_container: bool,
    action: CrashAction,
) -> Result<CrashDisposition> {
    let disposition = if in_container {
        CrashDisposition::Exit {
            status: EXIT_EXCEPTION,
        }
    } else {
        match action {
            CrashAction::Poweroff => CrashDisposition::Poweroff,
            CrashAction::Reboot => CrashDisposition::Reboot { delay_seconds: 10 },
            CrashAction::Freeze => CrashDisposition::Freeze,
        }
    };

    Ok(disposition)
}

pub fn install_crash_handler<F>(signals: &[i32], installer: F) -> Result<CrashHandlerInstall>
where
    F: FnOnce(&[i32]) -> Result<()>,
{
    if signals.is_empty() {
        return Err(Errno::EINVAL);
    }

    let ignored_error = installer(signals).err();
    Ok(CrashHandlerInstall {
        installed_signals: signals.to_vec(),
        ignored_error,
    })
}

fn parse_kernel_boolean(value: Option<&str>) -> Option<bool> {
    value
        .map(systemd_basic_rs::string_table::parse_boolean)
        .unwrap_or(Some(true))
}

fn early_core_pattern_is_active(value: &str) -> bool {
    // C only accepts absolute values here before writing the early
    // `/proc/sys/kernel/core_pattern` setting; malformed or relative values
    // warn and retain an earlier valid assignment. The Rust sidecar has no
    // core-pattern owner, so preserve that assignment behavior and fail
    // closed for the values C would apply.
    value.starts_with('/')
}

/// Return the highest-priority C-accepted crash startup setting that Rust PID
/// 1 would otherwise silently ignore. This keeps C's last-valid-assignment
/// behavior: malformed values warn and retain the earlier value.
pub fn unsupported_crash_startup_policy_from_cmdline(
    cmdline: &str,
) -> Option<UnsupportedCrashStartupPolicy> {
    let mut early_core_pattern = None;
    let mut crash_shell = None;
    let mut crash_chvt = false;
    let mut crash_action = None;

    for word in cmdline.split_ascii_whitespace() {
        let (key, value) = match word.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (word, None),
        };

        match key {
            "systemd.early_core_pattern" => {
                if let Some(value) = value
                    && early_core_pattern_is_active(value)
                {
                    early_core_pattern = Some(value.to_string());
                }
            }
            "systemd.crash_shell" => {
                if let Some(enabled) = parse_kernel_boolean(value) {
                    crash_shell = Some(enabled);
                }
            }
            "systemd.crash_chvt" => match value {
                // C treats the key without an argument as enabling the
                // feature. `parse_crash_chvt()` returns -1 for `no` and
                // otherwise returns the selected VT (0 means enabled without
                // selecting a concrete VT); malformed values keep the prior
                // setting and are only warned about.
                None => crash_chvt = true,
                Some(value) => {
                    if let Ok(chvt) = crate::load_fragment::parse_crash_chvt(value) {
                        crash_chvt = chvt >= 0;
                    }
                }
            },
            "systemd.crash_action" => {
                if let Some(value) = value
                    && matches!(value, "freeze" | "reboot" | "poweroff")
                {
                    crash_action = Some(value.to_string());
                }
            }
            "systemd.crash_reboot" => {
                if let Some(enabled) = parse_kernel_boolean(value) {
                    crash_action = Some(if enabled { "reboot" } else { "freeze" }.to_string());
                }
            }
            _ => {}
        }
    }

    if early_core_pattern.is_some() {
        return Some(UnsupportedCrashStartupPolicy::EarlyCorePattern);
    }
    if crash_shell == Some(true) {
        return Some(UnsupportedCrashStartupPolicy::CrashShell);
    }
    if crash_chvt {
        return Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal);
    }
    if let Some(action) = crash_action
        && action != "freeze"
    {
        return Some(UnsupportedCrashStartupPolicy::CrashAction(action));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_crash_prefers_exit() {
        let action = freeze_or_exit_or_reboot(true, CrashAction::Reboot).unwrap();
        assert_eq!(
            action,
            CrashDisposition::Exit {
                status: EXIT_EXCEPTION
            }
        );
    }

    #[test]
    fn reboot_action_keeps_delay() {
        let action = freeze_or_exit_or_reboot(false, CrashAction::Reboot).unwrap();
        assert_eq!(action, CrashDisposition::Reboot { delay_seconds: 10 });
    }

    #[test]
    fn crash_handler_install_records_ignored_error() {
        let install = install_crash_handler(&[6, 11], |_| Err(Errno::ENOMEM)).unwrap();
        assert_eq!(install.installed_signals, vec![6, 11]);
        assert_eq!(install.ignored_error, Some(Errno::ENOMEM));
    }

    #[test]
    fn empty_signal_set_is_rejected() {
        let error = install_crash_handler::<_>(&[], |_| Ok(())).unwrap_err();
        assert_eq!(error, Errno::EINVAL);
    }

    #[test]
    fn early_core_pattern_fails_closed_only_for_c_accepted_absolute_paths() {
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline(
                "systemd.early_core_pattern=/run/early-core"
            ),
            Some(UnsupportedCrashStartupPolicy::EarlyCorePattern)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline(
                "systemd.early_core_pattern=relative-core"
            ),
            None,
            "C warns and ignores relative core-pattern values"
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline(
                "systemd.early_core_pattern=/run/early-core systemd.early_core_pattern=relative-core"
            ),
            Some(UnsupportedCrashStartupPolicy::EarlyCorePattern),
            "a later C-invalid relative value retains the earlier active core pattern"
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.early_core_pattern="),
            None,
            "a missing C value leaves the default untouched"
        );
    }

    #[test]
    fn crash_startup_policy_preserves_c_crash_switch_semantics() {
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_shell"),
            Some(UnsupportedCrashStartupPolicy::CrashShell)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt"),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_action=reboot"),
            Some(UnsupportedCrashStartupPolicy::CrashAction(
                "reboot".to_string()
            ))
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_action=freeze"),
            None
        );
    }

    #[test]
    fn crash_change_vt_matches_c_boolean_integer_and_last_assignment_rules() {
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt"),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt=yes"),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt=0"),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt=7"),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal)
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt=no"),
            None
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline("systemd.crash_chvt=-1"),
            None
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline(
                "systemd.crash_chvt=yes systemd.crash_chvt=invalid"
            ),
            Some(UnsupportedCrashStartupPolicy::CrashChangeVirtualTerminal),
            "an invalid later assignment must retain C's earlier valid setting"
        );
        assert_eq!(
            unsupported_crash_startup_policy_from_cmdline(
                "systemd.crash_chvt=yes systemd.crash_chvt=-1"
            ),
            None
        );
    }
}
