// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/emergency-action.c, src/core/emergency-action.h
//
//! Compiled-but-disconnected emergency-action model.
//!
//! This records the C policy in a testable value model. It is not the live
//! [`crate::runtime_manager::RuntimeManager`] owner, but it shares that
//! manager's canonical objective vocabulary.

use crate::ffi::Errno;
pub use crate::manager_tables::ManagerObjective;

pub const SOURCE_PATH_C: &str = "src/core/emergency-action.c";
pub const SOURCE_PATH_H: &str = "src/core/emergency-action.h";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyAction {
    None,
    Exit,
    ExitForce,
    Reboot,
    RebootForce,
    RebootImmediate,
    Poweroff,
    PoweroffForce,
    PoweroffImmediate,
    SoftReboot,
    SoftRebootForce,
    Kexec,
    KexecForce,
    Halt,
    HaltForce,
    HaltImmediate,
}

impl EmergencyAction {
    pub const LAST_USER_ACTION: Self = Self::ExitForce;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exit => "exit",
            Self::ExitForce => "exit-force",
            Self::Reboot => "reboot",
            Self::RebootForce => "reboot-force",
            Self::RebootImmediate => "reboot-immediate",
            Self::Poweroff => "poweroff",
            Self::PoweroffForce => "poweroff-force",
            Self::PoweroffImmediate => "poweroff-immediate",
            Self::SoftReboot => "soft-reboot",
            Self::SoftRebootForce => "soft-reboot-force",
            Self::Kexec => "kexec",
            Self::KexecForce => "kexec-force",
            Self::Halt => "halt",
            Self::HaltForce => "halt-force",
            Self::HaltImmediate => "halt-immediate",
        }
    }

    pub fn from_str(value: &str) -> Result<Self, Errno> {
        match value {
            "none" => Ok(Self::None),
            "exit" => Ok(Self::Exit),
            "exit-force" => Ok(Self::ExitForce),
            "reboot" => Ok(Self::Reboot),
            "reboot-force" => Ok(Self::RebootForce),
            "reboot-immediate" => Ok(Self::RebootImmediate),
            "poweroff" => Ok(Self::Poweroff),
            "poweroff-force" => Ok(Self::PoweroffForce),
            "poweroff-immediate" => Ok(Self::PoweroffImmediate),
            "soft-reboot" => Ok(Self::SoftReboot),
            "soft-reboot-force" => Ok(Self::SoftRebootForce),
            "kexec" => Ok(Self::Kexec),
            "kexec-force" => Ok(Self::KexecForce),
            "halt" => Ok(Self::Halt),
            "halt-force" => Ok(Self::HaltForce),
            "halt-immediate" => Ok(Self::HaltImmediate),
            _ => Err(Errno::EINVAL),
        }
    }

    pub const fn is_shutdown_sensitive(self) -> bool {
        matches!(
            self,
            Self::Reboot
                | Self::SoftReboot
                | Self::Poweroff
                | Self::Exit
                | Self::Kexec
                | Self::Halt
        )
    }

    pub const fn supports_sleep(self) -> bool {
        matches!(
            self,
            Self::ExitForce
                | Self::RebootForce
                | Self::RebootImmediate
                | Self::PoweroffForce
                | Self::PoweroffImmediate
                | Self::SoftRebootForce
                | Self::KexecForce
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyActionFlags(u32);

impl EmergencyActionFlags {
    pub const NONE: Self = Self(0);
    pub const IS_WATCHDOG: Self = Self(1 << 0);
    pub const WARN: Self = Self(1 << 1);
    pub const SLEEP_5S: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootMode {
    Restart2,
    AutoBoot,
    PowerOff,
    HaltSystem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootCall {
    pub mode: RebootMode,
    pub argument: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manager {
    pub shutdown_target_active: bool,
    pub service_watchdogs: bool,
    pub is_user: bool,
    pub in_container: bool,
    pub objective: ManagerObjective,
    pub return_value: Option<i32>,
    pub logs: Vec<String>,
    pub status_messages: Vec<String>,
    pub requested_jobs: Vec<&'static str>,
    pub reboot_calls: Vec<RebootCall>,
    pub sync_performed: usize,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            shutdown_target_active: false,
            service_watchdogs: true,
            is_user: false,
            in_container: false,
            objective: ManagerObjective::Ok,
            return_value: None,
            logs: Vec::new(),
            status_messages: Vec::new(),
            requested_jobs: Vec::new(),
            reboot_calls: Vec::new(),
            sync_performed: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmergencyOutcome {
    pub skipped: bool,
    pub slept: bool,
}

pub fn parse_emergency_action(
    value: &str,
    runtime_scope: RuntimeScope,
) -> Result<EmergencyAction, Errno> {
    let action = EmergencyAction::from_str(value)?;
    if runtime_scope != RuntimeScope::System && is_after_last_user_action(action) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(action)
}

fn is_after_last_user_action(action: EmergencyAction) -> bool {
    !matches!(
        action,
        EmergencyAction::None | EmergencyAction::Exit | EmergencyAction::ExitForce
    )
}

fn log_and_status(
    manager: &mut Manager,
    action: EmergencyAction,
    flags: EmergencyActionFlags,
    message: &str,
    reason: &str,
) -> bool {
    let warn = flags.contains(EmergencyActionFlags::WARN);
    manager.logs.push(format!("{message}: {reason}"));

    let do_sleep =
        warn && flags.contains(EmergencyActionFlags::SLEEP_5S) && action.supports_sleep();

    if warn {
        let suffix = if do_sleep { ", proceeding in 5s" } else { "" };
        manager
            .status_messages
            .push(format!("{message}: {reason}{suffix}"));
    }

    do_sleep
}

pub fn emergency_action(
    manager: &mut Manager,
    action: EmergencyAction,
    flags: EmergencyActionFlags,
    reboot_arg: Option<&str>,
    exit_status: i32,
    reason: &str,
) -> Result<EmergencyOutcome, Errno> {
    if reason.is_empty() {
        return Err(Errno::EINVAL);
    }

    if action == EmergencyAction::None {
        return Ok(EmergencyOutcome {
            skipped: true,
            slept: false,
        });
    }

    if action.is_shutdown_sensitive() && manager.shutdown_target_active {
        manager.logs.push(format!(
            "Shutdown is already active. Skipping emergency action request {}.",
            action.as_str()
        ));
        return Ok(EmergencyOutcome {
            skipped: true,
            slept: false,
        });
    }

    if flags.contains(EmergencyActionFlags::IS_WATCHDOG) && !manager.service_watchdogs {
        manager
            .logs
            .push(format!("Watchdog disabled! Not acting on: {reason}"));
        return Ok(EmergencyOutcome {
            skipped: true,
            slept: false,
        });
    }

    let mut outcome = EmergencyOutcome::default();

    match action {
        EmergencyAction::Reboot => {
            outcome.slept = log_and_status(manager, action, flags, "Rebooting", reason);
            manager.requested_jobs.push("reboot.target");
        }
        EmergencyAction::RebootForce => {
            outcome.slept = log_and_status(manager, action, flags, "Forcibly rebooting", reason);
            manager.objective = ManagerObjective::Reboot;
        }
        EmergencyAction::RebootImmediate => {
            outcome.slept = log_and_status(manager, action, flags, "Rebooting immediately", reason);
            manager.sync_performed += 1;
            if let Some(arg) = reboot_arg.filter(|arg| !arg.is_empty()) {
                manager
                    .logs
                    .push(format!("Rebooting with argument '{arg}'."));
                manager.reboot_calls.push(RebootCall {
                    mode: RebootMode::Restart2,
                    argument: Some(arg.to_string()),
                });
            }
            manager.logs.push("Rebooting.".into());
            manager.reboot_calls.push(RebootCall {
                mode: RebootMode::AutoBoot,
                argument: None,
            });
        }
        EmergencyAction::SoftReboot => {
            outcome.slept = log_and_status(manager, action, flags, "Soft-rebooting", reason);
            manager.requested_jobs.push("soft-reboot.target");
        }
        EmergencyAction::SoftRebootForce => {
            outcome.slept =
                log_and_status(manager, action, flags, "Forcibly soft-rebooting", reason);
            manager.objective = ManagerObjective::SoftReboot;
        }
        EmergencyAction::Exit => {
            if exit_status >= 0 {
                manager.return_value = Some(exit_status);
            }

            if manager.is_user || manager.in_container {
                outcome.slept = log_and_status(manager, action, flags, "Exiting", reason);
                manager.requested_jobs.push("exit.target");
            } else {
                manager.logs.push(
                    "Doing \"poweroff\" action instead of an \"exit\" emergency action.".into(),
                );
                outcome.slept = log_and_status(
                    manager,
                    EmergencyAction::Poweroff,
                    flags,
                    "Powering off",
                    reason,
                );
                manager.requested_jobs.push("poweroff.target");
            }
        }
        EmergencyAction::Poweroff => {
            outcome.slept = log_and_status(manager, action, flags, "Powering off", reason);
            manager.requested_jobs.push("poweroff.target");
        }
        EmergencyAction::ExitForce => {
            if exit_status >= 0 {
                manager.return_value = Some(exit_status);
            }

            if manager.is_user || manager.in_container {
                outcome.slept =
                    log_and_status(manager, action, flags, "Exiting immediately", reason);
                manager.objective = ManagerObjective::Exit;
            } else {
                manager.logs.push(
                    "Doing \"poweroff-force\" action instead of an \"exit-force\" emergency action."
                        .into(),
                );
                outcome.slept = log_and_status(
                    manager,
                    EmergencyAction::PoweroffForce,
                    flags,
                    "Forcibly powering off",
                    reason,
                );
                manager.objective = ManagerObjective::Poweroff;
            }
        }
        EmergencyAction::PoweroffForce => {
            outcome.slept = log_and_status(manager, action, flags, "Forcibly powering off", reason);
            manager.objective = ManagerObjective::Poweroff;
        }
        EmergencyAction::PoweroffImmediate => {
            outcome.slept =
                log_and_status(manager, action, flags, "Powering off immediately", reason);
            manager.sync_performed += 1;
            manager.logs.push("Powering off.".into());
            manager.reboot_calls.push(RebootCall {
                mode: RebootMode::PowerOff,
                argument: None,
            });
        }
        EmergencyAction::Kexec => {
            outcome.slept = log_and_status(manager, action, flags, "Executing kexec", reason);
            manager.requested_jobs.push("kexec.target");
        }
        EmergencyAction::KexecForce => {
            outcome.slept =
                log_and_status(manager, action, flags, "Forcibly executing kexec", reason);
            manager.objective = ManagerObjective::Kexec;
        }
        EmergencyAction::Halt => {
            outcome.slept = log_and_status(manager, action, flags, "Halting", reason);
            manager.requested_jobs.push("halt.target");
        }
        EmergencyAction::HaltForce => {
            outcome.slept = log_and_status(manager, action, flags, "Forcibly halting", reason);
            manager.objective = ManagerObjective::Halt;
        }
        EmergencyAction::HaltImmediate => {
            outcome.slept = log_and_status(manager, action, flags, "Halting immediately", reason);
            manager.sync_performed += 1;
            manager.logs.push("Halting.".into());
            manager.reboot_calls.push(RebootCall {
                mode: RebootMode::HaltSystem,
                argument: None,
            });
        }
        EmergencyAction::None => unreachable!(),
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_paths_match_c_and_header() {
        assert_eq!(SOURCE_PATH_C, "src/core/emergency-action.c");
        assert_eq!(SOURCE_PATH_H, "src/core/emergency-action.h");
    }

    #[test]
    fn string_roundtrip_covers_table() {
        let actions = [
            EmergencyAction::None,
            EmergencyAction::Exit,
            EmergencyAction::ExitForce,
            EmergencyAction::Reboot,
            EmergencyAction::RebootForce,
            EmergencyAction::RebootImmediate,
            EmergencyAction::Poweroff,
            EmergencyAction::PoweroffForce,
            EmergencyAction::PoweroffImmediate,
            EmergencyAction::SoftReboot,
            EmergencyAction::SoftRebootForce,
            EmergencyAction::Kexec,
            EmergencyAction::KexecForce,
            EmergencyAction::Halt,
            EmergencyAction::HaltForce,
            EmergencyAction::HaltImmediate,
        ];

        for action in actions {
            assert_eq!(EmergencyAction::from_str(action.as_str()).unwrap(), action);
        }
    }

    #[test]
    fn parse_rejects_system_only_actions_in_user_scope() {
        assert_eq!(
            parse_emergency_action("reboot", RuntimeScope::User).unwrap_err(),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn parse_accepts_user_scope_exit_force() {
        assert_eq!(
            parse_emergency_action("exit-force", RuntimeScope::User).unwrap(),
            EmergencyAction::ExitForce
        );
    }

    #[test]
    fn none_is_a_no_op() {
        let mut manager = Manager::default();
        let outcome = emergency_action(
            &mut manager,
            EmergencyAction::None,
            EmergencyActionFlags::NONE,
            None,
            -1,
            "ignored",
        )
        .unwrap();

        assert!(outcome.skipped);
        assert!(manager.requested_jobs.is_empty());
    }

    #[test]
    fn shutdown_active_skips_sensitive_actions() {
        let mut manager = Manager {
            shutdown_target_active: true,
            ..Manager::default()
        };
        let outcome = emergency_action(
            &mut manager,
            EmergencyAction::Reboot,
            EmergencyActionFlags::NONE,
            None,
            -1,
            "failure",
        )
        .unwrap();

        assert!(outcome.skipped);
        assert!(manager.requested_jobs.is_empty());
    }

    #[test]
    fn watchdog_disable_skips_watchdog_triggered_action() {
        let mut manager = Manager {
            service_watchdogs: false,
            ..Manager::default()
        };
        let outcome = emergency_action(
            &mut manager,
            EmergencyAction::Poweroff,
            EmergencyActionFlags::IS_WATCHDOG,
            None,
            -1,
            "watchdog",
        )
        .unwrap();

        assert!(outcome.skipped);
        assert!(manager.logs[0].contains("Watchdog disabled"));
    }

    #[test]
    fn exit_falls_back_to_poweroff_for_system_manager() {
        let mut manager = Manager::default();
        emergency_action(
            &mut manager,
            EmergencyAction::Exit,
            EmergencyActionFlags::NONE,
            None,
            42,
            "test",
        )
        .unwrap();

        assert_eq!(manager.return_value, Some(42));
        assert_eq!(manager.requested_jobs, vec!["poweroff.target"]);
        assert!(manager.logs.iter().any(|line| line.contains("poweroff")));
    }

    #[test]
    fn exit_force_sets_exit_objective_for_user_manager() {
        let mut manager = Manager {
            is_user: true,
            ..Manager::default()
        };
        emergency_action(
            &mut manager,
            EmergencyAction::ExitForce,
            EmergencyActionFlags::NONE,
            None,
            9,
            "failure",
        )
        .unwrap();

        assert_eq!(manager.objective, ManagerObjective::Exit);
        assert_eq!(manager.return_value, Some(9));
    }

    #[test]
    fn reboot_immediate_syncs_and_uses_argument_then_fallback() {
        let mut manager = Manager::default();
        emergency_action(
            &mut manager,
            EmergencyAction::RebootImmediate,
            EmergencyActionFlags::NONE,
            Some("rescue"),
            -1,
            "panic",
        )
        .unwrap();

        assert_eq!(manager.sync_performed, 1);
        assert_eq!(manager.reboot_calls.len(), 2);
        assert_eq!(manager.reboot_calls[0].mode, RebootMode::Restart2);
        assert_eq!(manager.reboot_calls[1].mode, RebootMode::AutoBoot);
    }

    #[test]
    fn warn_and_sleep_are_only_reported_for_supported_actions() {
        let mut manager = Manager::default();
        let outcome = emergency_action(
            &mut manager,
            EmergencyAction::PoweroffForce,
            EmergencyActionFlags::WARN.with(EmergencyActionFlags::SLEEP_5S),
            None,
            -1,
            "oops",
        )
        .unwrap();

        assert!(outcome.slept);
        assert!(manager.status_messages[0].contains("proceeding in 5s"));
    }
}
