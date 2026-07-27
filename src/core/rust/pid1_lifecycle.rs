// SPDX-License-Identifier: LGPL-2.1-or-later

//! Pure decoding for the signal-owned portion of the PID 1 lifecycle.
//!
//! Signal ingestion and manager mutation deliberately remain separate. The
//! signalfd callback creates one [`SignalRecord`]; the event-loop owner decodes
//! and applies one [`SignalAction`] in FIFO order.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalRecord {
    pub signal: i32,
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub code: i32,
    pub value: i32,
}

// Keep the PID 1 signal path on the canonical manager objective vocabulary.
// A signal is only one of several possible producers of an objective, and it
// must not invent a parallel subset that can later drift from manager.c.
pub use crate::manager_tables::ManagerObjective;

/// The boundary between the manager event loop and PID 1's outer lifecycle.
///
/// C's `manager_loop()` stops dispatching once an objective is set; its caller
/// then performs reload, reexec, root-switch, or shutdown work. This type
/// keeps that ordering explicit without letting an event callback perform a
/// partial process-global transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterLoopExit {
    Reload,
    Reexecute,
    SwitchRoot,
    SoftReboot,
    Exit,
    Shutdown(ShutdownObjective),
}

/// Shutdown actions are process-global lifecycle requests, not unit jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownObjective {
    Halt,
    Poweroff,
    Reboot,
    Kexec,
}

/// Convert a canonical manager objective into the outer-loop return contract.
/// `Ok` means the event loop must keep dispatching and therefore has no return
/// value. The remaining variants follow `invoke_main_loop()` in C exactly:
/// reload first, reexec/root-switch/soft-reboot next, then exit/shutdown.
pub const fn outer_loop_exit(objective: ManagerObjective) -> Option<OuterLoopExit> {
    match objective {
        ManagerObjective::Ok => None,
        ManagerObjective::Reload => Some(OuterLoopExit::Reload),
        ManagerObjective::Reexecute => Some(OuterLoopExit::Reexecute),
        ManagerObjective::SwitchRoot => Some(OuterLoopExit::SwitchRoot),
        ManagerObjective::SoftReboot => Some(OuterLoopExit::SoftReboot),
        ManagerObjective::Exit => Some(OuterLoopExit::Exit),
        ManagerObjective::Halt => Some(OuterLoopExit::Shutdown(ShutdownObjective::Halt)),
        ManagerObjective::Poweroff => Some(OuterLoopExit::Shutdown(ShutdownObjective::Poweroff)),
        ManagerObjective::Reboot => Some(OuterLoopExit::Shutdown(ShutdownObjective::Reboot)),
        ManagerObjective::Kexec => Some(OuterLoopExit::Shutdown(ShutdownObjective::Kexec)),
    }
}

impl OuterLoopExit {
    pub const fn operation_name(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Reexecute => "reexecute",
            Self::SwitchRoot => "switch-root",
            Self::SoftReboot => "soft-reboot",
            Self::Exit => "exit",
            Self::Shutdown(ShutdownObjective::Halt) => "halt",
            Self::Shutdown(ShutdownObjective::Poweroff) => "poweroff",
            Self::Shutdown(ShutdownObjective::Reboot) => "reboot",
            Self::Shutdown(ShutdownObjective::Kexec) => "kexec",
        }
    }

    /// State transfer that must exist before the objective can be completed
    /// honestly. The current outer owner reports this and stops instead of
    /// accepting an operation while retaining stale runtime state.
    pub const fn missing_runtime_contract(self) -> &'static str {
        match self {
            Self::Reload => {
                "RuntimeManager serialization, unit re-enumeration, deserialization, and coldplug"
            }
            Self::Reexecute => {
                "RuntimeManager serialization plus descriptor-preserving exec handoff"
            }
            Self::SwitchRoot => {
                "RuntimeManager serialization, root-switch ownership transfer, and exec handoff"
            }
            Self::SoftReboot => {
                "RuntimeManager serialization, soft-reboot teardown, and exec handoff"
            }
            Self::Exit => "a user-manager return-value and caller handoff path",
            Self::Shutdown(_) => {
                "the systemd-shutdown handoff, remaining-process cleanup, and reboot syscall path"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialTarget {
    Default,
    Rescue,
    Emergency,
    Halt,
    Poweroff,
    Reboot,
    Kexec,
    SoftReboot,
    CtrlAltDel,
    KeyboardRequest,
    PowerFailure,
}

impl SpecialTarget {
    pub const fn unit_name(self) -> &'static str {
        match self {
            Self::Default => "default.target",
            Self::Rescue => "rescue.target",
            Self::Emergency => "emergency.target",
            Self::Halt => "halt.target",
            Self::Poweroff => "poweroff.target",
            Self::Reboot => "reboot.target",
            Self::Kexec => "kexec.target",
            Self::SoftReboot => "soft-reboot.target",
            Self::CtrlAltDel => "ctrl-alt-del.target",
            Self::KeyboardRequest => "kbrequest.target",
            Self::PowerFailure => "sigpwr.target",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialTargetMode {
    Replace,
    ReplaceIrreversibly,
    Isolate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerControl {
    EnableStatus,
    DisableStatus,
    DebugLogLevel,
    RestoreLogLevel,
    RestoreLogTarget,
    ConsoleLogTarget,
    KmsgLogTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    ReapChildren,
    RequestObjective(ManagerObjective),
    StartSpecial {
        target: SpecialTarget,
        mode: SpecialTargetMode,
    },
    ReconnectBus,
    DumpManager,
    CommonControl(SignalRecord),
    ManagerControl(ManagerControl),
    Ignore,
    Unsupported(SignalRecord),
}

pub fn decode_system_signal(record: SignalRecord, realtime_min: i32) -> SignalAction {
    match record.signal {
        libc::SIGCHLD => SignalAction::ReapChildren,
        libc::SIGTERM => SignalAction::RequestObjective(ManagerObjective::Reexecute),
        libc::SIGINT => SignalAction::StartSpecial {
            target: SpecialTarget::CtrlAltDel,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        libc::SIGWINCH => SignalAction::StartSpecial {
            target: SpecialTarget::KeyboardRequest,
            mode: SpecialTargetMode::Replace,
        },
        libc::SIGPWR => SignalAction::StartSpecial {
            target: SpecialTarget::PowerFailure,
            mode: SpecialTargetMode::Replace,
        },
        libc::SIGUSR1 => SignalAction::ReconnectBus,
        libc::SIGUSR2 => SignalAction::DumpManager,
        libc::SIGHUP => SignalAction::RequestObjective(ManagerObjective::Reload),
        signal if signal == realtime_min => SignalAction::StartSpecial {
            target: SpecialTarget::Default,
            mode: SpecialTargetMode::Isolate,
        },
        signal if signal == realtime_min + 1 => SignalAction::StartSpecial {
            target: SpecialTarget::Rescue,
            mode: SpecialTargetMode::Isolate,
        },
        signal if signal == realtime_min + 2 => SignalAction::StartSpecial {
            target: SpecialTarget::Emergency,
            mode: SpecialTargetMode::Isolate,
        },
        signal if signal == realtime_min + 3 => SignalAction::StartSpecial {
            target: SpecialTarget::Halt,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        signal if signal == realtime_min + 4 => SignalAction::StartSpecial {
            target: SpecialTarget::Poweroff,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        signal if signal == realtime_min + 5 => SignalAction::StartSpecial {
            target: SpecialTarget::Reboot,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        signal if signal == realtime_min + 6 => SignalAction::StartSpecial {
            target: SpecialTarget::Kexec,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        signal if signal == realtime_min + 7 => SignalAction::StartSpecial {
            target: SpecialTarget::SoftReboot,
            mode: SpecialTargetMode::ReplaceIrreversibly,
        },
        signal if signal == realtime_min + 13 => {
            SignalAction::RequestObjective(ManagerObjective::Halt)
        }
        signal if signal == realtime_min + 14 => {
            SignalAction::RequestObjective(ManagerObjective::Poweroff)
        }
        signal if signal == realtime_min + 15 => {
            SignalAction::RequestObjective(ManagerObjective::Reboot)
        }
        signal if signal == realtime_min + 16 => {
            SignalAction::RequestObjective(ManagerObjective::Kexec)
        }
        signal if signal == realtime_min + 17 => {
            SignalAction::RequestObjective(ManagerObjective::SoftReboot)
        }
        signal if signal == realtime_min + 18 => SignalAction::CommonControl(record),
        signal if signal == realtime_min + 20 => {
            SignalAction::ManagerControl(ManagerControl::EnableStatus)
        }
        signal if signal == realtime_min + 21 => {
            SignalAction::ManagerControl(ManagerControl::DisableStatus)
        }
        signal if signal == realtime_min + 22 => {
            SignalAction::ManagerControl(ManagerControl::DebugLogLevel)
        }
        signal if signal == realtime_min + 23 => {
            SignalAction::ManagerControl(ManagerControl::RestoreLogLevel)
        }
        signal if signal == realtime_min + 24 => SignalAction::Ignore,
        signal if signal == realtime_min + 25 => {
            SignalAction::RequestObjective(ManagerObjective::Reexecute)
        }
        signal if signal == realtime_min + 26 || signal == realtime_min + 29 => {
            SignalAction::ManagerControl(ManagerControl::RestoreLogTarget)
        }
        signal if signal == realtime_min + 27 => {
            SignalAction::ManagerControl(ManagerControl::ConsoleLogTarget)
        }
        signal if signal == realtime_min + 28 => {
            SignalAction::ManagerControl(ManagerControl::KmsgLogTarget)
        }
        _ => SignalAction::Unsupported(record),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(signal: i32) -> SignalRecord {
        SignalRecord {
            signal,
            sender_pid: 42,
            sender_uid: 1000,
            code: libc::SI_USER,
            value: 0,
        }
    }

    #[test]
    fn system_manager_standard_signal_mapping_matches_c() {
        let realtime_min = 100;
        assert_eq!(
            decode_system_signal(record(libc::SIGTERM), realtime_min),
            SignalAction::RequestObjective(ManagerObjective::Reexecute)
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGHUP), realtime_min),
            SignalAction::RequestObjective(ManagerObjective::Reload)
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGINT), realtime_min),
            SignalAction::StartSpecial {
                target: SpecialTarget::CtrlAltDel,
                mode: SpecialTargetMode::ReplaceIrreversibly,
            }
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGCHLD), realtime_min),
            SignalAction::ReapChildren
        );
    }

    #[test]
    fn standard_operational_signals_select_the_c_special_targets() {
        let realtime_min = 100;
        assert_eq!(
            decode_system_signal(record(libc::SIGWINCH), realtime_min),
            SignalAction::StartSpecial {
                target: SpecialTarget::KeyboardRequest,
                mode: SpecialTargetMode::Replace,
            }
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGPWR), realtime_min),
            SignalAction::StartSpecial {
                target: SpecialTarget::PowerFailure,
                mode: SpecialTargetMode::Replace,
            }
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGUSR1), realtime_min),
            SignalAction::ReconnectBus
        );
        assert_eq!(
            decode_system_signal(record(libc::SIGUSR2), realtime_min),
            SignalAction::DumpManager
        );
    }

    #[test]
    fn realtime_objectives_and_targets_are_not_conflated() {
        let realtime_min = 100;
        assert_eq!(
            decode_system_signal(record(realtime_min + 4), realtime_min),
            SignalAction::StartSpecial {
                target: SpecialTarget::Poweroff,
                mode: SpecialTargetMode::ReplaceIrreversibly,
            }
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 14), realtime_min),
            SignalAction::RequestObjective(ManagerObjective::Poweroff)
        );
    }

    #[test]
    fn outer_loop_exit_uses_the_c_objective_groups() {
        assert_eq!(outer_loop_exit(ManagerObjective::Ok), None);
        assert_eq!(
            outer_loop_exit(ManagerObjective::Reload),
            Some(OuterLoopExit::Reload)
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Reexecute),
            Some(OuterLoopExit::Reexecute)
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::SwitchRoot),
            Some(OuterLoopExit::SwitchRoot)
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::SoftReboot),
            Some(OuterLoopExit::SoftReboot)
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Exit),
            Some(OuterLoopExit::Exit)
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Reboot),
            Some(OuterLoopExit::Shutdown(ShutdownObjective::Reboot))
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Poweroff),
            Some(OuterLoopExit::Shutdown(ShutdownObjective::Poweroff))
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Halt),
            Some(OuterLoopExit::Shutdown(ShutdownObjective::Halt))
        );
        assert_eq!(
            outer_loop_exit(ManagerObjective::Kexec),
            Some(OuterLoopExit::Shutdown(ShutdownObjective::Kexec))
        );
    }

    #[test]
    fn common_control_preserves_sender_and_payload() {
        let realtime_min = 100;
        let command = SignalRecord {
            signal: realtime_min + 18,
            sender_pid: 7,
            sender_uid: 8,
            code: libc::SI_QUEUE,
            value: 0x301,
        };
        assert_eq!(
            decode_system_signal(command, realtime_min),
            SignalAction::CommonControl(command)
        );
    }

    #[test]
    fn realtime_manager_controls_match_the_c_offsets() {
        let realtime_min = 100;
        assert_eq!(
            decode_system_signal(record(realtime_min + 20), realtime_min),
            SignalAction::ManagerControl(ManagerControl::EnableStatus)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 21), realtime_min),
            SignalAction::ManagerControl(ManagerControl::DisableStatus)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 22), realtime_min),
            SignalAction::ManagerControl(ManagerControl::DebugLogLevel)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 23), realtime_min),
            SignalAction::ManagerControl(ManagerControl::RestoreLogLevel)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 24), realtime_min),
            SignalAction::Ignore
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 25), realtime_min),
            SignalAction::RequestObjective(ManagerObjective::Reexecute)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 26), realtime_min),
            SignalAction::ManagerControl(ManagerControl::RestoreLogTarget)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 27), realtime_min),
            SignalAction::ManagerControl(ManagerControl::ConsoleLogTarget)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 28), realtime_min),
            SignalAction::ManagerControl(ManagerControl::KmsgLogTarget)
        );
        assert_eq!(
            decode_system_signal(record(realtime_min + 29), realtime_min),
            SignalAction::ManagerControl(ManagerControl::RestoreLogTarget)
        );
    }

    #[test]
    fn unallocated_realtime_offset_and_unknown_signal_preserve_the_record() {
        let realtime_min = 100;
        let reserved_gap = record(realtime_min + 8);
        assert_eq!(
            decode_system_signal(reserved_gap, realtime_min),
            SignalAction::Unsupported(reserved_gap)
        );

        let unknown = record(999);
        assert_eq!(
            decode_system_signal(unknown, realtime_min),
            SignalAction::Unsupported(unknown)
        );
    }

    #[test]
    fn special_target_names_match_manager_special_unit_names() {
        assert_eq!(SpecialTarget::CtrlAltDel.unit_name(), "ctrl-alt-del.target");
        assert_eq!(
            SpecialTarget::KeyboardRequest.unit_name(),
            "kbrequest.target"
        );
        assert_eq!(SpecialTarget::PowerFailure.unit_name(), "sigpwr.target");
        assert_eq!(SpecialTarget::SoftReboot.unit_name(), "soft-reboot.target");
    }
}
