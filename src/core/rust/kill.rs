// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/kill.c, src/core/kill.h
//
use std::{fmt, str::FromStr};

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;
pub const SIGABRT: i32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillError {
    InvalidKillMode,
    InvalidKillWhom,
}

impl fmt::Display for KillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for KillError {}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMode {
    ControlGroup = 0,
    Process = 1,
    Mixed = 2,
    None = 3,
}

impl KillMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlGroup => "control-group",
            Self::Process => "process",
            Self::Mixed => "mixed",
            Self::None => "none",
        }
    }
}

impl FromStr for KillMode {
    type Err = KillError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "control-group" => Ok(Self::ControlGroup),
            "process" => Ok(Self::Process),
            "mixed" => Ok(Self::Mixed),
            "none" => Ok(Self::None),
            _ => Err(KillError::InvalidKillMode),
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillWhom {
    Main = 0,
    Control = 1,
    All = 2,
    MainFail = 3,
    ControlFail = 4,
    AllFail = 5,
    Cgroup = 6,
    CgroupFail = 7,
}

impl KillWhom {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Control => "control",
            Self::All => "all",
            Self::MainFail => "main-fail",
            Self::ControlFail => "control-fail",
            Self::AllFail => "all-fail",
            Self::Cgroup => "cgroup",
            Self::CgroupFail => "cgroup-fail",
        }
    }
}

impl FromStr for KillWhom {
    type Err = KillError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "main" => Ok(Self::Main),
            "control" => Ok(Self::Control),
            "all" => Ok(Self::All),
            "main-fail" => Ok(Self::MainFail),
            "control-fail" => Ok(Self::ControlFail),
            "all-fail" => Ok(Self::AllFail),
            "cgroup" => Ok(Self::Cgroup),
            "cgroup-fail" => Ok(Self::CgroupFail),
            _ => Err(KillError::InvalidKillWhom),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillContext {
    pub kill_mode: KillMode,
    pub kill_signal: i32,
    pub restart_kill_signal: i32,
    pub final_kill_signal: i32,
    pub watchdog_signal: i32,
    pub send_sigkill: bool,
    pub send_sighup: bool,
}

impl Default for KillContext {
    fn default() -> Self {
        Self {
            kill_mode: KillMode::ControlGroup,
            kill_signal: SIGTERM,
            restart_kill_signal: 0,
            final_kill_signal: SIGKILL,
            watchdog_signal: SIGABRT,
            send_sigkill: true,
            send_sighup: false,
        }
    }
}

pub fn kill_context_init() -> KillContext {
    KillContext::default()
}

pub fn restart_kill_signal(context: &KillContext) -> i32 {
    if context.restart_kill_signal != 0 {
        context.restart_kill_signal
    } else {
        context.kill_signal
    }
}

pub fn signal_to_string(signal: i32) -> String {
    match signal {
        SIGTERM => "TERM".into(),
        SIGKILL => "KILL".into(),
        SIGABRT => "ABRT".into(),
        other => other.to_string(),
    }
}

pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub fn kill_context_dump(context: &KillContext, prefix: Option<&str>) -> String {
    let prefix = prefix.unwrap_or("");
    format!(
        "{prefix}KillMode: {}\n{prefix}KillSignal: SIG{}\n{prefix}RestartKillSignal: SIG{}\n{prefix}FinalKillSignal: SIG{}\n{prefix}SendSIGKILL: {}\n{prefix}SendSIGHUP: {}\n",
        context.kill_mode.as_str(),
        signal_to_string(context.kill_signal),
        signal_to_string(restart_kill_signal(context)),
        signal_to_string(context.final_kill_signal),
        yes_no(context.send_sigkill),
        yes_no(context.send_sighup),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_uses_c_defaults() {
        let context = kill_context_init();
        assert_eq!(context.kill_signal, SIGTERM);
        assert_eq!(context.final_kill_signal, SIGKILL);
        assert!(context.send_sigkill);
    }

    #[test]
    fn restart_signal_falls_back_to_kill_signal() {
        let context = kill_context_init();
        assert_eq!(restart_kill_signal(&context), SIGTERM);
    }

    #[test]
    fn restart_signal_prefers_override() {
        let mut context = kill_context_init();
        context.restart_kill_signal = 1;
        assert_eq!(restart_kill_signal(&context), 1);
    }

    #[test]
    fn kill_mode_round_trips() {
        assert_eq!(KillMode::from_str("mixed").unwrap().as_str(), "mixed");
    }

    #[test]
    fn kill_mode_rejects_unknown_values() {
        assert_eq!(KillMode::from_str("bogus"), Err(KillError::InvalidKillMode));
    }

    #[test]
    fn kill_whom_round_trips() {
        assert_eq!(
            KillWhom::from_str("cgroup-fail").unwrap().as_str(),
            "cgroup-fail"
        );
    }

    #[test]
    fn kill_whom_rejects_unknown_values() {
        assert_eq!(KillWhom::from_str("bogus"), Err(KillError::InvalidKillWhom));
    }

    #[test]
    fn dump_matches_expected_shape() {
        let dump = kill_context_dump(&kill_context_init(), Some("prefix-"));
        assert!(dump.contains("prefix-KillMode: control-group"));
        assert!(dump.contains("prefix-SendSIGKILL: yes"));
    }

    #[test]
    fn yes_no_formats_booleans() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn signal_to_string_uses_names_for_known_signals() {
        assert_eq!(signal_to_string(SIGABRT), "ABRT");
        assert_eq!(signal_to_string(10), "10");
    }
}
