// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/service.c, src/core/service.h
//
use std::str::FromStr;

use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseServiceTableError;

impl ParseServiceTableError {
    pub const fn errno(self) -> i32 {
        Errno::EINVAL.to_neg_errno()
    }
}

macro_rules! service_enum {
    ($name:ident, $err:expr, $(($variant:ident, $index:expr, $text:expr)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub const fn to_index(self) -> i32 {
                match self {
                    $(Self::$variant => $index),+
                }
            }

            pub const fn from_index(value: i32) -> Option<Self> {
                match value {
                    $($index => Some(Self::$variant),)+
                    _ => None,
                }
            }

        }

        impl FromStr for $name {
            type Err = ParseServiceTableError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err($err),
                }
            }
        }
    };
}

service_enum!(
    ServiceRestart,
    ParseServiceTableError,
    (No, 0, "no"),
    (OnSuccess, 1, "on-success"),
    (OnFailure, 2, "on-failure"),
    (OnAbnormal, 3, "on-abnormal"),
    (OnWatchdog, 4, "on-watchdog"),
    (OnAbort, 5, "on-abort"),
    (Always, 6, "always"),
);

service_enum!(
    ServiceRestartMode,
    ParseServiceTableError,
    (Normal, 0, "normal"),
    (Direct, 1, "direct"),
    (Debug, 2, "debug"),
);

service_enum!(
    ServiceType,
    ParseServiceTableError,
    (Simple, 0, "simple"),
    (Forking, 1, "forking"),
    (Oneshot, 2, "oneshot"),
    (Dbus, 3, "dbus"),
    (Notify, 4, "notify"),
    (NotifyReload, 5, "notify-reload"),
    (Idle, 6, "idle"),
    (Exec, 7, "exec"),
);

service_enum!(
    ServiceExitType,
    ParseServiceTableError,
    (Main, 0, "main"),
    (Cgroup, 1, "cgroup"),
);

service_enum!(
    ServiceExecCommand,
    ParseServiceTableError,
    (Condition, 0, "ExecCondition"),
    (StartPre, 1, "ExecStartPre"),
    (Start, 2, "ExecStart"),
    (StartPost, 3, "ExecStartPost"),
    (Reload, 4, "ExecReload"),
    (ReloadPost, 5, "ExecReloadPost"),
    (Stop, 6, "ExecStop"),
    (StopPost, 7, "ExecStopPost"),
);

service_enum!(
    NotifyState,
    ParseServiceTableError,
    (Ready, 0, "ready"),
    (Reloading, 1, "reloading"),
    (ReloadReady, 2, "reload-ready"),
    (Stopping, 3, "stopping"),
);

service_enum!(
    ServiceResult,
    ParseServiceTableError,
    (Success, 0, "success"),
    (FailureResources, 1, "resources"),
    (FailureProtocol, 2, "protocol"),
    (FailureTimeout, 3, "timeout"),
    (FailureExitCode, 4, "exit-code"),
    (FailureSignal, 5, "signal"),
    (FailureCoreDump, 6, "core-dump"),
    (FailureWatchdog, 7, "watchdog"),
    (FailureStartLimitHit, 8, "start-limit-hit"),
    (FailureOomKill, 9, "oom-kill"),
    (SkipCondition, 10, "exec-condition"),
);

service_enum!(
    ServiceTimeoutFailureMode,
    ParseServiceTableError,
    (Terminate, 0, "terminate"),
    (Abort, 1, "abort"),
    (Kill, 2, "kill"),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceRefreshOnReload {
    Extensions,
    Credentials,
}

impl ServiceRefreshOnReload {
    pub const DEFAULT: Self = Self::Extensions;

    pub const fn bit(self) -> u32 {
        match self {
            Self::Extensions => 1 << 0,
            Self::Credentials => 1 << 1,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extensions => "extensions",
            Self::Credentials => "credentials",
        }
    }
}

impl FromStr for ServiceRefreshOnReload {
    type Err = ParseServiceTableError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "extensions" => Ok(Self::Extensions),
            "credentials" => Ok(Self::Credentials),
            _ => Err(ParseServiceTableError),
        }
    }
}

pub const fn service_restart_to_string(value: ServiceRestart) -> &'static str {
    value.as_str()
}

pub fn service_restart_from_string(value: &str) -> Result<ServiceRestart, ParseServiceTableError> {
    ServiceRestart::from_str(value)
}

pub const fn service_restart_mode_to_string(value: ServiceRestartMode) -> &'static str {
    value.as_str()
}

pub fn service_restart_mode_from_string(
    value: &str,
) -> Result<ServiceRestartMode, ParseServiceTableError> {
    ServiceRestartMode::from_str(value)
}

pub const fn service_type_to_string(value: ServiceType) -> &'static str {
    value.as_str()
}

pub fn service_type_from_string(value: &str) -> Result<ServiceType, ParseServiceTableError> {
    ServiceType::from_str(value)
}

pub const fn service_exit_type_to_string(value: ServiceExitType) -> &'static str {
    value.as_str()
}

pub fn service_exit_type_from_string(
    value: &str,
) -> Result<ServiceExitType, ParseServiceTableError> {
    ServiceExitType::from_str(value)
}

pub const fn service_exec_command_to_string(value: ServiceExecCommand) -> &'static str {
    value.as_str()
}

pub fn service_exec_command_from_string(
    value: &str,
) -> Result<ServiceExecCommand, ParseServiceTableError> {
    ServiceExecCommand::from_str(value)
}

pub fn service_exec_ex_command_to_string(value: ServiceExecCommand) -> String {
    format!("{}Ex", value.as_str())
}

pub fn service_exec_ex_command_from_string(
    value: &str,
) -> Result<ServiceExecCommand, ParseServiceTableError> {
    let base = value.strip_suffix("Ex").ok_or(ParseServiceTableError)?;
    ServiceExecCommand::from_str(base)
}

pub const fn notify_state_to_string(value: NotifyState) -> &'static str {
    value.as_str()
}

pub fn notify_state_from_string(value: &str) -> Result<NotifyState, ParseServiceTableError> {
    NotifyState::from_str(value)
}

pub const fn service_result_to_string(value: ServiceResult) -> &'static str {
    value.as_str()
}

pub fn service_result_from_string(value: &str) -> Result<ServiceResult, ParseServiceTableError> {
    ServiceResult::from_str(value)
}

pub const fn service_timeout_failure_mode_to_string(
    value: ServiceTimeoutFailureMode,
) -> &'static str {
    value.as_str()
}

pub fn service_timeout_failure_mode_from_string(
    value: &str,
) -> Result<ServiceTimeoutFailureMode, ParseServiceTableError> {
    ServiceTimeoutFailureMode::from_str(value)
}

pub fn service_refresh_on_reload_flag_from_string(
    value: &str,
) -> Result<ServiceRefreshOnReload, ParseServiceTableError> {
    ServiceRefreshOnReload::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_round_trip_matches_c_order() {
        assert_eq!(ServiceRestart::from_index(0), Some(ServiceRestart::No));
        assert_eq!(ServiceRestart::from_index(6), Some(ServiceRestart::Always));
        assert_eq!(
            service_restart_to_string(ServiceRestart::OnFailure),
            "on-failure"
        );
        assert_eq!(
            service_restart_from_string("on-watchdog"),
            Ok(ServiceRestart::OnWatchdog)
        );
    }

    #[test]
    fn restart_mode_round_trip_matches_c_order() {
        assert_eq!(ServiceRestartMode::Direct.to_index(), 1);
        assert_eq!(
            service_restart_mode_from_string("debug"),
            Ok(ServiceRestartMode::Debug)
        );
    }

    #[test]
    fn service_type_round_trip_matches_c_order() {
        assert_eq!(ServiceType::Exec.to_index(), 7);
        assert_eq!(
            service_type_from_string("notify-reload"),
            Ok(ServiceType::NotifyReload)
        );
    }

    #[test]
    fn exit_type_round_trip_matches_c_order() {
        assert_eq!(
            service_exit_type_to_string(ServiceExitType::Cgroup),
            "cgroup"
        );
        assert_eq!(
            service_exit_type_from_string("main"),
            Ok(ServiceExitType::Main)
        );
    }

    #[test]
    fn exec_command_ex_helpers_follow_c_suffixing() {
        assert_eq!(
            service_exec_ex_command_to_string(ServiceExecCommand::ReloadPost),
            "ExecReloadPostEx"
        );
        assert_eq!(
            service_exec_ex_command_from_string("ExecStartEx"),
            Ok(ServiceExecCommand::Start)
        );
    }

    #[test]
    fn notify_state_round_trip_matches_c_order() {
        assert_eq!(NotifyState::ReloadReady.to_index(), 2);
        assert_eq!(
            notify_state_from_string("stopping"),
            Ok(NotifyState::Stopping)
        );
    }

    #[test]
    fn service_result_round_trip_matches_c_order() {
        assert_eq!(ServiceResult::SkipCondition.to_index(), 10);
        assert_eq!(
            service_result_from_string("oom-kill"),
            Ok(ServiceResult::FailureOomKill)
        );
    }

    #[test]
    fn timeout_failure_mode_round_trip_matches_c_order() {
        assert_eq!(
            service_timeout_failure_mode_to_string(ServiceTimeoutFailureMode::Abort),
            "abort"
        );
        assert_eq!(
            service_timeout_failure_mode_from_string("kill"),
            Ok(ServiceTimeoutFailureMode::Kill)
        );
    }

    #[test]
    fn refresh_on_reload_flags_parse() {
        assert_eq!(
            service_refresh_on_reload_flag_from_string("extensions"),
            Ok(ServiceRefreshOnReload::Extensions)
        );
        assert_eq!(ServiceRefreshOnReload::Credentials.bit(), 1 << 1);
        assert_eq!(
            ServiceRefreshOnReload::DEFAULT,
            ServiceRefreshOnReload::Extensions
        );
    }

    #[test]
    fn invalid_values_return_einval_shape() {
        let err = service_type_from_string("bogus").unwrap_err();
        assert_eq!(err.errno(), Errno::EINVAL.to_neg_errno());
        assert_eq!(ServiceExecCommand::from_index(-1), None);
        assert!(service_exec_ex_command_from_string("ExecStart").is_err());
    }
}
