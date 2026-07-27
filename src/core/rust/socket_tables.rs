// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/socket.c, src/core/socket.h
//

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketExecCommand {
    StartPre,
    StartChown,
    StartPost,
    StopPre,
    StopPost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketResult {
    Success,
    Resources,
    Timeout,
    ExitCode,
    Signal,
    CoreDump,
    StartLimitHit,
    TriggerLimitHit,
    ServiceStartLimitHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketTimestamping {
    Off,
    Us,
    Ns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDeferTrigger {
    No,
    Yes,
    Patient,
}

pub fn socket_exec_command_to_string(value: SocketExecCommand) -> &'static str {
    match value {
        SocketExecCommand::StartPre => "ExecStartPre",
        SocketExecCommand::StartChown => "ExecStartChown",
        SocketExecCommand::StartPost => "ExecStartPost",
        SocketExecCommand::StopPre => "ExecStopPre",
        SocketExecCommand::StopPost => "ExecStopPost",
    }
}

pub fn socket_exec_command_from_string(value: &str) -> Result<SocketExecCommand> {
    match value {
        "ExecStartPre" => Ok(SocketExecCommand::StartPre),
        "ExecStartChown" => Ok(SocketExecCommand::StartChown),
        "ExecStartPost" => Ok(SocketExecCommand::StartPost),
        "ExecStopPre" => Ok(SocketExecCommand::StopPre),
        "ExecStopPost" => Ok(SocketExecCommand::StopPost),
        _ => Err(Errno::EINVAL),
    }
}

pub fn socket_result_to_string(value: SocketResult) -> &'static str {
    match value {
        SocketResult::Success => "success",
        SocketResult::Resources => "resources",
        SocketResult::Timeout => "timeout",
        SocketResult::ExitCode => "exit-code",
        SocketResult::Signal => "signal",
        SocketResult::CoreDump => "core-dump",
        SocketResult::StartLimitHit => "start-limit-hit",
        SocketResult::TriggerLimitHit => "trigger-limit-hit",
        SocketResult::ServiceStartLimitHit => "service-start-limit-hit",
    }
}

pub fn socket_result_from_string(value: &str) -> Result<SocketResult> {
    match value {
        "success" => Ok(SocketResult::Success),
        "resources" => Ok(SocketResult::Resources),
        "timeout" => Ok(SocketResult::Timeout),
        "exit-code" => Ok(SocketResult::ExitCode),
        "signal" => Ok(SocketResult::Signal),
        "core-dump" => Ok(SocketResult::CoreDump),
        "start-limit-hit" => Ok(SocketResult::StartLimitHit),
        "trigger-limit-hit" => Ok(SocketResult::TriggerLimitHit),
        "service-start-limit-hit" => Ok(SocketResult::ServiceStartLimitHit),
        _ => Err(Errno::EINVAL),
    }
}

pub fn socket_timestamping_to_string(value: SocketTimestamping) -> &'static str {
    match value {
        SocketTimestamping::Off => "off",
        SocketTimestamping::Us => "us",
        SocketTimestamping::Ns => "ns",
    }
}

pub fn socket_timestamping_from_string(value: &str) -> Result<SocketTimestamping> {
    match value {
        "off" => Ok(SocketTimestamping::Off),
        "us" => Ok(SocketTimestamping::Us),
        "ns" => Ok(SocketTimestamping::Ns),
        _ => Err(Errno::EINVAL),
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "y" | "yes" | "t" | "true" | "on" => Some(true),
        "0" | "n" | "no" | "f" | "false" | "off" => Some(false),
        _ => None,
    }
}

pub fn socket_timestamping_from_string_harder(value: &str) -> Result<SocketTimestamping> {
    if let Ok(parsed) = socket_timestamping_from_string(value) {
        return Ok(parsed);
    }

    match value {
        "nsec" => Ok(SocketTimestamping::Ns),
        "usec" | "µs" | "μs" => Ok(SocketTimestamping::Us),
        _ => match parse_boolean(value) {
            Some(true) => Ok(SocketTimestamping::Ns),
            Some(false) => Ok(SocketTimestamping::Off),
            None => Err(Errno::EINVAL),
        },
    }
}

pub fn socket_defer_trigger_to_string(value: SocketDeferTrigger) -> &'static str {
    match value {
        SocketDeferTrigger::No => "no",
        SocketDeferTrigger::Yes => "yes",
        SocketDeferTrigger::Patient => "patient",
    }
}

pub fn socket_defer_trigger_from_string(value: &str) -> Result<SocketDeferTrigger> {
    match value {
        "no" => Ok(SocketDeferTrigger::No),
        "yes" => Ok(SocketDeferTrigger::Yes),
        "patient" => Ok(SocketDeferTrigger::Patient),
        _ => match parse_boolean(value) {
            Some(true) => Ok(SocketDeferTrigger::Yes),
            Some(false) => Ok(SocketDeferTrigger::No),
            None => Err(Errno::EINVAL),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_command_round_trip() {
        let value = SocketExecCommand::StartPost;
        assert_eq!(
            socket_exec_command_from_string(socket_exec_command_to_string(value)).unwrap(),
            value
        );
    }

    #[test]
    fn exec_command_rejects_unknown() {
        assert_eq!(
            socket_exec_command_from_string("bogus").unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn socket_result_round_trip() {
        let value = SocketResult::TriggerLimitHit;
        assert_eq!(
            socket_result_from_string(socket_result_to_string(value)).unwrap(),
            value
        );
    }

    #[test]
    fn timestamping_round_trip() {
        let value = SocketTimestamping::Us;
        assert_eq!(
            socket_timestamping_from_string(socket_timestamping_to_string(value)).unwrap(),
            value
        );
    }

    #[test]
    fn timestamping_harder_accepts_aliases() {
        assert_eq!(
            socket_timestamping_from_string_harder("nsec").unwrap(),
            SocketTimestamping::Ns
        );
        assert_eq!(
            socket_timestamping_from_string_harder("usec").unwrap(),
            SocketTimestamping::Us
        );
    }

    #[test]
    fn timestamping_harder_accepts_boolean() {
        assert_eq!(
            socket_timestamping_from_string_harder("true").unwrap(),
            SocketTimestamping::Ns
        );
        assert_eq!(
            socket_timestamping_from_string_harder("off").unwrap(),
            SocketTimestamping::Off
        );
    }

    #[test]
    fn defer_trigger_accepts_boolean_compat() {
        assert_eq!(
            socket_defer_trigger_from_string("1").unwrap(),
            SocketDeferTrigger::Yes
        );
        assert_eq!(
            socket_defer_trigger_from_string("0").unwrap(),
            SocketDeferTrigger::No
        );
    }

    #[test]
    fn defer_trigger_keeps_patient() {
        assert_eq!(
            socket_defer_trigger_to_string(SocketDeferTrigger::Patient),
            "patient"
        );
    }

    #[test]
    fn timestamping_harder_rejects_unknown() {
        assert_eq!(
            socket_timestamping_from_string_harder("later").unwrap_err(),
            Errno::EINVAL
        );
    }
}
