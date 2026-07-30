// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/mount.c, src/core/mount.h

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountExecCommand {
    Mount,
    Unmount,
    Remount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountResult {
    Success,
    FailureResources,
    FailureTimeout,
    FailureExitCode,
    FailureSignal,
    FailureCoreDump,
    FailureStartLimitHit,
    FailureProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMountExecCommandError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMountResultError;

impl MountExecCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mount => "ExecMount",
            Self::Unmount => "ExecUnmount",
            Self::Remount => "ExecRemount",
        }
    }

    pub const fn to_index(self) -> i32 {
        match self {
            Self::Mount => 0,
            Self::Unmount => 1,
            Self::Remount => 2,
        }
    }

    pub const fn from_index(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Mount),
            1 => Some(Self::Unmount),
            2 => Some(Self::Remount),
            _ => None,
        }
    }
}

impl FromStr for MountExecCommand {
    type Err = ParseMountExecCommandError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ExecMount" => Ok(Self::Mount),
            "ExecUnmount" => Ok(Self::Unmount),
            "ExecRemount" => Ok(Self::Remount),
            _ => Err(ParseMountExecCommandError),
        }
    }
}

impl MountResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::FailureResources => "resources",
            Self::FailureTimeout => "timeout",
            Self::FailureExitCode => "exit-code",
            Self::FailureSignal => "signal",
            Self::FailureCoreDump => "core-dump",
            Self::FailureStartLimitHit => "start-limit-hit",
            Self::FailureProtocol => "protocol",
        }
    }

    pub const fn to_index(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::FailureResources => 1,
            Self::FailureTimeout => 2,
            Self::FailureExitCode => 3,
            Self::FailureSignal => 4,
            Self::FailureCoreDump => 5,
            Self::FailureStartLimitHit => 6,
            Self::FailureProtocol => 7,
        }
    }

    pub const fn from_index(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::FailureResources),
            2 => Some(Self::FailureTimeout),
            3 => Some(Self::FailureExitCode),
            4 => Some(Self::FailureSignal),
            5 => Some(Self::FailureCoreDump),
            6 => Some(Self::FailureStartLimitHit),
            7 => Some(Self::FailureProtocol),
            _ => None,
        }
    }
}

impl FromStr for MountResult {
    type Err = ParseMountResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::FailureResources),
            "timeout" => Ok(Self::FailureTimeout),
            "exit-code" => Ok(Self::FailureExitCode),
            "signal" => Ok(Self::FailureSignal),
            "core-dump" => Ok(Self::FailureCoreDump),
            "start-limit-hit" => Ok(Self::FailureStartLimitHit),
            "protocol" => Ok(Self::FailureProtocol),
            _ => Err(ParseMountResultError),
        }
    }
}

pub const fn mount_exec_command_to_string(command: MountExecCommand) -> &'static str {
    command.as_str()
}

pub fn mount_exec_command_from_string(
    value: &str,
) -> Result<MountExecCommand, ParseMountExecCommandError> {
    MountExecCommand::from_str(value)
}

pub const fn mount_result_to_string(result: MountResult) -> &'static str {
    result.as_str()
}

pub fn mount_result_from_string(value: &str) -> Result<MountResult, ParseMountResultError> {
    MountResult::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_mount_round_trips() {
        let value = MountExecCommand::Mount;
        assert_eq!(MountExecCommand::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn exec_unmount_round_trips() {
        let value = MountExecCommand::Unmount;
        assert_eq!(MountExecCommand::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn exec_remount_round_trips() {
        let value = MountExecCommand::Remount;
        assert_eq!(MountExecCommand::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn invalid_exec_command_is_rejected() {
        assert_eq!(
            MountExecCommand::from_str("ExecBogus"),
            Err(ParseMountExecCommandError)
        );
    }

    #[test]
    fn exec_command_indexes_follow_the_c_enum() {
        assert_eq!(MountExecCommand::Mount.to_index(), 0);
        assert_eq!(MountExecCommand::Unmount.to_index(), 1);
        assert_eq!(MountExecCommand::Remount.to_index(), 2);
        assert_eq!(MountExecCommand::from_index(3), None);
    }

    #[test]
    fn mount_result_strings_round_trip() {
        for (index, expected) in [
            MountResult::Success,
            MountResult::FailureResources,
            MountResult::FailureTimeout,
            MountResult::FailureExitCode,
            MountResult::FailureSignal,
            MountResult::FailureCoreDump,
            MountResult::FailureStartLimitHit,
            MountResult::FailureProtocol,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(MountResult::from_index(index as i32), Some(expected));
            assert_eq!(MountResult::from_str(expected.as_str()), Ok(expected));
        }
    }

    #[test]
    fn invalid_mount_result_is_rejected() {
        assert_eq!(MountResult::from_str("bogus"), Err(ParseMountResultError));
    }

    #[test]
    fn helper_functions_match_methods() {
        assert_eq!(
            mount_exec_command_to_string(MountExecCommand::Unmount),
            "ExecUnmount"
        );
        assert_eq!(
            mount_exec_command_from_string("ExecRemount"),
            Ok(MountExecCommand::Remount)
        );
        assert_eq!(
            mount_result_to_string(MountResult::FailureProtocol),
            "protocol"
        );
        assert_eq!(
            mount_result_from_string("core-dump"),
            Ok(MountResult::FailureCoreDump)
        );
    }
}
