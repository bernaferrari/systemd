// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/swap.c, src/core/swap.h
//

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapTableError {
    InvalidValue,
}

pub type Result<T> = std::result::Result<T, SwapTableError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapExecCommand {
    Activate,
    Deactivate,
}

impl SwapExecCommand {
    const TABLE: [&str; 2] = ["ExecActivate", "ExecDeactivate"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activate => Self::TABLE[0],
            Self::Deactivate => Self::TABLE[1],
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "ExecActivate" => Ok(Self::Activate),
            "ExecDeactivate" => Ok(Self::Deactivate),
            _ => Err(SwapTableError::InvalidValue),
        }
    }

    pub fn from_raw(value: usize) -> Result<Self> {
        match value {
            0 => Ok(Self::Activate),
            1 => Ok(Self::Deactivate),
            _ => Err(SwapTableError::InvalidValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapResult {
    Success,
    Resources,
    Timeout,
    ExitCode,
    Signal,
    CoreDump,
    StartLimitHit,
}

impl SwapResult {
    const TABLE: [&str; 7] = [
        "success",
        "resources",
        "timeout",
        "exit-code",
        "signal",
        "core-dump",
        "start-limit-hit",
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => Self::TABLE[0],
            Self::Resources => Self::TABLE[1],
            Self::Timeout => Self::TABLE[2],
            Self::ExitCode => Self::TABLE[3],
            Self::Signal => Self::TABLE[4],
            Self::CoreDump => Self::TABLE[5],
            Self::StartLimitHit => Self::TABLE[6],
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::Resources),
            "timeout" => Ok(Self::Timeout),
            "exit-code" => Ok(Self::ExitCode),
            "signal" => Ok(Self::Signal),
            "core-dump" => Ok(Self::CoreDump),
            "start-limit-hit" => Ok(Self::StartLimitHit),
            _ => Err(SwapTableError::InvalidValue),
        }
    }

    pub fn from_raw(value: usize) -> Result<Self> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Resources),
            2 => Ok(Self::Timeout),
            3 => Ok(Self::ExitCode),
            4 => Ok(Self::Signal),
            5 => Ok(Self::CoreDump),
            6 => Ok(Self::StartLimitHit),
            _ => Err(SwapTableError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_exec_command_roundtrips_by_string() {
        for command in [SwapExecCommand::Activate, SwapExecCommand::Deactivate] {
            assert_eq!(SwapExecCommand::from_str(command.as_str()), Ok(command));
        }
    }

    #[test]
    fn swap_exec_command_roundtrips_by_raw_value() {
        assert_eq!(SwapExecCommand::from_raw(0), Ok(SwapExecCommand::Activate));
        assert_eq!(
            SwapExecCommand::from_raw(1),
            Ok(SwapExecCommand::Deactivate)
        );
    }

    #[test]
    fn swap_exec_command_rejects_unknown_inputs() {
        assert_eq!(
            SwapExecCommand::from_str("ExecReload"),
            Err(SwapTableError::InvalidValue)
        );
        assert_eq!(
            SwapExecCommand::from_raw(2),
            Err(SwapTableError::InvalidValue)
        );
    }

    #[test]
    fn swap_result_roundtrips_by_string() {
        for result in [
            SwapResult::Success,
            SwapResult::Resources,
            SwapResult::Timeout,
            SwapResult::ExitCode,
            SwapResult::Signal,
            SwapResult::CoreDump,
            SwapResult::StartLimitHit,
        ] {
            assert_eq!(SwapResult::from_str(result.as_str()), Ok(result));
        }
    }

    #[test]
    fn swap_result_roundtrips_by_raw_value() {
        assert_eq!(SwapResult::from_raw(0), Ok(SwapResult::Success));
        assert_eq!(SwapResult::from_raw(6), Ok(SwapResult::StartLimitHit));
    }

    #[test]
    fn swap_result_rejects_unknown_inputs() {
        assert_eq!(
            SwapResult::from_str("permission"),
            Err(SwapTableError::InvalidValue)
        );
        assert_eq!(SwapResult::from_raw(7), Err(SwapTableError::InvalidValue));
    }
}
