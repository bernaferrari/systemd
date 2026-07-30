// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/scope.c, src/core/scope.h
//

use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeResult {
    Success,
    FailureResources,
    FailureTimeout,
    FailureOomKill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeResultError {
    InvalidIndex(i32),
    InvalidName(String),
}

impl ScopeResult {
    pub const TABLE: [&str; 4] = ["success", "resources", "timeout", "oom-kill"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::FailureResources => "resources",
            Self::FailureTimeout => "timeout",
            Self::FailureOomKill => "oom-kill",
        }
    }
}

impl FromStr for ScopeResult {
    type Err = ScopeResultError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::FailureResources),
            "timeout" => Ok(Self::FailureTimeout),
            "oom-kill" => Ok(Self::FailureOomKill),
            other => Err(ScopeResultError::InvalidName(other.to_string())),
        }
    }
}

impl ScopeResult {
    pub fn from_index(index: i32) -> Result<Self, ScopeResultError> {
        match index {
            0 => Ok(Self::Success),
            1 => Ok(Self::FailureResources),
            2 => Ok(Self::FailureTimeout),
            3 => Ok(Self::FailureOomKill),
            other => Err(ScopeResultError::InvalidIndex(other)),
        }
    }

    pub fn index(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::FailureResources => 1,
            Self::FailureTimeout => 2,
            Self::FailureOomKill => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_strings() {
        for value in [
            ScopeResult::Success,
            ScopeResult::FailureResources,
            ScopeResult::FailureTimeout,
            ScopeResult::FailureOomKill,
        ] {
            assert_eq!(ScopeResult::from_str(value.as_str()).unwrap(), value);
        }
    }

    #[test]
    fn round_trips_indices() {
        for index in 0..4 {
            let value = ScopeResult::from_index(index).unwrap();
            assert_eq!(value.index(), index);
        }
    }

    #[test]
    fn rejects_unknown_scope_result_inputs() {
        assert_eq!(
            ScopeResult::from_str("broken").unwrap_err(),
            ScopeResultError::InvalidName("broken".into())
        );
        assert_eq!(
            ScopeResult::from_index(99).unwrap_err(),
            ScopeResultError::InvalidIndex(99)
        );
    }
}
