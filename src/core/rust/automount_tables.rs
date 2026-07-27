// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/automount.c, src/core/automount.h
//
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomountResult {
    Success,
    FailureResources,
    FailureUnmounted,
    FailureStartLimitHit,
    FailureMountStartLimitHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseAutomountResultError;

impl AutomountResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::FailureResources => "resources",
            Self::FailureUnmounted => "unmounted",
            Self::FailureStartLimitHit => "start-limit-hit",
            Self::FailureMountStartLimitHit => "mount-start-limit-hit",
        }
    }

    pub const fn to_index(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::FailureResources => 1,
            Self::FailureUnmounted => 2,
            Self::FailureStartLimitHit => 3,
            Self::FailureMountStartLimitHit => 4,
        }
    }

    pub const fn from_index(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::FailureResources),
            2 => Some(Self::FailureUnmounted),
            3 => Some(Self::FailureStartLimitHit),
            4 => Some(Self::FailureMountStartLimitHit),
            _ => None,
        }
    }

    pub fn from_str(value: &str) -> Result<Self, ParseAutomountResultError> {
        match value {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::FailureResources),
            "unmounted" => Ok(Self::FailureUnmounted),
            "start-limit-hit" => Ok(Self::FailureStartLimitHit),
            "mount-start-limit-hit" => Ok(Self::FailureMountStartLimitHit),
            _ => Err(ParseAutomountResultError),
        }
    }
}

pub const fn automount_result_to_string(result: AutomountResult) -> &'static str {
    result.as_str()
}

pub fn automount_result_from_string(
    value: &str,
) -> Result<AutomountResult, ParseAutomountResultError> {
    AutomountResult::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_round_trips() {
        let value = AutomountResult::Success;
        assert_eq!(AutomountResult::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn resources_round_trips() {
        let value = AutomountResult::FailureResources;
        assert_eq!(AutomountResult::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn unmounted_round_trips() {
        let value = AutomountResult::FailureUnmounted;
        assert_eq!(AutomountResult::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn start_limit_round_trips() {
        let value = AutomountResult::FailureStartLimitHit;
        assert_eq!(AutomountResult::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn mount_start_limit_round_trips() {
        let value = AutomountResult::FailureMountStartLimitHit;
        assert_eq!(AutomountResult::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn invalid_string_is_rejected() {
        assert_eq!(
            AutomountResult::from_str("bogus"),
            Err(ParseAutomountResultError)
        );
    }

    #[test]
    fn invalid_index_is_rejected() {
        assert_eq!(AutomountResult::from_index(-1), None);
        assert_eq!(AutomountResult::from_index(5), None);
    }

    #[test]
    fn indexes_follow_c_enum_order() {
        assert_eq!(AutomountResult::Success.to_index(), 0);
        assert_eq!(AutomountResult::FailureResources.to_index(), 1);
        assert_eq!(AutomountResult::FailureUnmounted.to_index(), 2);
        assert_eq!(AutomountResult::FailureStartLimitHit.to_index(), 3);
        assert_eq!(AutomountResult::FailureMountStartLimitHit.to_index(), 4);
    }

    #[test]
    fn helper_functions_match_methods() {
        let value = AutomountResult::FailureUnmounted;
        assert_eq!(automount_result_to_string(value), value.as_str());
        assert_eq!(automount_result_from_string("unmounted"), Ok(value));
    }
}
