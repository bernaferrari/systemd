// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/path.c, src/core/path.h

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    Exists,
    ExistsGlob,
    DirectoryNotEmpty,
    Changed,
    Modified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResult {
    Success,
    FailureResources,
    FailureStartLimitHit,
    FailureUnitStartLimitHit,
    FailureTriggerLimitHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePathTypeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePathResultError;

impl PathType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exists => "PathExists",
            Self::ExistsGlob => "PathExistsGlob",
            Self::DirectoryNotEmpty => "DirectoryNotEmpty",
            Self::Changed => "PathChanged",
            Self::Modified => "PathModified",
        }
    }

    pub const fn to_index(self) -> i32 {
        match self {
            Self::Exists => 0,
            Self::ExistsGlob => 1,
            Self::DirectoryNotEmpty => 2,
            Self::Changed => 3,
            Self::Modified => 4,
        }
    }

    pub const fn from_index(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Exists),
            1 => Some(Self::ExistsGlob),
            2 => Some(Self::DirectoryNotEmpty),
            3 => Some(Self::Changed),
            4 => Some(Self::Modified),
            _ => None,
        }
    }

    pub fn from_str(value: &str) -> Result<Self, ParsePathTypeError> {
        match value {
            "PathExists" => Ok(Self::Exists),
            "PathExistsGlob" => Ok(Self::ExistsGlob),
            "DirectoryNotEmpty" => Ok(Self::DirectoryNotEmpty),
            "PathChanged" => Ok(Self::Changed),
            "PathModified" => Ok(Self::Modified),
            _ => Err(ParsePathTypeError),
        }
    }
}

impl PathResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::FailureResources => "resources",
            Self::FailureStartLimitHit => "start-limit-hit",
            Self::FailureUnitStartLimitHit => "unit-start-limit-hit",
            Self::FailureTriggerLimitHit => "trigger-limit-hit",
        }
    }

    pub const fn to_index(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::FailureResources => 1,
            Self::FailureStartLimitHit => 2,
            Self::FailureUnitStartLimitHit => 3,
            Self::FailureTriggerLimitHit => 4,
        }
    }

    pub const fn from_index(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::FailureResources),
            2 => Some(Self::FailureStartLimitHit),
            3 => Some(Self::FailureUnitStartLimitHit),
            4 => Some(Self::FailureTriggerLimitHit),
            _ => None,
        }
    }

    pub fn from_str(value: &str) -> Result<Self, ParsePathResultError> {
        match value {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::FailureResources),
            "start-limit-hit" => Ok(Self::FailureStartLimitHit),
            "unit-start-limit-hit" => Ok(Self::FailureUnitStartLimitHit),
            "trigger-limit-hit" => Ok(Self::FailureTriggerLimitHit),
            _ => Err(ParsePathResultError),
        }
    }
}

pub const fn path_type_to_string(path_type: PathType) -> &'static str {
    path_type.as_str()
}

pub fn path_type_from_string(value: &str) -> Result<PathType, ParsePathTypeError> {
    PathType::from_str(value)
}

pub const fn path_result_to_string(path_result: PathResult) -> &'static str {
    path_result.as_str()
}

pub fn path_result_from_string(value: &str) -> Result<PathResult, ParsePathResultError> {
    PathResult::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_exists_round_trips() {
        let value = PathType::Exists;
        assert_eq!(PathType::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn path_exists_glob_round_trips() {
        let value = PathType::ExistsGlob;
        assert_eq!(PathType::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn directory_not_empty_round_trips() {
        let value = PathType::DirectoryNotEmpty;
        assert_eq!(PathType::from_str(value.as_str()), Ok(value));
    }

    #[test]
    fn changed_and_modified_indexes_match_the_c_enum() {
        assert_eq!(PathType::Changed.to_index(), 3);
        assert_eq!(PathType::Modified.to_index(), 4);
        assert_eq!(PathType::from_index(5), None);
    }

    #[test]
    fn invalid_path_type_is_rejected() {
        assert_eq!(PathType::from_str("PathNever"), Err(ParsePathTypeError));
    }

    #[test]
    fn path_result_strings_round_trip() {
        for (index, expected) in [
            PathResult::Success,
            PathResult::FailureResources,
            PathResult::FailureStartLimitHit,
            PathResult::FailureUnitStartLimitHit,
            PathResult::FailureTriggerLimitHit,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(PathResult::from_index(index as i32), Some(expected));
            assert_eq!(PathResult::from_str(expected.as_str()), Ok(expected));
        }
    }

    #[test]
    fn invalid_path_result_is_rejected() {
        assert_eq!(
            PathResult::from_str("not-a-result"),
            Err(ParsePathResultError)
        );
    }

    #[test]
    fn helper_functions_match_methods() {
        assert_eq!(path_type_to_string(PathType::Modified), "PathModified");
        assert_eq!(
            path_type_from_string("DirectoryNotEmpty"),
            Ok(PathType::DirectoryNotEmpty)
        );
        assert_eq!(
            path_result_to_string(PathResult::FailureTriggerLimitHit),
            "trigger-limit-hit"
        );
        assert_eq!(
            path_result_from_string("unit-start-limit-hit"),
            Ok(PathResult::FailureUnitStartLimitHit)
        );
    }
}
