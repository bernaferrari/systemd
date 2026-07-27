// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/timer.c
//

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerTableError {
    InvalidValue,
}

pub type Result<T> = std::result::Result<T, TimerTableError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerBase {
    Active,
    Boot,
    Startup,
    UnitActive,
    UnitInactive,
    Calendar,
}

impl TimerBase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "OnActiveSec",
            Self::Boot => "OnBootSec",
            Self::Startup => "OnStartupSec",
            Self::UnitActive => "OnUnitActiveSec",
            Self::UnitInactive => "OnUnitInactiveSec",
            Self::Calendar => "OnCalendar",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "OnActiveSec" => Ok(Self::Active),
            "OnBootSec" => Ok(Self::Boot),
            "OnStartupSec" => Ok(Self::Startup),
            "OnUnitActiveSec" => Ok(Self::UnitActive),
            "OnUnitInactiveSec" => Ok(Self::UnitInactive),
            "OnCalendar" => Ok(Self::Calendar),
            _ => Err(TimerTableError::InvalidValue),
        }
    }

    pub fn to_usec_string(self) -> String {
        match self.as_str().strip_suffix("Sec") {
            Some(prefix) => format!("{prefix}USec"),
            None => self.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerResult {
    Success,
    Resources,
    StartLimitHit,
}

impl TimerResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Resources => "resources",
            Self::StartLimitHit => "start-limit-hit",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "resources" => Ok(Self::Resources),
            "start-limit-hit" => Ok(Self::StartLimitHit),
            _ => Err(TimerTableError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_base_roundtrips() {
        for base in [
            TimerBase::Active,
            TimerBase::Boot,
            TimerBase::Startup,
            TimerBase::UnitActive,
            TimerBase::UnitInactive,
            TimerBase::Calendar,
        ] {
            assert_eq!(TimerBase::from_str(base.as_str()), Ok(base));
        }
    }

    #[test]
    fn timer_base_rejects_unknown_values() {
        assert_eq!(
            TimerBase::from_str("OnMountSec"),
            Err(TimerTableError::InvalidValue)
        );
    }

    #[test]
    fn timer_base_usec_conversion_rewrites_sec_suffix() {
        assert_eq!(TimerBase::Active.to_usec_string(), "OnActiveUSec");
        assert_eq!(
            TimerBase::UnitInactive.to_usec_string(),
            "OnUnitInactiveUSec"
        );
    }

    #[test]
    fn timer_base_usec_conversion_leaves_non_sec_suffix_unchanged() {
        assert_eq!(TimerBase::Calendar.to_usec_string(), "OnCalendar");
    }

    #[test]
    fn timer_result_roundtrips() {
        for result in [
            TimerResult::Success,
            TimerResult::Resources,
            TimerResult::StartLimitHit,
        ] {
            assert_eq!(TimerResult::from_str(result.as_str()), Ok(result));
        }
    }

    #[test]
    fn timer_result_rejects_unknown_values() {
        assert_eq!(
            TimerResult::from_str("timeout"),
            Err(TimerTableError::InvalidValue)
        );
    }
}
