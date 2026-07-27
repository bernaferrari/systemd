// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/ioprio-util.c, src/shared/ioprio-util.h
//
// I/O priority class parsing and string table utilities.

use std::fmt;
use std::str::FromStr;

const IOPRIO_NR_CLASSES: i32 = 8;
const IOPRIO_NR_LEVELS: i32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoPrioClass {
    None = 0,
    Realtime = 1,
    BestEffort = 2,
    Idle = 3,
}

impl IoPrioClass {
    pub const ALL: [IoPrioClass; 4] = [
        IoPrioClass::None,
        IoPrioClass::Realtime,
        IoPrioClass::BestEffort,
        IoPrioClass::Idle,
    ];

    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(IoPrioClass::None),
            1 => Some(IoPrioClass::Realtime),
            2 => Some(IoPrioClass::BestEffort),
            3 => Some(IoPrioClass::Idle),
            _ => None,
        }
    }

    pub fn is_valid_i32(v: i32) -> bool {
        Self::from_i32(v).is_some()
    }

    pub fn to_i32_with_fallback(v: i32) -> String {
        match Self::from_i32(v) {
            Some(c) => c.to_string(),
            None => v.to_string(),
        }
    }

    pub fn from_str_with_fallback(s: &str) -> Option<i32> {
        for c in Self::ALL {
            if c.to_string() == s {
                return Some(c as i32);
            }
        }
        s.parse::<i32>()
            .ok()
            .filter(|&n| n >= 0 && n < IOPRIO_NR_CLASSES)
    }
}

impl fmt::Display for IoPrioClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IoPrioClass::None => "none",
            IoPrioClass::Realtime => "realtime",
            IoPrioClass::BestEffort => "best-effort",
            IoPrioClass::Idle => "idle",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIoPrioClassError(());

impl fmt::Display for ParseIoPrioClassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid I/O priority class")
    }
}

impl std::error::Error for ParseIoPrioClassError {}

impl FromStr for IoPrioClass {
    type Err = ParseIoPrioClassError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => IoPrioClass::None,
            "realtime" => IoPrioClass::Realtime,
            "best-effort" => IoPrioClass::BestEffort,
            "idle" => IoPrioClass::Idle,
            _ => return Err(ParseIoPrioClassError(())),
        })
    }
}

pub fn ioprio_priority_is_valid(i: i32) -> bool {
    i >= 0 && i < IOPRIO_NR_LEVELS
}

pub fn ioprio_parse_priority(s: &str) -> Option<i32> {
    let i = s.parse::<i32>().ok()?;
    if ioprio_priority_is_valid(i) {
        Some(i)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_is_valid() {
        assert!(IoPrioClass::is_valid_i32(0));
        assert!(IoPrioClass::is_valid_i32(1));
        assert!(IoPrioClass::is_valid_i32(2));
        assert!(IoPrioClass::is_valid_i32(3));
        assert!(!IoPrioClass::is_valid_i32(4));
        assert!(!IoPrioClass::is_valid_i32(-1));
        assert!(!IoPrioClass::is_valid_i32(99));
    }

    #[test]
    fn test_priority_is_valid() {
        assert!(ioprio_priority_is_valid(0));
        assert!(ioprio_priority_is_valid(4));
        assert!(ioprio_priority_is_valid(7));
        assert!(!ioprio_priority_is_valid(-1));
        assert!(!ioprio_priority_is_valid(8));
    }

    #[test]
    fn test_class_display() {
        assert_eq!(IoPrioClass::None.to_string(), "none");
        assert_eq!(IoPrioClass::Realtime.to_string(), "realtime");
        assert_eq!(IoPrioClass::BestEffort.to_string(), "best-effort");
        assert_eq!(IoPrioClass::Idle.to_string(), "idle");
    }

    #[test]
    fn test_class_from_str() {
        assert_eq!("none".parse(), Ok(IoPrioClass::None));
        assert_eq!("realtime".parse(), Ok(IoPrioClass::Realtime));
        assert_eq!("best-effort".parse(), Ok(IoPrioClass::BestEffort));
        assert_eq!("idle".parse(), Ok(IoPrioClass::Idle));
        assert!("invalid".parse::<IoPrioClass>().is_err());
    }

    #[test]
    fn test_class_roundtrip() {
        for c in IoPrioClass::ALL {
            let s = c.to_string();
            assert_eq!(s.parse::<IoPrioClass>(), Ok(c));
        }
    }

    #[test]
    fn test_to_i32_with_fallback() {
        assert_eq!(IoPrioClass::to_i32_with_fallback(0), "none");
        assert_eq!(IoPrioClass::to_i32_with_fallback(2), "best-effort");
        assert_eq!(IoPrioClass::to_i32_with_fallback(5), "5");
    }

    #[test]
    fn test_from_str_with_fallback() {
        assert_eq!(IoPrioClass::from_str_with_fallback("none"), Some(0));
        assert_eq!(IoPrioClass::from_str_with_fallback("realtime"), Some(1));
        assert_eq!(IoPrioClass::from_str_with_fallback("3"), Some(3));
        assert_eq!(IoPrioClass::from_str_with_fallback("7"), Some(7));
        assert_eq!(IoPrioClass::from_str_with_fallback("invalid"), None);
        assert_eq!(IoPrioClass::from_str_with_fallback("8"), None);
        assert_eq!(IoPrioClass::from_str_with_fallback("-1"), None);
    }

    #[test]
    fn test_parse_priority() {
        assert_eq!(ioprio_parse_priority("0"), Some(0));
        assert_eq!(ioprio_parse_priority("4"), Some(4));
        assert_eq!(ioprio_parse_priority("7"), Some(7));
        assert_eq!(ioprio_parse_priority("-1"), None);
        assert_eq!(ioprio_parse_priority("8"), None);
        assert_eq!(ioprio_parse_priority("abc"), None);
    }
}
