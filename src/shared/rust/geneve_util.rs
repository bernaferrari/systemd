// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/geneve-util.c, src/shared/geneve-util.h
//
// GENEVE (Generic Network Virtualization Encapsulation) DF (Don't Fragment) settings.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneveDF {
    Unset = 0,
    Set = 1,
    Inherit = 2,
}

impl GeneveDF {
    pub const ALL: [GeneveDF; 3] = [GeneveDF::Unset, GeneveDF::Set, GeneveDF::Inherit];

    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(GeneveDF::Unset),
            1 => Some(GeneveDF::Set),
            2 => Some(GeneveDF::Inherit),
            _ => None,
        }
    }
}

impl fmt::Display for GeneveDF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GeneveDF::Unset => "unset",
            GeneveDF::Set => "set",
            GeneveDF::Inherit => "inherit",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseGeneveDFError(());

impl fmt::Display for ParseGeneveDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Geneve DF mode")
    }
}

impl std::error::Error for ParseGeneveDFError {}

impl FromStr for GeneveDF {
    type Err = ParseGeneveDFError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "unset" => GeneveDF::Unset,
            "set" => GeneveDF::Set,
            "inherit" => GeneveDF::Inherit,
            _ => return Err(ParseGeneveDFError(())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(GeneveDF::Unset.to_string(), "unset");
        assert_eq!(GeneveDF::Set.to_string(), "set");
        assert_eq!(GeneveDF::Inherit.to_string(), "inherit");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("unset".parse(), Ok(GeneveDF::Unset));
        assert_eq!("set".parse(), Ok(GeneveDF::Set));
        assert_eq!("inherit".parse(), Ok(GeneveDF::Inherit));
        assert!("invalid".parse::<GeneveDF>().is_err());
        assert!("".parse::<GeneveDF>().is_err());
    }

    #[test]
    fn test_from_i32() {
        assert_eq!(GeneveDF::from_i32(0), Some(GeneveDF::Unset));
        assert_eq!(GeneveDF::from_i32(1), Some(GeneveDF::Set));
        assert_eq!(GeneveDF::from_i32(2), Some(GeneveDF::Inherit));
        assert_eq!(GeneveDF::from_i32(-1), None);
        assert_eq!(GeneveDF::from_i32(3), None);
        assert_eq!(GeneveDF::from_i32(100), None);
    }

    #[test]
    fn test_roundtrip() {
        for df in GeneveDF::ALL {
            let s = df.to_string();
            assert_eq!(s.parse::<GeneveDF>(), Ok(df));
            assert_eq!(GeneveDF::from_i32(df as i32), Some(df));
        }
    }

    #[test]
    fn test_enum_values_match_c() {
        assert_eq!(GeneveDF::Unset as i32, 0);
        assert_eq!(GeneveDF::Set as i32, 1);
        assert_eq!(GeneveDF::Inherit as i32, 2);
    }
}
