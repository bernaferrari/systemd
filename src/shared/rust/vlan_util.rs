// SPDX-License-Identifier: LGPL-2.1-or-later
/* PORT-SYNC: src/shared/vlan-util.c */

use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

/// Maximum valid VLAN ID (12-bit field: 0–4094).
/// Note that VLAN ID 0 is permitted, as the Linux kernel accepts it.
pub const VLANID_MAX: u16 = 4094;

/// Sentinel value indicating an invalid / unset VLAN ID.
pub const VLANID_INVALID: u16 = u16::MAX;

#[inline]
pub const fn vlanid_is_valid(id: u16) -> bool {
    id <= VLANID_MAX
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseVlanIdError {
    InvalidNumber,
    OutOfRange,
}

impl fmt::Display for ParseVlanIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNumber => f.write_str("invalid VLAN ID: not a valid number"),
            Self::OutOfRange => {
                write!(f, "VLAN identifier outside of valid range 0..={VLANID_MAX}")
            }
        }
    }
}

impl std::error::Error for ParseVlanIdError {}

impl From<ParseIntError> for ParseVlanIdError {
    fn from(_: ParseIntError) -> Self {
        Self::InvalidNumber
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseVidRangeError {
    InvalidFormat,
    InvalidLower,
    InvalidUpper,
    OutOfRange,
}

impl fmt::Display for ParseVidRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => {
                f.write_str("invalid VLAN ID range format, expected \"LOWER-UPPER\"")
            }
            Self::InvalidLower => {
                f.write_str("invalid VLAN ID range: lower bound is not a valid number")
            }
            Self::InvalidUpper => {
                f.write_str("invalid VLAN ID range: upper bound is not a valid number")
            }
            Self::OutOfRange => write!(
                f,
                "VLAN ID range values must be in 0..={VLANID_MAX} and lower <= upper"
            ),
        }
    }
}

impl std::error::Error for ParseVidRangeError {}

pub fn parse_vlanid(s: &str) -> Result<u16, ParseVlanIdError> {
    let id: u16 = s.parse()?;
    if !vlanid_is_valid(id) {
        return Err(ParseVlanIdError::OutOfRange);
    }
    Ok(id)
}

pub fn parse_vid_range(s: &str) -> Result<(u16, u16), ParseVidRangeError> {
    let (lower_str, upper_str) = s.split_once('-').ok_or(ParseVidRangeError::InvalidFormat)?;

    let lower: u16 = lower_str
        .parse()
        .map_err(|_| ParseVidRangeError::InvalidLower)?;
    let upper: u16 = upper_str
        .parse()
        .map_err(|_| ParseVidRangeError::InvalidUpper)?;

    if lower > VLANID_MAX || upper > VLANID_MAX || lower > upper {
        return Err(ParseVidRangeError::OutOfRange);
    }

    Ok((lower, upper))
}

pub fn parse_default_port_vlanid(s: &str) -> Result<u16, ParseVlanIdError> {
    if s == "none" {
        return Ok(0);
    }
    parse_vlanid(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VlanId(u16);

impl VlanId {
    pub const MAX: u16 = VLANID_MAX;

    pub const fn new_unchecked(value: u16) -> Self {
        Self(value)
    }

    pub const fn new(value: u16) -> Option<Self> {
        if vlanid_is_valid(value) {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for VlanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for VlanId {
    type Err = ParseVlanIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = parse_vlanid(s)?;
        Ok(Self(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlanid_zero_is_valid() {
        assert!(vlanid_is_valid(0));
    }

    #[test]
    fn vlanid_one_is_valid() {
        assert!(vlanid_is_valid(1));
    }

    #[test]
    fn vlanid_max_is_valid() {
        assert!(vlanid_is_valid(VLANID_MAX));
    }

    #[test]
    fn vlanid_max_plus_one_is_invalid() {
        assert!(!vlanid_is_valid(VLANID_MAX + 1));
    }

    #[test]
    fn vlanid_u16_max_is_invalid() {
        assert!(!vlanid_is_valid(u16::MAX));
    }

    #[test]
    fn parse_vlanid_valid_values() {
        assert_eq!(parse_vlanid("0").unwrap(), 0);
        assert_eq!(parse_vlanid("1").unwrap(), 1);
        assert_eq!(parse_vlanid("100").unwrap(), 100);
        assert_eq!(parse_vlanid("4094").unwrap(), VLANID_MAX);
    }

    #[test]
    fn parse_vlanid_out_of_range() {
        assert_eq!(parse_vlanid("4095"), Err(ParseVlanIdError::OutOfRange));
        assert_eq!(parse_vlanid("65535"), Err(ParseVlanIdError::OutOfRange));
    }

    #[test]
    fn parse_vlanid_invalid_number() {
        assert_eq!(parse_vlanid("abc"), Err(ParseVlanIdError::InvalidNumber));
        assert_eq!(parse_vlanid(""), Err(ParseVlanIdError::InvalidNumber));
        assert_eq!(parse_vlanid("-1"), Err(ParseVlanIdError::InvalidNumber));
        assert_eq!(parse_vlanid(" 100"), Err(ParseVlanIdError::InvalidNumber));
    }

    #[test]
    fn parse_vlanid_overflow() {
        assert_eq!(parse_vlanid("70000"), Err(ParseVlanIdError::InvalidNumber));
    }

    #[test]
    fn parse_vid_range_valid() {
        assert_eq!(parse_vid_range("10-20").unwrap(), (10, 20));
        assert_eq!(parse_vid_range("0-0").unwrap(), (0, 0));
        assert_eq!(parse_vid_range("0-4094").unwrap(), (0, VLANID_MAX));
        assert_eq!(parse_vid_range("100-100").unwrap(), (100, 100));
    }

    #[test]
    fn parse_vid_range_inverted() {
        assert_eq!(
            parse_vid_range("20-10"),
            Err(ParseVidRangeError::OutOfRange)
        );
    }

    #[test]
    fn parse_vid_range_upper_exceeds_max() {
        assert_eq!(
            parse_vid_range("0-4095"),
            Err(ParseVidRangeError::OutOfRange)
        );
    }

    #[test]
    fn parse_vid_range_lower_exceeds_max() {
        assert_eq!(
            parse_vid_range("4095-4095"),
            Err(ParseVidRangeError::OutOfRange)
        );
    }

    #[test]
    fn parse_vid_range_missing_separator() {
        assert_eq!(
            parse_vid_range("100"),
            Err(ParseVidRangeError::InvalidFormat)
        );
    }

    #[test]
    fn parse_vid_range_non_numeric() {
        assert_eq!(
            parse_vid_range("abc-def"),
            Err(ParseVidRangeError::InvalidLower)
        );
        assert_eq!(
            parse_vid_range("10-def"),
            Err(ParseVidRangeError::InvalidUpper)
        );
    }

    #[test]
    fn parse_vid_range_too_many_separators() {
        assert_eq!(
            parse_vid_range("1-2-3"),
            Err(ParseVidRangeError::InvalidUpper)
        );
    }

    #[test]
    fn parse_default_port_vlanid_none() {
        assert_eq!(parse_default_port_vlanid("none").unwrap(), 0);
    }

    #[test]
    fn parse_default_port_vlanid_numeric() {
        assert_eq!(parse_default_port_vlanid("100").unwrap(), 100);
    }

    #[test]
    fn parse_default_port_vlanid_out_of_range() {
        assert_eq!(
            parse_default_port_vlanid("9999"),
            Err(ParseVlanIdError::OutOfRange)
        );
    }

    #[test]
    fn vlanid_newtype_valid() {
        assert_eq!(VlanId::new(0).unwrap().get(), 0);
        assert_eq!(VlanId::new(VLANID_MAX).unwrap().get(), VLANID_MAX);
    }

    #[test]
    fn vlanid_newtype_invalid() {
        assert!(VlanId::new(VLANID_MAX + 1).is_none());
        assert!(VlanId::new(u16::MAX).is_none());
    }

    #[test]
    fn vlanid_from_str_valid() {
        let v: VlanId = "42".parse().unwrap();
        assert_eq!(v.get(), 42);
    }

    #[test]
    fn vlanid_from_str_invalid() {
        assert!("abc".parse::<VlanId>().is_err());
        assert!("4095".parse::<VlanId>().is_err());
    }

    #[test]
    fn vlanid_display() {
        assert_eq!(format!("{}", VlanId::new(123).unwrap()), "123");
        assert_eq!(format!("{}", VlanId::new(0).unwrap()), "0");
    }

    #[test]
    fn constants_match_c_header() {
        assert_eq!(VLANID_MAX, 4094);
        assert_eq!(VLANID_INVALID, u16::MAX);
    }
}
