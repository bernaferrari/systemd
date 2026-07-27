// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/macvlan-util.c

use std::fmt;
use std::str::FromStr;

pub const MACVLAN_MODE_PRIVATE: u32 = 1;
pub const MACVLAN_MODE_VEPA: u32 = 2;
pub const MACVLAN_MODE_BRIDGE: u32 = 4;
pub const MACVLAN_MODE_PASSTHRU: u32 = 8;
pub const MACVLAN_MODE_SOURCE: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMacVlanModeError {
    InvalidMode,
}

impl fmt::Display for ParseMacVlanModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMode => f.write_str("invalid macvlan mode"),
        }
    }
}

impl std::error::Error for ParseMacVlanModeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacVlanMode {
    Private,
    Vepa,
    Bridge,
    Passthru,
    Source,
    Invalid,
}

struct MacVlanModeEntry {
    value: u32,
    name: &'static str,
    mode: MacVlanMode,
}

const MACVLAN_MODE_TABLE: &[MacVlanModeEntry] = &[
    MacVlanModeEntry {
        value: MACVLAN_MODE_PRIVATE,
        name: "private",
        mode: MacVlanMode::Private,
    },
    MacVlanModeEntry {
        value: MACVLAN_MODE_VEPA,
        name: "vepa",
        mode: MacVlanMode::Vepa,
    },
    MacVlanModeEntry {
        value: MACVLAN_MODE_BRIDGE,
        name: "bridge",
        mode: MacVlanMode::Bridge,
    },
    MacVlanModeEntry {
        value: MACVLAN_MODE_PASSTHRU,
        name: "passthru",
        mode: MacVlanMode::Passthru,
    },
    MacVlanModeEntry {
        value: MACVLAN_MODE_SOURCE,
        name: "source",
        mode: MacVlanMode::Source,
    },
];

pub fn macvlan_mode_to_string(mode: u32) -> Option<&'static str> {
    MACVLAN_MODE_TABLE
        .iter()
        .find(|e| e.value == mode)
        .map(|e| e.name)
}

pub fn macvlan_mode_from_string(s: &str) -> Option<MacVlanMode> {
    MACVLAN_MODE_TABLE
        .iter()
        .find(|e| e.name == s)
        .map(|e| e.mode)
}

impl From<u32> for MacVlanMode {
    fn from(value: u32) -> Self {
        MACVLAN_MODE_TABLE
            .iter()
            .find(|e| e.value == value)
            .map(|e| e.mode)
            .unwrap_or(MacVlanMode::Invalid)
    }
}

impl fmt::Display for MacVlanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => f.write_str("private"),
            Self::Vepa => f.write_str("vepa"),
            Self::Bridge => f.write_str("bridge"),
            Self::Passthru => f.write_str("passthru"),
            Self::Source => f.write_str("source"),
            Self::Invalid => f.write_str("invalid"),
        }
    }
}

impl FromStr for MacVlanMode {
    type Err = ParseMacVlanModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macvlan_mode_from_string(s).ok_or(ParseMacVlanModeError::InvalidMode)
    }
}

impl MacVlanMode {
    pub const fn to_value(self) -> u32 {
        match self {
            Self::Private => MACVLAN_MODE_PRIVATE,
            Self::Vepa => MACVLAN_MODE_VEPA,
            Self::Bridge => MACVLAN_MODE_BRIDGE,
            Self::Passthru => MACVLAN_MODE_PASSTHRU,
            Self::Source => MACVLAN_MODE_SOURCE,
            Self::Invalid => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_string_known_modes() {
        assert_eq!(
            macvlan_mode_to_string(MACVLAN_MODE_PRIVATE),
            Some("private")
        );
        assert_eq!(macvlan_mode_to_string(MACVLAN_MODE_VEPA), Some("vepa"));
        assert_eq!(macvlan_mode_to_string(MACVLAN_MODE_BRIDGE), Some("bridge"));
        assert_eq!(
            macvlan_mode_to_string(MACVLAN_MODE_PASSTHRU),
            Some("passthru")
        );
        assert_eq!(macvlan_mode_to_string(MACVLAN_MODE_SOURCE), Some("source"));
    }

    #[test]
    fn to_string_unknown_value() {
        assert_eq!(macvlan_mode_to_string(99), None);
        assert_eq!(macvlan_mode_to_string(0), None);
        assert_eq!(macvlan_mode_to_string(3), None);
    }

    #[test]
    fn from_string_known_modes() {
        assert_eq!(
            macvlan_mode_from_string("private"),
            Some(MacVlanMode::Private)
        );
        assert_eq!(macvlan_mode_from_string("vepa"), Some(MacVlanMode::Vepa));
        assert_eq!(
            macvlan_mode_from_string("bridge"),
            Some(MacVlanMode::Bridge)
        );
        assert_eq!(
            macvlan_mode_from_string("passthru"),
            Some(MacVlanMode::Passthru)
        );
        assert_eq!(
            macvlan_mode_from_string("source"),
            Some(MacVlanMode::Source)
        );
    }

    #[test]
    fn from_string_unknown() {
        assert_eq!(macvlan_mode_from_string("invalid"), None);
        assert_eq!(macvlan_mode_from_string(""), None);
        assert_eq!(macvlan_mode_from_string("PRIVATE"), None);
    }

    #[test]
    fn from_u32_known() {
        assert_eq!(
            MacVlanMode::from(MACVLAN_MODE_PRIVATE),
            MacVlanMode::Private
        );
        assert_eq!(MacVlanMode::from(MACVLAN_MODE_VEPA), MacVlanMode::Vepa);
        assert_eq!(MacVlanMode::from(MACVLAN_MODE_BRIDGE), MacVlanMode::Bridge);
        assert_eq!(
            MacVlanMode::from(MACVLAN_MODE_PASSTHRU),
            MacVlanMode::Passthru
        );
        assert_eq!(MacVlanMode::from(MACVLAN_MODE_SOURCE), MacVlanMode::Source);
    }

    #[test]
    fn from_u32_unknown() {
        assert_eq!(MacVlanMode::from(99), MacVlanMode::Invalid);
        assert_eq!(MacVlanMode::from(0), MacVlanMode::Invalid);
        assert_eq!(MacVlanMode::from(3), MacVlanMode::Invalid);
    }

    #[test]
    fn display_known_modes() {
        assert_eq!(format!("{}", MacVlanMode::Private), "private");
        assert_eq!(format!("{}", MacVlanMode::Vepa), "vepa");
        assert_eq!(format!("{}", MacVlanMode::Bridge), "bridge");
        assert_eq!(format!("{}", MacVlanMode::Passthru), "passthru");
        assert_eq!(format!("{}", MacVlanMode::Source), "source");
    }

    #[test]
    fn display_invalid() {
        assert_eq!(format!("{}", MacVlanMode::Invalid), "invalid");
    }

    #[test]
    fn from_str_known_modes() {
        assert_eq!(
            "private".parse::<MacVlanMode>().unwrap(),
            MacVlanMode::Private
        );
        assert_eq!("vepa".parse::<MacVlanMode>().unwrap(), MacVlanMode::Vepa);
        assert_eq!(
            "bridge".parse::<MacVlanMode>().unwrap(),
            MacVlanMode::Bridge
        );
        assert_eq!(
            "passthru".parse::<MacVlanMode>().unwrap(),
            MacVlanMode::Passthru
        );
        assert_eq!(
            "source".parse::<MacVlanMode>().unwrap(),
            MacVlanMode::Source
        );
    }

    #[test]
    fn from_str_unknown() {
        assert!("invalid".parse::<MacVlanMode>().is_err());
        assert!("".parse::<MacVlanMode>().is_err());
        assert!("PRIVATE".parse::<MacVlanMode>().is_err());
    }

    #[test]
    fn to_value_roundtrip() {
        assert_eq!(MacVlanMode::Private.to_value(), MACVLAN_MODE_PRIVATE);
        assert_eq!(MacVlanMode::Vepa.to_value(), MACVLAN_MODE_VEPA);
        assert_eq!(MacVlanMode::Bridge.to_value(), MACVLAN_MODE_BRIDGE);
        assert_eq!(MacVlanMode::Passthru.to_value(), MACVLAN_MODE_PASSTHRU);
        assert_eq!(MacVlanMode::Source.to_value(), MACVLAN_MODE_SOURCE);
        assert_eq!(MacVlanMode::Invalid.to_value(), 0);
    }

    #[test]
    fn round_trip_all_modes() {
        for entry in MACVLAN_MODE_TABLE {
            let name = macvlan_mode_to_string(entry.value).unwrap();
            let mode = macvlan_mode_from_string(name).unwrap();
            assert_eq!(
                mode.to_value(),
                entry.value,
                "round-trip failed for {}",
                entry.name
            );
        }
    }

    #[test]
    fn round_trip_enum_to_from_str() {
        for mode in [
            MacVlanMode::Private,
            MacVlanMode::Vepa,
            MacVlanMode::Bridge,
            MacVlanMode::Passthru,
            MacVlanMode::Source,
        ] {
            let s = mode.to_string();
            let back: MacVlanMode = s.parse().unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn round_trip_u32_to_enum_to_string() {
        for entry in MACVLAN_MODE_TABLE {
            let mode = MacVlanMode::from(entry.value);
            let name = macvlan_mode_to_string(entry.value).unwrap();
            assert_eq!(mode.to_string(), name);
        }
    }

    #[test]
    fn constants_match_linux_header() {
        assert_eq!(MACVLAN_MODE_PRIVATE, 1);
        assert_eq!(MACVLAN_MODE_VEPA, 2);
        assert_eq!(MACVLAN_MODE_BRIDGE, 4);
        assert_eq!(MACVLAN_MODE_PASSTHRU, 8);
        assert_eq!(MACVLAN_MODE_SOURCE, 16);
    }

    #[test]
    fn parse_error_display() {
        let err = ParseMacVlanModeError::InvalidMode;
        assert_eq!(format!("{err}"), "invalid macvlan mode");
    }
}
