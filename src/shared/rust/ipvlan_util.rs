// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/ipvlan-util.c, src/shared/ipvlan-util.h
//
// IPvLAN mode and flags string table utilities.
//
// Provides idiomatic Rust enums for IPVlanMode (L2, L3, L3S) and
// IPVlanFlags (bridge, private, vepa) with bidirectional string
// conversion. Mirrors the C DEFINE_STRING_TABLE_LOOKUP pattern.

// ── Error type ─────────────────────────────────────────────────────────────

/// Error returned when parsing an IPvLAN mode or flags string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpvlanParseError {
    kind: IpvlanParseErrorKind,
    input: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpvlanParseErrorKind {
    InvalidMode,
    InvalidFlags,
}

impl IpvlanParseError {
    fn invalid_mode(input: &str) -> Self {
        Self {
            kind: IpvlanParseErrorKind::InvalidMode,
            input: input.to_string(),
        }
    }

    fn invalid_flags(input: &str) -> Self {
        Self {
            kind: IpvlanParseErrorKind::InvalidFlags,
            input: input.to_string(),
        }
    }
}

impl std::fmt::Display for IpvlanParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            IpvlanParseErrorKind::InvalidMode => {
                write!(f, "Failed to parse IPvLAN mode: '{}'", self.input)
            }
            IpvlanParseErrorKind::InvalidFlags => {
                write!(f, "Failed to parse IPvLAN flags: '{}'", self.input)
            }
        }
    }
}

impl std::error::Error for IpvlanParseError {}

// ── IPVlanMode ─────────────────────────────────────────────────────────────

/// IPvLAN operating mode.
///
/// Corresponds to `IPVlanMode` in `src/shared/ipvlan-util.h`.
/// Maps to kernel values from `<linux/if_link.h>`:
/// - `IPVLAN_MODE_L2` (0) — Layer 2 bridging
/// - `IPVLAN_MODE_L3` (1) — Layer 3 routing
/// - `IPVLAN_MODE_L3S` (2) — Layer 3 routing with source filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVlanMode {
    /// Layer 2 mode — frames are switched at L2 between master and slaves.
    L2,
    /// Layer 3 mode — traffic is routed between master and slaves.
    L3,
    /// Layer 3 source mode — like L3 but with source address filtering.
    L3S,
}

impl IPVlanMode {
    /// Parse an IPvLAN mode from a string (case-insensitive).
    ///
    /// Accepted values: `"L2"`, `"L3"`, `"L3S"`.
    pub fn from_str_lossy(s: &str) -> Result<Self, IpvlanParseError> {
        match s {
            "L2" => Ok(Self::L2),
            "L3" => Ok(Self::L3),
            "L3S" => Ok(Self::L3S),
            _ => Err(IpvlanParseError::invalid_mode(s)),
        }
    }

    /// Convert to the integer value used by the kernel (`<linux/if_link.h>`).
    pub fn to_i32(self) -> i32 {
        match self {
            Self::L2 => 0,
            Self::L3 => 1,
            Self::L3S => 2,
        }
    }

    /// Try to convert from the kernel integer value.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::L2),
            1 => Some(Self::L3),
            2 => Some(Self::L3S),
            _ => None,
        }
    }

    /// All mode variants in canonical order.
    pub const ALL: [Self; 3] = [Self::L2, Self::L3, Self::L3S];
}

impl std::fmt::Display for IPVlanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L3S => "L3S",
        })
    }
}

impl std::str::FromStr for IPVlanMode {
    type Err = IpvlanParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_lossy(s)
    }
}

// ── IPVlanFlags ────────────────────────────────────────────────────────────

/// IPvLAN flags controlling isolation behavior.
///
/// Corresponds to `IPVlanFlags` in `src/shared/ipvlan-util.h`.
/// Maps to kernel flags from `<linux/if_link.h>`:
/// - `bridge` (0) — traffic forwarded between slaves
/// - `private` (1) — `IPVLAN_F_PRIVATE`, no slave-to-slave communication
/// - `vepa` (2) — `IPVLAN_F_VEPA`, Virtual Ethernet Port Aggregator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVlanFlags {
    /// Bridge mode — frames are forwarded between slaves.
    Bridge,
    /// Private mode — slaves cannot communicate with each other.
    Private,
    /// VEPA mode — Virtual Ethernet Port Aggregator.
    Vepa,
}

impl IPVlanFlags {
    /// Parse IPvLAN flags from a string (case-insensitive).
    ///
    /// Accepted values: `"bridge"`, `"private"`, `"vepa"`.
    pub fn from_str_lossy(s: &str) -> Result<Self, IpvlanParseError> {
        match s {
            "bridge" => Ok(Self::Bridge),
            "private" => Ok(Self::Private),
            "vepa" => Ok(Self::Vepa),
            _ => Err(IpvlanParseError::invalid_flags(s)),
        }
    }

    /// Convert to the integer value used by the kernel.
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Bridge => 0,
            Self::Private => 1,
            Self::Vepa => 2,
        }
    }

    /// Try to convert from the kernel integer value.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Bridge),
            1 => Some(Self::Private),
            2 => Some(Self::Vepa),
            _ => None,
        }
    }

    /// All flag variants in canonical order.
    pub const ALL: [Self; 3] = [Self::Bridge, Self::Private, Self::Vepa];
}

impl std::fmt::Display for IPVlanFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Bridge => "bridge",
            Self::Private => "private",
            Self::Vepa => "vepa",
        })
    }
}

impl std::str::FromStr for IPVlanFlags {
    type Err = IpvlanParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_lossy(s)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPVlanMode Display ─────────────────────────────────────────────

    #[test]
    fn test_ipvlan_mode_display() {
        assert_eq!(IPVlanMode::L2.to_string(), "L2");
        assert_eq!(IPVlanMode::L3.to_string(), "L3");
        assert_eq!(IPVlanMode::L3S.to_string(), "L3S");
    }

    // ── IPVlanMode from_str ────────────────────────────────────────────

    #[test]
    fn test_ipvlan_mode_from_str_valid() {
        assert_eq!("L2".parse::<IPVlanMode>().unwrap(), IPVlanMode::L2);
        assert_eq!("L3".parse::<IPVlanMode>().unwrap(), IPVlanMode::L3);
        assert_eq!("L3S".parse::<IPVlanMode>().unwrap(), IPVlanMode::L3S);
    }

    #[test]
    fn test_ipvlan_mode_from_str_invalid() {
        let err = "bogus".parse::<IPVlanMode>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidMode);
        assert!(err.to_string().contains("bogus"));

        let err = "".parse::<IPVlanMode>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidMode);

        let err = "l2".parse::<IPVlanMode>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidMode);
    }

    #[test]
    fn test_ipvlan_mode_from_str_lossy_valid() {
        assert_eq!(IPVlanMode::from_str_lossy("L2").unwrap(), IPVlanMode::L2);
        assert_eq!(IPVlanMode::from_str_lossy("L3").unwrap(), IPVlanMode::L3);
        assert_eq!(IPVlanMode::from_str_lossy("L3S").unwrap(), IPVlanMode::L3S);
    }

    #[test]
    fn test_ipvlan_mode_from_str_lossy_invalid() {
        assert!(IPVlanMode::from_str_lossy("L4").is_err());
        assert!(IPVlanMode::from_str_lossy("l2").is_err());
    }

    // ── IPVlanMode i32 round-trip ──────────────────────────────────────

    #[test]
    fn test_ipvlan_mode_to_i32() {
        assert_eq!(IPVlanMode::L2.to_i32(), 0);
        assert_eq!(IPVlanMode::L3.to_i32(), 1);
        assert_eq!(IPVlanMode::L3S.to_i32(), 2);
    }

    #[test]
    fn test_ipvlan_mode_from_i32_valid() {
        assert_eq!(IPVlanMode::from_i32(0), Some(IPVlanMode::L2));
        assert_eq!(IPVlanMode::from_i32(1), Some(IPVlanMode::L3));
        assert_eq!(IPVlanMode::from_i32(2), Some(IPVlanMode::L3S));
    }

    #[test]
    fn test_ipvlan_mode_from_i32_invalid() {
        assert_eq!(IPVlanMode::from_i32(-1), None);
        assert_eq!(IPVlanMode::from_i32(3), None);
        assert_eq!(IPVlanMode::from_i32(99), None);
    }

    #[test]
    fn test_ipvlan_mode_i32_roundtrip() {
        for mode in IPVlanMode::ALL {
            let i = mode.to_i32();
            assert_eq!(IPVlanMode::from_i32(i), Some(mode));
        }
    }

    // ── IPVlanFlags Display ────────────────────────────────────────────

    #[test]
    fn test_ipvlan_flags_display() {
        assert_eq!(IPVlanFlags::Bridge.to_string(), "bridge");
        assert_eq!(IPVlanFlags::Private.to_string(), "private");
        assert_eq!(IPVlanFlags::Vepa.to_string(), "vepa");
    }

    // ── IPVlanFlags from_str ───────────────────────────────────────────

    #[test]
    fn test_ipvlan_flags_from_str_valid() {
        assert_eq!(
            "bridge".parse::<IPVlanFlags>().unwrap(),
            IPVlanFlags::Bridge
        );
        assert_eq!(
            "private".parse::<IPVlanFlags>().unwrap(),
            IPVlanFlags::Private
        );
        assert_eq!("vepa".parse::<IPVlanFlags>().unwrap(), IPVlanFlags::Vepa);
    }

    #[test]
    fn test_ipvlan_flags_from_str_invalid() {
        let err = "bogus".parse::<IPVlanFlags>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidFlags);
        assert!(err.to_string().contains("bogus"));

        let err = "".parse::<IPVlanFlags>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidFlags);

        let err = "Bridge".parse::<IPVlanFlags>().unwrap_err();
        assert_eq!(err.kind, IpvlanParseErrorKind::InvalidFlags);
    }

    #[test]
    fn test_ipvlan_flags_from_str_lossy_valid() {
        assert_eq!(
            IPVlanFlags::from_str_lossy("bridge").unwrap(),
            IPVlanFlags::Bridge
        );
        assert_eq!(
            IPVlanFlags::from_str_lossy("private").unwrap(),
            IPVlanFlags::Private
        );
        assert_eq!(
            IPVlanFlags::from_str_lossy("vepa").unwrap(),
            IPVlanFlags::Vepa
        );
    }

    #[test]
    fn test_ipvlan_flags_from_str_lossy_invalid() {
        assert!(IPVlanFlags::from_str_lossy("Bridge").is_err());
        assert!(IPVlanFlags::from_str_lossy("PRIVATE").is_err());
        assert!(IPVlanFlags::from_str_lossy("").is_err());
    }

    // ── IPVlanFlags i32 round-trip ─────────────────────────────────────

    #[test]
    fn test_ipvlan_flags_to_i32() {
        assert_eq!(IPVlanFlags::Bridge.to_i32(), 0);
        assert_eq!(IPVlanFlags::Private.to_i32(), 1);
        assert_eq!(IPVlanFlags::Vepa.to_i32(), 2);
    }

    #[test]
    fn test_ipvlan_flags_from_i32_valid() {
        assert_eq!(IPVlanFlags::from_i32(0), Some(IPVlanFlags::Bridge));
        assert_eq!(IPVlanFlags::from_i32(1), Some(IPVlanFlags::Private));
        assert_eq!(IPVlanFlags::from_i32(2), Some(IPVlanFlags::Vepa));
    }

    #[test]
    fn test_ipvlan_flags_from_i32_invalid() {
        assert_eq!(IPVlanFlags::from_i32(-1), None);
        assert_eq!(IPVlanFlags::from_i32(3), None);
        assert_eq!(IPVlanFlags::from_i32(99), None);
    }

    #[test]
    fn test_ipvlan_flags_i32_roundtrip() {
        for flags in IPVlanFlags::ALL {
            let i = flags.to_i32();
            assert_eq!(IPVlanFlags::from_i32(i), Some(flags));
        }
    }

    // ── Error type ─────────────────────────────────────────────────────

    #[test]
    fn test_ipvlan_parse_error_display() {
        let err = IpvlanParseError::invalid_mode("bad");
        assert!(err.to_string().contains("bad"));
        assert!(err.to_string().contains("mode"));

        let err = IpvlanParseError::invalid_flags("bad");
        assert!(err.to_string().contains("bad"));
        assert!(err.to_string().contains("flags"));
    }

    #[test]
    fn test_ipvlan_parse_error_debug() {
        let err = IpvlanParseError::invalid_mode("x");
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidMode"));
        assert!(debug.contains("x"));
    }

    #[test]
    fn test_ipvlan_parse_error_equality() {
        let a = IpvlanParseError::invalid_mode("L4");
        let b = IpvlanParseError::invalid_mode("L4");
        assert_eq!(a, b);

        let c = IpvlanParseError::invalid_flags("L4");
        assert_ne!(a, c);
    }

    // ── Enum properties ────────────────────────────────────────────────

    #[test]
    fn test_ipvlan_mode_all_variants() {
        assert_eq!(IPVlanMode::ALL.len(), 3);
        assert!(IPVlanMode::ALL.contains(&IPVlanMode::L2));
        assert!(IPVlanMode::ALL.contains(&IPVlanMode::L3));
        assert!(IPVlanMode::ALL.contains(&IPVlanMode::L3S));
    }

    #[test]
    fn test_ipvlan_flags_all_variants() {
        assert_eq!(IPVlanFlags::ALL.len(), 3);
        assert!(IPVlanFlags::ALL.contains(&IPVlanFlags::Bridge));
        assert!(IPVlanFlags::ALL.contains(&IPVlanFlags::Private));
        assert!(IPVlanFlags::ALL.contains(&IPVlanFlags::Vepa));
    }

    #[test]
    fn test_ipvlan_mode_copy() {
        let mode = IPVlanMode::L2;
        let copy = mode;
        assert_eq!(mode, copy);
    }

    #[test]
    fn test_ipvlan_flags_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(IPVlanFlags::Bridge);
        set.insert(IPVlanFlags::Private);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&IPVlanFlags::Bridge));
        assert!(set.contains(&IPVlanFlags::Private));
        assert!(!set.contains(&IPVlanFlags::Vepa));
    }
}
