// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-network/network-util.c, src/libsystemd/sd-network/network-util.h

use std::str::FromStr;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AddressFamily {
    AddressFamilyNo = 0,
    AddressFamilyIpv4 = 1,
    AddressFamilyIpv6 = 2,
    AddressFamilyYes = 3,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LinkOperationalState {
    Missing = 0,
    Off = 1,
    NoCarrier = 2,
    Dormant = 3,
    DegradedCarrier = 4,
    Carrier = 5,
    Degraded = 6,
    Enslaved = 7,
    Routable = 8,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkCarrierState {
    Off = 1,
    NoCarrier = 2,
    Dormant = 3,
    DegradedCarrier = 4,
    Carrier = 5,
    Enslaved = 7,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkAddressState {
    Off = 0,
    Degraded = 1,
    Routable = 2,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LinkOnlineState {
    Offline = 0,
    Partial = 1,
    Online = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkOperationalStateRange {
    pub min: LinkOperationalState,
    pub max: LinkOperationalState,
}

pub const LINK_OPERSTATE_RANGE_DEFAULT: LinkOperationalStateRange = LinkOperationalStateRange {
    min: LinkOperationalState::Degraded,
    max: LinkOperationalState::Routable,
};

pub const LINK_OPERSTATE_RANGE_INVALID: Option<LinkOperationalStateRange> = None;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub online_state: Option<LinkOnlineState>,
    pub carrier_state: Option<LinkCarrierState>,
    pub address_state: Option<LinkAddressState>,
    pub per_link_operational_state: std::collections::BTreeMap<i32, LinkOperationalState>,
}

impl AddressFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddressFamilyNo => "any",
            Self::AddressFamilyIpv4 => "ipv4",
            Self::AddressFamilyIpv6 => "ipv6",
            Self::AddressFamilyYes => "both",
        }
    }
}

impl LinkOperationalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Off => "off",
            Self::NoCarrier => "no-carrier",
            Self::Dormant => "dormant",
            Self::DegradedCarrier => "degraded-carrier",
            Self::Carrier => "carrier",
            Self::Degraded => "degraded",
            Self::Enslaved => "enslaved",
            Self::Routable => "routable",
        }
    }
}

impl LinkCarrierState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::NoCarrier => "no-carrier",
            Self::Dormant => "dormant",
            Self::DegradedCarrier => "degraded-carrier",
            Self::Carrier => "carrier",
            Self::Enslaved => "enslaved",
        }
    }
}

impl LinkAddressState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Degraded => "degraded",
            Self::Routable => "routable",
        }
    }
}

impl LinkOnlineState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Partial => "partial",
            Self::Online => "online",
        }
    }
}

impl FromStr for AddressFamily {
    type Err = i32;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "any" => Ok(Self::AddressFamilyNo),
            "ipv4" => Ok(Self::AddressFamilyIpv4),
            "ipv6" => Ok(Self::AddressFamilyIpv6),
            "both" => Ok(Self::AddressFamilyYes),
            _ => Err(NEG_EINVAL),
        }
    }
}

impl FromStr for LinkOperationalState {
    type Err = i32;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "missing" => Ok(Self::Missing),
            "off" => Ok(Self::Off),
            "no-carrier" => Ok(Self::NoCarrier),
            "dormant" => Ok(Self::Dormant),
            "degraded-carrier" => Ok(Self::DegradedCarrier),
            "carrier" => Ok(Self::Carrier),
            "degraded" => Ok(Self::Degraded),
            "enslaved" => Ok(Self::Enslaved),
            "routable" => Ok(Self::Routable),
            _ => Err(NEG_EINVAL),
        }
    }
}

impl FromStr for LinkCarrierState {
    type Err = i32;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "off" => Ok(Self::Off),
            "no-carrier" => Ok(Self::NoCarrier),
            "dormant" => Ok(Self::Dormant),
            "degraded-carrier" => Ok(Self::DegradedCarrier),
            "carrier" => Ok(Self::Carrier),
            "enslaved" => Ok(Self::Enslaved),
            _ => Err(NEG_EINVAL),
        }
    }
}

impl FromStr for LinkAddressState {
    type Err = i32;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "off" => Ok(Self::Off),
            "degraded" => Ok(Self::Degraded),
            "routable" => Ok(Self::Routable),
            _ => Err(NEG_EINVAL),
        }
    }
}

impl FromStr for LinkOnlineState {
    type Err = i32;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "offline" => Ok(Self::Offline),
            "partial" => Ok(Self::Partial),
            "online" => Ok(Self::Online),
            _ => Err(NEG_EINVAL),
        }
    }
}

pub fn af_to_address_family(af: i32) -> AddressFamily {
    match af {
        libc::AF_INET => AddressFamily::AddressFamilyIpv4,
        libc::AF_INET6 => AddressFamily::AddressFamilyIpv6,
        _ => AddressFamily::AddressFamilyNo,
    }
}

pub fn operational_state_is_valid(state: LinkOperationalState) -> bool {
    state <= LinkOperationalState::Routable
}

pub fn operational_state_range_is_valid(range: &LinkOperationalStateRange) -> bool {
    operational_state_is_valid(range.min)
        && operational_state_is_valid(range.max)
        && range.min <= range.max
}

pub fn operational_state_is_in_range(
    state: LinkOperationalState,
    range: &LinkOperationalStateRange,
) -> bool {
    range.min <= state && state <= range.max
}

pub fn parse_operational_state_range(s: &str) -> Result<LinkOperationalStateRange> {
    if s.is_empty() || s == ":" {
        return Err(NEG_EINVAL);
    }

    let (left, right) = match s.split_once(':') {
        Some((l, r)) => (l, Some(r)),
        None => (s, None),
    };

    let min = if left.is_empty() {
        LinkOperationalState::Missing
    } else {
        left.parse()?
    };
    let max = if let Some(r) = right {
        if r.is_empty() {
            LinkOperationalState::Routable
        } else {
            r.parse()?
        }
    } else {
        LinkOperationalState::Routable
    };

    let range = LinkOperationalStateRange { min, max };
    if operational_state_range_is_valid(&range) {
        Ok(range)
    } else {
        Err(NEG_EINVAL)
    }
}

pub fn network_link_get_operational_state(
    snapshot: &NetworkSnapshot,
    ifindex: i32,
) -> Result<LinkOperationalState> {
    if ifindex <= 0 {
        return Err(NEG_EINVAL);
    }
    snapshot
        .per_link_operational_state
        .get(&ifindex)
        .copied()
        .ok_or(NEG_EINVAL)
}

pub fn network_is_online(snapshot: &NetworkSnapshot) -> bool {
    if snapshot
        .online_state
        .is_some_and(|s| s >= LinkOnlineState::Partial)
    {
        return true;
    }

    if snapshot.online_state.is_none() {
        return match (snapshot.carrier_state, snapshot.address_state) {
            (None, _) | (_, None) => true,
            (
                Some(LinkCarrierState::DegradedCarrier | LinkCarrierState::Carrier),
                Some(LinkAddressState::Routable | LinkAddressState::Degraded),
            ) => true,
            _ => false,
        };
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_operstate_to_and_from_string() {
        let state = LinkOperationalState::DegradedCarrier;
        assert_eq!(state.as_str(), "degraded-carrier");
        assert_eq!(
            "degraded-carrier".parse::<LinkOperationalState>().unwrap(),
            state
        );
    }

    #[test]
    fn converts_carrier_state() {
        assert_eq!(LinkCarrierState::Carrier.as_str(), "carrier");
        assert_eq!(
            "enslaved".parse::<LinkCarrierState>().unwrap(),
            LinkCarrierState::Enslaved
        );
    }

    #[test]
    fn converts_address_family() {
        assert_eq!(
            af_to_address_family(libc::AF_INET),
            AddressFamily::AddressFamilyIpv4
        );
        assert_eq!(
            "both".parse::<AddressFamily>().unwrap(),
            AddressFamily::AddressFamilyYes
        );
    }

    #[test]
    fn parses_single_state_range() {
        let range = parse_operational_state_range("degraded").unwrap();
        assert_eq!(range.min, LinkOperationalState::Degraded);
        assert_eq!(range.max, LinkOperationalState::Routable);
    }

    #[test]
    fn parses_open_ended_state_range() {
        let range = parse_operational_state_range(":carrier").unwrap();
        assert_eq!(range.min, LinkOperationalState::Missing);
        assert_eq!(range.max, LinkOperationalState::Carrier);
    }

    #[test]
    fn rejects_invalid_state_range() {
        assert_eq!(
            parse_operational_state_range("routable:off"),
            Err(NEG_EINVAL)
        );
        assert_eq!(parse_operational_state_range(":"), Err(NEG_EINVAL));
    }

    #[test]
    fn evaluates_explicit_online_state() {
        let snapshot = NetworkSnapshot {
            online_state: Some(LinkOnlineState::Online),
            ..Default::default()
        };
        assert!(network_is_online(&snapshot));
    }

    #[test]
    fn falls_back_to_carrier_and_address_guess() {
        let snapshot = NetworkSnapshot {
            online_state: None,
            carrier_state: Some(LinkCarrierState::Carrier),
            address_state: Some(LinkAddressState::Routable),
            ..Default::default()
        };
        assert!(network_is_online(&snapshot));
    }

    #[test]
    fn treats_unknown_network_data_as_online() {
        let snapshot = NetworkSnapshot::default();
        assert!(network_is_online(&snapshot));
    }

    #[test]
    fn returns_operational_state_for_link() {
        let mut snapshot = NetworkSnapshot::default();
        snapshot
            .per_link_operational_state
            .insert(2, LinkOperationalState::Carrier);
        assert_eq!(
            network_link_get_operational_state(&snapshot, 2).unwrap(),
            LinkOperationalState::Carrier
        );
    }
}
