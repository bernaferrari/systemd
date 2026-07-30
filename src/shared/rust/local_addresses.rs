// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: systemd/src/shared/local-addresses.c, systemd/src/shared/local-addresses.h

use crate::ffi::*;
use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_HOST: u8 = 254;
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const IFA_F_DEPRECATED: u32 = 0x20;
pub const IFA_F_TENTATIVE: u32 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl InAddr {
    pub fn family(&self) -> i32 {
        match self {
            InAddr::V4(_) => AF_INET,
            InAddr::V6(_) => AF_INET6,
        }
    }

    pub fn is_null(&self) -> bool {
        match self {
            InAddr::V4(a) => a.is_unspecified(),
            InAddr::V6(a) => a.is_unspecified(),
        }
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        match self {
            InAddr::V4(a) => a.octets().to_vec(),
            InAddr::V6(a) => a.octets().to_vec(),
        }
    }

    fn from_family_bytes(family: i32, bytes: &[u8]) -> Option<Self> {
        match family {
            AF_INET if bytes.len() == 4 => {
                let arr: [u8; 4] = bytes[..4].try_into().ok()?;
                Some(InAddr::V4(Ipv4Addr::from(arr)))
            }
            AF_INET6 if bytes.len() == 16 => {
                let arr: [u8; 16] = bytes[..16].try_into().ok()?;
                Some(InAddr::V6(Ipv6Addr::from(arr)))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub ifindex: i32,
    pub scope: u8,
    pub priority: u32,
    pub weight: u32,
    pub family: i32,
    pub address: InAddr,
    pub prefsrc: Option<InAddr>,
}

impl LocalAddress {
    pub fn new(ifindex: i32, scope: u8, family: i32, address: InAddr) -> Self {
        Self {
            ifindex,
            scope,
            priority: 0,
            weight: 0,
            family,
            address,
            prefsrc: None,
        }
    }

    pub fn with_full(
        ifindex: i32,
        scope: u8,
        priority: u32,
        weight: u32,
        family: i32,
        address: InAddr,
        prefsrc: Option<InAddr>,
    ) -> Self {
        Self {
            ifindex,
            scope: 0,
            priority,
            weight,
            family,
            address,
            prefsrc,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == AF_INET
    }

    pub fn is_ipv6(&self) -> bool {
        self.family == AF_INET6
    }

    pub fn prefsrc_is_set(&self) -> bool {
        self.prefsrc.as_ref().is_some_and(|p| !p.is_null())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAddressError {
    InvalidFamily(i32),
    InvalidIfindex(i32),
    NoSuchDevice,
    NetlinkFailed(i32),
    SystemError(i32),
    NoData,
    BadMessage,
    HostUnreachable,
}

impl std::fmt::Display for LocalAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalAddressError::InvalidFamily(family) => {
                write!(f, "invalid address family: {family}")
            }
            LocalAddressError::InvalidIfindex(idx) => write!(f, "invalid interface index: {idx}"),
            LocalAddressError::NoSuchDevice => write!(f, "no such device"),
            LocalAddressError::NetlinkFailed(e) => write!(f, "netlink failed: {e}"),
            LocalAddressError::SystemError(e) => write!(f, "system error: {e}"),
            LocalAddressError::NoData => write!(f, "no data available"),
            LocalAddressError::BadMessage => write!(f, "bad message format"),
            LocalAddressError::HostUnreachable => write!(f, "host unreachable"),
        }
    }
}

impl std::error::Error for LocalAddressError {}

pub fn address_compare(a: &LocalAddress, b: &LocalAddress) -> Ordering {
    match (a.family, b.family) {
        (AF_INET, AF_INET6) => return Ordering::Less,
        (AF_INET6, AF_INET) => return Ordering::Greater,
        _ => {}
    }

    a.scope
        .cmp(&b.scope)
        .then_with(|| a.priority.cmp(&b.priority))
        .then_with(|| a.weight.cmp(&b.weight))
        .then_with(|| a.ifindex.cmp(&b.ifindex))
        .then_with(|| a.address.address_bytes().cmp(&b.address.address_bytes()))
}

pub fn has_local_address(addresses: &[LocalAddress], needle: &LocalAddress) -> bool {
    addresses
        .iter()
        .any(|a| address_compare(a, needle) == Ordering::Equal)
}

pub fn suppress_duplicates(list: &mut Vec<LocalAddress>) {
    if list.len() < 2 {
        return;
    }
    let mut write = 1;
    for i in 1..list.len() {
        if address_compare(&list[i], &list[write - 1]) != Ordering::Equal {
            list[write] = list[i].clone();
            write += 1;
        }
    }
    list.truncate(write);
}

pub fn sort_and_dedup(addresses: &mut Vec<LocalAddress>) {
    addresses.sort_by(address_compare);
    suppress_duplicates(addresses);
}

pub fn add_local_address(
    list: &mut Vec<LocalAddress>,
    ifindex: i32,
    scope: u8,
    family: i32,
    address: InAddr,
) -> Result<(), LocalAddressError> {
    add_local_address_full(list, ifindex, scope, 0, 0, family, address, None)
}

pub fn add_local_address_full(
    list: &mut Vec<LocalAddress>,
    ifindex: i32,
    scope: u8,
    priority: u32,
    weight: u32,
    family: i32,
    address: InAddr,
    prefsrc: Option<InAddr>,
) -> Result<(), LocalAddressError> {
    if ifindex <= 0 {
        return Err(LocalAddressError::InvalidIfindex(ifindex));
    }
    if !matches!(family, AF_INET | AF_INET6) {
        return Err(LocalAddressError::InvalidFamily(family));
    }
    list.push(LocalAddress::with_full(
        ifindex, scope, priority, weight, family, address, prefsrc,
    ));
    Ok(())
}

pub fn is_valid_family(family: i32) -> bool {
    matches!(family, AF_INET | AF_INET6)
}

pub fn family_matches(af: i32, family: i32) -> bool {
    af == AF_UNSPEC || af == family
}

pub fn should_skip_scope(ifindex: i32, scope: u8) -> bool {
    ifindex == 0 && matches!(scope, RT_SCOPE_HOST | RT_SCOPE_NOWHERE)
}

pub fn is_deprecated_or_tentative(flags: u32) -> bool {
    (flags & (IFA_F_DEPRECATED | IFA_F_TENTATIVE)) != 0
}

pub fn make_gateway(
    ifindex: i32,
    priority: u32,
    weight: u32,
    family: i32,
    address: InAddr,
    prefsrc: Option<InAddr>,
) -> Result<LocalAddress, LocalAddressError> {
    if ifindex <= 0 {
        return Err(LocalAddressError::InvalidIfindex(ifindex));
    }
    if !is_valid_family(family) {
        return Err(LocalAddressError::InvalidFamily(family));
    }
    Ok(LocalAddress::with_full(
        ifindex, /* scope= */ 0, priority, weight, family, address, prefsrc,
    ))
}

pub fn make_outbound(ifindex: i32, family: i32, address: InAddr) -> LocalAddress {
    LocalAddress::new(ifindex, 0, family, address)
}

pub fn find_prefsrc_match(gateway: &LocalAddress, addresses: &[LocalAddress]) -> bool {
    let prefsrc = match &gateway.prefsrc {
        Some(p) if !p.is_null() => p,
        _ => return false,
    };

    addresses.iter().any(|a| {
        a.ifindex == gateway.ifindex && a.family == gateway.family && a.address == *prefsrc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> InAddr {
        InAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> InAddr {
        InAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn addr(ifindex: i32, scope: u8, family: i32, address: InAddr) -> LocalAddress {
        LocalAddress::new(ifindex, scope, family, address)
    }

    fn addr_full(
        ifindex: i32,
        scope: u8,
        priority: u32,
        weight: u32,
        family: i32,
        address: InAddr,
        prefsrc: Option<InAddr>,
    ) -> LocalAddress {
        LocalAddress::with_full(ifindex, scope, priority, weight, family, address, prefsrc)
    }

    #[test]
    fn test_in_addr_family() {
        assert_eq!(v4(1, 2, 3, 4).family(), AF_INET);
        assert_eq!(v6(0, 0, 0, 0, 0, 0, 0, 1).family(), AF_INET6);
    }

    #[test]
    fn test_in_addr_is_null() {
        assert!(v4(0, 0, 0, 0).is_null());
        assert!(!v4(1, 0, 0, 0).is_null());
        assert!(v6(0, 0, 0, 0, 0, 0, 0, 0).is_null());
        assert!(!v6(0, 0, 0, 0, 0, 0, 0, 1).is_null());
    }

    #[test]
    fn test_is_valid_family() {
        assert!(is_valid_family(AF_INET));
        assert!(is_valid_family(AF_INET6));
        assert!(!is_valid_family(AF_UNSPEC));
        assert!(!is_valid_family(99));
    }

    #[test]
    fn test_family_matches() {
        assert!(family_matches(AF_UNSPEC, AF_INET));
        assert!(family_matches(AF_UNSPEC, AF_INET6));
        assert!(family_matches(AF_INET, AF_INET));
        assert!(!family_matches(AF_INET, AF_INET6));
    }

    #[test]
    fn test_address_compare_ipv4_before_ipv6() {
        let a = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        let b = addr(1, 0, AF_INET6, v6(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(address_compare(&a, &b), Ordering::Less);
        assert_eq!(address_compare(&b, &a), Ordering::Greater);
    }

    #[test]
    fn test_address_compare_by_scope() {
        let a = addr(1, RT_SCOPE_UNIVERSE, AF_INET, v4(10, 0, 0, 1));
        let b = addr(1, RT_SCOPE_HOST, AF_INET, v4(10, 0, 0, 2));
        assert_eq!(address_compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_address_compare_by_priority() {
        let mut a = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        let mut b = addr(1, 0, AF_INET, v4(10, 0, 0, 2));
        b.priority = 100;
        a.priority = 50;
        assert_eq!(address_compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_address_compare_by_ifindex() {
        let a = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        let b = addr(2, 0, AF_INET, v4(10, 0, 0, 2));
        assert_eq!(address_compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_address_compare_equal() {
        let a = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        let b = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        assert_eq!(address_compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_has_local_address_found() {
        let list = vec![
            addr(1, 0, AF_INET, v4(10, 0, 0, 1)),
            addr(2, 0, AF_INET, v4(192, 168, 1, 1)),
        ];
        let needle = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        assert!(has_local_address(&list, &needle));
    }

    #[test]
    fn test_has_local_address_not_found() {
        let list = vec![addr(1, 0, AF_INET, v4(10, 0, 0, 1))];
        let needle = addr(1, 0, AF_INET, v4(10, 0, 0, 2));
        assert!(!has_local_address(&list, &needle));
    }

    #[test]
    fn test_has_local_address_empty() {
        let needle = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        assert!(!has_local_address(&[], &needle));
    }

    #[test]
    fn test_suppress_duplicates() {
        let mut list = vec![
            addr(1, 0, AF_INET, v4(10, 0, 0, 1)),
            addr(1, 0, AF_INET, v4(10, 0, 0, 1)),
            addr(2, 0, AF_INET, v4(192, 168, 1, 1)),
            addr(2, 0, AF_INET, v4(192, 168, 1, 1)),
        ];
        suppress_duplicates(&mut list);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].address, v4(10, 0, 0, 1));
        assert_eq!(list[1].address, v4(192, 168, 1, 1));
    }

    #[test]
    fn test_suppress_duplicates_short() {
        let mut list = vec![addr(1, 0, AF_INET, v4(10, 0, 0, 1))];
        suppress_duplicates(&mut list);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_sort_and_dedup() {
        let mut list = vec![
            addr(2, 0, AF_INET, v4(192, 168, 1, 1)),
            addr(1, 0, AF_INET, v4(10, 0, 0, 1)),
            addr(2, 0, AF_INET, v4(192, 168, 1, 1)),
            addr(1, 0, AF_INET6, v6(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        sort_and_dedup(&mut list);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].family, AF_INET);
        assert_eq!(list[0].ifindex, 1);
        assert_eq!(list[1].family, AF_INET);
        assert_eq!(list[1].ifindex, 2);
        assert_eq!(list[2].family, AF_INET6);
    }

    #[test]
    fn test_add_local_address_full() {
        let mut list = Vec::new();
        add_local_address_full(
            &mut list,
            1,
            0,
            100,
            50,
            AF_INET,
            v4(10, 0, 0, 1),
            Some(v4(10, 0, 0, 2)),
        )
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ifindex, 1);
        assert_eq!(list[0].priority, 100);
        assert_eq!(list[0].weight, 50);
        assert_eq!(list[0].prefsrc, Some(v4(10, 0, 0, 2)));
    }

    #[test]
    fn test_add_local_address_invalid_ifindex() {
        let mut list = Vec::new();
        let r = add_local_address(&mut list, 0, 0, AF_INET, v4(10, 0, 0, 1));
        assert_eq!(r, Err(LocalAddressError::InvalidIfindex(0)));
        assert!(list.is_empty());
    }

    #[test]
    fn test_add_local_address_invalid_family() {
        let mut list = Vec::new();
        let r = add_local_address(&mut list, 1, 0, AF_UNSPEC, v4(10, 0, 0, 1));
        assert_eq!(r, Err(LocalAddressError::InvalidFamily(AF_UNSPEC)));
    }

    #[test]
    fn test_should_skip_scope() {
        assert!(should_skip_scope(0, RT_SCOPE_HOST));
        assert!(should_skip_scope(0, RT_SCOPE_NOWHERE));
        assert!(!should_skip_scope(0, RT_SCOPE_UNIVERSE));
        assert!(!should_skip_scope(1, RT_SCOPE_HOST));
        assert!(!should_skip_scope(1, RT_SCOPE_NOWHERE));
    }

    #[test]
    fn test_is_deprecated_or_tentative() {
        assert!(is_deprecated_or_tentative(IFA_F_DEPRECATED));
        assert!(is_deprecated_or_tentative(IFA_F_TENTATIVE));
        assert!(is_deprecated_or_tentative(
            IFA_F_DEPRECATED | IFA_F_TENTATIVE
        ));
        assert!(!is_deprecated_or_tentative(0));
        assert!(!is_deprecated_or_tentative(0x01));
    }

    #[test]
    fn test_make_gateway() {
        let gw = make_gateway(
            1,
            100,
            50,
            AF_INET,
            v4(192, 168, 1, 1),
            Some(v4(10, 0, 0, 1)),
        )
        .unwrap();
        assert_eq!(gw.ifindex, 1);
        assert_eq!(gw.scope, 0);
        assert_eq!(gw.priority, 100);
        assert_eq!(gw.weight, 50);
    }

    #[test]
    fn test_make_gateway_invalid() {
        assert!(make_gateway(0, 0, 0, AF_INET, v4(0, 0, 0, 0), None).is_err());
        assert!(make_gateway(-1, 0, 0, AF_INET, v4(0, 0, 0, 0), None).is_err());
        assert!(make_gateway(1, 0, 0, AF_UNSPEC, v4(0, 0, 0, 0), None).is_err());
    }

    #[test]
    fn test_make_outbound() {
        let ob = make_outbound(2, AF_INET6, v6(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ob.ifindex, 2);
        assert_eq!(ob.scope, 0);
        assert_eq!(ob.priority, 0);
        assert_eq!(ob.weight, 0);
        assert_eq!(ob.family, AF_INET6);
    }

    #[test]
    fn test_find_prefsrc_match_found() {
        let gateway = addr_full(
            1,
            0,
            100,
            0,
            AF_INET,
            v4(192, 168, 1, 1),
            Some(v4(10, 0, 0, 5)),
        );
        let addresses = vec![
            addr(1, 0, AF_INET, v4(10, 0, 0, 5)),
            addr(2, 0, AF_INET, v4(10, 0, 0, 1)),
        ];
        assert!(find_prefsrc_match(&gateway, &addresses));
    }

    #[test]
    fn test_find_prefsrc_match_wrong_interface() {
        let gateway = addr_full(
            1,
            0,
            100,
            0,
            AF_INET,
            v4(192, 168, 1, 1),
            Some(v4(10, 0, 0, 5)),
        );
        let addresses = vec![addr(2, 0, AF_INET, v4(10, 0, 0, 5))];
        assert!(!find_prefsrc_match(&gateway, &addresses));
    }

    #[test]
    fn test_find_prefsrc_match_no_prefsrc() {
        let gateway = addr_full(1, 0, 100, 0, AF_INET, v4(192, 168, 1, 1), None);
        let addresses = vec![addr(1, 0, AF_INET, v4(10, 0, 0, 5))];
        assert!(!find_prefsrc_match(&gateway, &addresses));
    }

    #[test]
    fn test_find_prefsrc_match_null_prefsrc() {
        let gateway = addr_full(
            1,
            0,
            100,
            0,
            AF_INET,
            v4(192, 168, 1, 1),
            Some(v4(0, 0, 0, 0)),
        );
        let addresses = vec![addr(1, 0, AF_INET, v4(0, 0, 0, 0))];
        assert!(!find_prefsrc_match(&gateway, &addresses));
    }

    #[test]
    fn test_local_address_is_ipv4_ipv6() {
        let a = addr(1, 0, AF_INET, v4(10, 0, 0, 1));
        let b = addr(1, 0, AF_INET6, v6(0, 0, 0, 0, 0, 0, 0, 1));
        assert!(a.is_ipv4());
        assert!(!a.is_ipv6());
        assert!(b.is_ipv6());
        assert!(!b.is_ipv4());
    }

    #[test]
    fn test_prefsrc_is_set() {
        let with = addr_full(1, 0, 0, 0, AF_INET, v4(10, 0, 0, 1), Some(v4(10, 0, 0, 2)));
        let without = addr_full(1, 0, 0, 0, AF_INET, v4(10, 0, 0, 1), None);
        let null_prefsrc = addr_full(1, 0, 0, 0, AF_INET, v4(10, 0, 0, 1), Some(v4(0, 0, 0, 0)));
        assert!(with.prefsrc_is_set());
        assert!(!without.prefsrc_is_set());
        assert!(!null_prefsrc.prefsrc_is_set());
    }
}
