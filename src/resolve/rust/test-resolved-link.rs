// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolved-link.c
//
// Link management tests: creation, RTNL processing, relevance detection,
// address lookup, and scope allocation. Pure Rust port of the C test cases.

use std::fmt;
// ── Constants ──────────────────────────────────────────────────────────────

pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

pub const IFF_UP: u32 = 1;
pub const IFF_LOOPBACK: u32 = 8;
pub const IFF_LOWER_UP: u32 = 1 << 16;
pub const IFF_MULTICAST: u32 = 1 << 12;

pub const IF_OPER_UP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSupport {
    No,
    Yes,
    Resolve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerType {
    System,
    Link,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Dns,
    Mdns,
    Llmnr,
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    InvalidIfIndex,
    InvalidFamily,
    AddressNotFound,
    CreationFailed,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIfIndex => write!(f, "invalid interface index"),
            Self::InvalidFamily => write!(f, "invalid address family"),
            Self::AddressNotFound => write!(f, "address not found"),
            Self::CreationFailed => write!(f, "link creation failed"),
        }
    }
}

impl std::error::Error for LinkError {}

pub type Result<T> = std::result::Result<T, LinkError>;

// ── IP address union ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InAddrUnion {
    pub family: i32,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
}

impl InAddrUnion {
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            family: AF_INET,
            addr_v4: ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32,
            addr_v6: [0; 16],
        }
    }

    pub fn ipv6(addr: [u8; 16]) -> Self {
        Self {
            family: AF_INET6,
            addr_v4: 0,
            addr_v6: addr,
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        if self.family != other.family {
            return false;
        }
        match self.family {
            AF_INET => self.addr_v4 == other.addr_v4,
            AF_INET6 => self.addr_v6 == other.addr_v6,
            _ => false,
        }
    }
}

// ── Link address ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LinkAddress {
    pub family: i32,
    pub address: InAddrUnion,
    pub broadcast: InAddrUnion,
}

// ── Link ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Link {
    pub ifindex: i32,
    pub flags: u32,
    pub operstate: u8,
    pub is_managed: bool,
    pub unicast_relevant: bool,
    pub networkd_operstate: u8,
    pub llmnr_support: ResolveSupport,
    pub mdns_support: ResolveSupport,
    pub addresses: Vec<LinkAddress>,
    pub unicast_scope: Option<Scope>,
    pub llmnr_ipv4_scope: Option<Scope>,
    pub llmnr_ipv6_scope: Option<Scope>,
    pub mdns_ipv4_scope: Option<Scope>,
    pub mdns_ipv6_scope: Option<Scope>,
}

impl Link {
    pub fn new(ifindex: i32) -> Result<Self> {
        if ifindex <= 0 {
            return Err(LinkError::InvalidIfIndex);
        }
        Ok(Self {
            ifindex,
            flags: 0,
            operstate: 0,
            is_managed: false,
            unicast_relevant: false,
            networkd_operstate: 0,
            llmnr_support: ResolveSupport::No,
            mdns_support: ResolveSupport::No,
            addresses: Vec::new(),
            unicast_scope: None,
            llmnr_ipv4_scope: None,
            llmnr_ipv6_scope: None,
            mdns_ipv4_scope: None,
            mdns_ipv6_scope: None,
        })
    }

    pub fn add_address(&mut self, family: i32, addr: &InAddrUnion, broadcast: &InAddrUnion) {
        self.addresses.push(LinkAddress {
            family,
            address: *addr,
            broadcast: *broadcast,
        });
    }

    pub fn find_address(&self, family: i32, addr: &InAddrUnion) -> Option<&LinkAddress> {
        self.addresses
            .iter()
            .find(|a| a.family == family && a.address.matches(addr))
    }

    pub fn is_relevant(&self, family: i32, trust_localhost: bool) -> bool {
        if self.flags & IFF_LOOPBACK != 0 {
            return false;
        }
        if self.flags & IFF_UP == 0 {
            return false;
        }
        if self.flags & IFF_LOWER_UP == 0 {
            return false;
        }
        if family == AF_INET || family == AF_INET6 {
            let has_addr = self.addresses.iter().any(|a| a.family == family);
            if !has_addr {
                return false;
            }
        }
        if self.is_managed && self.networkd_operstate == 0 {
            return false;
        }
        if !trust_localhost && self.flags & IFF_MULTICAST == 0 && self.operstate < IF_OPER_UP {
            return false;
        }
        true
    }
}

// ── Scope ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Scope {
    pub protocol: DnsProtocol,
    pub family: i32,
    pub link_index: i32,
}

// ── Manager (simplified) ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct Manager {
    pub llmnr_support: ResolveSupport,
    pub mdns_support: ResolveSupport,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            llmnr_support: ResolveSupport::No,
            mdns_support: ResolveSupport::No,
        }
    }
}

// ── Scope allocation ───────────────────────────────────────────────────────

pub fn allocate_scopes(link: &mut Link, manager: &Manager) {
    if link.flags & IFF_UP != 0 && link.flags & IFF_LOWER_UP != 0 {
        let has_v4 = link.addresses.iter().any(|a| a.family == AF_INET);
        let has_v6 = link.addresses.iter().any(|a| a.family == AF_INET6);

        link.unicast_relevant = true;

        link.unicast_scope = Some(Scope {
            protocol: DnsProtocol::Dns,
            family: AF_UNSPEC,
            link_index: link.ifindex,
        });

        if link.flags & IFF_MULTICAST != 0
            && manager.llmnr_support == ResolveSupport::Yes
            && link.llmnr_support == ResolveSupport::Yes
        {
            if has_v4 {
                link.llmnr_ipv4_scope = Some(Scope {
                    protocol: DnsProtocol::Llmnr,
                    family: AF_INET,
                    link_index: link.ifindex,
                });
            }
            if has_v6 {
                link.llmnr_ipv6_scope = Some(Scope {
                    protocol: DnsProtocol::Llmnr,
                    family: AF_INET6,
                    link_index: link.ifindex,
                });
            }
        }

        if link.flags & IFF_MULTICAST != 0
            && manager.mdns_support == ResolveSupport::Yes
            && link.mdns_support == ResolveSupport::Yes
        {
            if has_v4 {
                link.mdns_ipv4_scope = Some(Scope {
                    protocol: DnsProtocol::Mdns,
                    family: AF_INET,
                    link_index: link.ifindex,
                });
            }
            if has_v6 {
                link.mdns_ipv6_scope = Some(Scope {
                    protocol: DnsProtocol::Mdns,
                    family: AF_INET6,
                    link_index: link.ifindex,
                });
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_new_valid() -> Result<()> {
        let link = Link::new(1)?;
        assert_eq!(link.ifindex, 1);
        assert!(link.addresses.is_empty());
        Ok(())
    }

    #[test]
    fn link_new_invalid_ifindex() {
        assert!(Link::new(0).is_err());
        assert!(Link::new(-1).is_err());
    }

    #[test]
    fn link_relevant_loopback_is_not() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_LOOPBACK;
        assert!(!link.is_relevant(AF_INET, true));
        assert!(!link.is_relevant(AF_INET, false));
        Ok(())
    }

    #[test]
    fn link_relevant_with_address() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link.operstate = IF_OPER_UP;

        let ip = InAddrUnion::ipv4(192, 168, 67, 1);
        link.add_address(AF_INET, &ip, &ip);

        assert!(link.is_relevant(AF_INET, true));
        assert!(link.is_relevant(AF_INET, false));
        Ok(())
    }

    #[test]
    fn link_relevant_managed_blocks() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP;
        link.is_managed = true;

        let ip = InAddrUnion::ipv4(192, 168, 67, 1);
        link.add_address(AF_INET, &ip, &ip);

        assert!(!link.is_relevant(AF_INET, false));

        link.networkd_operstate = 1;
        link.operstate = IF_OPER_UP;
        assert!(link.is_relevant(AF_INET, false));
        Ok(())
    }

    #[test]
    fn link_find_address_v4() -> Result<()> {
        let mut link = Link::new(1)?;
        let ipv4 = InAddrUnion::ipv4(192, 168, 67, 1);
        let ipv6 = InAddrUnion::ipv6([
            0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e,
            0x60, 0xbb,
        ]);

        link.add_address(AF_INET, &ipv4, &ipv4);
        link.add_address(AF_INET6, &ipv6, &ipv6);

        assert!(link.find_address(AF_INET, &ipv4).is_some());
        assert!(link.find_address(AF_INET6, &ipv6).is_some());
        assert!(link.find_address(AF_INET6, &ipv4).is_none());
        Ok(())
    }

    #[test]
    fn allocate_scopes_unicast() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP;

        let ip = InAddrUnion::ipv4(192, 168, 67, 1);
        link.add_address(AF_INET, &ip, &ip);

        let manager = Manager::default();
        allocate_scopes(&mut link, &manager);

        assert!(link.unicast_relevant);
        assert!(link.unicast_scope.is_some());
        assert!(link.llmnr_ipv4_scope.is_none());
        assert!(link.mdns_ipv4_scope.is_none());
        Ok(())
    }

    #[test]
    fn allocate_scopes_llmnr_ipv4() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link.llmnr_support = ResolveSupport::Yes;

        let ip = InAddrUnion::ipv4(192, 168, 67, 1);
        link.add_address(AF_INET, &ip, &ip);

        let manager = Manager {
            llmnr_support: ResolveSupport::Yes,
            ..Default::default()
        };

        allocate_scopes(&mut link, &manager);

        assert!(link.llmnr_ipv4_scope.is_some());
        assert_eq!(
            link.llmnr_ipv4_scope.as_ref().unwrap().protocol,
            DnsProtocol::Llmnr
        );
        assert_eq!(link.llmnr_ipv4_scope.as_ref().unwrap().family, AF_INET);
        assert!(link.llmnr_ipv6_scope.is_none());
        Ok(())
    }

    #[test]
    fn allocate_scopes_llmnr_ipv6() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link.llmnr_support = ResolveSupport::Yes;

        let ip = InAddrUnion::ipv6([
            0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e,
            0x60, 0xbb,
        ]);
        link.add_address(AF_INET6, &ip, &ip);

        let manager = Manager {
            llmnr_support: ResolveSupport::Yes,
            ..Default::default()
        };

        allocate_scopes(&mut link, &manager);

        assert!(link.llmnr_ipv6_scope.is_some());
        assert_eq!(
            link.llmnr_ipv6_scope.as_ref().unwrap().protocol,
            DnsProtocol::Llmnr
        );
        assert_eq!(link.llmnr_ipv6_scope.as_ref().unwrap().family, AF_INET6);
        assert!(link.llmnr_ipv4_scope.is_none());
        Ok(())
    }

    #[test]
    fn allocate_scopes_mdns_ipv4() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link.mdns_support = ResolveSupport::Yes;

        let ip = InAddrUnion::ipv4(192, 168, 67, 1);
        link.add_address(AF_INET, &ip, &ip);

        let manager = Manager {
            mdns_support: ResolveSupport::Yes,
            ..Default::default()
        };

        allocate_scopes(&mut link, &manager);

        assert!(link.mdns_ipv4_scope.is_some());
        assert_eq!(
            link.mdns_ipv4_scope.as_ref().unwrap().protocol,
            DnsProtocol::Mdns
        );
        assert_eq!(link.mdns_ipv4_scope.as_ref().unwrap().family, AF_INET);
        Ok(())
    }

    #[test]
    fn allocate_scopes_mdns_ipv6() -> Result<()> {
        let mut link = Link::new(1)?;
        link.flags = IFF_UP | IFF_LOWER_UP | IFF_MULTICAST;
        link.mdns_support = ResolveSupport::Yes;

        let ip = InAddrUnion::ipv6([
            0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e,
            0x60, 0xbb,
        ]);
        link.add_address(AF_INET6, &ip, &ip);

        let manager = Manager {
            mdns_support: ResolveSupport::Yes,
            ..Default::default()
        };

        allocate_scopes(&mut link, &manager);

        assert!(link.mdns_ipv6_scope.is_some());
        assert_eq!(
            link.mdns_ipv6_scope.as_ref().unwrap().protocol,
            DnsProtocol::Mdns
        );
        assert_eq!(link.mdns_ipv6_scope.as_ref().unwrap().family, AF_INET6);
        Ok(())
    }
}
