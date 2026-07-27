// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-message-rtnl.c
//

pub type Result<T> = std::result::Result<T, RtnlError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtnlError {
    WrongKind,
    PrefixOutOfRange,
    MissingChangeMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec,
    Inet,
    Inet6,
    Bridge,
}

impl AddressFamily {
    fn address_bits(self) -> u8 {
        match self {
            Self::Inet => 32,
            Self::Inet6 => 128,
            Self::Unspec | Self::Bridge => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMessage {
    pub family: AddressFamily,
    pub prefixlen: u8,
    pub scope: u8,
    pub ifindex: i32,
}

impl AddrMessage {
    pub fn set_prefixlen(&mut self, prefixlen: u8) -> Result<()> {
        if prefixlen > self.family.address_bits() {
            return Err(RtnlError::PrefixOutOfRange);
        }
        self.prefixlen = prefixlen;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMessage {
    pub family: AddressFamily,
    pub ifindex: i32,
    pub kind_type: u16,
    pub flags: u32,
    pub change: u32,
}

impl LinkMessage {
    pub fn set_flags(&mut self, flags: u32, change: u32) -> Result<()> {
        if change == 0 {
            return Err(RtnlError::MissingChangeMask);
        }
        self.flags = flags;
        self.change = change;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMessage {
    pub family: AddressFamily,
    pub dst_prefixlen: u8,
    pub src_prefixlen: u8,
    pub tos: u8,
    pub table: u8,
    pub scope: u8,
    pub kind_type: u8,
    pub flags: u32,
    pub protocol: u8,
}

impl RouteMessage {
    pub fn set_dst_prefixlen(&mut self, prefixlen: u8) -> Result<()> {
        if prefixlen > self.family.address_bits() {
            return Err(RtnlError::PrefixOutOfRange);
        }
        self.dst_prefixlen = prefixlen;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighMessage {
    pub family: AddressFamily,
    pub ifindex: i32,
    pub state: u16,
    pub flags: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_prefixlen_honors_family_width() {
        let mut msg = AddrMessage {
            family: AddressFamily::Inet,
            prefixlen: 0,
            scope: 0,
            ifindex: 1,
        };
        assert_eq!(msg.set_prefixlen(24), Ok(()));
        assert_eq!(msg.set_prefixlen(33), Err(RtnlError::PrefixOutOfRange));
    }

    #[test]
    fn link_flags_need_change_mask() {
        let mut msg = LinkMessage {
            family: AddressFamily::Bridge,
            ifindex: 1,
            kind_type: 0,
            flags: 0,
            change: 0,
        };
        assert_eq!(msg.set_flags(1, 0), Err(RtnlError::MissingChangeMask));
        assert_eq!(msg.set_flags(1, u32::MAX), Ok(()));
    }

    #[test]
    fn route_prefixlen_honors_ipv6_width() {
        let mut msg = RouteMessage {
            family: AddressFamily::Inet6,
            dst_prefixlen: 0,
            src_prefixlen: 0,
            tos: 0,
            table: 0,
            scope: 0,
            kind_type: 0,
            flags: 0,
            protocol: 0,
        };
        assert_eq!(msg.set_dst_prefixlen(128), Ok(()));
        assert_eq!(msg.set_dst_prefixlen(129), Err(RtnlError::PrefixOutOfRange));
    }

    #[test]
    fn neigh_message_keeps_basic_fields() {
        let msg = NeighMessage {
            family: AddressFamily::Inet,
            ifindex: 4,
            state: 2,
            flags: 1,
        };
        assert_eq!(msg.ifindex, 4);
        assert_eq!(msg.state, 2);
    }
}
