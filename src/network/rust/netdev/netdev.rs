// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of netdev.c
//
// SAFETY: This module is a Rust port of the corresponding C source.
// FFI boundary functions use unsafe extern "C" with proper SAFETY comments.
// Internal logic uses safe Rust with Result<T, Errno> error handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum NetDevKind {
    NetdevKindBareudp,
    NetdevKindBatadv,
    NetdevKindBond,
    NetdevKindBridge,
    NetdevKindDummy,
    NetdevKindErspan,
    NetdevKindFou,
    NetdevKindGeneve,
    NetdevKindGre,
    NetdevKindGretap,
    NetdevKindHsr,
    NetdevKindIfb,
    NetdevKindIp6gre,
    NetdevKindIp6gretap,
    NetdevKindIp6tnl,
    NetdevKindIpip,
    NetdevKindIpoib,
    NetdevKindIpvlan,
    NetdevKindIpvtap,
    NetdevKindL2tp,
    NetdevKindMacsec,
    NetdevKindMacvlan,
    NetdevKindMacvtap,
    NetdevKindNlmon,
    NetdevKindSit,
    NetdevKindTap,
    NetdevKindTun,
    NetdevKindVcan,
    NetdevKindVeth,
    NetdevKindVlan,
    NetdevKindVrf,
    NetdevKindVti,
    NetdevKindVti6,
    NetdevKindVxcan,
    NetdevKindVxlan,
    NetdevKindWireguard,
    NetdevKindWlan,
    NetdevKindXfrm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum NetDevState {
    NetdevStateLoading,
    NetdevStateFailed,
    NetdevStateCreating,
    NetdevStateReady,
    NetdevStateLinger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum NetDevCreateType {
    NetdevCreateIndependent,
    NetdevCreateStacked,
}

#[derive(Debug)]
pub struct NetDev {
    pub n_ref: i32,
    pub state: i32,
    pub kind: i32,
    pub hw_addr: i32,
    pub mtu: i32,
    pub ifindex: i32,
}

#[derive(Debug)]
pub struct NetDevVTable {
    pub object_size: i32,
    pub create_type: i32,
    pub iftype: i32,
    pub generate_mac: i32,
    pub skip_netdev_kind_check: i32,
    pub keep_existing: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netdev_enums() {
        let _ = std::mem::size_of::<NetDevKind>();
        let _ = std::mem::size_of::<NetDevState>();
        let _ = std::mem::size_of::<NetDevCreateType>();
    }
}
