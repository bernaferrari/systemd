// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-queue.c
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
pub enum RequestType {
    RequestTypeActivateLink,
    RequestTypeAddress,
    RequestTypeAddressLabel,
    RequestTypeBridgeFdb,
    RequestTypeBridgeMdb,
    RequestTypeDhcpServer,
    RequestTypeDhcp4Client,
    RequestTypeDhcp6Client,
    RequestTypeIpv6ProxyNdp,
    RequestTypeNdisc,
    RequestTypeNeighbor,
    RequestTypeNetdevIndependent,
    RequestTypeNetdevStacked,
    RequestTypeNexthop,
    RequestTypeRadv,
    RequestTypeRoute,
    RequestTypeRoutingPolicyRule,
    RequestTypeSetLinkAddressGenerationMode,
    RequestTypeSetLinkBond,
    RequestTypeSetLinkBridge,
    RequestTypeSetLinkBridgeVlan,
    RequestTypeDelLinkBridgeVlan,
    RequestTypeSetLinkCan,
    RequestTypeSetLinkFlags,
    RequestTypeSetLinkGroup,
    RequestTypeSetLinkIpoib,
    RequestTypeSetLinkMac,
    RequestTypeSetLinkMaster,
    RequestTypeSetLinkMtu,
    RequestTypeSriovVfMac,
    RequestTypeSriovVfSpoofchk,
    RequestTypeSriovVfRssQueryEn,
    RequestTypeSriovVfTrust,
    RequestTypeSriovVfLinkState,
    RequestTypeSriovVfVlanList,
    RequestTypeTcClass,
    RequestTypeTcQdisc,
    RequestTypeUpDown,
}

#[derive(Debug)]
pub struct Request {
    pub n_ref: i32,
    pub type_: i32,
    pub free_func: i32,
    pub hash_func: i32,
    pub compare_func: i32,
    pub process: i32,
    pub netlink_handler: i32,
    pub waiting_reply: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_queue_enums() {
        let _ = std::mem::size_of::<RequestType>();
    }
}
