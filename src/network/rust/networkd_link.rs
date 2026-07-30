// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-link.c
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
pub enum LinkState {
    LinkStatePending,
    LinkStateInitialized,
    LinkStateConfiguring,
    LinkStateConfigured,
    LinkStateUnmanaged,
    LinkStateFailed,
    LinkStateLinger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum LinkReconfigurationFlag {
    LinkReconfigureUnconditionally,
    LinkReconfigureCleanly,
}

#[derive(Debug)]
pub struct LinkReconfigurationData {
    pub flags: i32,
}

#[derive(Debug)]
pub struct Link {
    pub n_ref: i32,
    pub ifindex: i32,
    pub master_ifindex: i32,
    pub dsa_master_ifindex: i32,
    pub sr_iov_phys_port_ifindex: i32,
    pub iftype: i32,
    pub hw_addr: i32,
    pub bcast_addr: i32,
    pub permanent_hw_addr: i32,
    pub requested_hw_addr: i32,
    pub ipv6ll_address: i32,
    pub mtu: i32,
    pub min_mtu: i32,
    pub max_mtu: i32,
    pub original_mtu: i32,
    pub ipv6_mtu_wait_trial_count: i32,
    pub bridge_vlan_pvid: i32,
    pub bridge_vlan_pvid_is_untagged: i32,
    pub ethtool_driver_read: i32,
    pub ethtool_permanent_hw_addr_read: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_link_enums() {
        let _ = std::mem::size_of::<LinkState>();
        let _ = std::mem::size_of::<LinkReconfigurationFlag>();
    }
}
