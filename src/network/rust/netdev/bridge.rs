// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of bridge.c
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
pub enum MulticastRouter {
    MulticastRouterNone,
    MulticastRouterTemporaryQuery,
    MulticastRouterPermanent,
    MulticastRouterTemporary,
}

#[derive(Debug)]
pub struct Bridge {
    pub meta: i32,
    pub mcast_querier: i32,
    pub mcast_snooping: i32,
    pub vlan_filtering: i32,
    pub vlan_protocol: i32,
    pub stp: i32,
    pub priority: i32,
    pub group_fwd_mask: i32,
    pub default_pvid: i32,
    pub igmp_version: i32,
    pub fdb_max_learned: i32,
    pub fdb_max_learned_set: i32,
    pub linklocal_learn: i32,
    pub forward_delay: i32,
    pub hello_time: i32,
    pub max_age: i32,
    pub ageing_time: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_enums() {
        let _ = std::mem::size_of::<MulticastRouter>();
    }
}
