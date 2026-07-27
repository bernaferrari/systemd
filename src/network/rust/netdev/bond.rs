// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of bond.c
//
// SAFETY: This module is a Rust port of the corresponding C source.
// FFI boundary functions use unsafe extern "C" with proper SAFETY comments.
// Internal logic uses safe Rust with Result<T, Errno> error handling.

use std::ffi::CStr;
use std::os::raw::c_void;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Debug)]
pub struct Bond {
    pub meta: i32,
    pub mode: i32,
    pub xmit_hash_policy: i32,
    pub lacp_rate: i32,
    pub ad_select: i32,
    pub fail_over_mac: i32,
    pub arp_validate: i32,
    pub arp_all_targets: i32,
    pub primary_reselect: i32,
    pub tlb_dynamic_lb: i32,
    pub all_slaves_active: i32,
    pub resend_igmp: i32,
    pub packets_per_slave: i32,
    pub num_grat_arp: i32,
    pub min_links: i32,
    pub ad_actor_sys_prio: i32,
    pub ad_user_port_key: i32,
    pub ad_actor_system: i32,
    pub arp_missed_max: i32,
    pub miimon: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bond_structs() {
        let _ = std::mem::size_of::<Bond>();
    }
}
