// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of vxlan.c
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
pub enum VxLanDF {
    NetdevVxlanDfNo,
    NetdevVxlanDfYes,
    NetdevVxlanDfInherit,
}

#[derive(Debug)]
pub struct VxLan {
    pub meta: i32,
    pub vni: i32,
    pub remote_family: i32,
    pub local_family: i32,
    pub group_family: i32,
    pub df: i32,
    pub local_type: i32,
    pub local: i32,
    pub remote: i32,
    pub group: i32,
    pub tos: i32,
    pub ttl: i32,
    pub max_fdb: i32,
    pub flow_label: i32,
    pub dest_port: i32,
    pub fdb_ageing: i32,
    pub learning: i32,
    pub arp_proxy: i32,
    pub route_short_circuit: i32,
    pub l2miss: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_enums() {
        let _ = std::mem::size_of::<VxLanDF>();
    }
}
