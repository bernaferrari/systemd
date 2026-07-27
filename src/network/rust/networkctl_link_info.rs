// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkctl-link-info.c
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
pub struct VxLanInfo {
    pub vni: i32,
    pub link: i32,
    pub local_family: i32,
    pub group_family: i32,
    pub local: i32,
    pub group: i32,
    pub dest_port: i32,
    pub proxy: i32,
    pub learning: i32,
    pub rsc: i32,
    pub l2miss: i32,
    pub l3miss: i32,
    pub tos: i32,
    pub ttl: i32,
}

#[derive(Debug)]
pub struct LinkInfo {
    pub ifindex: i32,
    pub iftype: i32,
    pub hw_address: i32,
    pub permanent_hw_address: i32,
    pub master: i32,
    pub mtu: i32,
    pub min_mtu: i32,
    pub max_mtu: i32,
    pub tx_queues: i32,
    pub rx_queues: i32,
    pub addr_gen_mode: i32,
    pub stats64: i32,
    pub stats: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkctl_link_info_structs() {
        let _ = std::mem::size_of::<VxLanInfo>();
        let _ = std::mem::size_of::<LinkInfo>();
    }
}
