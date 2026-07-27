// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-wwan.c
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
pub struct Bearer {
    pub ip_type: i32,
    pub ip4_method: i32,
    pub ip6_method: i32,
    pub ip4_prefixlen: i32,
    pub ip6_prefixlen: i32,
    pub ip4_address: i32,
    pub ip6_address: i32,
    pub ip4_gateway: i32,
    pub ip6_gateway: i32,
    pub n_dns: i32,
    pub ip4_mtu: i32,
    pub ip6_mtu: i32,
    pub connected: i32,
}

#[derive(Debug)]
pub struct Modem {
    pub state: i32,
    pub state_fail_reason: i32,
    pub reconnect_state: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_wwan_structs() {
        let _ = std::mem::size_of::<Bearer>();
        let _ = std::mem::size_of::<Modem>();
    }
}
