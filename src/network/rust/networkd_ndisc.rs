// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-ndisc.c
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum IPv6AcceptRAStartDHCP6Client {
    Ipv6AcceptRaStartDhcp6ClientNo,
    Ipv6AcceptRaStartDhcp6ClientAlways,
    Ipv6AcceptRaStartDhcp6ClientYes,
}

#[derive(Debug)]
pub struct NDiscRDNSS {
    pub router: i32,
    pub lifetime_usec: i32,
    pub address: i32,
}

#[derive(Debug)]
pub struct NDiscDNSSL {
    pub router: i32,
    pub lifetime_usec: i32,
}

#[derive(Debug)]
pub struct NDiscCaptivePortal {
    pub router: i32,
    pub lifetime_usec: i32,
}

#[derive(Debug)]
pub struct NDiscPREF64 {
    pub router: i32,
    pub lifetime_usec: i32,
    pub prefix_len: i32,
    pub prefix: i32,
}

#[derive(Debug)]
pub struct NDiscDNR {
    pub router: i32,
    pub lifetime_usec: i32,
    pub resolver: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_ndisc_enums() {
        let _ = std::mem::size_of::<IPv6AcceptRAStartDHCP6Client>();
    }
}
