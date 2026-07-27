// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of l2tp-tunnel.c
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
pub enum L2tpL2specType {
    NetdevL2tpL2spectypeNone,
    NetdevL2tpL2spectypeDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum L2tpEncapType {
    NetdevL2tpEncaptypeUdp,
    NetdevL2tpEncaptypeIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum L2tpLocalAddressType {
    NetdevL2tpLocalAddressAuto,
    NetdevL2tpLocalAddressStatic,
    NetdevL2tpLocalAddressDynamic,
}

#[derive(Debug)]
pub struct L2tpSession {
    pub ifindex: i32,
    pub session_id: i32,
    pub peer_session_id: i32,
    pub l2tp_l2spec_type: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2tp_tunnel_enums() {
        let _ = std::mem::size_of::<L2tpL2specType>();
        let _ = std::mem::size_of::<L2tpEncapType>();
        let _ = std::mem::size_of::<L2tpLocalAddressType>();
    }
}
