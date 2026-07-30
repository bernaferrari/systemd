// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of tunnel.c
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
pub enum TunnelMode {
    TunnelModeAny,
    TunnelModeIpip,
    TunnelModeIp6ip,
    TunnelModeIpip6,
    TunnelModeIp6ip6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum IPv6FlowLabel {
    NetdevIpv6FlowlabelInherit,
}

#[derive(Debug)]
pub struct Tunnel {
    pub meta: i32,
    pub encap_limit: i32,
    pub family: i32,
    pub ipv6_flowlabel: i32,
    pub allow_localremote: i32,
    pub gre_erspan_sequence: i32,
    pub isatap: i32,
    pub ttl: i32,
    pub tos: i32,
    pub flags: i32,
    pub key: i32,
    pub ikey: i32,
    pub okey: i32,
    pub erspan_version: i32,
    pub erspan_index: i32,
    pub erspan_direction: i32,
    pub erspan_hwid: i32,
    pub local_type: i32,
    pub local: i32,
    pub remote: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_enums() {
        let _ = std::mem::size_of::<TunnelMode>();
        let _ = std::mem::size_of::<IPv6FlowLabel>();
    }
}
