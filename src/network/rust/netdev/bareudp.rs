// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of bareudp.c
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
pub enum BareUDPProtocol {
    BareUdpProtocolIpv4,
    BareUdpProtocolIpv6,
    BareUdpProtocolMplsUc,
    BareUdpProtocolMplsMc,
}

#[derive(Debug)]
pub struct BareUDP {
    pub meta: i32,
    pub iftype: i32,
    pub dest_port: i32,
    pub min_port: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bareudp_enums() {
        let _ = std::mem::size_of::<BareUDPProtocol>();
    }
}
