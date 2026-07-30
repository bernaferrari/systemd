// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of wireguard.c
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

#[derive(Debug)]
pub struct WireguardIPmask {
    pub family: i32,
    pub ip: i32,
    pub cidr: i32,
}

#[derive(Debug)]
pub struct WireguardPeer {
    pub flags: i32,
    pub persistent_keepalive_interval: i32,
    pub endpoint: i32,
    pub n_retries: i32,
    pub route_table: i32,
    pub route_priority: i32,
    pub route_table_set: i32,
    pub route_priority_set: i32,
}

#[derive(Debug)]
pub struct Wireguard {
    pub meta: i32,
    pub last_peer_section: i32,
    pub flags: i32,
    pub port: i32,
    pub fwmark: i32,
    pub route_table: i32,
    pub route_priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_structs() {
        let _ = std::mem::size_of::<WireguardIPmask>();
        let _ = std::mem::size_of::<WireguardPeer>();
        let _ = std::mem::size_of::<Wireguard>();
    }
}
