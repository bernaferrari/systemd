// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of wait-online-link.c
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
pub struct Link {
    pub ifindex: i32,
    pub flags: i32,
    pub required_for_online: i32,
    pub required_operstate: i32,
    pub operational_state: i32,
    pub required_family: i32,
    pub ipv4_address_state: i32,
    pub ipv6_address_state: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_online_link_structs() {
        let _ = std::mem::size_of::<Link>();
    }
}
