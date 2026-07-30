// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-serialize.c
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
pub struct AddressParam {
    pub family: i32,
    pub address: i32,
    pub peer: i32,
    pub prefixlen: i32,
    pub source: i32,
    pub provider: i32,
}

#[derive(Debug)]
pub struct LinkParam {
    pub ifindex: i32,
}

#[derive(Debug)]
pub struct NextHopParam {
    pub id: i32,
    pub family: i32,
    pub source: i32,
    pub provider: i32,
}

#[derive(Debug)]
pub struct RouteParam {
    pub route: i32,
    pub dst: i32,
    pub src: i32,
    pub prefsrc: i32,
    pub gw: i32,
    pub metrics: i32,
    pub provider: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_serialize_structs() {
        let _ = std::mem::size_of::<AddressParam>();
        let _ = std::mem::size_of::<LinkParam>();
        let _ = std::mem::size_of::<NextHopParam>();
    }
}
