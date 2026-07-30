// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of vlan.c
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
pub struct VLan {
    pub meta: i32,
    pub id: i32,
    pub protocol: i32,
    pub gvrp: i32,
    pub mvrp: i32,
    pub loose_binding: i32,
    pub reorder_hdr: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_structs() {
        let _ = std::mem::size_of::<VLan>();
    }
}
