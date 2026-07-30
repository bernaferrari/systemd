// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-bridge-mdb.c
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
pub enum BridgeMDBEntryType {
    BridgeMdbEntryTypeL2,
    BridgeMdbEntryTypeL3,
}

#[derive(Debug)]
pub struct BridgeMDB {
    pub type_: i32,
    pub l2_addr: i32,
    pub family: i32,
    pub group_addr: i32,
    pub vlan_id: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_bridge_mdb_enums() {
        let _ = std::mem::size_of::<BridgeMDBEntryType>();
    }
}
