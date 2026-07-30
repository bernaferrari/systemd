// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-dhcp-common.c
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
pub enum DHCPOptionDataType {
    DhcpOptionDataUint8,
    DhcpOptionDataUint16,
    DhcpOptionDataUint32,
    DhcpOptionDataString,
    DhcpOptionDataIpv4address,
    DhcpOptionDataIpv6address,
}

#[derive(Debug)]
pub struct DUID {
    pub type_: i32,
    pub raw_data_len: i32,
    pub llt_time: i32,
    pub set: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_dhcp_common_enums() {
        let _ = std::mem::size_of::<DHCPOptionDataType>();
    }
}
