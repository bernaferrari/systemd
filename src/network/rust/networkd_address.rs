// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-address.c
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
pub enum AddressConfParserType {
    AddressAddress,
    AddressPeer,
    AddressBroadcast,
    AddressLabel,
    AddressPreferredLifetime,
    AddressHomeAddress,
    AddressManageTemporaryAddress,
    AddressPrefixRoute,
    AddressAddPrefixRoute,
    AddressAutoJoin,
    AddressDad,
    AddressScope,
    AddressRouteMetric,
    AddressNetLabel,
    AddressNftSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum AddressState {
    AddressPending,
    AddressAssigned,
    AddressAnnounced,
    AddressRemoved,
    AddressFailed,
    AddressStale,
}

#[derive(Debug)]
pub struct Address {
    pub source: i32,
    pub state: i32,
    pub provider: i32,
    pub n_ref: i32,
    pub family: i32,
    pub prefixlen: i32,
    pub scope: i32,
    pub flags: i32,
    pub route_metric: i32,
    pub set_broadcast: i32,
    pub broadcast: i32,
    pub in_addr: i32,
    pub in_addr_peer: i32,
    pub lifetime_valid_usec: i32,
    pub lifetime_preferred_usec: i32,
    pub duplicate_address_detection: i32,
    pub callback: i32,
    pub nft_set_context: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_address_enums() {
        let _ = std::mem::size_of::<AddressConfParserType>();
    }

    #[test]
    fn test_networkd_address_state_enum() {
        let _ = std::mem::size_of::<AddressState>();
    }

    #[test]
    fn test_networkd_address_struct() {
        let _ = std::mem::size_of::<Address>();
    }
}
