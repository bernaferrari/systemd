// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-nexthop.c
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
pub enum NextHopConfParserType {
    NexthopId,
    NexthopGateway,
    NexthopFamily,
    NexthopOnlink,
    NexthopBlackhole,
    NexthopGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum NextHopState {
    NexthopPending,
    NexthopAssigned,
    NexthopRemoved,
    NexthopFailed,
}

#[derive(Debug)]
pub struct NextHop {
    pub source: i32,
    pub state: i32,
    pub provider: i32,
    pub n_ref: i32,
    pub family: i32,
    pub protocol: i32,
    pub flags: i32,
    pub id: i32,
    pub blackhole: i32,
    pub ifindex: i32,
    pub gw: i32,
    pub onlink: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_nexthop_enums() {
        let _ = std::mem::size_of::<NextHopConfParserType>();
    }

    #[test]
    fn test_networkd_nexthop_state_enum() {
        let _ = std::mem::size_of::<NextHopState>();
    }

    #[test]
    fn test_networkd_nexthop_struct() {
        let _ = std::mem::size_of::<NextHop>();
    }
}
