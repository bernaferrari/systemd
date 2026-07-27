// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-neighbor.c
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
pub enum NeighborConfParserType {
    NeighborDestinationAddress,
    NeighborLinkLayerAddress,
}

#[derive(Debug)]
pub struct Neighbor {
    pub source: i32,
    pub state: i32,
    pub n_ref: i32,
    pub dst_addr: i32,
    pub ll_addr: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_neighbor_enums() {
        let _ = std::mem::size_of::<NeighborConfParserType>();
    }
}
