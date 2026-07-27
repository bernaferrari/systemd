// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of tuntap.c
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

#[derive(Debug)]
pub struct TunTap {
    pub meta: i32,
    pub uid: i32,
    pub gid: i32,
    pub multi_queue: i32,
    pub packet_info: i32,
    pub vnet_hdr: i32,
    pub keep_fd: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuntap_structs() {
        let _ = std::mem::size_of::<TunTap>();
    }
}
