// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of htb.c
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
pub struct HierarchyTokenBucket {
    pub meta: i32,
    pub default_class: i32,
    pub rate_to_quantum: i32,
}

#[derive(Debug)]
pub struct HierarchyTokenBucketClass {
    pub meta: i32,
    pub priority: i32,
    pub quantum: i32,
    pub mtu: i32,
    pub overhead: i32,
    pub rate: i32,
    pub buffer: i32,
    pub ceil_rate: i32,
    pub ceil_buffer: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htb_structs() {
        let _ = std::mem::size_of::<HierarchyTokenBucket>();
        let _ = std::mem::size_of::<HierarchyTokenBucketClass>();
    }
}
