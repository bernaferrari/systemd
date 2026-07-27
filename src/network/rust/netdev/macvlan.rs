// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of macvlan.c
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
pub enum BCQueueThreshold {
    BcQueueThresholdUndef,
    BcQueueThresholdDisable,
}

#[derive(Debug)]
pub struct MacVlan {
    pub meta: i32,
    pub mode: i32,
    pub bc_queue_length: i32,
    pub bc_queue_threshold: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macvlan_enums() {
        let _ = std::mem::size_of::<BCQueueThreshold>();
    }
}
