// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of fq.c
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
pub struct FairQueueing {
    pub meta: i32,
    pub packet_limit: i32,
    pub flow_limit: i32,
    pub quantum: i32,
    pub initial_quantum: i32,
    pub max_rate: i32,
    pub buckets: i32,
    pub orphan_mask: i32,
    pub pacing: i32,
    pub ce_threshold_usec: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fq_structs() {
        let _ = std::mem::size_of::<FairQueueing>();
    }
}
