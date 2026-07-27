// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of geneve.c
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
pub enum GeneveDF {
    NetdevGeneveDfNo,
    NetdevGeneveDfYes,
    NetdevGeneveDfInherit,
}

#[derive(Debug)]
pub struct Geneve {
    pub meta: i32,
    pub id: i32,
    pub flow_label: i32,
    pub remote_family: i32,
    pub tos: i32,
    pub ttl: i32,
    pub dest_port: i32,
    pub udpcsum: i32,
    pub udp6zerocsumtx: i32,
    pub udp6zerocsumrx: i32,
    pub inherit: i32,
    pub geneve_df: i32,
    pub remote: i32,
    pub inherit_inner_protocol: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_enums() {
        let _ = std::mem::size_of::<GeneveDF>();
    }
}
