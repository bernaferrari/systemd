// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Behavioral Rust components for libsystemd-network.

use std::fmt;
use std::num::NonZeroI32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(NonZeroI32);

impl Errno {
    pub const fn new(code: i32) -> Option<Self> {
        match NonZeroI32::new(code) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> i32 {
        self.0.get()
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "errno({})", self.get())
    }
}

impl std::error::Error for Errno {}

pub const EINVAL: Errno = match Errno::new(22) {
    Some(errno) => errno,
    None => panic!("EINVAL must be non-zero"),
};

pub mod dhcp_option;
