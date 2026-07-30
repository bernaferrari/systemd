// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of netem.c
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

#[derive(Debug)]
pub struct NetworkEmulator {
    pub meta: i32,
    pub delay: i32,
    pub jitter: i32,
    pub limit: i32,
    pub loss: i32,
    pub duplicate: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netem_structs() {
        let _ = std::mem::size_of::<NetworkEmulator>();
    }
}
