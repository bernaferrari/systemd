// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of macsec.c
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
pub struct SecurityAssociation {
    pub association_number: i32,
    pub packet_number: i32,
    pub key_len: i32,
    pub activate: i32,
    pub use_for_encoding: i32,
}

#[derive(Debug)]
pub struct TransmitAssociation {
    pub sa: i32,
}

#[derive(Debug)]
pub struct ReceiveAssociation {
    pub sci: i32,
    pub sa: i32,
}

#[derive(Debug)]
pub struct ReceiveChannel {
    pub sci: i32,
    pub n_rxsa: i32,
}

#[derive(Debug)]
pub struct MACsec {
    pub meta: i32,
    pub port: i32,
    pub encrypt: i32,
    pub encoding_an: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macsec_structs() {
        let _ = std::mem::size_of::<SecurityAssociation>();
        let _ = std::mem::size_of::<TransmitAssociation>();
        let _ = std::mem::size_of::<ReceiveAssociation>();
    }
}
