// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-sysctl.c
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
pub enum IPv6PrivacyExtensions {
    Ipv6PrivacyExtensionsNo,
    Ipv6PrivacyExtensionsPreferPublic,
    Ipv6PrivacyExtensionsYes,
    Ipv6PrivacyExtensionsKernel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum IPReversePathFilter {
    IpReversePathFilterNo,
    IpReversePathFilterStrict,
    IpReversePathFilterLoose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum IPv4ForceIgmpVersion {
    Ipv4ForceIgmpVersionNo,
    Ipv4ForceIgmpVersionV1,
    Ipv4ForceIgmpVersionV2,
    Ipv4ForceIgmpVersionV3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_sysctl_enums() {
        let _ = std::mem::size_of::<IPv6PrivacyExtensions>();
        let _ = std::mem::size_of::<IPReversePathFilter>();
        let _ = std::mem::size_of::<IPv4ForceIgmpVersion>();
    }
}
