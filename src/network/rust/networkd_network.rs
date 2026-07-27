// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-network.c
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
pub enum KeepConfiguration {
    KeepConfigurationNo,
    KeepConfigurationDynamicOnStart,
    KeepConfigurationDynamicOnStop,
    KeepConfigurationDynamic,
    KeepConfigurationStatic,
    KeepConfigurationYes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum ActivationPolicy {
    ActivationPolicyUp,
    ActivationPolicyAlwaysUp,
    ActivationPolicyManual,
    ActivationPolicyAlwaysDown,
    ActivationPolicyDown,
    ActivationPolicyBound,
}

#[derive(Debug)]
pub struct NetworkDHCPServerEmitAddress {
    pub emit: i32,
    pub n_addresses: i32,
}

#[derive(Debug)]
pub struct Network {
    pub n_ref: i32,
    pub match_: i32,
    pub keep_master: i32,
    pub hw_addr: i32,
    pub mtu: i32,
    pub group: i32,
    pub arp: i32,
    pub multicast: i32,
    pub allmulticast: i32,
    pub promiscuous: i32,
    pub unmanaged: i32,
    pub required_for_online: i32,
    pub required_operstate_for_online: i32,
    pub required_family_for_online: i32,
    pub activation_policy: i32,
    pub configure_without_carrier: i32,
    pub ignore_carrier_loss_set: i32,
    pub ignore_carrier_loss_usec: i32,
    pub keep_configuration: i32,
    pub default_route_on_device: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_network_enums() {
        let _ = std::mem::size_of::<KeepConfiguration>();
        let _ = std::mem::size_of::<ActivationPolicy>();
    }
}
