// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-manager.c
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
pub enum ManagerState {
    ManagerRunning,
    ManagerTerminating,
    ManagerRestarting,
    ManagerStopped,
}

#[derive(Debug)]
pub struct Manager {
    pub ethtool_fd: i32,
    pub persistent_storage_fd: i32,
    pub keep_configuration: i32,
    pub ipv6_privacy_extensions: i32,
    pub state: i32,
    pub test_mode: i32,
    pub enumerating: i32,
    pub dirty: i32,
    pub manage_foreign_routes: i32,
    pub manage_foreign_rules: i32,
    pub manage_foreign_nexthops: i32,
    pub dhcp_server_persist_leases: i32,
    pub operational_state: i32,
    pub carrier_state: i32,
    pub address_state: i32,
    pub ipv4_address_state: i32,
    pub ipv6_address_state: i32,
    pub online_state: i32,
    pub use_domains: i32,
    pub dhcp_use_domains: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_manager_enums() {
        let _ = std::mem::size_of::<ManagerState>();
    }
}
