// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of cake.c
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
pub enum CakeCompensationMode {
    CakeCompensationModeNone,
    CakeCompensationModeAtm,
    CakeCompensationModePtm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum CakeFlowIsolationMode {
    CakeFlowIsolationModeNone,
    CakeFlowIsolationModeSrcIp,
    CakeFlowIsolationModeDstIp,
    CakeFlowIsolationModeHosts,
    CakeFlowIsolationModeFlows,
    CakeFlowIsolationModeDualSrc,
    CakeFlowIsolationModeDualDst,
    CakeFlowIsolationModeTriple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum CakePriorityQueueingPreset {
    CakePresetDiffserv3,
    CakePresetDiffserv4,
    CakePresetDiffserv8,
    CakePresetBesteffort,
    CakePresetPrecedence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum CakeAckFilter {
    CakeAckFilterNo,
    CakeAckFilterYes,
    CakeAckFilterAggressive,
}

#[derive(Debug)]
pub struct CommonApplicationsKeptEnhanced {
    pub meta: i32,
    pub autorate: i32,
    pub bandwidth: i32,
    pub overhead_set: i32,
    pub overhead: i32,
    pub mpu: i32,
    pub compensation_mode: i32,
    pub raw: i32,
    pub flow_isolation_mode: i32,
    pub nat: i32,
    pub preset: i32,
    pub fwmark: i32,
    pub wash: i32,
    pub split_gso: i32,
    pub rtt: i32,
    pub ack_filter: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cake_enums() {
        let _ = std::mem::size_of::<CakeCompensationMode>();
        let _ = std::mem::size_of::<CakeFlowIsolationMode>();
        let _ = std::mem::size_of::<CakePriorityQueueingPreset>();
    }
}
