// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of batadv.c
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BatadvGatewayModes {
    BatadvGatewayModeOff,
    BatadvGatewayModeClient,
    BatadvGatewayModeServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BatadvRoutingAlgorithm {
    BatadvRoutingAlgorithmBatmanV,
    BatadvRoutingAlgorithmBatmanIv,
}

#[derive(Debug)]
pub struct Batadv {
    pub meta: i32,
    pub gateway_mode: i32,
    pub gateway_bandwidth_down: i32,
    pub gateway_bandwidth_up: i32,
    pub hop_penalty: i32,
    pub routing_algorithm: i32,
    pub originator_interval: i32,
    pub aggregation: i32,
    pub bridge_loop_avoidance: i32,
    pub distributed_arp_table: i32,
    pub fragmentation: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batadv_enums() {
        let _ = std::mem::size_of::<BatadvGatewayModes>();
        let _ = std::mem::size_of::<BatadvRoutingAlgorithm>();
    }
}
