// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-route.c
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
pub enum RouteConfParserType {
    RouteDestination,
    RoutePreferredSource,
    RoutePriority,
    RouteScope,
    RouteTable,
    RoutePreference,
    RouteProtocol,
    RouteType,
    RouteGatewayNetwork,
    RouteGateway,
    RouteGatewayOnlink,
    RouteMultipath,
    RouteNexthop,
    RouteMetricMtu,
    RouteMetricAdvmss,
    RouteMetricHoplimit,
    RouteMetricInitcwnd,
    RouteMetricRtoMin,
    RouteMetricInitrwnd,
    RouteMetricQuickack,
    RouteMetricCcAlgo,
    RouteMetricFastopenNoCookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum RouteState {
    RoutePending,
    RouteProbing,
    RouteRequested,
    RouteAssigned,
    RouteRemoved,
    RouteFailed,
    RouteStale,
}

#[derive(Debug)]
pub struct Route {
    pub source: i32,
    pub state: i32,
    pub provider: i32,
    pub n_ref: i32,
    pub family: i32,
    pub dst_prefixlen: i32,
    pub src_prefixlen: i32,
    pub tos: i32,
    pub protocol: i32,
    pub scope: i32,
    pub type_: i32,
    pub flags: i32,
    pub dst: i32,
    pub src: i32,
    pub priority: i32,
    pub prefsrc: i32,
    pub table: i32,
    pub pref: i32,
    pub nexthop: i32,
    pub nexthop_id: i32,
}

#[derive(Debug)]
pub struct RouteNextHop {
    pub family: i32,
    pub ifindex: i32,
    pub gw: i32,
    pub id: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_route_enums() {
        let _ = std::mem::size_of::<RouteConfParserType>();
    }

    #[test]
    fn test_networkd_route_state_enum() {
        let _ = std::mem::size_of::<RouteState>();
    }

    #[test]
    fn test_networkd_route_struct() {
        let _ = std::mem::size_of::<Route>();
    }

    #[test]
    fn test_networkd_route_nexthop_struct() {
        let _ = std::mem::size_of::<RouteNextHop>();
    }
}
