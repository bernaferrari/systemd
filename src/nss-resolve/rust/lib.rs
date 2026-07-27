// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/nss-resolve/nss-resolve.c
pub const SD_RESOLVED_NO_VALIDATE: u64 = 1 << 0;
pub const SD_RESOLVED_NO_SYNTHESIZE: u64 = 1 << 1;
pub const SD_RESOLVED_NO_CACHE: u64 = 1 << 2;
pub const SD_RESOLVED_NO_ZONE: u64 = 1 << 3;
pub const SD_RESOLVED_NO_TRUST_ANCHOR: u64 = 1 << 4;
pub const SD_RESOLVED_NO_NETWORK: u64 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success,
    NotFound,
    TryAgain,
    Unavail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveQuerySettings {
    pub validate: Option<bool>,
    pub synthesize: Option<bool>,
    pub cache: Option<bool>,
    pub zone: Option<bool>,
    pub trust_anchor: Option<bool>,
    pub network: Option<bool>,
}

pub fn error_shall_fallback(error_id: &str) -> bool {
    matches!(
        error_id,
        "org.varlink.service.Disconnected"
            | "org.varlink.service.Timeout"
            | "org.varlink.service.ProtocolViolation"
            | "org.varlink.service.InterfaceNotFound"
            | "org.varlink.service.MethodNotFound"
            | "org.varlink.service.MethodNotImplemented"
    )
}

pub fn error_shall_try_again(error_id: &str) -> bool {
    matches!(
        error_id,
        "io.systemd.Resolve.NoNameServers"
            | "io.systemd.Resolve.QueryTimedOut"
            | "io.systemd.Resolve.MaxAttemptsReached"
            | "io.systemd.Resolve.NetworkDown"
    )
}

pub fn ifindex_to_scopeid(family: i32, address: &[u8], ifindex: i32) -> u32 {
    const AF_INET6: i32 = 10;

    if family != AF_INET6 || ifindex <= 0 || address.len() != 16 {
        return 0;
    }

    let is_link_local = address[0] == 0xfe && (address[1] & 0xc0) == 0x80;
    if is_link_local {
        ifindex as u32
    } else {
        0
    }
}

fn query_flag(value: Option<bool>, flag: u64) -> u64 {
    matches!(value, Some(false)).then_some(flag).unwrap_or(0)
}

pub fn query_flags(settings: ResolveQuerySettings) -> u64 {
    query_flag(settings.validate, SD_RESOLVED_NO_VALIDATE)
        | query_flag(settings.synthesize, SD_RESOLVED_NO_SYNTHESIZE)
        | query_flag(settings.cache, SD_RESOLVED_NO_CACHE)
        | query_flag(settings.zone, SD_RESOLVED_NO_ZONE)
        | query_flag(settings.trust_anchor, SD_RESOLVED_NO_TRUST_ANCHOR)
        | query_flag(settings.network, SD_RESOLVED_NO_NETWORK)
}

pub fn query_ifindex(interface_index: Option<i32>) -> i32 {
    interface_index.filter(|value| *value > 0).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_errors_match_varlink_transport_failures() {
        assert!(error_shall_fallback("org.varlink.service.Timeout"));
        assert!(error_shall_fallback("org.varlink.service.MethodNotFound"));
        assert!(!error_shall_fallback("io.systemd.Resolve.NoNameServers"));
    }

    #[test]
    fn try_again_errors_match_runtime_resolution_failures() {
        assert!(error_shall_try_again("io.systemd.Resolve.QueryTimedOut"));
        assert!(error_shall_try_again("io.systemd.Resolve.NetworkDown"));
        assert!(!error_shall_try_again("org.varlink.service.Timeout"));
    }

    #[test]
    fn scopeid_is_zero_for_non_ipv6() {
        assert_eq!(ifindex_to_scopeid(2, &[127, 0, 0, 1], 3), 0);
    }

    #[test]
    fn scopeid_is_zero_for_non_link_local_ipv6() {
        let mut address = [0u8; 16];
        address[0] = 0x20;
        address[1] = 0x01;
        assert_eq!(ifindex_to_scopeid(10, &address, 3), 0);
    }

    #[test]
    fn scopeid_uses_ifindex_for_link_local_ipv6() {
        let mut address = [0u8; 16];
        address[0] = 0xfe;
        address[1] = 0x80;
        assert_eq!(ifindex_to_scopeid(10, &address, 7), 7);
    }

    #[test]
    fn query_flags_set_bits_when_features_are_disabled() {
        let flags = query_flags(ResolveQuerySettings {
            validate: Some(false),
            synthesize: Some(true),
            cache: Some(false),
            zone: None,
            trust_anchor: Some(false),
            network: Some(false),
        });

        assert_eq!(
            flags,
            SD_RESOLVED_NO_VALIDATE
                | SD_RESOLVED_NO_CACHE
                | SD_RESOLVED_NO_TRUST_ANCHOR
                | SD_RESOLVED_NO_NETWORK
        );
    }

    #[test]
    fn query_ifindex_sanitizes_invalid_values() {
        assert_eq!(query_ifindex(Some(-1)), 0);
        assert_eq!(query_ifindex(None), 0);
        assert_eq!(query_ifindex(Some(11)), 11);
    }

    #[test]
    fn nss_status_variants_are_distinct() {
        assert_ne!(NssStatus::Success, NssStatus::TryAgain);
    }
}
