// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-socket.c
//
// D-Bus property access and transient property management for socket units.
//
// Provides socket-specific enums with string tables, protocol name mapping,
// size-t truncation checks, socket port types, and the transient property
// dispatch classification logic used when creating runtime socket units.

// ── Socket result enum ────────────────────────────────────────────────────

/// Socket result types, corresponding to SocketResult in socket.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketResult {
    Success,
    FailureResources,
    FailureTimeout,
    FailureExitCode,
    FailureSignal,
    FailureCoreDump,
    FailureWatchdog,
    FailureStartLimitHit,
}

static SOCKET_RESULT_TABLE: &[&str] = &[
    "success",
    "failure-resources",
    "failure-timeout",
    "failure-exit-code",
    "failure-signal",
    "failure-core-dump",
    "failure-watchdog",
    "failure-start-limit-hit",
];

// ── Bind IPv6-only enum ───────────────────────────────────────────────────

/// Socket address bind IPv6 mode, corresponding to SocketAddressBindIPv6Only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAddressBindIPv6Only {
    Default,
    Both,
    IPv6Only,
}

static BIND_IPV6_ONLY_TABLE: &[&str] = &["default", "both", "ipv6-only"];

// ── Socket timestamping enum ──────────────────────────────────────────────

/// Socket timestamping mode, corresponding to SocketTimestamping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketTimestamping {
    Off,
    RxSoftware,
    TxSoftware,
    TxHardware,
}

static SOCKET_TIMESTAMPING_TABLE: &[&str] = &["off", "rx-so", "tx-software", "tx-hardware"];

// ── Socket defer trigger enum ─────────────────────────────────────────────

/// Socket defer trigger type, corresponding to SocketDeferTrigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDeferTrigger {
    None,
    Connected,
    Accepted,
}

static SOCKET_DEFER_TRIGGER_TABLE: &[&str] = &["none", "connected", "accepted"];

// ── Socket port type ──────────────────────────────────────────────────────

/// Socket port type for listen addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPortType {
    Stream,
    SequentialPacket,
    Datagram,
    Sequential,
    Fifo,
    Special,
    Netlink,
    USBFunction,
    USBFunctionFifo,
    USBFunctionSequential,
}

static SOCKET_PORT_TYPE_TABLE: &[&str] = &[
    "Stream",
    "SequentialPacket",
    "Datagram",
    "Sequential",
    "FIFO",
    "Special",
    "Netlink",
    "USBFunction",
    "USBFunctionFifo",
    "USBFunctionSequential",
];

// ── Protocol constants ────────────────────────────────────────────────────

/// IPPROTO_IP constant.
pub const IPPROTO_IP: i32 = 0;
/// IPPROTO_UDPLITE constant.
pub const IPPROTO_UDPLITE: i32 = 136;
/// IPPROTO_SCTP constant.
pub const IPPROTO_SCTP: i32 = 132;
/// IPPROTO_MPTCP constant.
pub const IPPROTO_MPTCP: i32 = 262;

// ── EINVAL sentinel ───────────────────────────────────────────────────────

const EINVAL: i32 = -22;

// ── Core functions ────────────────────────────────────────────────────────

/// Check if a u64 value can be stored in a usize without truncation.
///
/// Port of `check_size_t_truncation()` from dbus-socket.c.
pub fn check_size_t_truncation(t: u64) -> bool {
    t as usize as u64 == t
}

/// Map a socket protocol number to its name string.
///
/// Port of `socket_protocol_to_string()` from dbus-socket.c.
/// IPPROTO_IP (0) returns an empty string. For UDPLITE/SCTP/MPTCP
/// returns the protocol name. Returns None for unknown protocols.
pub fn socket_protocol_to_string(i: i32) -> Option<&'static str> {
    if i == IPPROTO_IP {
        return Some("");
    }
    match i {
        IPPROTO_UDPLITE => Some("udplite"),
        IPPROTO_SCTP => Some("sctp"),
        IPPROTO_MPTCP => Some("mptcp"),
        _ => None,
    }
}

/// Parse a socket protocol name back to its number.
pub fn socket_protocol_from_string(s: &str) -> Option<i32> {
    match s {
        "" => Some(IPPROTO_IP),
        "udplite" => Some(IPPROTO_UDPLITE),
        "sctp" => Some(IPPROTO_SCTP),
        "mptcp" => Some(IPPROTO_MPTCP),
        _ => None,
    }
}

// ── Generic table helpers ─────────────────────────────────────────────────

fn table_to_string<'a>(table: &'a [&'a str], idx: usize) -> Result<&'a str, i32> {
    table.get(idx).copied().ok_or(EINVAL)
}

fn table_from_string(table: &[&str], s: &str) -> Result<usize, i32> {
    table.iter().position(|entry| *entry == s).ok_or(EINVAL)
}

// ── Socket result helpers ─────────────────────────────────────────────────

/// Convert a SocketResult to its string representation.
pub fn socket_result_to_string(v: SocketResult) -> Result<&'static str, i32> {
    table_to_string(SOCKET_RESULT_TABLE, v as usize)
}

/// Parse a SocketResult from its string representation.
pub fn socket_result_from_string(s: &str) -> Result<SocketResult, i32> {
    let idx = table_from_string(SOCKET_RESULT_TABLE, s)?;
    Ok(match idx {
        0 => SocketResult::Success,
        1 => SocketResult::FailureResources,
        2 => SocketResult::FailureTimeout,
        3 => SocketResult::FailureExitCode,
        4 => SocketResult::FailureSignal,
        5 => SocketResult::FailureCoreDump,
        6 => SocketResult::FailureWatchdog,
        7 => SocketResult::FailureStartLimitHit,
        _ => return Err(EINVAL),
    })
}

// ── Bind IPv6-only helpers ────────────────────────────────────────────────

/// Convert a SocketAddressBindIPv6Only to its string representation.
pub fn bind_ipv6_only_to_string(v: SocketAddressBindIPv6Only) -> Result<&'static str, i32> {
    table_to_string(BIND_IPV6_ONLY_TABLE, v as usize)
}

/// Parse a SocketAddressBindIPv6Only from its string representation.
pub fn bind_ipv6_only_from_string(s: &str) -> Result<SocketAddressBindIPv6Only, i32> {
    let idx = table_from_string(BIND_IPV6_ONLY_TABLE, s)?;
    Ok(match idx {
        0 => SocketAddressBindIPv6Only::Default,
        1 => SocketAddressBindIPv6Only::Both,
        2 => SocketAddressBindIPv6Only::IPv6Only,
        _ => return Err(EINVAL),
    })
}

// ── Timestamping helpers ──────────────────────────────────────────────────

/// Convert a SocketTimestamping to its string representation.
pub fn socket_timestamping_to_string(v: SocketTimestamping) -> Result<&'static str, i32> {
    table_to_string(SOCKET_TIMESTAMPING_TABLE, v as usize)
}

/// Parse a SocketTimestamping from its string representation.
pub fn socket_timestamping_from_string(s: &str) -> Result<SocketTimestamping, i32> {
    let idx = table_from_string(SOCKET_TIMESTAMPING_TABLE, s)?;
    Ok(match idx {
        0 => SocketTimestamping::Off,
        1 => SocketTimestamping::RxSoftware,
        2 => SocketTimestamping::TxSoftware,
        3 => SocketTimestamping::TxHardware,
        _ => return Err(EINVAL),
    })
}

// ── Defer trigger helpers ─────────────────────────────────────────────────

/// Convert a SocketDeferTrigger to its string representation.
pub fn socket_defer_trigger_to_string(v: SocketDeferTrigger) -> Result<&'static str, i32> {
    table_to_string(SOCKET_DEFER_TRIGGER_TABLE, v as usize)
}

/// Parse a SocketDeferTrigger from its string representation.
pub fn socket_defer_trigger_from_string(s: &str) -> Result<SocketDeferTrigger, i32> {
    let idx = table_from_string(SOCKET_DEFER_TRIGGER_TABLE, s)?;
    Ok(match idx {
        0 => SocketDeferTrigger::None,
        1 => SocketDeferTrigger::Connected,
        2 => SocketDeferTrigger::Accepted,
        _ => return Err(EINVAL),
    })
}

// ── Socket port type helpers ──────────────────────────────────────────────

/// Convert a SocketPortType to its D-Bus string representation.
pub fn socket_port_type_to_string(t: SocketPortType) -> Result<&'static str, i32> {
    table_to_string(SOCKET_PORT_TYPE_TABLE, t as usize)
}

/// Parse a SocketPortType from its D-Bus string representation.
pub fn socket_port_type_from_string(s: &str) -> Result<SocketPortType, i32> {
    for (idx, entry) in SOCKET_PORT_TYPE_TABLE.iter().enumerate() {
        if entry.eq_ignore_ascii_case(s) {
            return Ok(match idx {
                0 => SocketPortType::Stream,
                1 => SocketPortType::SequentialPacket,
                2 => SocketPortType::Datagram,
                3 => SocketPortType::Sequential,
                4 => SocketPortType::Fifo,
                5 => SocketPortType::Special,
                6 => SocketPortType::Netlink,
                7 => SocketPortType::USBFunction,
                8 => SocketPortType::USBFunctionFifo,
                9 => SocketPortType::USBFunctionSequential,
                _ => return Err(EINVAL),
            });
        }
    }
    Err(EINVAL)
}

// ── Listen entry ──────────────────────────────────────────────────────────

/// A single listen entry corresponding to the D-Bus (ss) struct
/// in the "Listen" property of socket units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenEntry {
    pub port_type: SocketPortType,
    pub address: String,
}

/// Build the list of listen entries for a socket unit.
///
/// Port of the `property_get_listen` D-Bus property getter logic.
pub fn build_listen_entries(ports: &[(SocketPortType, &str)]) -> Vec<ListenEntry> {
    ports
        .iter()
        .map(|(t, a)| ListenEntry {
            port_type: *t,
            address: a.to_string(),
        })
        .collect()
}

// ── Transient property classification ─────────────────────────────────────

/// Categories of transient properties for socket units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransientPropertyKind {
    Boolean,
    Unsigned,
    Integer,
    Usec,
    String,
    Mode,
    SizeCheckTruncation,
    BindIPv6Only,
    Timestamping,
    DeferTrigger,
    Symlinks,
    Listen,
    ExecCommand,
    Unknown,
}

/// Classify a transient property name into its kind.
///
/// Port of the dispatch logic in `bus_socket_set_transient_property()`.
pub fn classify_transient_property(name: &str) -> TransientPropertyKind {
    match name {
        "Accept"
        | "FlushPending"
        | "Writable"
        | "KeepAlive"
        | "NoDelay"
        | "FreeBind"
        | "Transparent"
        | "Broadcast"
        | "PassCredentials"
        | "PassPIDFD"
        | "PassSecurity"
        | "PassPacketInfo"
        | "AcceptFileDescriptors"
        | "ReusePort"
        | "RemoveOnStop"
        | "SELinuxContextFromNet"
        | "PassFileDescriptorsToExec" => TransientPropertyKind::Boolean,

        "Backlog"
        | "MaxConnections"
        | "MaxConnectionsPerSource"
        | "KeepAliveProbes"
        | "TriggerLimitBurst"
        | "PollLimitBurst" => TransientPropertyKind::Unsigned,

        "Priority" | "IPTTL" | "Mark" => TransientPropertyKind::Integer,

        "IPTOS" | "SocketProtocol" => TransientPropertyKind::Integer,

        "TimeoutUSec"
        | "KeepAliveTimeUSec"
        | "KeepAliveIntervalUSec"
        | "DeferAcceptUSec"
        | "TriggerLimitIntervalUSec"
        | "PollLimitIntervalUSec"
        | "DeferTriggerMaxUSec" => TransientPropertyKind::Usec,

        "SmackLabel" | "SmackLabelIPin" | "SmackLabelIPOut" | "TCPCongestion" | "SocketUser"
        | "SocketGroup" | "BindToDevice" | "FileDescriptorName" => TransientPropertyKind::String,

        "SocketMode" | "DirectoryMode" => TransientPropertyKind::Mode,

        "MessageQueueMaxMessages" | "MessageQueueMessageSize" => TransientPropertyKind::Integer,

        "ReceiveBuffer" | "SendBuffer" | "PipeSize" => TransientPropertyKind::SizeCheckTruncation,

        "BindIPv6Only" => TransientPropertyKind::BindIPv6Only,
        "Timestamping" => TransientPropertyKind::Timestamping,
        "DeferTrigger" => TransientPropertyKind::DeferTrigger,
        "Symlinks" => TransientPropertyKind::Symlinks,
        "Listen" => TransientPropertyKind::Listen,

        n if n.starts_with("ExecStartPre")
            || n.starts_with("ExecStartPost")
            || n.starts_with("ExecStopPre")
            || n.starts_with("ExecStopPost") =>
        {
            TransientPropertyKind::ExecCommand
        }

        _ => TransientPropertyKind::Unknown,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_size_t_truncation_fits() {
        assert!(check_size_t_truncation(0));
        assert!(check_size_t_truncation(42));
        assert!(check_size_t_truncation(0xFFFF));
        assert!(check_size_t_truncation(usize::MAX as u64));
    }

    #[test]
    fn test_check_size_t_truncation_overflow() {
        if usize::BITS < 64 {
            assert!(!check_size_t_truncation(usize::MAX as u64 + 1));
            assert!(!check_size_t_truncation(u64::MAX));
        }
    }

    #[test]
    fn test_socket_protocol_to_string_known() {
        assert_eq!(socket_protocol_to_string(IPPROTO_IP), Some(""));
        assert_eq!(socket_protocol_to_string(IPPROTO_UDPLITE), Some("udplite"));
        assert_eq!(socket_protocol_to_string(IPPROTO_SCTP), Some("sctp"));
        assert_eq!(socket_protocol_to_string(IPPROTO_MPTCP), Some("mptcp"));
    }

    #[test]
    fn test_socket_protocol_to_string_unknown() {
        assert_eq!(socket_protocol_to_string(99), None);
        assert_eq!(socket_protocol_to_string(-1), None);
    }

    #[test]
    fn test_socket_protocol_roundtrip() {
        for &proto in &[IPPROTO_IP, IPPROTO_UDPLITE, IPPROTO_SCTP, IPPROTO_MPTCP] {
            let name = socket_protocol_to_string(proto).unwrap();
            assert_eq!(socket_protocol_from_string(name), Some(proto));
        }
    }

    #[test]
    fn test_socket_result_roundtrip() {
        let all = [
            SocketResult::Success,
            SocketResult::FailureResources,
            SocketResult::FailureTimeout,
            SocketResult::FailureExitCode,
            SocketResult::FailureSignal,
            SocketResult::FailureCoreDump,
            SocketResult::FailureWatchdog,
            SocketResult::FailureStartLimitHit,
        ];
        for variant in &all {
            let s = socket_result_to_string(*variant).unwrap();
            let back = socket_result_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_socket_result_invalid() {
        assert!(socket_result_from_string("nonexistent").is_err());
        assert!(socket_result_to_string(SocketResult::Success).is_ok());
    }

    #[test]
    fn test_bind_ipv6_only_roundtrip() {
        let all = [
            SocketAddressBindIPv6Only::Default,
            SocketAddressBindIPv6Only::Both,
            SocketAddressBindIPv6Only::IPv6Only,
        ];
        for variant in &all {
            let s = bind_ipv6_only_to_string(*variant).unwrap();
            let back = bind_ipv6_only_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_socket_timestamping_roundtrip() {
        let all = [
            SocketTimestamping::Off,
            SocketTimestamping::RxSoftware,
            SocketTimestamping::TxSoftware,
            SocketTimestamping::TxHardware,
        ];
        for variant in &all {
            let s = socket_timestamping_to_string(*variant).unwrap();
            let back = socket_timestamping_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_socket_defer_trigger_roundtrip() {
        let all = [
            SocketDeferTrigger::None,
            SocketDeferTrigger::Connected,
            SocketDeferTrigger::Accepted,
        ];
        for variant in &all {
            let s = socket_defer_trigger_to_string(*variant).unwrap();
            let back = socket_defer_trigger_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_socket_port_type_roundtrip() {
        for (idx, &name) in SOCKET_PORT_TYPE_TABLE.iter().enumerate() {
            let port_type = socket_port_type_from_string(name).unwrap();
            assert_eq!(port_type as usize, idx);
            assert_eq!(socket_port_type_to_string(port_type).unwrap(), name);
        }
    }

    #[test]
    fn test_socket_port_type_case_insensitive() {
        assert_eq!(
            socket_port_type_from_string("stream").unwrap(),
            SocketPortType::Stream
        );
        assert_eq!(
            socket_port_type_from_string("DATAGRAM").unwrap(),
            SocketPortType::Datagram
        );
    }

    #[test]
    fn test_build_listen_entries() {
        let ports = &[
            (SocketPortType::Stream, "/run/foo.sock"),
            (SocketPortType::Datagram, "0.0.0.0:8080"),
        ];
        let entries = build_listen_entries(ports);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].port_type, SocketPortType::Stream);
        assert_eq!(entries[0].address, "/run/foo.sock");
        assert_eq!(entries[1].port_type, SocketPortType::Datagram);
        assert_eq!(entries[1].address, "0.0.0.0:8080");
    }

    #[test]
    fn test_build_listen_entries_empty() {
        let ports: &[(SocketPortType, &str)] = &[];
        let entries = build_listen_entries(ports);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_classify_transient_property_all_categories() {
        assert_eq!(
            classify_transient_property("Accept"),
            TransientPropertyKind::Boolean
        );
        assert_eq!(
            classify_transient_property("Backlog"),
            TransientPropertyKind::Unsigned
        );
        assert_eq!(
            classify_transient_property("Priority"),
            TransientPropertyKind::Integer
        );
        assert_eq!(
            classify_transient_property("TimeoutUSec"),
            TransientPropertyKind::Usec
        );
        assert_eq!(
            classify_transient_property("SmackLabel"),
            TransientPropertyKind::String
        );
        assert_eq!(
            classify_transient_property("SocketMode"),
            TransientPropertyKind::Mode
        );
        assert_eq!(
            classify_transient_property("ReceiveBuffer"),
            TransientPropertyKind::SizeCheckTruncation
        );
        assert_eq!(
            classify_transient_property("BindIPv6Only"),
            TransientPropertyKind::BindIPv6Only
        );
        assert_eq!(
            classify_transient_property("Timestamping"),
            TransientPropertyKind::Timestamping
        );
        assert_eq!(
            classify_transient_property("DeferTrigger"),
            TransientPropertyKind::DeferTrigger
        );
        assert_eq!(
            classify_transient_property("Symlinks"),
            TransientPropertyKind::Symlinks
        );
        assert_eq!(
            classify_transient_property("Listen"),
            TransientPropertyKind::Listen
        );
        assert_eq!(
            classify_transient_property("ExecStartPre"),
            TransientPropertyKind::ExecCommand
        );
        assert_eq!(
            classify_transient_property("UnknownProp"),
            TransientPropertyKind::Unknown
        );
    }

    #[test]
    fn test_socket_port_type_invalid() {
        assert!(socket_port_type_from_string("nonexistent").is_err());
    }
}
