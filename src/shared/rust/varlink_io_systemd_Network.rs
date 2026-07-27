// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Network.c
//
// Varlink interface definition for io.systemd.Network.
//
// Top-level network management interface for systemd-networkd.
// Provides methods to describe all interfaces, get overall states,
// retrieve the namespace ID, list LLDP neighbors, and set persistent storage.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.Network";

// ── Enum types ────────────────────────────────────────────────────────────

/// Administrative state of a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Pending,
    Initialized,
    Configuring,
    Configured,
    Unmanaged,
    Failed,
    Linger,
}

impl LinkState {
    /// All known values.
    pub const VALUES: &[Self] = &[
        Self::Pending,
        Self::Initialized,
        Self::Configuring,
        Self::Configured,
        Self::Unmanaged,
        Self::Failed,
        Self::Linger,
    ];

    /// Parse from the varlink wire string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(Self::Pending),
            "initialized" => Ok(Self::Initialized),
            "configuring" => Ok(Self::Configuring),
            "configured" => Ok(Self::Configured),
            "unmanaged" => Ok(Self::Unmanaged),
            "failed" => Ok(Self::Failed),
            "linger" => Ok(Self::Linger),
            _ => Err(format!("unknown LinkState: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Initialized => "initialized",
            Self::Configuring => "configuring",
            Self::Configured => "configured",
            Self::Unmanaged => "unmanaged",
            Self::Failed => "failed",
            Self::Linger => "linger",
        }
    }
}

/// Address configuration state of a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAddressState {
    Off,
    Degraded,
    Routable,
}

impl LinkAddressState {
    /// All known values.
    pub const VALUES: &[Self] = &[Self::Off, Self::Degraded, Self::Routable];

    /// Parse from the varlink wire string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(Self::Off),
            "degraded" => Ok(Self::Degraded),
            "routable" => Ok(Self::Routable),
            _ => Err(format!("unknown LinkAddressState: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Degraded => "degraded",
            Self::Routable => "routable",
        }
    }
}

/// Online state of a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOnlineState {
    Offline,
    Partial,
    Online,
}

impl LinkOnlineState {
    /// All known values.
    pub const VALUES: &[Self] = &[Self::Offline, Self::Partial, Self::Online];

    /// Parse from the varlink wire string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "offline" => Ok(Self::Offline),
            "partial" => Ok(Self::Partial),
            "online" => Ok(Self::Online),
            _ => Err(format!("unknown LinkOnlineState: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Partial => "partial",
            Self::Online => "online",
        }
    }
}

/// Required address family for online detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRequiredAddressFamily {
    Any,
    Ipv4,
    Ipv6,
    Both,
}

impl LinkRequiredAddressFamily {
    /// All known values.
    pub const VALUES: &[Self] = &[Self::Any, Self::Ipv4, Self::Ipv6, Self::Both];

    /// Parse from the varlink wire string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "any" => Ok(Self::Any),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "both" => Ok(Self::Both),
            _ => Err(format!("unknown LinkRequiredAddressFamily: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Both => "both",
        }
    }
}

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_DESCRIBE: &str = "Describe";
pub const METHOD_GET_STATES: &str = "GetStates";
pub const METHOD_GET_NAMESPACE_ID: &str = "GetNamespaceId";
pub const METHOD_GET_LLDP_NEIGHBORS: &str = "GetLLDPNeighbors";
pub const METHOD_SET_PERSISTENT_STORAGE: &str = "SetPersistentStorage";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_DESCRIBE,
        METHOD_GET_STATES,
        METHOD_GET_NAMESPACE_ID,
        METHOD_GET_LLDP_NEIGHBORS,
        METHOD_SET_PERSISTENT_STORAGE,
    ]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMethod {
    Describe,
    GetStates,
    GetNamespaceId,
    GetLLDPNeighbors,
    SetPersistentStorage,
}

impl NetworkMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Describe => METHOD_DESCRIBE,
            Self::GetStates => METHOD_GET_STATES,
            Self::GetNamespaceId => METHOD_GET_NAMESPACE_ID,
            Self::GetLLDPNeighbors => METHOD_GET_LLDP_NEIGHBORS,
            Self::SetPersistentStorage => METHOD_SET_PERSISTENT_STORAGE,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<NetworkMethod, String> {
    match name {
        METHOD_DESCRIBE => Ok(NetworkMethod::Describe),
        METHOD_GET_STATES => Ok(NetworkMethod::GetStates),
        METHOD_GET_NAMESPACE_ID => Ok(NetworkMethod::GetNamespaceId),
        METHOD_GET_LLDP_NEIGHBORS => Ok(NetworkMethod::GetLLDPNeighbors),
        METHOD_SET_PERSISTENT_STORAGE => Ok(NetworkMethod::SetPersistentStorage),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    AlreadyReloading,
    StorageReadOnly,
}

impl NetworkError {
    /// Parse from the varlink error string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "AlreadyReloading" => Ok(Self::AlreadyReloading),
            "StorageReadOnly" => Ok(Self::StorageReadOnly),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AlreadyReloading => "AlreadyReloading",
            Self::StorageReadOnly => "StorageReadOnly",
        }
    }
}

/// All error names as string slices.
pub fn error_names() -> &'static [&'static str] {
    &["AlreadyReloading", "StorageReadOnly"]
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input for SetPersistentStorage method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPersistentStorageInput {
    /// Whether persistent storage is ready and writable.
    pub ready: bool,
}

/// Input for GetLLDPNeighbors method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetLLDPNeighborsInput {
    /// Filter by interface index (optional).
    pub interface_index: Option<i64>,
    /// Filter by interface name (optional).
    pub interface_name: Option<String>,
}

/// Output for GetNamespaceId method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNamespaceIdOutput {
    /// Network namespace inode number.
    pub namespace_id: i64,
    /// Network namespace ID (cookie) assigned by the kernel.
    pub namespace_nsid: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Network");
    }

    #[test]
    fn test_link_state_roundtrip() {
        for v in LinkState::VALUES {
            assert_eq!(LinkState::from_str(v.as_str()), Ok(*v));
        }
        assert!(LinkState::from_str("bogus").is_err());
    }

    #[test]
    fn test_link_address_state_roundtrip() {
        for v in LinkAddressState::VALUES {
            assert_eq!(LinkAddressState::from_str(v.as_str()), Ok(*v));
        }
        assert!(LinkAddressState::from_str("bogus").is_err());
    }

    #[test]
    fn test_link_online_state_roundtrip() {
        for v in LinkOnlineState::VALUES {
            assert_eq!(LinkOnlineState::from_str(v.as_str()), Ok(*v));
        }
    }

    #[test]
    fn test_link_required_address_family_roundtrip() {
        for v in LinkRequiredAddressFamily::VALUES {
            assert_eq!(LinkRequiredAddressFamily::from_str(v.as_str()), Ok(*v));
        }
    }

    #[test]
    fn test_method_names_count() {
        assert_eq!(method_names().len(), 5);
    }

    #[test]
    fn test_has_method() {
        assert!(has_method("Describe"));
        assert!(has_method("GetStates"));
        assert!(has_method("GetNamespaceId"));
        assert!(has_method("GetLLDPNeighbors"));
        assert!(has_method("SetPersistentStorage"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_all() {
        assert_eq!(parse_method("Describe"), Ok(NetworkMethod::Describe));
        assert_eq!(parse_method("GetStates"), Ok(NetworkMethod::GetStates));
        assert_eq!(
            parse_method("GetNamespaceId"),
            Ok(NetworkMethod::GetNamespaceId)
        );
        assert_eq!(
            parse_method("GetLLDPNeighbors"),
            Ok(NetworkMethod::GetLLDPNeighbors)
        );
        assert_eq!(
            parse_method("SetPersistentStorage"),
            Ok(NetworkMethod::SetPersistentStorage)
        );
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("nope").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_error_roundtrip() {
        assert_eq!(
            NetworkError::from_str("AlreadyReloading"),
            Ok(NetworkError::AlreadyReloading)
        );
        assert_eq!(
            NetworkError::from_str("StorageReadOnly"),
            Ok(NetworkError::StorageReadOnly)
        );
        assert!(NetworkError::from_str("bogus").is_err());
        assert_eq!(NetworkError::AlreadyReloading.as_str(), "AlreadyReloading");
        assert_eq!(NetworkError::StorageReadOnly.as_str(), "StorageReadOnly");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(error_names().len(), 2);
    }

    #[test]
    fn test_set_persistent_storage_input() {
        let input = SetPersistentStorageInput { ready: true };
        assert!(input.ready);
    }

    #[test]
    fn test_get_lldp_neighbors_input() {
        let input = GetLLDPNeighborsInput {
            interface_index: Some(2),
            interface_name: Some("eth0".to_string()),
        };
        assert_eq!(input.interface_index, Some(2));
        assert_eq!(input.interface_name.as_deref(), Some("eth0"));
    }
}
