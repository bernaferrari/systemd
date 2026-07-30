// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.NamespaceResource.c
//
// Varlink interface definition for io.systemd.NamespaceResource.
//
// Allocate transient UID ranges for user namespaces, and assign mounts,
// cgroups and networking devices to them.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.NamespaceResource";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Type of user range allocation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocateUserRangeType {
    /// Allocate a transient UID/GID range from the dynamic range pool.
    Managed,
    /// Create a user namespace that maps the peer UID/GID to itself.
    Self_,
}

impl AllocateUserRangeType {
    /// All known enum values.
    pub const VALUES: &[Self] = &[Self::Managed, Self::Self_];

    /// Parse from the varlink wire string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "managed" => Ok(Self::Managed),
            "self" => Ok(Self::Self_),
            _ => Err(format!("unknown AllocateUserRangeType: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Self_ => "self",
        }
    }
}

// ── Method identifiers ────────────────────────────────────────────────────

/// Method names defined by this interface.
pub const METHOD_ALLOCATE_USER_RANGE: &str = "AllocateUserRange";
pub const METHOD_REGISTER_USER_NAMESPACE: &str = "RegisterUserNamespace";
pub const METHOD_ADD_MOUNT_TO_USER_NAMESPACE: &str = "AddMountToUserNamespace";
pub const METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE: &str = "AddControlGroupToUserNamespace";
pub const METHOD_ADD_NETWORK_TO_USER_NAMESPACE: &str = "AddNetworkToUserNamespace";

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceResourceMethod {
    AllocateUserRange,
    RegisterUserNamespace,
    AddMountToUserNamespace,
    AddControlGroupToUserNamespace,
    AddNetworkToUserNamespace,
}

impl NamespaceResourceMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AllocateUserRange => METHOD_ALLOCATE_USER_RANGE,
            Self::RegisterUserNamespace => METHOD_REGISTER_USER_NAMESPACE,
            Self::AddMountToUserNamespace => METHOD_ADD_MOUNT_TO_USER_NAMESPACE,
            Self::AddControlGroupToUserNamespace => METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE,
            Self::AddNetworkToUserNamespace => METHOD_ADD_NETWORK_TO_USER_NAMESPACE,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<NamespaceResourceMethod, String> {
    match name {
        METHOD_ALLOCATE_USER_RANGE => Ok(NamespaceResourceMethod::AllocateUserRange),
        METHOD_REGISTER_USER_NAMESPACE => Ok(NamespaceResourceMethod::RegisterUserNamespace),
        METHOD_ADD_MOUNT_TO_USER_NAMESPACE => Ok(NamespaceResourceMethod::AddMountToUserNamespace),
        METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE => {
            Ok(NamespaceResourceMethod::AddControlGroupToUserNamespace)
        }
        METHOD_ADD_NETWORK_TO_USER_NAMESPACE => {
            Ok(NamespaceResourceMethod::AddNetworkToUserNamespace)
        }
        _ => Err(format!("unknown method: {name}")),
    }
}

/// All method names.
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_ALLOCATE_USER_RANGE,
        METHOD_REGISTER_USER_NAMESPACE,
        METHOD_ADD_MOUNT_TO_USER_NAMESPACE,
        METHOD_ADD_CONTROL_GROUP_TO_USER_NAMESPACE,
        METHOD_ADD_NETWORK_TO_USER_NAMESPACE,
    ]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

// ── Method input/output structs ───────────────────────────────────────────

/// Input parameters for AllocateUserRange.
#[derive(Debug, Clone, PartialEq)]
pub struct AllocateUserRangeInput {
    /// Short name for the user namespace.
    pub name: String,
    /// Whether to mangle the provided name.
    pub mangle_name: Option<bool>,
    /// Number of UIDs to assign (1 or 65536).
    pub size: i64,
    /// Target UID inside the user namespace.
    pub target: Option<i64>,
    /// File descriptor to an allocated userns.
    pub user_namespace_file_descriptor: i64,
    /// The type of allocation to perform.
    pub allocation_type: Option<AllocateUserRangeType>,
    /// Number of container UID/GID ranges to delegate (0-16).
    pub delegate_container_ranges: Option<i64>,
    /// Whether to map the foreign UID range 1:1.
    pub map_foreign: Option<bool>,
}

/// Output from AllocateUserRange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocateUserRangeOutput {
    /// The name assigned to the user namespace.
    pub name: Option<String>,
}

/// Input parameters for RegisterUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserNamespaceInput {
    /// Short name for the user namespace.
    pub name: String,
    /// Whether to mangle the provided name.
    pub mangle_name: Option<bool>,
    /// File descriptor for a fully initialized user namespace.
    pub user_namespace_file_descriptor: i64,
}

/// Output from RegisterUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterUserNamespaceOutput {
    /// The name assigned to the user namespace.
    pub name: Option<String>,
}

/// Input parameters for AddMountToUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMountToUserNamespaceInput {
    /// User namespace file descriptor.
    pub user_namespace_file_descriptor: i64,
    /// Mount file descriptor to allowlist.
    pub mount_file_descriptor: i64,
}

/// Input parameters for AddControlGroupToUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddControlGroupToUserNamespaceInput {
    /// User namespace file descriptor.
    pub user_namespace_file_descriptor: i64,
    /// Cgroup file descriptor to assign.
    pub control_group_file_descriptor: i64,
}

/// Network mode for AddNetworkToUserNamespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Veth,
    Tap,
}

impl NetworkMode {
    /// Parse from varlink wire string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "veth" => Ok(Self::Veth),
            "tap" => Ok(Self::Tap),
            _ => Err(format!("unknown NetworkMode: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Veth => "veth",
            Self::Tap => "tap",
        }
    }
}

/// Input parameters for AddNetworkToUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddNetworkToUserNamespaceInput {
    /// User namespace file descriptor.
    pub user_namespace_file_descriptor: i64,
    /// Network namespace file descriptor (veth only).
    pub network_namespace_file_descriptor: Option<i64>,
    /// Interface name inside the network namespace (veth only).
    pub namespace_interface_name: Option<String>,
    /// Networking mode: veth or tap.
    pub mode: String,
}

/// Output from AddNetworkToUserNamespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddNetworkToUserNamespaceOutput {
    /// Host-side interface name.
    pub host_interface_name: String,
    /// Namespace-side interface name (veth only).
    pub namespace_interface_name: Option<String>,
    /// File descriptor for namespace side (tap only).
    pub interface_file_descriptor: Option<i64>,
}

// ── Error types ───────────────────────────────────────────────────────────

/// Error names defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceResourceError {
    UserNamespaceInterfaceNotSupported,
    NameExists,
    UserNamespaceExists,
    DynamicRangeUnavailable,
    NoDynamicRange,
    UserNamespaceNotRegistered,
    UserNamespaceWithoutUserRange,
    TooManyControlGroups,
    ControlGroupAlreadyAdded,
    TooManyNetworkInterfaces,
    TooManyDelegations,
}

impl NamespaceResourceError {
    /// All known error identifiers.
    pub const VALUES: &[Self] = &[
        Self::UserNamespaceInterfaceNotSupported,
        Self::NameExists,
        Self::UserNamespaceExists,
        Self::DynamicRangeUnavailable,
        Self::NoDynamicRange,
        Self::UserNamespaceNotRegistered,
        Self::UserNamespaceWithoutUserRange,
        Self::TooManyControlGroups,
        Self::ControlGroupAlreadyAdded,
        Self::TooManyNetworkInterfaces,
        Self::TooManyDelegations,
    ];

    /// Parse from the varlink error string.
    #[expect(
        clippy::should_implement_trait,
        reason = "retain the generated inherent API alongside FromStr"
    )]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "UserNamespaceInterfaceNotSupported" => Ok(Self::UserNamespaceInterfaceNotSupported),
            "NameExists" => Ok(Self::NameExists),
            "UserNamespaceExists" => Ok(Self::UserNamespaceExists),
            "DynamicRangeUnavailable" => Ok(Self::DynamicRangeUnavailable),
            "NoDynamicRange" => Ok(Self::NoDynamicRange),
            "UserNamespaceNotRegistered" => Ok(Self::UserNamespaceNotRegistered),
            "UserNamespaceWithoutUserRange" => Ok(Self::UserNamespaceWithoutUserRange),
            "TooManyControlGroups" => Ok(Self::TooManyControlGroups),
            "ControlGroupAlreadyAdded" => Ok(Self::ControlGroupAlreadyAdded),
            "TooManyNetworkInterfaces" => Ok(Self::TooManyNetworkInterfaces),
            "TooManyDelegations" => Ok(Self::TooManyDelegations),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserNamespaceInterfaceNotSupported => "UserNamespaceInterfaceNotSupported",
            Self::NameExists => "NameExists",
            Self::UserNamespaceExists => "UserNamespaceExists",
            Self::DynamicRangeUnavailable => "DynamicRangeUnavailable",
            Self::NoDynamicRange => "NoDynamicRange",
            Self::UserNamespaceNotRegistered => "UserNamespaceNotRegistered",
            Self::UserNamespaceWithoutUserRange => "UserNamespaceWithoutUserRange",
            Self::TooManyControlGroups => "TooManyControlGroups",
            Self::ControlGroupAlreadyAdded => "ControlGroupAlreadyAdded",
            Self::TooManyNetworkInterfaces => "TooManyNetworkInterfaces",
            Self::TooManyDelegations => "TooManyDelegations",
        }
    }
}

/// All error names as string slices.
pub fn error_names() -> Vec<&'static str> {
    NamespaceResourceError::VALUES
        .iter()
        .map(|e| e.as_str())
        .collect()
}

/// Validate the size field for AllocateUserRange.
pub fn validate_allocate_size(
    size: i64,
    allocation_type: Option<AllocateUserRangeType>,
) -> Result<(), String> {
    match allocation_type {
        Some(AllocateUserRangeType::Self_) if size != 1 => {
            Err("size must be 1 when type is 'self'".to_string())
        }
        _ if size != 1 && size != 65536 => Err("size must be 1 or 65536".to_string()),
        _ => Ok(()),
    }
}

/// Validate the target field for AllocateUserRange.
pub fn validate_allocate_target(
    target: Option<i64>,
    allocation_type: Option<AllocateUserRangeType>,
) -> Result<(), String> {
    match (target, allocation_type) {
        (Some(t), Some(AllocateUserRangeType::Self_)) if t != 0 => {
            Err("target must be 0 or unset when type is 'self'".to_string())
        }
        _ => Ok(()),
    }
}

/// Validate the delegate container ranges field.
pub fn validate_delegate_ranges(ranges: Option<i64>) -> Result<(), String> {
    match ranges {
        Some(r) if r < 0 || r > 16 => {
            Err("delegateContainerRanges must be between 0 and 16".to_string())
        }
        _ => Ok(()),
    }
}

macro_rules! impl_varlink_from_str {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::str::FromStr for $ty {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <$ty>::from_str(s)
            }
        }
    )+};
}

impl_varlink_from_str!(AllocateUserRangeType, NetworkMode, NamespaceResourceError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_from_str_matches_wire_parsers() {
        assert_eq!(
            "managed".parse::<AllocateUserRangeType>(),
            Ok(AllocateUserRangeType::Managed)
        );
        assert_eq!("veth".parse::<NetworkMode>(), Ok(NetworkMode::Veth));
        assert_eq!(
            "NameExists".parse::<NamespaceResourceError>(),
            Ok(NamespaceResourceError::NameExists)
        );
    }

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.NamespaceResource");
    }

    #[test]
    fn test_allocate_user_range_type_roundtrip() {
        for t in AllocateUserRangeType::VALUES {
            assert_eq!(AllocateUserRangeType::from_str(t.as_str()), Ok(*t));
        }
    }

    #[test]
    fn test_allocate_user_range_type_unknown() {
        assert!(AllocateUserRangeType::from_str("invalid").is_err());
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 5);
        assert!(has_method("AllocateUserRange"));
        assert!(has_method("RegisterUserNamespace"));
        assert!(has_method("AddMountToUserNamespace"));
        assert!(has_method("AddControlGroupToUserNamespace"));
        assert!(has_method("AddNetworkToUserNamespace"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_all() {
        assert_eq!(
            parse_method("AllocateUserRange"),
            Ok(NamespaceResourceMethod::AllocateUserRange)
        );
        assert_eq!(
            parse_method("RegisterUserNamespace"),
            Ok(NamespaceResourceMethod::RegisterUserNamespace)
        );
        assert_eq!(
            parse_method("AddMountToUserNamespace"),
            Ok(NamespaceResourceMethod::AddMountToUserNamespace)
        );
        assert_eq!(
            parse_method("AddControlGroupToUserNamespace"),
            Ok(NamespaceResourceMethod::AddControlGroupToUserNamespace)
        );
        assert_eq!(
            parse_method("AddNetworkToUserNamespace"),
            Ok(NamespaceResourceMethod::AddNetworkToUserNamespace)
        );
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("nonexistent").is_err());
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
        for e in NamespaceResourceError::VALUES {
            assert_eq!(NamespaceResourceError::from_str(e.as_str()), Ok(*e));
        }
    }

    #[test]
    fn test_error_names_count() {
        assert_eq!(error_names().len(), 11);
    }

    #[test]
    fn test_network_mode_roundtrip() {
        assert_eq!(NetworkMode::from_str("veth"), Ok(NetworkMode::Veth));
        assert_eq!(NetworkMode::from_str("tap"), Ok(NetworkMode::Tap));
        assert!(NetworkMode::from_str("invalid").is_err());
        assert_eq!(NetworkMode::Veth.as_str(), "veth");
        assert_eq!(NetworkMode::Tap.as_str(), "tap");
    }

    #[test]
    fn test_validate_allocate_size() {
        assert!(validate_allocate_size(1, None).is_ok());
        assert!(validate_allocate_size(65536, None).is_ok());
        assert!(validate_allocate_size(1, Some(AllocateUserRangeType::Self_)).is_ok());
        assert!(validate_allocate_size(65536, Some(AllocateUserRangeType::Self_)).is_err());
        assert!(validate_allocate_size(42, None).is_err());
    }

    #[test]
    fn test_validate_allocate_target() {
        assert!(validate_allocate_target(None, None).is_ok());
        assert!(validate_allocate_target(Some(0), Some(AllocateUserRangeType::Self_)).is_ok());
        assert!(validate_allocate_target(Some(5), Some(AllocateUserRangeType::Self_)).is_err());
        assert!(validate_allocate_target(Some(5), None).is_ok());
    }

    #[test]
    fn test_validate_delegate_ranges() {
        assert!(validate_delegate_ranges(None).is_ok());
        assert!(validate_delegate_ranges(Some(0)).is_ok());
        assert!(validate_delegate_ranges(Some(16)).is_ok());
        assert!(validate_delegate_ranges(Some(-1)).is_err());
        assert!(validate_delegate_ranges(Some(17)).is_err());
    }
}
