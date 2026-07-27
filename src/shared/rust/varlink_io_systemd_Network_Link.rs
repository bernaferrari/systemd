// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Network.Link.c
//
// Varlink interface definition for io.systemd.Network.Link.
//
// Operations on individual network links managed by systemd-networkd:
// bring up, bring down, renew DHCP leases, reconfigure, and describe.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.Network.Link";

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_DESCRIBE: &str = "Describe";
pub const METHOD_UP: &str = "Up";
pub const METHOD_DOWN: &str = "Down";
pub const METHOD_RENEW: &str = "Renew";
pub const METHOD_FORCE_RENEW: &str = "ForceRenew";
pub const METHOD_RECONFIGURE: &str = "Reconfigure";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_DESCRIBE,
        METHOD_UP,
        METHOD_DOWN,
        METHOD_RENEW,
        METHOD_FORCE_RENEW,
        METHOD_RECONFIGURE,
    ]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLinkMethod {
    Describe,
    Up,
    Down,
    Renew,
    ForceRenew,
    Reconfigure,
}

impl NetworkLinkMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Describe => METHOD_DESCRIBE,
            Self::Up => METHOD_UP,
            Self::Down => METHOD_DOWN,
            Self::Renew => METHOD_RENEW,
            Self::ForceRenew => METHOD_FORCE_RENEW,
            Self::Reconfigure => METHOD_RECONFIGURE,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<NetworkLinkMethod, String> {
    match name {
        METHOD_DESCRIBE => Ok(NetworkLinkMethod::Describe),
        METHOD_UP => Ok(NetworkLinkMethod::Up),
        METHOD_DOWN => Ok(NetworkLinkMethod::Down),
        METHOD_RENEW => Ok(NetworkLinkMethod::Renew),
        METHOD_FORCE_RENEW => Ok(NetworkLinkMethod::ForceRenew),
        METHOD_RECONFIGURE => Ok(NetworkLinkMethod::Reconfigure),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method input structs ──────────────────────────────────────────────────

/// Common interface identification inputs shared by all methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkIdentification {
    /// Index of the interface.
    pub interface_index: Option<i64>,
    /// Name of the interface.
    pub interface_name: Option<String>,
}

impl LinkIdentification {
    /// Create empty identification (both fields unset).
    pub fn new() -> Self {
        Self {
            interface_index: None,
            interface_name: None,
        }
    }

    /// Identify by interface index.
    pub fn from_index(index: i64) -> Self {
        Self {
            interface_index: Some(index),
            interface_name: None,
        }
    }

    /// Identify by interface name.
    pub fn from_name(name: &str) -> Self {
        Self {
            interface_index: None,
            interface_name: Some(name.to_string()),
        }
    }

    /// Identify by both index and name.
    pub fn from_both(index: i64, name: &str) -> Self {
        Self {
            interface_index: Some(index),
            interface_name: Some(name.to_string()),
        }
    }

    /// Validate that at least one identifier is provided.
    pub fn validate(&self) -> Result<(), String> {
        if self.interface_index.is_none() && self.interface_name.is_none() {
            return Err("either InterfaceIndex or InterfaceName must be specified".to_string());
        }
        Ok(())
    }
}

impl Default for LinkIdentification {
    fn default() -> Self {
        Self::new()
    }
}

/// Input parameters for the Up method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

/// Input parameters for the Down method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

/// Input parameters for the Renew method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

/// Input parameters for the ForceRenew method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceRenewInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

/// Input parameters for the Reconfigure method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconfigureInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

/// Input parameters for the Describe method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribeInput {
    /// Interface identification.
    pub link: LinkIdentification,
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLinkError {
    /// The specified interface is not managed by systemd-networkd.
    InterfaceUnmanaged,
}

impl NetworkLinkError {
    /// Parse from the varlink error string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "InterfaceUnmanaged" => Ok(Self::InterfaceUnmanaged),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InterfaceUnmanaged => "InterfaceUnmanaged",
        }
    }
}

/// All error names as string slices.
pub fn error_names() -> &'static [&'static str] {
    &["InterfaceUnmanaged"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Network.Link");
    }

    #[test]
    fn test_method_names_count() {
        assert_eq!(method_names().len(), 6);
    }

    #[test]
    fn test_has_method() {
        assert!(has_method("Describe"));
        assert!(has_method("Up"));
        assert!(has_method("Down"));
        assert!(has_method("Renew"));
        assert!(has_method("ForceRenew"));
        assert!(has_method("Reconfigure"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_all() {
        assert_eq!(parse_method("Describe"), Ok(NetworkLinkMethod::Describe));
        assert_eq!(parse_method("Up"), Ok(NetworkLinkMethod::Up));
        assert_eq!(parse_method("Down"), Ok(NetworkLinkMethod::Down));
        assert_eq!(parse_method("Renew"), Ok(NetworkLinkMethod::Renew));
        assert_eq!(
            parse_method("ForceRenew"),
            Ok(NetworkLinkMethod::ForceRenew)
        );
        assert_eq!(
            parse_method("Reconfigure"),
            Ok(NetworkLinkMethod::Reconfigure)
        );
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_link_identification_from_index() {
        let id = LinkIdentification::from_index(2);
        assert_eq!(id.interface_index, Some(2));
        assert_eq!(id.interface_name, None);
    }

    #[test]
    fn test_link_identification_from_name() {
        let id = LinkIdentification::from_name("eth0");
        assert_eq!(id.interface_index, None);
        assert_eq!(id.interface_name.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_link_identification_from_both() {
        let id = LinkIdentification::from_both(2, "eth0");
        assert_eq!(id.interface_index, Some(2));
        assert_eq!(id.interface_name.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_link_identification_validate() {
        assert!(LinkIdentification::from_index(1).validate().is_ok());
        assert!(LinkIdentification::from_name("eth0").validate().is_ok());
        assert!(LinkIdentification::new().validate().is_err());
    }

    #[test]
    fn test_error_roundtrip() {
        assert_eq!(
            NetworkLinkError::from_str("InterfaceUnmanaged"),
            Ok(NetworkLinkError::InterfaceUnmanaged),
        );
        assert!(NetworkLinkError::from_str("bogus").is_err());
        assert_eq!(
            NetworkLinkError::InterfaceUnmanaged.as_str(),
            "InterfaceUnmanaged"
        );
    }

    #[test]
    fn test_error_names() {
        assert_eq!(error_names().len(), 1);
        assert!(error_names().contains(&"InterfaceUnmanaged"));
    }
}
