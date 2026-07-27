// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Network.Link.c
//
// Varlink interface definition for io.systemd.Network.Link
// Network link control operations via systemd-networkd.

pub const INTERFACE_NAME: &str = "io.systemd.Network.Link";

pub const METHOD_DESCRIBE: &str = "io.systemd.Network.Link.Describe";
pub const METHOD_UP: &str = "io.systemd.Network.Link.Up";
pub const METHOD_DOWN: &str = "io.systemd.Network.Link.Down";
pub const METHOD_RENEW: &str = "io.systemd.Network.Link.Renew";
pub const METHOD_FORCE_RENEW: &str = "io.systemd.Network.Link.ForceRenew";
pub const METHOD_RECONFIGURE: &str = "io.systemd.Network.Link.Reconfigure";

pub const ERROR_INTERFACE_UNMANAGED: &str = "io.systemd.Network.Link.InterfaceUnmanaged";

pub const PARAM_INTERFACE_INDEX: &str = "InterfaceIndex";
pub const PARAM_INTERFACE_NAME: &str = "InterfaceName";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkLinkError {
    MissingIdentification,
    ConflictingIdentification,
    UnknownMethod(String),
}

impl std::fmt::Display for NetworkLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkLinkError::MissingIdentification => {
                write!(f, "either InterfaceIndex or InterfaceName is required")
            }
            NetworkLinkError::ConflictingIdentification => {
                write!(
                    f,
                    "InterfaceIndex and InterfaceName must reference the same link"
                )
            }
            NetworkLinkError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for NetworkLinkError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "methods": {
    "Describe": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      },
      "return": {
        "Interface": { "type": "Interface" }
      }
    },
    "Up": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      }
    },
    "Down": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      }
    },
    "Renew": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      }
    },
    "ForceRenew": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      }
    },
    "Reconfigure": {
      "parameters": {
        "InterfaceIndex": { "type": "int", "nullable": true },
        "InterfaceName": { "type": "string", "nullable": true }
      }
    }
  },
  "errors": {
    "InterfaceUnmanaged": { "description": "The specified interface is not managed by systemd-networkd." }
  },
  "interface": "io.systemd.Network.Link",
  "description": "Network link control operations via systemd-networkd."
}"#
}

#[derive(Debug, Clone, Default)]
pub struct LinkIdentification {
    pub interface_index: Option<i64>,
    pub interface_name: Option<String>,
}

impl LinkIdentification {
    pub fn by_index(index: i64) -> Self {
        Self {
            interface_index: Some(index),
            interface_name: None,
        }
    }

    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            interface_index: None,
            interface_name: Some(name.into()),
        }
    }

    pub fn both(index: i64, name: impl Into<String>) -> Self {
        Self {
            interface_index: Some(index),
            interface_name: Some(name.into()),
        }
    }

    pub fn validate(&self) -> Result<(), NetworkLinkError> {
        match (self.interface_index, &self.interface_name) {
            (None, None) => Err(NetworkLinkError::MissingIdentification),
            _ => Ok(()),
        }
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, NetworkLinkError> {
    match method {
        METHOD_DESCRIBE | METHOD_UP | METHOD_DOWN | METHOD_RENEW | METHOD_FORCE_RENEW
        | METHOD_RECONFIGURE => Ok(method),
        _ => Err(NetworkLinkError::UnknownMethod(method.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Network.Link");
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_UP.contains("Up"));
        assert!(METHOD_DOWN.contains("Down"));
        assert!(METHOD_RENEW.contains("Renew"));
        assert!(METHOD_FORCE_RENEW.contains("ForceRenew"));
        assert!(METHOD_RECONFIGURE.contains("Reconfigure"));
        assert!(METHOD_DESCRIBE.contains("Describe"));
    }

    #[test]
    fn test_error_name() {
        assert_eq!(
            ERROR_INTERFACE_UNMANAGED,
            "io.systemd.Network.Link.InterfaceUnmanaged"
        );
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_INTERFACE_INDEX, "InterfaceIndex");
        assert_eq!(PARAM_INTERFACE_NAME, "InterfaceName");
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.Network.Link"));
        assert!(json.contains("InterfaceUnmanaged"));
        assert!(json.contains("Describe"));
        assert!(json.contains("Up"));
        assert!(json.contains("Down"));
    }

    #[test]
    fn test_link_identification_by_index() {
        let id = LinkIdentification::by_index(2);
        assert_eq!(id.interface_index, Some(2));
        assert!(id.interface_name.is_none());
    }

    #[test]
    fn test_link_identification_by_name() {
        let id = LinkIdentification::by_name("eth0");
        assert!(id.interface_index.is_none());
        assert_eq!(id.interface_name.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_link_identification_both() {
        let id = LinkIdentification::both(2, "eth0");
        assert_eq!(id.interface_index, Some(2));
        assert_eq!(id.interface_name.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_link_identification_validate_ok() {
        assert!(LinkIdentification::by_index(1).validate().is_ok());
        assert!(LinkIdentification::by_name("wlan0").validate().is_ok());
        assert!(LinkIdentification::both(3, "ens3").validate().is_ok());
    }

    #[test]
    fn test_link_identification_validate_missing() {
        let id = LinkIdentification::default();
        assert_eq!(id.validate(), Err(NetworkLinkError::MissingIdentification));
    }

    #[test]
    fn test_validate_method_name_known() {
        assert!(validate_method_name(METHOD_UP).is_ok());
        assert!(validate_method_name(METHOD_DOWN).is_ok());
        assert!(validate_method_name(METHOD_DESCRIBE).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.Network.Link.Bogus").is_err());
    }

    #[test]
    fn test_link_identification_clone() {
        let id = LinkIdentification::by_index(5);
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }
}
