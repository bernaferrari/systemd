// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.InstanceMetadata.c
//
// Varlink interface definition for io.systemd.InstanceMetadata.
//
// APIs for acquiring cloud instance metadata service (IMDS) information,
// including well-known data fields and vendor info queries.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.InstanceMetadata";

pub const METHOD_GET: &str = "Get";
pub const METHOD_GET_VENDOR_INFO: &str = "GetVendorInfo";

pub const METHODS: &[&str] = &[METHOD_GET, METHOD_GET_VENDOR_INFO];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Well-known cloud instance metadata data fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WellKnown {
    Base,
    Hostname,
    Region,
    Zone,
    Ipv4Public,
    Ipv6Public,
    SshKey,
    Userdata,
    UserdataBase,
    UserdataBase64,
}

impl WellKnown {
    /// All variants of WellKnown
    pub const ALL: &[WellKnown] = &[
        WellKnown::Base,
        WellKnown::Hostname,
        WellKnown::Region,
        WellKnown::Zone,
        WellKnown::Ipv4Public,
        WellKnown::Ipv6Public,
        WellKnown::SshKey,
        WellKnown::Userdata,
        WellKnown::UserdataBase,
        WellKnown::UserdataBase64,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            WellKnown::Base => "base",
            WellKnown::Hostname => "hostname",
            WellKnown::Region => "region",
            WellKnown::Zone => "zone",
            WellKnown::Ipv4Public => "ipv4_public",
            WellKnown::Ipv6Public => "ipv6_public",
            WellKnown::SshKey => "ssh_key",
            WellKnown::Userdata => "userdata",
            WellKnown::UserdataBase => "userdata_base",
            WellKnown::UserdataBase64 => "userdata_base64",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "base" => Some(WellKnown::Base),
            "hostname" => Some(WellKnown::Hostname),
            "region" => Some(WellKnown::Region),
            "zone" => Some(WellKnown::Zone),
            "ipv4_public" => Some(WellKnown::Ipv4Public),
            "ipv6_public" => Some(WellKnown::Ipv6Public),
            "ssh_key" => Some(WellKnown::SshKey),
            "userdata" => Some(WellKnown::Userdata),
            "userdata_base" => Some(WellKnown::UserdataBase),
            "userdata_base64" => Some(WellKnown::UserdataBase64),
            _ => None,
        }
    }

    /// Returns true if this well-known key relates to network addressing
    pub fn is_network(&self) -> bool {
        matches!(self, WellKnown::Ipv4Public | WellKnown::Ipv6Public)
    }

    /// Returns true if this well-known key relates to user data
    pub fn is_userdata(&self) -> bool {
        matches!(
            self,
            WellKnown::Userdata | WellKnown::UserdataBase | WellKnown::UserdataBase64
        )
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Input parameters for the Get method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInput {
    /// The key to retrieve
    pub key: Option<String>,
    /// Start with a well-known key
    pub well_known: Option<WellKnown>,
    /// The network interface to use
    pub interface: Option<i64>,
    /// Refresh cached data if older (CLOCK_BOOTTIME, us)
    pub refresh_usec: Option<i64>,
    /// Whether to accept cached data
    pub cache: Option<bool>,
    /// The firewall mark value to use
    pub firewall_mark: Option<i64>,
    /// Controls whether to wait for connectivity
    pub wait: Option<bool>,
}

impl GetInput {
    /// Validate that either a key or well_known is specified
    pub fn validate(&self) -> Result<(), InstanceMetadataError> {
        if self.key.is_none() && self.well_known.is_none() {
            return Err(InstanceMetadataError::KeyNotFound);
        }
        if let Some(iface) = self.interface {
            if iface < 0 {
                return Err(InstanceMetadataError::NotAvailable);
            }
        }
        Ok(())
    }
}

/// Output from the Get method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOutput {
    /// The data in Base64 encoding
    pub data: String,
    /// The interface the data was found on
    pub interface: Option<i64>,
}

/// Output from the GetVendorInfo method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorInfo {
    /// The detected cloud vendor
    pub vendor: Option<String>,
    /// The URL to acquire the token from
    pub token_url: Option<String>,
    /// The HTTP header to configure the refresh timeout
    pub refresh_header_name: Option<String>,
    /// The base URL to acquire the data from
    pub data_url: Option<String>,
    /// A suffix to append to the data URL
    pub data_url_suffix: Option<String>,
    /// The HTTP header to pass the token in
    pub token_header_name: Option<String>,
    /// Additional HTTP headers
    pub extra_header: Vec<String>,
}

impl VendorInfo {
    /// Check if essential vendor info fields are present
    pub fn has_vendor(&self) -> bool {
        self.vendor.is_some()
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceMetadataError {
    /// The requested key is not found on the IMDS server
    KeyNotFound,
    /// Well-known key is not set
    WellKnownKeyUnset,
    /// IMDS is disabled or otherwise not available
    NotAvailable,
    /// IMDS is not supported
    NotSupported,
    /// Communication with IMDS failed
    CommunicationFailure,
    /// Timeout reached
    Timeout,
}

impl InstanceMetadataError {
    pub fn error_id(&self) -> &'static str {
        match self {
            InstanceMetadataError::KeyNotFound => "io.systemd.InstanceMetadata.KeyNotFound",
            InstanceMetadataError::WellKnownKeyUnset => {
                "io.systemd.InstanceMetadata.WellKnownKeyUnset"
            }
            InstanceMetadataError::NotAvailable => "io.systemd.InstanceMetadata.NotAvailable",
            InstanceMetadataError::NotSupported => "io.systemd.InstanceMetadata.NotSupported",
            InstanceMetadataError::CommunicationFailure => {
                "io.systemd.InstanceMetadata.CommunicationFailure"
            }
            InstanceMetadataError::Timeout => "io.systemd.InstanceMetadata.Timeout",
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.InstanceMetadata.KeyNotFound",
    "io.systemd.InstanceMetadata.WellKnownKeyUnset",
    "io.systemd.InstanceMetadata.NotAvailable",
    "io.systemd.InstanceMetadata.NotSupported",
    "io.systemd.InstanceMetadata.CommunicationFailure",
    "io.systemd.InstanceMetadata.Timeout",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Resolve a key string to a WellKnown variant if applicable
pub fn resolve_well_known_key(key: &str) -> Option<WellKnown> {
    WellKnown::from_str(key)
}

/// Validate that at least one of key or well_known is provided
pub fn validate_get_params(
    key: Option<&str>,
    well_known: Option<WellKnown>,
) -> Result<(), InstanceMetadataError> {
    if key.is_none() && well_known.is_none() {
        return Err(InstanceMetadataError::KeyNotFound);
    }
    if let Some(k) = key {
        if k.is_empty() {
            return Err(InstanceMetadataError::KeyNotFound);
        }
    }
    Ok(())
}

/// Check if a refresh interval is reasonable (must be non-negative)
pub fn is_valid_refresh_usec(usec: i64) -> bool {
    usec >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.InstanceMetadata");
    }

    #[test]
    fn test_well_known_roundtrip() {
        for wk in WellKnown::ALL {
            assert_eq!(WellKnown::from_str(wk.as_str()), Some(*wk));
        }
        assert_eq!(WellKnown::ALL.len(), 10);
    }

    #[test]
    fn test_well_known_from_str_invalid() {
        assert_eq!(WellKnown::from_str("unknown"), None);
        assert_eq!(WellKnown::from_str(""), None);
    }

    #[test]
    fn test_well_known_categories() {
        assert!(WellKnown::Ipv4Public.is_network());
        assert!(WellKnown::Ipv6Public.is_network());
        assert!(!WellKnown::Hostname.is_network());

        assert!(WellKnown::Userdata.is_userdata());
        assert!(WellKnown::UserdataBase.is_userdata());
        assert!(WellKnown::UserdataBase64.is_userdata());
        assert!(!WellKnown::Hostname.is_userdata());
    }

    #[test]
    fn test_get_input_validate_success() {
        let input = GetInput {
            key: Some("test".into()),
            well_known: None,
            interface: None,
            refresh_usec: None,
            cache: None,
            firewall_mark: None,
            wait: None,
        };
        assert!(input.validate().is_ok());

        let input2 = GetInput {
            key: None,
            well_known: Some(WellKnown::Hostname),
            interface: None,
            refresh_usec: None,
            cache: None,
            firewall_mark: None,
            wait: None,
        };
        assert!(input2.validate().is_ok());
    }

    #[test]
    fn test_get_input_validate_no_key() {
        let input = GetInput {
            key: None,
            well_known: None,
            interface: None,
            refresh_usec: None,
            cache: None,
            firewall_mark: None,
            wait: None,
        };
        assert_eq!(input.validate(), Err(InstanceMetadataError::KeyNotFound));
    }

    #[test]
    fn test_get_input_validate_negative_interface() {
        let input = GetInput {
            key: Some("test".into()),
            well_known: None,
            interface: Some(-1),
            refresh_usec: None,
            cache: None,
            firewall_mark: None,
            wait: None,
        };
        assert_eq!(input.validate(), Err(InstanceMetadataError::NotAvailable));
    }

    #[test]
    fn test_vendor_info_has_vendor() {
        let info = VendorInfo {
            vendor: Some("aws".into()),
            token_url: None,
            refresh_header_name: None,
            data_url: None,
            data_url_suffix: None,
            token_header_name: None,
            extra_header: vec![],
        };
        assert!(info.has_vendor());

        let info2 = VendorInfo {
            vendor: None,
            token_url: None,
            refresh_header_name: None,
            data_url: None,
            data_url_suffix: None,
            token_header_name: None,
            extra_header: vec![],
        };
        assert!(!info2.has_vendor());
    }

    #[test]
    fn test_error_ids() {
        assert!(
            InstanceMetadataError::KeyNotFound
                .error_id()
                .contains("KeyNotFound")
        );
        assert!(
            InstanceMetadataError::Timeout
                .error_id()
                .contains("Timeout")
        );
        assert!(
            InstanceMetadataError::CommunicationFailure
                .error_id()
                .contains("CommunicationFailure")
        );
        assert_eq!(ERROR_IDS.len(), 6);
    }

    #[test]
    fn test_validate_get_params() {
        assert!(validate_get_params(Some("key"), None).is_ok());
        assert!(validate_get_params(None, Some(WellKnown::Base)).is_ok());
        assert!(validate_get_params(None, None).is_err());
        assert!(validate_get_params(Some(""), None).is_err());
    }

    #[test]
    fn test_resolve_well_known_key() {
        assert_eq!(
            resolve_well_known_key("hostname"),
            Some(WellKnown::Hostname)
        );
        assert_eq!(resolve_well_known_key("ssh_key"), Some(WellKnown::SshKey));
        assert_eq!(resolve_well_known_key("unknown"), None);
    }

    #[test]
    fn test_is_valid_refresh_usec() {
        assert!(is_valid_refresh_usec(0));
        assert!(is_valid_refresh_usec(1000));
        assert!(!is_valid_refresh_usec(-1));
    }

    #[test]
    fn test_methods_constants() {
        assert_eq!(METHODS.len(), 2);
        assert!(METHODS.contains(&METHOD_GET));
        assert!(METHODS.contains(&METHOD_GET_VENDOR_INFO));
    }

    #[test]
    fn test_get_output() {
        let output = GetOutput {
            data: "aGVsbG8=".into(),
            interface: Some(1),
        };
        assert_eq!(output.data, "aGVsbG8=");
        assert_eq!(output.interface, Some(1));
    }
}
