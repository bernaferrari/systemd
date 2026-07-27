// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Hostname.c
//
// Varlink interface definition for io.systemd.Hostname.
//
// Hostname information APIs providing system identification data
// including hardware, firmware, OS, and kernel details.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Hostname";

pub const METHOD_DESCRIBE: &str = "io.systemd.Hostname.Describe";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Source of the system hostname, matching the C enum hostname_source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSource {
    /// Hostname comes from /etc/hostname (or systemd-hostname.service).
    Static,
    /// Hostname was set at runtime via sethostname().
    Transient,
    /// Hostname provided by the hardware/DHCP/default.
    Default,
}

impl HostnameSource {
    /// Parse a hostname source from its string representation.
    pub fn from_str(s: &str) -> Result<HostnameSource, i32> {
        match s {
            "static" => Ok(HostnameSource::Static),
            "transient" => Ok(HostnameSource::Transient),
            "default" => Ok(HostnameSource::Default),
            _ => Err(-22),
        }
    }

    /// Convert to the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            HostnameSource::Static => "static",
            HostnameSource::Transient => "transient",
            HostnameSource::Default => "default",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Complete hostname description returned by the Describe method.
#[derive(Debug, Clone, Default)]
pub struct HostnameDescription {
    /// The current hostname.
    pub hostname: String,
    /// The static hostname from /etc/hostname.
    pub static_hostname: Option<String>,
    /// The pretty hostname.
    pub pretty_hostname: Option<String>,
    /// The default hostname fallback.
    pub default_hostname: Option<String>,
    /// Where the hostname originates from.
    pub hostname_source: HostnameSource,
    /// The icon name (freedesktop.org spec).
    pub icon_name: Option<String>,
    /// The chassis type.
    pub chassis: Option<String>,
    /// An unique identifier of the system chassis.
    pub chassis_asset_tag: Option<String>,
    /// Deployment environment.
    pub deployment: Option<String>,
    /// Physical location.
    pub location: Option<String>,
    /// Kernel name (e.g. "Linux").
    pub kernel_name: String,
    /// Kernel release (e.g. "6.1.0").
    pub kernel_release: String,
    /// Kernel version string.
    pub kernel_version: String,
    /// Pretty OS name.
    pub os_pretty_name: Option<String>,
    /// Fancy OS name (may contain ANSI/Unicode).
    pub os_fancy_name: Option<String>,
    /// OS CPE name.
    pub os_cpe_name: Option<String>,
    /// OS home URL.
    pub os_home_url: Option<String>,
    /// OS support end timestamp in µs.
    pub os_support_end: Option<i64>,
    /// OS release data.
    pub os_release_data: Option<Vec<String>>,
    /// OS image ID.
    pub os_image_id: Option<String>,
    /// OS image version.
    pub os_image_version: Option<String>,
    /// Machine information data.
    pub machine_info_data: Option<Vec<String>>,
    /// Hardware vendor.
    pub hardware_vendor: Option<String>,
    /// Hardware model.
    pub hardware_model: Option<String>,
    /// Hardware serial number.
    pub hardware_serial: Option<String>,
    /// Hardware SKU.
    pub hardware_sku: Option<String>,
    /// Hardware version.
    pub hardware_version: Option<String>,
    /// Firmware version.
    pub firmware_version: Option<String>,
    /// Firmware vendor.
    pub firmware_vendor: Option<String>,
    /// Firmware date (as epoch µs).
    pub firmware_date: Option<i64>,
    /// Machine ID (128-bit hex).
    pub machine_id: String,
    /// Boot ID (128-bit hex).
    pub boot_id: String,
    /// Product UUID.
    pub product_uuid: Option<String>,
    /// VSOCK context ID.
    pub vsock_cid: Option<i64>,
}

impl HostnameDescription {
    /// Validate that all required fields are present.
    pub fn validate(&self) -> Result<(), i32> {
        if self.hostname.is_empty() {
            return Err(-22);
        }
        if self.kernel_name.is_empty() {
            return Err(-22);
        }
        if self.machine_id.is_empty() {
            return Err(-22);
        }
        if self.boot_id.is_empty() {
            return Err(-22);
        }
        Ok(())
    }

    /// Check if the hostname source is static (from /etc/hostname).
    pub fn is_static_hostname(&self) -> bool {
        self.hostname_source == HostnameSource::Static
    }

    /// Check if the hostname source is transient (set at runtime).
    pub fn is_transient_hostname(&self) -> bool {
        self.hostname_source == HostnameSource::Transient
    }

    /// Check if this description has hardware information.
    pub fn has_hardware_info(&self) -> bool {
        self.hardware_vendor.is_some() || self.hardware_model.is_some()
    }

    /// Check if this description has firmware information.
    pub fn has_firmware_info(&self) -> bool {
        self.firmware_vendor.is_some() || self.firmware_version.is_some()
    }

    /// Check if this description has OS support end date.
    pub fn has_os_support_end(&self) -> bool {
        self.os_support_end.is_some()
    }
}

// ── Interface definition ──────────────────────────────────────────────────

/// Returns the Varlink interface definition as a JSON string.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "methods": {
    "Describe": {
      "return": {
        "Hostname": { "type": "string" },
        "StaticHostname": { "type": "string", "nullable": true },
        "PrettyHostname": { "type": "string", "nullable": true },
        "DefaultHostname": { "type": "string", "nullable": true },
        "HostnameSource": { "type": "string" },
        "IconName": { "type": "string", "nullable": true },
        "Chassis": { "type": "string", "nullable": true },
        "ChassisAssetTag": { "type": "string", "nullable": true },
        "Deployment": { "type": "string", "nullable": true },
        "Location": { "type": "string", "nullable": true },
        "KernelName": { "type": "string" },
        "KernelRelease": { "type": "string" },
        "KernelVersion": { "type": "string" },
        "OperatingSystemPrettyName": { "type": "string", "nullable": true },
        "OperatingSystemFancyName": { "type": "string", "nullable": true },
        "OperatingSystemCPEName": { "type": "string", "nullable": true },
        "OperatingSystemHomeURL": { "type": "string", "nullable": true },
        "OperatingSystemSupportEnd": { "type": "int", "nullable": true },
        "OperatingSystemReleaseData": { "type": "[]string", "nullable": true },
        "OperatingSystemImageID": { "type": "string", "nullable": true },
        "OperatingSystemImageVersion": { "type": "string", "nullable": true },
        "MachineInformationData": { "type": "[]string", "nullable": true },
        "HardwareVendor": { "type": "string", "nullable": true },
        "HardwareModel": { "type": "string", "nullable": true },
        "HardwareSerial": { "type": "string", "nullable": true },
        "HardwareSKU": { "type": "string", "nullable": true },
        "HardwareVersion": { "type": "string", "nullable": true },
        "FirmwareVersion": { "type": "string", "nullable": true },
        "FirmwareVendor": { "type": "string", "nullable": true },
        "FirmwareDate": { "type": "int", "nullable": true },
        "MachineID": { "type": "string" },
        "BootID": { "type": "string" },
        "ProductUUID": { "type": "string", "nullable": true },
        "VSockCID": { "type": "int", "nullable": true }
      }
    }
  },
  "interface": "io.systemd.Hostname",
  "description": "Hostname information APIs."
}"#
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a short method name belongs to this interface.
pub fn is_method(name: &str) -> bool {
    matches!(name, "Describe")
}

/// Look up the fully qualified method name from a short name.
pub fn qualified_method(short: &str) -> Result<&'static str, i32> {
    match short {
        "Describe" => Ok(METHOD_DESCRIBE),
        _ => Err(-22),
    }
}

/// Parse a VSOCK context ID from a string.
pub fn parse_vsock_cid(s: &str) -> Result<i64, i32> {
    s.parse::<i64>().map_err(|_| -22)
}

/// Validate a 128-bit hex ID (machine ID / boot ID format).
pub fn validate_hex_id(id: &str) -> Result<(), i32> {
    if id.len() != 32 && id.len() != 33 {
        // 32 hex chars or 33 with embedded newline (some formats)
        // Actually, systemd uses 32-char hex strings (no dashes)
        // but also accepts 36-char UUID format
        if id.len() != 36 {
            return Err(-22);
        }
    }
    let cleaned = id.replace('-', "");
    if cleaned.len() != 32 {
        return Err(-22);
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(-22);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Hostname");
    }

    #[test]
    fn test_method_constant() {
        assert_eq!(METHOD_DESCRIBE, "io.systemd.Hostname.Describe");
    }

    #[test]
    fn test_hostname_source_from_str() {
        assert_eq!(
            HostnameSource::from_str("static"),
            Ok(HostnameSource::Static)
        );
        assert_eq!(
            HostnameSource::from_str("transient"),
            Ok(HostnameSource::Transient)
        );
        assert_eq!(
            HostnameSource::from_str("default"),
            Ok(HostnameSource::Default)
        );
        assert!(HostnameSource::from_str("invalid").is_err());
    }

    #[test]
    fn test_hostname_source_as_str() {
        assert_eq!(HostnameSource::Static.as_str(), "static");
        assert_eq!(HostnameSource::Transient.as_str(), "transient");
        assert_eq!(HostnameSource::Default.as_str(), "default");
    }

    #[test]
    fn test_hostname_source_roundtrip() {
        assert_eq!(
            HostnameSource::from_str(HostnameSource::Static.as_str()),
            Ok(HostnameSource::Static)
        );
        assert_eq!(
            HostnameSource::from_str(HostnameSource::Transient.as_str()),
            Ok(HostnameSource::Transient)
        );
        assert_eq!(
            HostnameSource::from_str(HostnameSource::Default.as_str()),
            Ok(HostnameSource::Default)
        );
    }

    #[test]
    fn test_hostname_description_validate_success() {
        let desc = HostnameDescription {
            hostname: "myhost".into(),
            kernel_name: "Linux".into(),
            machine_id: "abc123def456abc123def456abc12345".into(),
            boot_id: "def456abc123def456abc123def456ab0".into(),
            ..Default::default()
        };
        assert!(desc.validate().is_ok());
    }

    #[test]
    fn test_hostname_description_validate_empty_hostname() {
        let desc = HostnameDescription {
            hostname: String::new(),
            ..Default::default()
        };
        assert!(desc.validate().is_err());
    }

    #[test]
    fn test_hostname_description_validate_empty_machine_id() {
        let desc = HostnameDescription {
            hostname: "host".into(),
            machine_id: String::new(),
            ..Default::default()
        };
        assert!(desc.validate().is_err());
    }

    #[test]
    fn test_hostname_description_is_static() {
        let desc = HostnameDescription {
            hostname_source: HostnameSource::Static,
            ..Default::default()
        };
        assert!(desc.is_static_hostname());
        assert!(!desc.is_transient_hostname());
    }

    #[test]
    fn test_hostname_description_has_hardware_info() {
        let mut desc = HostnameDescription::default();
        assert!(!desc.has_hardware_info());
        desc.hardware_vendor = Some("Vendor".into());
        assert!(desc.has_hardware_info());
    }

    #[test]
    fn test_hostname_description_has_firmware_info() {
        let mut desc = HostnameDescription::default();
        assert!(!desc.has_firmware_info());
        desc.firmware_version = Some("1.0".into());
        assert!(desc.has_firmware_info());
    }

    #[test]
    fn test_hostname_description_has_os_support_end() {
        let mut desc = HostnameDescription::default();
        assert!(!desc.has_os_support_end());
        desc.os_support_end = Some(1735689600000000);
        assert!(desc.has_os_support_end());
    }

    #[test]
    fn test_interface_definition_contents() {
        let def = get_interface_definition();
        assert!(def.contains("io.systemd.Hostname"));
        assert!(def.contains("Describe"));
        assert!(def.contains("Hostname"));
        assert!(def.contains("MachineID"));
        assert!(def.contains("BootID"));
        assert!(def.contains("HardwareVendor"));
        assert!(def.contains("VSockCID"));
    }

    #[test]
    fn test_is_method() {
        assert!(is_method("Describe"));
        assert!(!is_method("describe"));
        assert!(!is_method("Ping"));
    }

    #[test]
    fn test_qualified_method() {
        assert_eq!(qualified_method("Describe"), Ok(METHOD_DESCRIBE));
        assert!(qualified_method("Ping").is_err());
    }

    #[test]
    fn test_parse_vsock_cid() {
        assert_eq!(parse_vsock_cid("3"), Ok(3));
        assert_eq!(parse_vsock_cid("-1"), Ok(-1));
        assert!(parse_vsock_cid("abc").is_err());
        assert!(parse_vsock_cid("").is_err());
    }

    #[test]
    fn test_validate_hex_id() {
        // Valid 32-char hex
        assert!(validate_hex_id("abc123def456abc123def456abc12345").is_ok());
        // Valid 36-char UUID format
        assert!(validate_hex_id("abc123de-f456-abc1-23de-f456abc12345").is_ok());
        // Invalid: too short
        assert!(validate_hex_id("abc").is_err());
        // Invalid: non-hex chars
        assert!(validate_hex_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
        // Invalid: empty
        assert!(validate_hex_id("").is_err());
    }
}
