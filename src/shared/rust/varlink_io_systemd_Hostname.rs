// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Hostname.c
//
// Rust shadow of the io.systemd.Hostname varlink interface.
//
// Types for the Describe method that returns comprehensive system
// hostname, OS, kernel, hardware, and firmware information.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Hostname";

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSource {
    Static,
    Transient,
    Default,
}

impl HostnameSource {
    pub fn from_varlink(s: &str) -> Result<HostnameSource, HostnameError> {
        match s {
            "static" => Ok(HostnameSource::Static),
            "transient" => Ok(HostnameSource::Transient),
            "default" => Ok(HostnameSource::Default),
            _ => Err(HostnameError::InvalidHostnameSource(s.to_owned())),
        }
    }

    pub fn to_varlink(self) -> &'static str {
        match self {
            HostnameSource::Static => "static",
            HostnameSource::Transient => "transient",
            HostnameSource::Default => "default",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct DescribeOutput {
    pub hostname: String,
    pub static_hostname: Option<String>,
    pub pretty_hostname: Option<String>,
    pub default_hostname: Option<String>,
    pub hostname_source: String,
    pub icon_name: Option<String>,
    pub chassis: Option<String>,
    pub chassis_asset_tag: Option<String>,
    pub deployment: Option<String>,
    pub location: Option<String>,
    pub kernel_name: String,
    pub kernel_release: String,
    pub kernel_version: String,
    pub operating_system_pretty_name: Option<String>,
    pub operating_system_fancy_name: Option<String>,
    pub operating_system_cpe_name: Option<String>,
    pub operating_system_home_url: Option<String>,
    pub operating_system_support_end: Option<i64>,
    pub operating_system_release_data: Vec<String>,
    pub operating_system_image_id: Option<String>,
    pub operating_system_image_version: Option<String>,
    pub machine_information_data: Vec<String>,
    pub hardware_vendor: Option<String>,
    pub hardware_model: Option<String>,
    pub hardware_serial: Option<String>,
    pub hardware_sku: Option<String>,
    pub hardware_version: Option<String>,
    pub firmware_version: Option<String>,
    pub firmware_vendor: Option<String>,
    pub firmware_date: Option<i64>,
    pub machine_id: String,
    pub boot_id: String,
    pub product_uuid: Option<String>,
    pub vsock_cid: Option<i64>,
}

impl DescribeOutput {
    pub fn minimal(
        hostname: String,
        kernel_name: String,
        kernel_release: String,
        kernel_version: String,
        machine_id: String,
        boot_id: String,
    ) -> Self {
        DescribeOutput {
            hostname_source: "transient".to_owned(),
            static_hostname: None,
            pretty_hostname: None,
            default_hostname: None,
            icon_name: None,
            chassis: None,
            chassis_asset_tag: None,
            deployment: None,
            location: None,
            operating_system_pretty_name: None,
            operating_system_fancy_name: None,
            operating_system_cpe_name: None,
            operating_system_home_url: None,
            operating_system_support_end: None,
            operating_system_release_data: Vec::new(),
            operating_system_image_id: None,
            operating_system_image_version: None,
            machine_information_data: Vec::new(),
            hardware_vendor: None,
            hardware_model: None,
            hardware_serial: None,
            hardware_sku: None,
            hardware_version: None,
            firmware_version: None,
            firmware_vendor: None,
            firmware_date: None,
            product_uuid: None,
            vsock_cid: None,
            hostname,
            kernel_name,
            kernel_release,
            kernel_version,
            machine_id,
            boot_id,
        }
    }

    pub fn has_pretty_hostname(&self) -> bool {
        self.pretty_hostname.is_some()
    }

    pub fn has_hardware_info(&self) -> bool {
        self.hardware_vendor.is_some() || self.hardware_model.is_some()
    }

    pub fn has_firmware_info(&self) -> bool {
        self.firmware_version.is_some() || self.firmware_vendor.is_some()
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum HostnameError {
    InvalidHostnameSource(String),
    EmptyHostname,
}

impl std::fmt::Display for HostnameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostnameError::InvalidHostnameSource(s) => write!(f, "InvalidHostnameSource: {}", s),
            HostnameError::EmptyHostname => write!(f, "EmptyHostname"),
        }
    }
}

impl std::error::Error for HostnameError {}

// ── Methods ───────────────────────────────────────────────────────────────

pub fn validate_describe_output(output: &DescribeOutput) -> Result<(), HostnameError> {
    if output.hostname.is_empty() {
        return Err(HostnameError::EmptyHostname);
    }
    if output.kernel_name.is_empty() {
        return Err(HostnameError::EmptyHostname);
    }
    if output.machine_id.is_empty() {
        return Err(HostnameError::EmptyHostname);
    }
    Ok(())
}

pub fn describe(output: &DescribeOutput) -> Result<&DescribeOutput, HostnameError> {
    validate_describe_output(output)?;
    Ok(output)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_output() -> DescribeOutput {
        DescribeOutput::minimal(
            "myhost".to_owned(),
            "Linux".to_owned(),
            "6.1.0".to_owned(),
            "#1 SMP".to_owned(),
            "abc123".to_owned(),
            "def456".to_owned(),
        )
    }

    #[test]
    fn describe_output_minimal_fields() {
        let out = sample_output();
        assert_eq!(out.hostname, "myhost");
        assert_eq!(out.kernel_name, "Linux");
        assert_eq!(out.kernel_release, "6.1.0");
        assert_eq!(out.kernel_version, "#1 SMP");
        assert_eq!(out.machine_id, "abc123");
        assert_eq!(out.boot_id, "def456");
    }

    #[test]
    fn describe_output_optional_fields_none() {
        let out = sample_output();
        assert!(out.static_hostname.is_none());
        assert!(out.pretty_hostname.is_none());
        assert!(out.chassis.is_none());
        assert!(out.hardware_vendor.is_none());
        assert!(out.firmware_version.is_none());
    }

    #[test]
    fn describe_output_collections_empty() {
        let out = sample_output();
        assert!(out.operating_system_release_data.is_empty());
        assert!(out.machine_information_data.is_empty());
    }

    #[test]
    fn describe_output_has_pretty_hostname_false() {
        let out = sample_output();
        assert!(!out.has_pretty_hostname());
    }

    #[test]
    fn describe_output_has_pretty_hostname_true() {
        let mut out = sample_output();
        out.pretty_hostname = Some("My Host".to_owned());
        assert!(out.has_pretty_hostname());
    }

    #[test]
    fn describe_output_has_hardware_info_false() {
        assert!(!sample_output().has_hardware_info());
    }

    #[test]
    fn describe_output_has_hardware_info_true() {
        let mut out = sample_output();
        out.hardware_vendor = Some("ACME".to_owned());
        assert!(out.has_hardware_info());
    }

    #[test]
    fn describe_output_has_firmware_info_false() {
        assert!(!sample_output().has_firmware_info());
    }

    #[test]
    fn describe_output_has_firmware_info_true() {
        let mut out = sample_output();
        out.firmware_version = Some("1.0".to_owned());
        assert!(out.has_firmware_info());
    }

    #[test]
    fn validate_accepts_valid_output() {
        assert!(validate_describe_output(&sample_output()).is_ok());
    }

    #[test]
    fn validate_rejects_empty_hostname() {
        let mut out = sample_output();
        out.hostname = String::new();
        assert_eq!(
            validate_describe_output(&out).unwrap_err(),
            HostnameError::EmptyHostname
        );
    }

    #[test]
    fn validate_rejects_empty_kernel_name() {
        let mut out = sample_output();
        out.kernel_name = String::new();
        assert_eq!(
            validate_describe_output(&out).unwrap_err(),
            HostnameError::EmptyHostname
        );
    }

    #[test]
    fn validate_rejects_empty_machine_id() {
        let mut out = sample_output();
        out.machine_id = String::new();
        assert_eq!(
            validate_describe_output(&out).unwrap_err(),
            HostnameError::EmptyHostname
        );
    }

    #[test]
    fn describe_succeeds_with_valid() {
        let out = sample_output();
        assert!(describe(&out).is_ok());
    }

    #[test]
    fn hostname_source_roundtrip() {
        assert_eq!(
            HostnameSource::from_varlink("static").unwrap(),
            HostnameSource::Static
        );
        assert_eq!(
            HostnameSource::from_varlink("transient").unwrap(),
            HostnameSource::Transient
        );
        assert_eq!(
            HostnameSource::from_varlink("default").unwrap(),
            HostnameSource::Default
        );
        assert_eq!(HostnameSource::Static.to_varlink(), "static");
        assert_eq!(HostnameSource::Transient.to_varlink(), "transient");
        assert_eq!(HostnameSource::Default.to_varlink(), "default");
    }

    #[test]
    fn hostname_source_invalid() {
        assert!(HostnameSource::from_varlink("other").is_err());
    }

    #[test]
    fn error_display() {
        assert_eq!(format!("{}", HostnameError::EmptyHostname), "EmptyHostname");
        assert_eq!(
            format!("{}", HostnameError::InvalidHostnameSource("x".to_owned())),
            "InvalidHostnameSource: x"
        );
    }

    #[test]
    fn interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Hostname");
    }
}
