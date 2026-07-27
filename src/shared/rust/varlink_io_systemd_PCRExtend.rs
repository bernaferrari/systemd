// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.PCRExtend.c
//
// Varlink interface definition for io.systemd.PCRExtend.
//
// TPM PCR Extension APIs. Provides the Extend method for measuring
// text or binary data into a PCR, and the EventType enum for
// categorizing what kind of data is being measured.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.PCRExtend";

/// Method name for extending a PCR.
pub const METHOD_EXTEND: &str = "Extend";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Event type to include in the userspace event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Phase,
    Filesystem,
    VolumeKey,
    MachineId,
    ProductId,
    Keyslot,
    NvpcrInit,
    NvpcrSeparator,
    DmVerity,
    ImdsUserdata,
}

impl EventType {
    /// All known values.
    pub const VALUES: &[Self] = &[
        Self::Phase,
        Self::Filesystem,
        Self::VolumeKey,
        Self::MachineId,
        Self::ProductId,
        Self::Keyslot,
        Self::NvpcrInit,
        Self::NvpcrSeparator,
        Self::DmVerity,
        Self::ImdsUserdata,
    ];

    /// Parse from the varlink wire string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "phase" => Ok(Self::Phase),
            "filesystem" => Ok(Self::Filesystem),
            "volume_key" => Ok(Self::VolumeKey),
            "machine_id" => Ok(Self::MachineId),
            "product_id" => Ok(Self::ProductId),
            "keyslot" => Ok(Self::Keyslot),
            "nvpcr_init" => Ok(Self::NvpcrInit),
            "nvpcr_separator" => Ok(Self::NvpcrSeparator),
            "dm_verity" => Ok(Self::DmVerity),
            "imds_userdata" => Ok(Self::ImdsUserdata),
            _ => Err(format!("unknown EventType: {s}")),
        }
    }

    /// Return the varlink wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Filesystem => "filesystem",
            Self::VolumeKey => "volume_key",
            Self::MachineId => "machine_id",
            Self::ProductId => "product_id",
            Self::Keyslot => "keyslot",
            Self::NvpcrInit => "nvpcr_init",
            Self::NvpcrSeparator => "nvpcr_separator",
            Self::DmVerity => "dm_verity",
            Self::ImdsUserdata => "imds_userdata",
        }
    }
}

// ── Method identifiers ────────────────────────────────────────────────────

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_EXTEND]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrExtendMethod {
    Extend,
}

impl PcrExtendMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Extend => METHOD_EXTEND,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<PcrExtendMethod, String> {
    match name {
        METHOD_EXTEND => Ok(PcrExtendMethod::Extend),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input parameters for the Extend method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendInput {
    /// PCR number to extend, in range 0..=23.
    pub pcr: Option<i64>,
    /// NvPCR to extend, identified by a string.
    pub nvpcr: Option<String>,
    /// Text string to measure.
    pub text: Option<String>,
    /// Binary data to measure, encoded in Base64.
    pub data: Option<String>,
    /// Event type for the event log.
    pub event_type: Option<EventType>,
}

impl ExtendInput {
    /// Create a new ExtendInput with all fields unset.
    pub fn new() -> Self {
        Self {
            pcr: None,
            nvpcr: None,
            text: None,
            data: None,
            event_type: None,
        }
    }

    /// Create input targeting a standard PCR number.
    pub fn from_pcr(pcr: i64) -> Self {
        Self {
            pcr: Some(pcr),
            nvpcr: None,
            text: None,
            data: None,
            event_type: None,
        }
    }

    /// Create input targeting an NvPCR.
    pub fn from_nvpcr(nvpcr: &str) -> Self {
        Self {
            pcr: None,
            nvpcr: Some(nvpcr.to_string()),
            text: None,
            data: None,
            event_type: None,
        }
    }

    /// Set text to measure.
    pub fn with_text(mut self, text: &str) -> Self {
        self.text = Some(text.to_string());
        self.data = None;
        self
    }

    /// Set binary data to measure (Base64 encoded).
    pub fn with_data(mut self, data: &str) -> Self {
        self.data = Some(data.to_string());
        self.text = None;
        self
    }

    /// Set the event type.
    pub fn with_event_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Validate the input parameters.
    pub fn validate(&self) -> Result<(), String> {
        // Either pcr or nvpcr must be specified, not both, not neither.
        match (self.pcr, &self.nvpcr) {
            (None, None) => return Err("either pcr or nvpcr must be specified".to_string()),
            (Some(_), Some(_)) => return Err("pcr and nvpcr are mutually exclusive".to_string()),
            _ => {}
        }

        // Validate PCR range.
        if let Some(pcr) = self.pcr {
            if !(0..=23).contains(&pcr) {
                return Err(format!("pcr must be in range 0..=23, got {pcr}"));
            }
        }

        // Either text or data must be specified, not both.
        match (&self.text, &self.data) {
            (None, None) => return Err("either text or data must be specified".to_string()),
            (Some(_), Some(_)) => return Err("text and data are mutually exclusive".to_string()),
            _ => {}
        }

        Ok(())
    }
}

impl Default for ExtendInput {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrExtendError {
    /// The specified NvPCR does not exist.
    NoSuchNvPCR,
}

impl PcrExtendError {
    /// Parse from the varlink error string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "NoSuchNvPCR" => Ok(Self::NoSuchNvPCR),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoSuchNvPCR => "NoSuchNvPCR",
        }
    }
}

/// All error names.
pub fn error_names() -> &'static [&'static str] {
    &["NoSuchNvPCR"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.PCRExtend");
    }

    #[test]
    fn test_event_type_roundtrip() {
        for v in EventType::VALUES {
            assert_eq!(EventType::from_str(v.as_str()), Ok(*v));
        }
    }

    #[test]
    fn test_event_type_unknown() {
        assert!(EventType::from_str("bogus").is_err());
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 1);
        assert!(has_method("Extend"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method() {
        assert_eq!(parse_method("Extend"), Ok(PcrExtendMethod::Extend));
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_extend_input_from_pcr() {
        let input = ExtendInput::from_pcr(7).with_text("hello");
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_extend_input_from_nvpcr() {
        let input = ExtendInput::from_nvpcr("my-nvpcr").with_data("AQID");
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_extend_input_no_target() {
        let input = ExtendInput::new().with_text("hello");
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_extend_input_both_targets() {
        let mut input = ExtendInput::from_pcr(7);
        input.nvpcr = Some("test".to_string());
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_extend_input_pcr_out_of_range() {
        let input = ExtendInput::from_pcr(24).with_text("hello");
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_extend_input_no_payload() {
        let input = ExtendInput::from_pcr(7);
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_extend_input_both_payloads() {
        let mut input = ExtendInput::from_pcr(7).with_text("hello");
        input.data = Some("AQID".to_string());
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_error_roundtrip() {
        assert_eq!(
            PcrExtendError::from_str("NoSuchNvPCR"),
            Ok(PcrExtendError::NoSuchNvPCR),
        );
        assert!(PcrExtendError::from_str("bogus").is_err());
        assert_eq!(PcrExtendError::NoSuchNvPCR.as_str(), "NoSuchNvPCR");
    }
}
