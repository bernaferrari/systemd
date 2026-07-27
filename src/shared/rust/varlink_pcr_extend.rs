// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.PCRExtend.c
//
// Varlink interface definition for io.systemd.PCRExtend
// TPM PCR Extension APIs.

pub const INTERFACE_NAME: &str = "io.systemd.PCRExtend";

pub const METHOD_EXTEND: &str = "io.systemd.PCRExtend.Extend";

pub const ERROR_NO_SUCH_NVPCR: &str = "io.systemd.PCRExtend.NoSuchNvPCR";

pub const PARAM_PCR: &str = "pcr";
pub const PARAM_NVPCR: &str = "nvpcr";
pub const PARAM_TEXT: &str = "text";
pub const PARAM_DATA: &str = "data";
pub const PARAM_EVENT_TYPE: &str = "eventType";

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
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Phase => "phase",
            EventType::Filesystem => "filesystem",
            EventType::VolumeKey => "volume_key",
            EventType::MachineId => "machine_id",
            EventType::ProductId => "product_id",
            EventType::Keyslot => "keyslot",
            EventType::NvpcrInit => "nvpcr_init",
            EventType::NvpcrSeparator => "nvpcr_separator",
            EventType::DmVerity => "dm_verity",
            EventType::ImdsUserdata => "imds_userdata",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "phase" => Some(EventType::Phase),
            "filesystem" => Some(EventType::Filesystem),
            "volume_key" => Some(EventType::VolumeKey),
            "machine_id" => Some(EventType::MachineId),
            "product_id" => Some(EventType::ProductId),
            "keyslot" => Some(EventType::Keyslot),
            "nvpcr_init" => Some(EventType::NvpcrInit),
            "nvpcr_separator" => Some(EventType::NvpcrSeparator),
            "dm_verity" => Some(EventType::DmVerity),
            "imds_userdata" => Some(EventType::ImdsUserdata),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcrExtendError {
    NeitherPcrNorNvpcr,
    BothPcrAndNvpcr,
    BothTextAndData,
    NeitherTextNorData,
    PcrOutOfRange(i64),
    UnknownMethod(String),
}

impl std::fmt::Display for PcrExtendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcrExtendError::NeitherPcrNorNvpcr => {
                write!(f, "either pcr or nvpcr must be specified")
            }
            PcrExtendError::BothPcrAndNvpcr => {
                write!(f, "pcr and nvpcr are mutually exclusive")
            }
            PcrExtendError::BothTextAndData => {
                write!(f, "text and data are mutually exclusive")
            }
            PcrExtendError::NeitherTextNorData => {
                write!(f, "either text or data must be specified")
            }
            PcrExtendError::PcrOutOfRange(v) => {
                write!(f, "PCR index {v} out of range 0..23")
            }
            PcrExtendError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for PcrExtendError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "EventType",
      "type": "enum",
      "values": ["phase", "filesystem", "volume_key", "machine_id", "product_id", "keyslot", "nvpcr_init", "nvpcr_separator", "dm_verity", "imds_userdata"]
    }
  ],
  "methods": {
    "Extend": {
      "parameters": {
        "pcr": { "type": "int", "nullable": true },
        "nvpcr": { "type": "string", "nullable": true },
        "text": { "type": "string", "nullable": true },
        "data": { "type": "string", "nullable": true },
        "eventType": { "type": "EventType", "nullable": true }
      }
    }
  },
  "errors": {
    "NoSuchNvPCR": { "description": "No such NvPCR found." }
  },
  "interface": "io.systemd.PCRExtend",
  "description": "TPM PCR Extension APIs."
}"#
}

#[derive(Debug, Clone, Default)]
pub struct ExtendParams {
    pub pcr: Option<i64>,
    pub nvpcr: Option<String>,
    pub text: Option<String>,
    pub data: Option<String>,
    pub event_type: Option<EventType>,
}

impl ExtendParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pcr(mut self, index: i64) -> Self {
        self.pcr = Some(index);
        self
    }

    pub fn nvpcr(mut self, name: impl Into<String>) -> Self {
        self.nvpcr = Some(name.into());
        self
    }

    pub fn text(mut self, value: impl Into<String>) -> Self {
        self.text = Some(value.into());
        self
    }

    pub fn data(mut self, value: impl Into<String>) -> Self {
        self.data = Some(value.into());
        self
    }

    pub fn event_type(mut self, et: EventType) -> Self {
        self.event_type = Some(et);
        self
    }

    pub fn validate(&self) -> Result<(), PcrExtendError> {
        match (self.pcr, &self.nvpcr) {
            (None, None) => return Err(PcrExtendError::NeitherPcrNorNvpcr),
            (Some(_), Some(_)) => return Err(PcrExtendError::BothPcrAndNvpcr),
            _ => {}
        }
        match (&self.text, &self.data) {
            (None, None) => return Err(PcrExtendError::NeitherTextNorData),
            (Some(_), Some(_)) => return Err(PcrExtendError::BothTextAndData),
            _ => {}
        }
        if let Some(pcr) = self.pcr {
            if !(0..=23).contains(&pcr) {
                return Err(PcrExtendError::PcrOutOfRange(pcr));
            }
        }
        Ok(())
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, PcrExtendError> {
    if method == METHOD_EXTEND {
        Ok(method)
    } else {
        Err(PcrExtendError::UnknownMethod(method.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.PCRExtend");
    }

    #[test]
    fn test_error_name() {
        assert_eq!(ERROR_NO_SUCH_NVPCR, "io.systemd.PCRExtend.NoSuchNvPCR");
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_PCR, "pcr");
        assert_eq!(PARAM_NVPCR, "nvpcr");
        assert_eq!(PARAM_TEXT, "text");
        assert_eq!(PARAM_DATA, "data");
        assert_eq!(PARAM_EVENT_TYPE, "eventType");
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.PCRExtend"));
        assert!(json.contains("Extend"));
        assert!(json.contains("EventType"));
        assert!(json.contains("NoSuchNvPCR"));
    }

    #[test]
    fn test_event_type_roundtrip() {
        let all = [
            EventType::Phase,
            EventType::Filesystem,
            EventType::VolumeKey,
            EventType::MachineId,
            EventType::ProductId,
            EventType::Keyslot,
            EventType::NvpcrInit,
            EventType::NvpcrSeparator,
            EventType::DmVerity,
            EventType::ImdsUserdata,
        ];
        for et in &all {
            assert_eq!(EventType::from_str(et.as_str()), Some(*et));
        }
    }

    #[test]
    fn test_event_type_unknown() {
        assert_eq!(EventType::from_str("unknown"), None);
    }

    #[test]
    fn test_extend_params_valid_pcr_text() {
        let params = ExtendParams::new().pcr(7).text("hello");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_extend_params_valid_nvpcr_data() {
        let params = ExtendParams::new().nvpcr("test").data("AQID");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_extend_params_neither_pcr_nor_nvpcr() {
        let params = ExtendParams::new().text("hello");
        assert_eq!(params.validate(), Err(PcrExtendError::NeitherPcrNorNvpcr));
    }

    #[test]
    fn test_extend_params_both_pcr_and_nvpcr() {
        let params = ExtendParams::new().pcr(7).nvpcr("test").text("hello");
        assert_eq!(params.validate(), Err(PcrExtendError::BothPcrAndNvpcr));
    }

    #[test]
    fn test_extend_params_neither_text_nor_data() {
        let params = ExtendParams::new().pcr(7);
        assert_eq!(params.validate(), Err(PcrExtendError::NeitherTextNorData));
    }

    #[test]
    fn test_extend_params_both_text_and_data() {
        let params = ExtendParams::new().pcr(7).text("hello").data("AQID");
        assert_eq!(params.validate(), Err(PcrExtendError::BothTextAndData));
    }

    #[test]
    fn test_extend_params_pcr_out_of_range() {
        let params = ExtendParams::new().pcr(99).text("hello");
        assert_eq!(params.validate(), Err(PcrExtendError::PcrOutOfRange(99)));
    }

    #[test]
    fn test_extend_params_pcr_boundary() {
        let params_ok = ExtendParams::new().pcr(0).text("hello");
        assert!(params_ok.validate().is_ok());

        let params_ok2 = ExtendParams::new().pcr(23).text("hello");
        assert!(params_ok2.validate().is_ok());
    }

    #[test]
    fn test_validate_method_name_ok() {
        assert!(validate_method_name(METHOD_EXTEND).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.PCRExtend.Bogus").is_err());
    }
}
