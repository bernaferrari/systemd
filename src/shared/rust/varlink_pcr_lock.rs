// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.PCRLock.c
//
// Varlink interface definition for io.systemd.PCRLock
// PCR (Platform Configuration Register) lock management interface

pub const INTERFACE_NAME: &str = "io.systemd.PCRLock";

pub const METHOD_READ_EVENT_LOG: &str = "io.systemd.PCRLock.ReadEventLog";
pub const METHOD_MAKE_POLICY: &str = "io.systemd.PCRLock.MakePolicy";
pub const METHOD_REMOVE_POLICY: &str = "io.systemd.PCRLock.RemovePolicy";

pub const ERROR_NO_CHANGE: &str = "io.systemd.PCRLock.NoChange";

pub const PARAM_FORCE: &str = "force";
pub const PARAM_RECORD: &str = "record";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcrLockError {
    UnknownMethod(String),
}

impl std::fmt::Display for PcrLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcrLockError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for PcrLockError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [],
  "methods": {
    "ReadEventLog": {
      "parameters": {},
      "return": {
        "record": { "type": "object" }
      },
      "flags": ["more"]
    },
    "MakePolicy": {
      "parameters": {
        "force": { "type": "bool", "nullable": true }
      },
      "return": {}
    },
    "RemovePolicy": {
      "parameters": {},
      "return": {}
    }
  },
  "errors": {
    "NoChange": {}
  },
  "interface": "io.systemd.PCRLock"
}"#
}

#[derive(Debug, Clone, Default)]
pub struct MakePolicyParams {
    pub force: Option<bool>,
}

impl MakePolicyParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn force(mut self, value: bool) -> Self {
        self.force = Some(value);
        self
    }

    pub fn validate(&self) -> Result<(), PcrLockError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ReadEventLogOutput {
    pub record: String,
}

impl ReadEventLogOutput {
    pub fn new(record: impl Into<String>) -> Self {
        Self {
            record: record.into(),
        }
    }

    pub fn validate(&self) -> Result<(), PcrLockError> {
        if self.record.is_empty() {
            return Err(PcrLockError::UnknownMethod("empty record".to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct RemovePolicyParams;

impl RemovePolicyParams {
    pub fn new() -> Self {
        Self
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, PcrLockError> {
    match method {
        METHOD_READ_EVENT_LOG | METHOD_MAKE_POLICY | METHOD_REMOVE_POLICY => Ok(method),
        _ => Err(PcrLockError::UnknownMethod(method.to_string())),
    }
}

pub fn is_known_method(method: &str) -> bool {
    matches!(
        method,
        METHOD_READ_EVENT_LOG | METHOD_MAKE_POLICY | METHOD_REMOVE_POLICY
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.PCRLock");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(METHOD_READ_EVENT_LOG, "io.systemd.PCRLock.ReadEventLog");
        assert_eq!(METHOD_MAKE_POLICY, "io.systemd.PCRLock.MakePolicy");
        assert_eq!(METHOD_REMOVE_POLICY, "io.systemd.PCRLock.RemovePolicy");
    }

    #[test]
    fn test_error_name() {
        assert_eq!(ERROR_NO_CHANGE, "io.systemd.PCRLock.NoChange");
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_FORCE, "force");
        assert_eq!(PARAM_RECORD, "record");
    }

    #[test]
    fn test_interface_definition_valid_json() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.PCRLock"));
        assert!(json.contains("ReadEventLog"));
        assert!(json.contains("MakePolicy"));
        assert!(json.contains("RemovePolicy"));
        assert!(json.contains("NoChange"));
        assert!(json.contains("record"));
        assert!(json.contains("force"));
    }

    #[test]
    fn test_make_policy_params_default() {
        let params = MakePolicyParams::new();
        assert!(params.force.is_none());
    }

    #[test]
    fn test_make_policy_params_builder() {
        let params = MakePolicyParams::new().force(true);
        assert_eq!(params.force, Some(true));
    }

    #[test]
    fn test_make_policy_params_clone() {
        let params = MakePolicyParams::new().force(true);
        let cloned = params.clone();
        assert_eq!(params.force, cloned.force);
    }

    #[test]
    fn test_make_policy_params_validate() {
        assert!(MakePolicyParams::new().validate().is_ok());
        assert!(MakePolicyParams::new().force(true).validate().is_ok());
    }

    #[test]
    fn test_read_event_log_output() {
        let output = ReadEventLogOutput::new(r#"{"pcr":7,"event":"..."}"#);
        assert_eq!(output.record, r#"{"pcr":7,"event":"..."}"#);
    }

    #[test]
    fn test_read_event_log_output_clone() {
        let output = ReadEventLogOutput::new("test");
        let cloned = output.clone();
        assert_eq!(output.record, cloned.record);
    }

    #[test]
    fn test_read_event_log_output_validate_ok() {
        let output = ReadEventLogOutput::new(r#"{"key":"val"}"#);
        assert!(output.validate().is_ok());
    }

    #[test]
    fn test_read_event_log_output_validate_empty() {
        let output = ReadEventLogOutput::new("");
        assert!(output.validate().is_err());
    }

    #[test]
    fn test_validate_method_name_known() {
        assert!(validate_method_name(METHOD_READ_EVENT_LOG).is_ok());
        assert!(validate_method_name(METHOD_MAKE_POLICY).is_ok());
        assert!(validate_method_name(METHOD_REMOVE_POLICY).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.PCRLock.Bogus").is_err());
    }

    #[test]
    fn test_is_known_method() {
        assert!(is_known_method(METHOD_READ_EVENT_LOG));
        assert!(is_known_method(METHOD_MAKE_POLICY));
        assert!(is_known_method(METHOD_REMOVE_POLICY));
        assert!(!is_known_method("io.systemd.PCRLock.Unknown"));
    }
}
