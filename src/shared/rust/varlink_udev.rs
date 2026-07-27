// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Udev.c
//
// Varlink interface definition for io.systemd.Udev
// An interface for controlling systemd-udevd.

pub const INTERFACE_NAME: &str = "io.systemd.Udev";

pub const METHOD_SET_TRACE: &str = "io.systemd.Udev.SetTrace";
pub const METHOD_SET_CHILDREN_MAX: &str = "io.systemd.Udev.SetChildrenMax";
pub const METHOD_SET_ENVIRONMENT: &str = "io.systemd.Udev.SetEnvironment";
pub const METHOD_REVERT: &str = "io.systemd.Udev.Revert";
pub const METHOD_START_EXEC_QUEUE: &str = "io.systemd.Udev.StartExecQueue";
pub const METHOD_STOP_EXEC_QUEUE: &str = "io.systemd.Udev.StopExecQueue";
pub const METHOD_EXIT: &str = "io.systemd.Udev.Exit";

pub const PARAM_ENABLE: &str = "enable";
pub const PARAM_NUMBER: &str = "number";
pub const PARAM_ASSIGNMENTS: &str = "assignments";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdevError {
    InvalidChildrenMax(i64),
    EmptyAssignments,
    InvalidAssignment(String),
    UnknownMethod(String),
}

impl std::fmt::Display for UdevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdevError::InvalidChildrenMax(v) => {
                write!(f, "invalid children max: {v} (must be >= 0)")
            }
            UdevError::EmptyAssignments => write!(f, "assignments must not be empty"),
            UdevError::InvalidAssignment(a) => write!(f, "invalid assignment: {a}"),
            UdevError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for UdevError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "methods": {
    "SetTrace": {
      "parameters": {
        "enable": { "type": "bool" }
      }
    },
    "SetChildrenMax": {
      "parameters": {
        "number": { "type": "int" }
      }
    },
    "SetEnvironment": {
      "parameters": {
        "assignments": { "type": "[]string" }
      }
    },
    "Revert": {},
    "StartExecQueue": {},
    "StopExecQueue": {},
    "Exit": {}
  },
  "interface": "io.systemd.Udev",
  "description": "An interface for controlling systemd-udevd."
}"#
}

#[derive(Debug, Clone, Default)]
pub struct SetTraceParams {
    pub enable: bool,
}

impl SetTraceParams {
    pub fn new(enable: bool) -> Self {
        Self { enable }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SetChildrenMaxParams {
    pub number: i64,
}

impl SetChildrenMaxParams {
    pub fn new(number: i64) -> Self {
        Self { number }
    }

    pub fn validate(&self) -> Result<(), UdevError> {
        if self.number < 0 {
            return Err(UdevError::InvalidChildrenMax(self.number));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SetEnvironmentParams {
    pub assignments: Vec<String>,
}

impl SetEnvironmentParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, assignment: impl Into<String>) -> Self {
        self.assignments.push(assignment.into());
        self
    }

    pub fn validate(&self) -> Result<(), UdevError> {
        if self.assignments.is_empty() {
            return Err(UdevError::EmptyAssignments);
        }
        for a in &self.assignments {
            if !a.contains('=') {
                return Err(UdevError::InvalidAssignment(a.clone()));
            }
        }
        Ok(())
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, UdevError> {
    match method {
        METHOD_SET_TRACE
        | METHOD_SET_CHILDREN_MAX
        | METHOD_SET_ENVIRONMENT
        | METHOD_REVERT
        | METHOD_START_EXEC_QUEUE
        | METHOD_STOP_EXEC_QUEUE
        | METHOD_EXIT => Ok(method),
        _ => Err(UdevError::UnknownMethod(method.to_string())),
    }
}

pub fn all_method_names() -> [&'static str; 7] {
    [
        METHOD_SET_TRACE,
        METHOD_SET_CHILDREN_MAX,
        METHOD_SET_ENVIRONMENT,
        METHOD_REVERT,
        METHOD_START_EXEC_QUEUE,
        METHOD_STOP_EXEC_QUEUE,
        METHOD_EXIT,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Udev");
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_SET_TRACE.contains("SetTrace"));
        assert!(METHOD_SET_CHILDREN_MAX.contains("SetChildrenMax"));
        assert!(METHOD_SET_ENVIRONMENT.contains("SetEnvironment"));
        assert!(METHOD_REVERT.contains("Revert"));
        assert!(METHOD_START_EXEC_QUEUE.contains("StartExecQueue"));
        assert!(METHOD_STOP_EXEC_QUEUE.contains("StopExecQueue"));
        assert!(METHOD_EXIT.contains("Exit"));
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_ENABLE, "enable");
        assert_eq!(PARAM_NUMBER, "number");
        assert_eq!(PARAM_ASSIGNMENTS, "assignments");
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.Udev"));
        assert!(json.contains("SetTrace"));
        assert!(json.contains("SetChildrenMax"));
        assert!(json.contains("SetEnvironment"));
        assert!(json.contains("Revert"));
        assert!(json.contains("Exit"));
    }

    #[test]
    fn test_set_trace_params() {
        let params = SetTraceParams::new(true);
        assert!(params.enable);
        let params = SetTraceParams::new(false);
        assert!(!params.enable);
    }

    #[test]
    fn test_set_children_max_params_valid() {
        let params = SetChildrenMaxParams::new(16);
        assert!(params.validate().is_ok());
        let params = SetChildrenMaxParams::new(0);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_set_children_max_params_invalid() {
        let params = SetChildrenMaxParams::new(-1);
        assert_eq!(params.validate(), Err(UdevError::InvalidChildrenMax(-1)));
    }

    #[test]
    fn test_set_environment_params_valid() {
        let params = SetEnvironmentParams::new()
            .add("KEY=VALUE")
            .add("OTHER=123");
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_set_environment_params_empty() {
        let params = SetEnvironmentParams::new();
        assert_eq!(params.validate(), Err(UdevError::EmptyAssignments));
    }

    #[test]
    fn test_set_environment_params_no_equals() {
        let params = SetEnvironmentParams::new().add("INVALID");
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_method_name_all() {
        for m in all_method_names() {
            assert!(validate_method_name(m).is_ok());
        }
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.Udev.Bogus").is_err());
    }

    #[test]
    fn test_all_method_names_count() {
        assert_eq!(all_method_names().len(), 7);
    }
}
