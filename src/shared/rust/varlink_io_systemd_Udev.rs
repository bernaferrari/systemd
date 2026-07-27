// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Udev.c
//
// Varlink interface definition for io.systemd.Udev
// An interface for controlling systemd-udevd.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Udev service
pub const INTERFACE_NAME: &str = "io.systemd.Udev";

/// Method: Enable/disable trace logging
pub const METHOD_SET_TRACE: &str = "io.systemd.Udev.SetTrace";

/// Method: Set maximum number of child processes
pub const METHOD_SET_CHILDREN_MAX: &str = "io.systemd.Udev.SetChildrenMax";

/// Method: Set global udev properties
pub const METHOD_SET_ENVIRONMENT: &str = "io.systemd.Udev.SetEnvironment";

/// Method: Revert previously set configurations
pub const METHOD_REVERT: &str = "io.systemd.Udev.Revert";

/// Method: Start processing queued events
pub const METHOD_START_EXEC_QUEUE: &str = "io.systemd.Udev.StartExecQueue";

/// Method: Stop processing queued events
pub const METHOD_STOP_EXEC_QUEUE: &str = "io.systemd.Udev.StopExecQueue";

/// Method: Terminate systemd-udevd
pub const METHOD_EXIT: &str = "io.systemd.Udev.Exit";

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for SetTrace method
#[derive(Debug, Clone)]
pub struct SetTraceParams {
    /// Enable or disable trace logging
    pub enable: bool,
}

impl SetTraceParams {
    /// Create new SetTraceParams
    pub fn new(enable: bool) -> Self {
        Self { enable }
    }
}

/// Parameters for SetChildrenMax method
#[derive(Debug, Clone)]
pub struct SetChildrenMaxParams {
    /// Maximum number of child processes (0 = auto-detect)
    pub number: i64,
}

impl SetChildrenMaxParams {
    /// Create new SetChildrenMaxParams
    pub fn new(number: i64) -> Self {
        Self { number }
    }

    /// Check if the value is auto-detect (0)
    pub fn is_auto(&self) -> bool {
        self.number == 0
    }
}

/// Parameters for SetEnvironment method
#[derive(Debug, Clone)]
pub struct SetEnvironmentParams {
    /// Global udev property assignments in KEY=VALUE format
    pub assignments: Vec<String>,
}

impl SetEnvironmentParams {
    /// Create new SetEnvironmentParams
    pub fn new(assignments: Vec<String>) -> Self {
        Self { assignments }
    }

    /// Parse a KEY=VALUE string into (key, value)
    pub fn parse_assignment(s: &str) -> Result<(&str, &str), i32> {
        let pos = s.find('=').ok_or(-22)?;
        Ok((&s[..pos], &s[pos + 1..]))
    }

    /// Validate all assignments
    pub fn validate(&self) -> Result<(), i32> {
        for a in &self.assignments {
            Self::parse_assignment(a)?;
        }
        Ok(())
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Get all known method names for this interface
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_SET_TRACE,
        METHOD_SET_CHILDREN_MAX,
        METHOD_SET_ENVIRONMENT,
        METHOD_REVERT,
        METHOD_START_EXEC_QUEUE,
        METHOD_STOP_EXEC_QUEUE,
        METHOD_EXIT,
    ]
}

/// Check if a method name belongs to this interface
pub fn is_known_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Validate the children max value (must be non-negative)
pub fn validate_children_max(number: i64) -> Result<(), i32> {
    if number < 0 {
        return Err(-22); // -EINVAL
    }
    Ok(())
}

/// Validate a KEY=VALUE assignment string
pub fn validate_assignment(s: &str) -> Result<(&str, &str), i32> {
    SetEnvironmentParams::parse_assignment(s)
}

/// Count the number of methods in this interface
pub fn method_count() -> usize {
    7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Udev");
    }

    #[test]
    fn test_method_names_const() {
        assert!(METHOD_SET_TRACE.contains("SetTrace"));
        assert!(METHOD_SET_CHILDREN_MAX.contains("SetChildrenMax"));
        assert!(METHOD_SET_ENVIRONMENT.contains("SetEnvironment"));
        assert!(METHOD_REVERT.contains("Revert"));
        assert!(METHOD_START_EXEC_QUEUE.contains("StartExecQueue"));
        assert!(METHOD_STOP_EXEC_QUEUE.contains("StopExecQueue"));
        assert!(METHOD_EXIT.contains("Exit"));
    }

    #[test]
    fn test_method_names_list() {
        let names = method_names();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&METHOD_SET_TRACE));
        assert!(names.contains(&METHOD_EXIT));
    }

    #[test]
    fn test_is_known_method() {
        assert!(is_known_method("io.systemd.Udev.SetTrace"));
        assert!(is_known_method("io.systemd.Udev.Exit"));
        assert!(!is_known_method("io.systemd.Udev.Unknown"));
        assert!(!is_known_method("io.systemd.Resolve.ResolveHostname"));
    }

    #[test]
    fn test_set_trace_params() {
        let params = SetTraceParams::new(true);
        assert!(params.enable);
        let params = SetTraceParams::new(false);
        assert!(!params.enable);
    }

    #[test]
    fn test_set_children_max_params() {
        let params = SetChildrenMaxParams::new(10);
        assert_eq!(params.number, 10);
        assert!(!params.is_auto());

        let params = SetChildrenMaxParams::new(0);
        assert!(params.is_auto());
    }

    #[test]
    fn test_validate_children_max() {
        assert!(validate_children_max(0).is_ok());
        assert!(validate_children_max(10).is_ok());
        assert!(validate_children_max(-1).is_err());
    }

    #[test]
    fn test_set_environment_params_parse() {
        let (key, val) = SetEnvironmentParams::parse_assignment("KEY=VALUE").unwrap();
        assert_eq!(key, "KEY");
        assert_eq!(val, "VALUE");

        let (key, val) = SetEnvironmentParams::parse_assignment("PATH=/usr/bin").unwrap();
        assert_eq!(key, "PATH");
        assert_eq!(val, "/usr/bin");

        assert!(SetEnvironmentParams::parse_assignment("NOEQUALSSIGN").is_err());
    }

    #[test]
    fn test_set_environment_params_validate() {
        let params =
            SetEnvironmentParams::new(vec!["KEY1=value1".to_string(), "KEY2=value2".to_string()]);
        assert!(params.validate().is_ok());

        let params = SetEnvironmentParams::new(vec!["INVALID".to_string()]);
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_assignment() {
        assert!(validate_assignment("FOO=bar").is_ok());
        assert!(validate_assignment("A=B=C").is_ok()); // value contains '='
        assert!(validate_assignment("NOKEY").is_err());
    }

    #[test]
    fn test_method_count() {
        assert_eq!(method_count(), 7);
    }

    #[test]
    fn test_set_environment_params_new() {
        let params = SetEnvironmentParams::new(vec![]);
        assert!(params.assignments.is_empty());
    }

    #[test]
    fn test_set_environment_parse_with_equals_in_value() {
        let (key, val) = SetEnvironmentParams::parse_assignment("OPT=--flag=value").unwrap();
        assert_eq!(key, "OPT");
        assert_eq!(val, "--flag=value");
    }
}
