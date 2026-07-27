// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.oom.c
//
// Varlink interface definition for io.systemd.oom.
//
// OOMd's varlink service where oomd is server and systemd --user is the client.
// Compare with io.systemd.ManagedOOM where the client/server roles are swapped.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.oom";

/// Method name for reporting managed OOM cgroups.
pub const METHOD_REPORT_MANAGED_OOM_CGROUPS: &str = "ReportManagedOOMCGroups";

// ── Struct types ──────────────────────────────────────────────────────────

/// A control group entry reported by oomd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlGroup {
    /// The OOM handling mode (e.g. "kill", "swap").
    pub mode: String,
    /// The cgroup path.
    pub path: String,
    /// The monitored property (e.g. "MemoryUsage").
    pub property: String,
    /// The limit value for the monitored property.
    pub limit: Option<i64>,
    /// The duration over which the property was monitored.
    pub duration: Option<i64>,
}

impl ControlGroup {
    /// Create a new ControlGroup with required fields.
    pub fn new(mode: &str, path: &str, property: &str) -> Self {
        Self {
            mode: mode.to_string(),
            path: path.to_string(),
            property: property.to_string(),
            limit: None,
            duration: None,
        }
    }

    /// Set the limit value.
    pub fn with_limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the duration value.
    pub fn with_duration(mut self, duration: i64) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Validate the control group entry.
    pub fn validate(&self) -> Result<(), String> {
        if self.mode.is_empty() {
            return Err("mode must not be empty".to_string());
        }
        if self.path.is_empty() {
            return Err("path must not be empty".to_string());
        }
        if self.property.is_empty() {
            return Err("property must not be empty".to_string());
        }
        Ok(())
    }
}

// ── Method identifiers ────────────────────────────────────────────────────

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_REPORT_MANAGED_OOM_CGROUPS]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomMethod {
    ReportManagedOOMCGroups,
}

impl OomMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReportManagedOOMCGroups => METHOD_REPORT_MANAGED_OOM_CGROUPS,
        }
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<OomMethod, String> {
    match name {
        METHOD_REPORT_MANAGED_OOM_CGROUPS => Ok(OomMethod::ReportManagedOOMCGroups),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input for the ReportManagedOOMCGroups method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportManagedOOMCGroupsInput {
    /// The list of control groups being reported.
    pub cgroups: Vec<ControlGroup>,
}

impl ReportManagedOOMCGroupsInput {
    /// Create a new input with the given control groups.
    pub fn new(cgroups: Vec<ControlGroup>) -> Self {
        Self { cgroups }
    }

    /// Validate all control groups in the input.
    pub fn validate(&self) -> Result<(), String> {
        if self.cgroups.is_empty() {
            return Err("cgroups must not be empty".to_string());
        }
        for cg in &self.cgroups {
            cg.validate()?;
        }
        Ok(())
    }
}

/// Error names defined by this interface.
pub fn error_names() -> &'static [&'static str] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.oom");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 1);
        assert!(has_method("ReportManagedOOMCGroups"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method() {
        assert_eq!(
            parse_method("ReportManagedOOMCGroups"),
            Ok(OomMethod::ReportManagedOOMCGroups)
        );
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        let m = parse_method("ReportManagedOOMCGroups").unwrap();
        assert_eq!(m.name(), "ReportManagedOOMCGroups");
    }

    #[test]
    fn test_control_group_new() {
        let cg = ControlGroup::new("kill", "/sys/fs/cgroup/test", "MemoryUsage");
        assert_eq!(cg.mode, "kill");
        assert_eq!(cg.path, "/sys/fs/cgroup/test");
        assert_eq!(cg.property, "MemoryUsage");
        assert_eq!(cg.limit, None);
        assert_eq!(cg.duration, None);
    }

    #[test]
    fn test_control_group_with_options() {
        let cg = ControlGroup::new("kill", "/test", "MemoryUsage")
            .with_limit(1073741824)
            .with_duration(30000000);
        assert_eq!(cg.limit, Some(1073741824));
        assert_eq!(cg.duration, Some(30000000));
    }

    #[test]
    fn test_control_group_validate() {
        let cg = ControlGroup::new("kill", "/test", "MemoryUsage");
        assert!(cg.validate().is_ok());
    }

    #[test]
    fn test_control_group_validate_empty_mode() {
        let cg = ControlGroup::new("", "/test", "MemoryUsage");
        assert!(cg.validate().is_err());
    }

    #[test]
    fn test_control_group_validate_empty_path() {
        let cg = ControlGroup::new("kill", "", "MemoryUsage");
        assert!(cg.validate().is_err());
    }

    #[test]
    fn test_control_group_validate_empty_property() {
        let cg = ControlGroup::new("kill", "/test", "");
        assert!(cg.validate().is_err());
    }

    #[test]
    fn test_report_input_validate() {
        let input = ReportManagedOOMCGroupsInput::new(vec![ControlGroup::new(
            "kill",
            "/test",
            "MemoryUsage",
        )]);
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_report_input_validate_empty() {
        let input = ReportManagedOOMCGroupsInput::new(vec![]);
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_error_names_empty() {
        assert!(error_names().is_empty());
    }
}
