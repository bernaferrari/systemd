// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.oom.c
//
// Varlink interface definition for io.systemd.oom
// oomd's Varlink service where oomd is server and systemd --user is the client.
//
// Compare with io.systemd.ManagedOOM where the client/server roles of the
// service manager and oomd are swapped!

pub const INTERFACE_NAME: &str = "io.systemd.oom";

pub const METHOD_REPORT: &str = "io.systemd.oom.ReportManagedOOMCGroups";

pub const TYPE_CONTROL_GROUP: &str = "ControlGroup";

pub const PARAM_CGROUPS: &str = "cgroups";

pub const FIELD_MODE: &str = "mode";
pub const FIELD_PATH: &str = "path";
pub const FIELD_PROPERTY: &str = "property";
pub const FIELD_LIMIT: &str = "limit";
pub const FIELD_DURATION: &str = "duration";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OomError {
    EmptyCgroupList,
    InvalidMode(String),
    EmptyPath,
    UnknownMethod(String),
}

impl std::fmt::Display for OomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OomError::EmptyCgroupList => write!(f, "cgroups list must not be empty"),
            OomError::InvalidMode(m) => write!(f, "invalid mode: {m}"),
            OomError::EmptyPath => write!(f, "cgroup path must not be empty"),
            OomError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for OomError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "ControlGroup",
      "type": "struct",
      "fields": {
        "mode": { "type": "string" },
        "path": { "type": "string" },
        "property": { "type": "string" },
        "limit": { "type": "int", "nullable": true },
        "duration": { "type": "int", "nullable": true }
      }
    }
  ],
  "methods": {
    "ReportManagedOOMCGroups": {
      "parameters": {
        "cgroups": {
          "type": "[]ControlGroup"
        }
      },
      "return": {}
    }
  },
  "interface": "io.systemd.oom"
}"#
}

#[derive(Debug, Clone, PartialEq)]
pub struct ControlGroup {
    pub mode: String,
    pub path: String,
    pub property: String,
    pub limit: Option<i64>,
    pub duration: Option<i64>,
}

impl ControlGroup {
    pub fn new(
        mode: impl Into<String>,
        path: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        Self {
            mode: mode.into(),
            path: path.into(),
            property: property.into(),
            limit: None,
            duration: None,
        }
    }

    pub fn limit(mut self, value: i64) -> Self {
        self.limit = Some(value);
        self
    }

    pub fn duration(mut self, value: i64) -> Self {
        self.duration = Some(value);
        self
    }

    pub fn validate(&self) -> Result<(), OomError> {
        if self.path.is_empty() {
            return Err(OomError::EmptyPath);
        }
        let valid_modes = ["memory", "cpu", "io", "swap"];
        if !valid_modes.contains(&self.mode.as_str()) {
            return Err(OomError::InvalidMode(self.mode.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReportParams {
    pub cgroups: Vec<ControlGroup>,
}

impl ReportParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, cg: ControlGroup) -> Self {
        self.cgroups.push(cg);
        self
    }

    pub fn validate(&self) -> Result<(), OomError> {
        if self.cgroups.is_empty() {
            return Err(OomError::EmptyCgroupList);
        }
        for cg in &self.cgroups {
            cg.validate()?;
        }
        Ok(())
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, OomError> {
    if method == METHOD_REPORT {
        Ok(method)
    } else {
        Err(OomError::UnknownMethod(method.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.oom");
    }

    #[test]
    fn test_method_name() {
        assert_eq!(METHOD_REPORT, "io.systemd.oom.ReportManagedOOMCGroups");
    }

    #[test]
    fn test_type_name() {
        assert_eq!(TYPE_CONTROL_GROUP, "ControlGroup");
    }

    #[test]
    fn test_field_names() {
        assert_eq!(FIELD_MODE, "mode");
        assert_eq!(FIELD_PATH, "path");
        assert_eq!(FIELD_PROPERTY, "property");
        assert_eq!(FIELD_LIMIT, "limit");
        assert_eq!(FIELD_DURATION, "duration");
    }

    #[test]
    fn test_interface_definition_valid_json() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.oom"));
        assert!(json.contains("ReportManagedOOMCGroups"));
        assert!(json.contains("ControlGroup"));
        assert!(json.contains("mode"));
        assert!(json.contains("path"));
        assert!(json.contains("property"));
    }

    #[test]
    fn test_control_group_new() {
        let cg = ControlGroup::new("memory", "/user.slice/user-1000.slice", "memory.pressure");
        assert_eq!(cg.mode, "memory");
        assert_eq!(cg.path, "/user.slice/user-1000.slice");
        assert_eq!(cg.property, "memory.pressure");
        assert!(cg.limit.is_none());
        assert!(cg.duration.is_none());
    }

    #[test]
    fn test_control_group_with_optional_fields() {
        let cg = ControlGroup::new("cpu", "/system.slice", "cpu.stat")
            .limit(50)
            .duration(5000);

        assert_eq!(cg.limit, Some(50));
        assert_eq!(cg.duration, Some(5000));
    }

    #[test]
    fn test_control_group_validate_ok() {
        let cg = ControlGroup::new("memory", "/user.slice", "memory.pressure");
        assert!(cg.validate().is_ok());
    }

    #[test]
    fn test_control_group_validate_empty_path() {
        let cg = ControlGroup::new("memory", "", "memory.pressure");
        assert_eq!(cg.validate(), Err(OomError::EmptyPath));
    }

    #[test]
    fn test_control_group_validate_invalid_mode() {
        let cg = ControlGroup::new("bogus", "/test", "test.property");
        assert!(cg.validate().is_err());
    }

    #[test]
    fn test_report_params_validate_empty() {
        let params = ReportParams::new();
        assert_eq!(params.validate(), Err(OomError::EmptyCgroupList));
    }

    #[test]
    fn test_report_params_validate_with_cgroups() {
        let params = ReportParams::new().add(ControlGroup::new(
            "memory",
            "/user.slice",
            "memory.pressure",
        ));
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_report_params_add_multiple() {
        let params = ReportParams::new()
            .add(ControlGroup::new(
                "memory",
                "/user.slice",
                "memory.pressure",
            ))
            .add(ControlGroup::new("cpu", "/system.slice", "cpu.stat"));

        assert_eq!(params.cgroups.len(), 2);
    }

    #[test]
    fn test_control_group_clone() {
        let cg = ControlGroup::new("memory", "/test", "test.property").limit(100);
        let cloned = cg.clone();
        assert_eq!(cg, cloned);
    }

    #[test]
    fn test_validate_method_name_ok() {
        assert!(validate_method_name(METHOD_REPORT).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.oom.Bogus").is_err());
    }
}
