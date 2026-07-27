// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.ManagedOOM.c
//
// Varlink interface definition for io.systemd.ManagedOOM
// PID1's Varlink service where PID 1 is the server and oomd is the client.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the ManagedOOM service
pub const INTERFACE_NAME: &str = "io.systemd.ManagedOOM";

/// Method name for SubscribeManagedOOMCGroups
pub const METHOD_SUBSCRIBE: &str = "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups";

/// Error name for SubscriptionTaken
pub const ERROR_SUBSCRIPTION_TAKEN: &str = "io.systemd.ManagedOOM.SubscriptionTaken";

/// Output parameter: cgroups
pub const PARAM_CGROUPS: &str = "cgroups";

/// Type name for ControlGroup
pub const TYPE_CONTROL_GROUP: &str = "ControlGroup";

/// OOM mode: memory
pub const MODE_MEMORY: &str = "memory";

/// OOM mode: cpu
pub const MODE_CPU: &str = "cpu";

// ── Enums ─────────────────────────────────────────────────────────────────

/// ManagedOOM mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOOMMode {
    Memory,
    Cpu,
}

impl ManagedOOMMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "memory" => Ok(ManagedOOMMode::Memory),
            "cpu" => Ok(ManagedOOMMode::Cpu),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ManagedOOMMode::Memory => "memory",
            ManagedOOMMode::Cpu => "cpu",
        }
    }
}

/// ManagedOOM swap action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOOMSwap {
    Auto,
    Kill,
}

impl ManagedOOMSwap {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "auto" => Ok(ManagedOOMSwap::Auto),
            "kill" => Ok(ManagedOOMSwap::Kill),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ManagedOOMSwap::Auto => "auto",
            ManagedOOMSwap::Kill => "kill",
        }
    }
}

/// ManagedOOM preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOOMPreference {
    None,
    Avoid,
    Omit,
}

impl ManagedOOMPreference {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "none" => Ok(ManagedOOMPreference::None),
            "avoid" => Ok(ManagedOOMPreference::Avoid),
            "omit" => Ok(ManagedOOMPreference::Omit),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ManagedOOMPreference::None => "none",
            ManagedOOMPreference::Avoid => "avoid",
            ManagedOOMPreference::Omit => "omit",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// ControlGroup struct representing a cgroup subscription
#[derive(Debug, Clone, PartialEq, Eq)]
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

    pub fn with_limit(mut self, value: i64) -> Self {
        self.limit = Some(value);
        self
    }

    pub fn with_duration(mut self, value: i64) -> Self {
        self.duration = Some(value);
        self
    }

    /// Validate the control group fields
    pub fn validate(&self) -> Result<(), i32> {
        if self.mode.is_empty() || self.path.is_empty() || self.property.is_empty() {
            return Err(-22);
        }
        if let Some(limit) = self.limit {
            if limit < 0 {
                return Err(-22);
            }
        }
        if let Some(duration) = self.duration {
            if duration < 0 {
                return Err(-22);
            }
        }
        Ok(())
    }
}

/// Parameters for SubscribeManagedOOMCGroups method
#[derive(Debug, Clone, Default)]
pub struct SubscribeParams {
    pub cgroups: Vec<ControlGroup>,
}

impl SubscribeParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, cg: ControlGroup) -> Self {
        self.cgroups.push(cg);
        self
    }

    /// Count control groups by mode
    pub fn count_by_mode(&self, mode: &str) -> usize {
        self.cgroups.iter().filter(|cg| cg.mode == mode).count()
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a mode string is known
pub fn is_known_mode(mode: &str) -> bool {
    matches!(mode, "memory" | "cpu")
}

/// Get the method names for this interface
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_SUBSCRIBE]
}

/// Get the error names for this interface
pub fn error_names() -> &'static [&'static str] {
    &[ERROR_SUBSCRIPTION_TAKEN]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.ManagedOOM");
    }

    #[test]
    fn test_method_name() {
        assert_eq!(
            METHOD_SUBSCRIBE,
            "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups"
        );
    }

    #[test]
    fn test_error_name() {
        assert_eq!(
            ERROR_SUBSCRIPTION_TAKEN,
            "io.systemd.ManagedOOM.SubscriptionTaken"
        );
    }

    #[test]
    fn test_control_group_new() {
        let cg = ControlGroup::new("memory", "/user.slice", "memory.pressure");
        assert_eq!(cg.mode, "memory");
        assert_eq!(cg.path, "/user.slice");
        assert_eq!(cg.property, "memory.pressure");
        assert!(cg.limit.is_none());
        assert!(cg.duration.is_none());
    }

    #[test]
    fn test_control_group_builder() {
        let cg = ControlGroup::new("memory", "/user.slice", "memory.pressure")
            .with_limit(80)
            .with_duration(10000);

        assert_eq!(cg.limit, Some(80));
        assert_eq!(cg.duration, Some(10000));
    }

    #[test]
    fn test_control_group_validate() {
        let cg = ControlGroup::new("memory", "/user.slice", "memory.pressure");
        assert!(cg.validate().is_ok());

        let empty_cg = ControlGroup::new("", "/user.slice", "memory.pressure");
        assert!(empty_cg.validate().is_err());

        let negative_limit =
            ControlGroup::new("memory", "/user.slice", "memory.pressure").with_limit(-1);
        assert!(negative_limit.validate().is_err());
    }

    #[test]
    fn test_control_group_clone() {
        let cg = ControlGroup::new("cpu", "/system.slice", "cpu.pressure");
        let cloned = cg.clone();
        assert_eq!(cg, cloned);
    }

    #[test]
    fn test_managed_oom_mode() {
        assert_eq!(
            ManagedOOMMode::from_str("memory"),
            Ok(ManagedOOMMode::Memory)
        );
        assert_eq!(ManagedOOMMode::from_str("cpu"), Ok(ManagedOOMMode::Cpu));
        assert!(ManagedOOMMode::from_str("io").is_err());
        assert_eq!(ManagedOOMMode::Memory.as_str(), "memory");
    }

    #[test]
    fn test_managed_oom_swap() {
        assert_eq!(ManagedOOMSwap::from_str("auto"), Ok(ManagedOOMSwap::Auto));
        assert_eq!(ManagedOOMSwap::from_str("kill"), Ok(ManagedOOMSwap::Kill));
        assert!(ManagedOOMSwap::from_str("none").is_err());
    }

    #[test]
    fn test_managed_oom_preference() {
        assert_eq!(
            ManagedOOMPreference::from_str("none"),
            Ok(ManagedOOMPreference::None)
        );
        assert_eq!(
            ManagedOOMPreference::from_str("avoid"),
            Ok(ManagedOOMPreference::Avoid)
        );
        assert_eq!(
            ManagedOOMPreference::from_str("omit"),
            Ok(ManagedOOMPreference::Omit)
        );
        assert!(ManagedOOMPreference::from_str("always").is_err());
    }

    #[test]
    fn test_subscribe_params() {
        let params = SubscribeParams::new()
            .add(ControlGroup::new(
                "memory",
                "/user.slice",
                "memory.pressure",
            ))
            .add(ControlGroup::new("cpu", "/system.slice", "cpu.pressure"));

        assert_eq!(params.cgroups.len(), 2);
        assert_eq!(params.count_by_mode("memory"), 1);
        assert_eq!(params.count_by_mode("cpu"), 1);
        assert_eq!(params.count_by_mode("io"), 0);
    }

    #[test]
    fn test_is_known_mode() {
        assert!(is_known_mode("memory"));
        assert!(is_known_mode("cpu"));
        assert!(!is_known_mode("io"));
    }

    #[test]
    fn test_method_and_error_names() {
        assert_eq!(method_names().len(), 1);
        assert_eq!(error_names().len(), 1);
    }
}
