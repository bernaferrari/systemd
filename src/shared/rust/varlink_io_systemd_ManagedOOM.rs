// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.ManagedOOM.c
//
// Varlink interface definition for io.systemd.ManagedOOM.
//
// PID1's Varlink service for OOM (Out-of-Memory) management.
// PID 1 is the server and oomd is the client, subscribing to
// cgroup monitoring for managed OOM kill decisions.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.ManagedOOM";

pub const METHOD_SUBSCRIBE_MANAGED_OOM_CGROUPS: &str = "SubscribeManagedOOMCGroups";

pub const METHODS: &[&str] = &[METHOD_SUBSCRIBE_MANAGED_OOM_CGROUPS];

// ── Enums ──────────────────────────────────────────────────────────────────

/// OOM kill action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomKillAction {
    /// Continue normal operation (no kill)
    Continue,
    /// Kill the cgroup
    Kill,
    /// Kill the cgroup and log
    KillAndLog,
}

impl OomKillAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            OomKillAction::Continue => "continue",
            OomKillAction::Kill => "kill",
            OomKillAction::KillAndLog => "kill-and-log",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "continue" => Some(OomKillAction::Continue),
            "kill" => Some(OomKillAction::Kill),
            "kill-and-log" => Some(OomKillAction::KillAndLog),
            _ => None,
        }
    }

    /// Whether this action terminates processes
    pub fn is_kill(&self) -> bool {
        matches!(self, OomKillAction::Kill | OomKillAction::KillAndLog)
    }
}

/// CGroup monitoring pressure level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// Low memory pressure
    Low,
    /// Medium memory pressure
    Medium,
    /// Critical memory pressure
    Critical,
}

impl PressureLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PressureLevel::Low => "low",
            PressureLevel::Medium => "medium",
            PressureLevel::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "low" => Some(PressureLevel::Low),
            "medium" => Some(PressureLevel::Medium),
            "critical" => Some(PressureLevel::Critical),
            _ => None,
        }
    }

    /// Numeric severity level (higher = more severe)
    pub fn severity(&self) -> u8 {
        match self {
            PressureLevel::Low => 0,
            PressureLevel::Medium => 1,
            PressureLevel::Critical => 2,
        }
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// CGroup path for OOM monitoring subscription
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlGroup {
    /// CGroup path
    pub path: String,
    /// OOM policy for this cgroup
    pub oom_policy: Option<String>,
    /// Memory usage in bytes
    pub memory_usage: Option<i64>,
    /// Memory limit in bytes
    pub memory_limit: Option<i64>,
    /// Pressure level if detected
    pub pressure_level: Option<PressureLevel>,
}

impl ControlGroup {
    /// Create a new control group entry
    pub fn new(path: String) -> Self {
        Self {
            path,
            oom_policy: None,
            memory_usage: None,
            memory_limit: None,
            pressure_level: None,
        }
    }

    /// Calculate memory usage as a fraction of limit
    pub fn usage_fraction(&self) -> Option<f64> {
        match (self.memory_usage, self.memory_limit) {
            (Some(usage), Some(limit)) if limit > 0 => Some(usage as f64 / limit as f64),
            _ => None,
        }
    }

    /// Check if memory usage exceeds a threshold (0.0 to 1.0)
    pub fn exceeds_threshold(&self, threshold: f64) -> Result<bool, ManagedOOMError> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(ManagedOOMError::SubscriptionTaken);
        }
        match self.usage_fraction() {
            Some(frac) => Ok(frac > threshold),
            None => Ok(false),
        }
    }
}

/// Output from the SubscribeManagedOOMCGroups method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOutput {
    /// List of monitored cgroups
    pub cgroups: Vec<ControlGroup>,
}

impl SubscribeOutput {
    /// Create empty subscription output
    pub fn new() -> Self {
        Self { cgroups: vec![] }
    }

    /// Number of subscribed cgroups
    pub fn len(&self) -> usize {
        self.cgroups.len()
    }

    /// Check if there are no subscribed cgroups
    pub fn is_empty(&self) -> bool {
        self.cgroups.is_empty()
    }

    /// Find a cgroup by path
    pub fn find_by_path(&self, path: &str) -> Option<&ControlGroup> {
        self.cgroups.iter().find(|cg| cg.path == path)
    }
}

impl Default for SubscribeOutput {
    fn default() -> Self {
        Self::new()
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOOMError {
    /// Another client has already taken the subscription
    SubscriptionTaken,
}

impl ManagedOOMError {
    pub fn error_id(&self) -> &'static str {
        match self {
            ManagedOOMError::SubscriptionTaken => "io.systemd.ManagedOOM.SubscriptionTaken",
        }
    }
}

pub const ERROR_IDS: &[&str] = &["io.systemd.ManagedOOM.SubscriptionTaken"];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a cgroup path
pub fn is_valid_cgroup_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/') && !path.contains('\0')
}

/// Parse a memory value string (e.g. "500M", "2G") to bytes
pub fn parse_memory_value(value: &str) -> Option<i64> {
    if value.is_empty() {
        return None;
    }

    let (num_part, multiplier) = if value.ends_with('G') || value.ends_with('g') {
        (&value[..value.len() - 1], 1024i64 * 1024 * 1024)
    } else if value.ends_with('M') || value.ends_with('m') {
        (&value[..value.len() - 1], 1024i64 * 1024)
    } else if value.ends_with('K') || value.ends_with('k') {
        (&value[..value.len() - 1], 1024i64)
    } else {
        (value, 1i64)
    };

    num_part.parse::<i64>().ok().map(|n| n * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.ManagedOOM");
        assert_eq!(METHODS.len(), 1);
    }

    #[test]
    fn test_oom_kill_action_roundtrip() {
        for s in &["continue", "kill", "kill-and-log"] {
            let action = OomKillAction::from_str(s).unwrap();
            assert_eq!(action.as_str(), *s);
        }
        assert_eq!(OomKillAction::from_str("unknown"), None);
    }

    #[test]
    fn test_oom_kill_action_is_kill() {
        assert!(OomKillAction::Kill.is_kill());
        assert!(OomKillAction::KillAndLog.is_kill());
        assert!(!OomKillAction::Continue.is_kill());
    }

    #[test]
    fn test_pressure_level_severity() {
        assert!(PressureLevel::Critical.severity() > PressureLevel::Medium.severity());
        assert!(PressureLevel::Medium.severity() > PressureLevel::Low.severity());
    }

    #[test]
    fn test_pressure_level_roundtrip() {
        assert_eq!(PressureLevel::from_str("low"), Some(PressureLevel::Low));
        assert_eq!(
            PressureLevel::from_str("medium"),
            Some(PressureLevel::Medium)
        );
        assert_eq!(
            PressureLevel::from_str("critical"),
            Some(PressureLevel::Critical)
        );
        assert_eq!(PressureLevel::from_str("high"), None);
    }

    #[test]
    fn test_control_group_usage_fraction() {
        let cg = ControlGroup {
            path: "/sys/fs/cgroup/test".into(),
            oom_policy: None,
            memory_usage: Some(512),
            memory_limit: Some(1024),
            pressure_level: None,
        };
        assert_eq!(cg.usage_fraction(), Some(0.5));

        let cg_no_limit = ControlGroup {
            path: "/sys/fs/cgroup/test".into(),
            oom_policy: None,
            memory_usage: Some(512),
            memory_limit: None,
            pressure_level: None,
        };
        assert_eq!(cg_no_limit.usage_fraction(), None);
    }

    #[test]
    fn test_control_group_exceeds_threshold() {
        let cg = ControlGroup {
            path: "/test".into(),
            oom_policy: None,
            memory_usage: Some(900),
            memory_limit: Some(1000),
            pressure_level: None,
        };
        assert_eq!(cg.exceeds_threshold(0.8), Ok(true));
        assert_eq!(cg.exceeds_threshold(0.95), Ok(false));
        assert!(cg.exceeds_threshold(1.5).is_err());
    }

    #[test]
    fn test_subscribe_output() {
        let mut output = SubscribeOutput::new();
        assert!(output.is_empty());
        output.cgroups.push(ControlGroup::new("/test".into()));
        assert_eq!(output.len(), 1);
        assert!(output.find_by_path("/test").is_some());
        assert!(output.find_by_path("/missing").is_none());
    }

    #[test]
    fn test_is_valid_cgroup_path() {
        assert!(is_valid_cgroup_path("/sys/fs/cgroup"));
        assert!(!is_valid_cgroup_path("relative/path"));
        assert!(!is_valid_cgroup_path(""));
        assert!(!is_valid_cgroup_path("/has\0null"));
    }

    #[test]
    fn test_parse_memory_value() {
        assert_eq!(parse_memory_value("1024"), Some(1024));
        assert_eq!(parse_memory_value("1K"), Some(1024));
        assert_eq!(parse_memory_value("1M"), Some(1024 * 1024));
        assert_eq!(parse_memory_value("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_memory_value("500m"), Some(500 * 1024 * 1024));
        assert_eq!(parse_memory_value("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_value(""), None);
        assert_eq!(parse_memory_value("abc"), None);
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 1);
        assert!(
            ManagedOOMError::SubscriptionTaken
                .error_id()
                .contains("SubscriptionTaken")
        );
    }

    #[test]
    fn test_control_group_new() {
        let cg = ControlGroup::new("/sys/fs/cgroup/test".into());
        assert_eq!(cg.path, "/sys/fs/cgroup/test");
        assert!(cg.oom_policy.is_none());
        assert!(cg.memory_usage.is_none());
        assert!(cg.memory_limit.is_none());
        assert!(cg.pressure_level.is_none());
    }
}
