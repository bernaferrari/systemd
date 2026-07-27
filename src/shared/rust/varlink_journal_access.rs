// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.JournalAccess.c
//
// Varlink interface definition for io.systemd.JournalAccess
// Journal log read APIs with filtering capabilities.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the JournalAccess service
pub const INTERFACE_NAME: &str = "io.systemd.JournalAccess";

/// Method name for GetEntries
pub const METHOD_GET_ENTRIES: &str = "io.systemd.JournalAccess.GetEntries";

/// Error name for NoMatches
pub const ERROR_NO_MATCHES: &str = "io.systemd.JournalAccess.NoMatches";

/// Error name for NoEntries
pub const ERROR_NO_ENTRIES: &str = "io.systemd.JournalAccess.NoEntries";

/// Input parameter: units - Systemd units to filter by
pub const PARAM_UNITS: &str = "units";

/// Input parameter: uid - UID to match user units for
pub const PARAM_UID: &str = "uid";

/// Input parameter: userUnits - User units to filter by
pub const PARAM_USER_UNITS: &str = "userUnits";

/// Input parameter: namespace - Journal namespace
pub const PARAM_NAMESPACE: &str = "namespace";

/// Input parameter: priority - Priority filter
pub const PARAM_PRIORITY: &str = "priority";

/// Input parameter: limit - Maximum entries to return
pub const PARAM_LIMIT: &str = "limit";

/// Output parameter: entry - Journal entry in flat JSON format
pub const PARAM_ENTRY: &str = "entry";

/// Default limit for GetEntries
pub const DEFAULT_LIMIT: i64 = 100;

/// Maximum limit for GetEntries
pub const MAX_LIMIT: i64 = 10000;

/// Minimum limit for GetEntries
pub const MIN_LIMIT: i64 = 1;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Priority levels for journal entries (syslog-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Err = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Priority {
    /// Create a Priority from an integer value
    pub fn from_i64(value: i64) -> Result<Self, i32> {
        match value {
            0 => Ok(Priority::Emerg),
            1 => Ok(Priority::Alert),
            2 => Ok(Priority::Crit),
            3 => Ok(Priority::Err),
            4 => Ok(Priority::Warning),
            5 => Ok(Priority::Notice),
            6 => Ok(Priority::Info),
            7 => Ok(Priority::Debug),
            _ => Err(-22),
        }
    }

    /// Get the priority name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::Emerg => "emerg",
            Priority::Alert => "alert",
            Priority::Crit => "crit",
            Priority::Err => "err",
            Priority::Warning => "warning",
            Priority::Notice => "notice",
            Priority::Info => "info",
            Priority::Debug => "debug",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for GetEntries method
#[derive(Debug, Clone, Default)]
pub struct GetEntriesParams {
    pub units: Option<Vec<String>>,
    pub uid: Option<i64>,
    pub user_units: Option<Vec<String>>,
    pub namespace: Option<String>,
    pub priority: Option<i64>,
    pub limit: Option<i64>,
}

impl GetEntriesParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn units(mut self, units: Vec<String>) -> Self {
        self.units = Some(units);
        self
    }

    pub fn uid(mut self, uid: i64) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn user_units(mut self, units: Vec<String>) -> Self {
        self.user_units = Some(units);
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn priority(mut self, priority: i64) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit.min(MAX_LIMIT).max(MIN_LIMIT));
        self
    }

    pub fn effective_limit(&self) -> i64 {
        self.limit
            .unwrap_or(DEFAULT_LIMIT)
            .min(MAX_LIMIT)
            .max(MIN_LIMIT)
    }

    /// Validate parameters
    pub fn validate(&self) -> Result<(), i32> {
        if let Some(p) = self.priority {
            if !(0..=7).contains(&p) {
                return Err(-22);
            }
        }
        Ok(())
    }
}

/// Output for GetEntries method - a single journal entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub data: String,
}

impl JournalEntry {
    pub fn new(data: impl Into<String>) -> Self {
        Self { data: data.into() }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Clamp a limit value to valid range
pub fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(MIN_LIMIT, MAX_LIMIT)
}

/// Validate a priority value (0-7)
pub fn validate_priority(priority: i64) -> Result<Priority, i32> {
    Priority::from_i64(priority)
}

/// Get all known parameter names
pub fn param_names() -> &'static [&'static str] {
    &[
        PARAM_UNITS,
        PARAM_UID,
        PARAM_USER_UNITS,
        PARAM_NAMESPACE,
        PARAM_PRIORITY,
        PARAM_LIMIT,
        PARAM_ENTRY,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.JournalAccess");
    }

    #[test]
    fn test_method_name() {
        assert_eq!(METHOD_GET_ENTRIES, "io.systemd.JournalAccess.GetEntries");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(ERROR_NO_MATCHES, "io.systemd.JournalAccess.NoMatches");
        assert_eq!(ERROR_NO_ENTRIES, "io.systemd.JournalAccess.NoEntries");
    }

    #[test]
    fn test_param_names_list() {
        let names = param_names();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&PARAM_UNITS));
        assert!(names.contains(&PARAM_ENTRY));
    }

    #[test]
    fn test_priority_from_i64() {
        assert_eq!(Priority::from_i64(0), Ok(Priority::Emerg));
        assert_eq!(Priority::from_i64(4), Ok(Priority::Warning));
        assert_eq!(Priority::from_i64(7), Ok(Priority::Debug));
        assert!(Priority::from_i64(8).is_err());
        assert!(Priority::from_i64(-1).is_err());
    }

    #[test]
    fn test_priority_as_str() {
        assert_eq!(Priority::Emerg.as_str(), "emerg");
        assert_eq!(Priority::Warning.as_str(), "warning");
        assert_eq!(Priority::Debug.as_str(), "debug");
    }

    #[test]
    fn test_get_entries_params_default() {
        let params = GetEntriesParams::new();
        assert!(params.units.is_none());
        assert!(params.uid.is_none());
        assert!(params.user_units.is_none());
        assert!(params.namespace.is_none());
        assert!(params.priority.is_none());
        assert!(params.limit.is_none());
    }

    #[test]
    fn test_get_entries_params_builder() {
        let params = GetEntriesParams::new()
            .units(vec!["foo.service".to_string()])
            .uid(1000)
            .user_units(vec!["bar.service".to_string()])
            .namespace("test")
            .priority(4)
            .limit(50);

        assert_eq!(params.units, Some(vec!["foo.service".to_string()]));
        assert_eq!(params.uid, Some(1000));
        assert_eq!(params.namespace, Some("test".to_string()));
        assert_eq!(params.priority, Some(4));
        assert_eq!(params.limit, Some(50));
    }

    #[test]
    fn test_get_entries_params_effective_limit() {
        assert_eq!(GetEntriesParams::new().effective_limit(), 100);
        assert_eq!(GetEntriesParams::new().limit(50).effective_limit(), 50);
        assert_eq!(
            GetEntriesParams::new().limit(50000).effective_limit(),
            10000
        );
        assert_eq!(GetEntriesParams::new().limit(0).effective_limit(), 1);
    }

    #[test]
    fn test_get_entries_params_validate() {
        let params = GetEntriesParams::new().priority(3);
        assert!(params.validate().is_ok());

        let params = GetEntriesParams::new().priority(8);
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_journal_entry() {
        let entry = JournalEntry::new(r#"{"MESSAGE":"test","_PID":"123"}"#);
        assert_eq!(entry.data, r#"{"MESSAGE":"test","_PID":"123"}"#);
    }

    #[test]
    fn test_clamp_limit() {
        assert_eq!(clamp_limit(50), 50);
        assert_eq!(clamp_limit(0), 1);
        assert_eq!(clamp_limit(50000), 10000);
    }

    #[test]
    fn test_validate_priority() {
        assert_eq!(validate_priority(0), Ok(Priority::Emerg));
        assert_eq!(validate_priority(7), Ok(Priority::Debug));
        assert!(validate_priority(8).is_err());
    }

    #[test]
    fn test_priority_equality() {
        assert_eq!(Priority::Info, Priority::Info);
        assert_ne!(Priority::Info, Priority::Debug);
    }

    #[test]
    fn test_journal_entry_equality() {
        let a = JournalEntry::new("data");
        let b = JournalEntry::new("data");
        assert_eq!(a, b);
    }
}
