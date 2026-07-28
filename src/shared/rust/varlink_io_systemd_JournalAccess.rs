// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.JournalAccess.c
//
// Varlink interface definition for io.systemd.JournalAccess.
//
// Journal log read APIs for retrieving journal entries filtered
// by unit, priority, namespace, and other criteria.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.JournalAccess";

pub const METHOD_GET_ENTRIES: &str = "GetEntries";

pub const METHODS: &[&str] = &[METHOD_GET_ENTRIES];

/// Default entry limit when not specified
pub const DEFAULT_ENTRY_LIMIT: i64 = 100;

/// Maximum allowed entry limit
pub const MAX_ENTRY_LIMIT: i64 = 10000;

/// Minimum syslog priority (emerg)
pub const PRIORITY_MIN: i64 = 0;

/// Maximum syslog priority (debug)
pub const PRIORITY_MAX: i64 = 7;

// ── Structs ────────────────────────────────────────────────────────────────

/// Input parameters for the GetEntries method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEntriesInput {
    /// Systemd units to filter by (e.g. ["foo.service"])
    pub units: Vec<String>,
    /// UID to match user units for
    pub uid: Option<i64>,
    /// User units to filter by (e.g. ["foo.service"])
    pub user_units: Vec<String>,
    /// Journal namespace to query
    pub namespace: Option<String>,
    /// Filter by message priority (0=emerg to 7=debug)
    pub priority: Option<i64>,
    /// Maximum number of entries to return
    pub limit: Option<i64>,
}

impl GetEntriesInput {
    /// Create a minimal input with default limit
    pub fn new() -> Self {
        Self {
            units: vec![],
            uid: None,
            user_units: vec![],
            namespace: None,
            priority: None,
            limit: None,
        }
    }

    /// Validate all input parameters
    pub fn validate(&self) -> Result<(), JournalAccessError> {
        if let Some(p) = self.priority {
            if !(PRIORITY_MIN..=PRIORITY_MAX).contains(&p) {
                return Err(JournalAccessError::NoEntries);
            }
        }
        if let Some(lim) = self.limit {
            if lim < 0 {
                return Err(JournalAccessError::NoEntries);
            }
        }
        if self.units.is_empty() && self.user_units.is_empty() && self.uid.is_none() {
            return Err(JournalAccessError::NoMatches);
        }
        Ok(())
    }

    /// Get the effective limit, applying defaults and caps
    pub fn effective_limit(&self) -> i64 {
        let raw = self.limit.unwrap_or(DEFAULT_ENTRY_LIMIT);
        raw.min(MAX_ENTRY_LIMIT).max(1)
    }
}

impl Default for GetEntriesInput {
    fn default() -> Self {
        Self::new()
    }
}

/// A single journal entry in flat JSON format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// The raw JSON object content of the entry
    pub fields: Vec<(String, String)>,
}

impl JournalEntry {
    /// Create a new journal entry from field key-value pairs
    pub fn new(fields: Vec<(String, String)>) -> Self {
        Self { fields }
    }

    /// Look up a field value by key
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Check if a field exists
    pub fn has_field(&self, key: &str) -> bool {
        self.fields.iter().any(|(k, _)| k == key)
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalAccessError {
    /// No matches found for specified unit patterns
    NoMatches,
    /// No journal entries matched the specified filters
    NoEntries,
}

impl JournalAccessError {
    pub fn error_id(&self) -> &'static str {
        match self {
            JournalAccessError::NoMatches => "io.systemd.JournalAccess.NoMatches",
            JournalAccessError::NoEntries => "io.systemd.JournalAccess.NoEntries",
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.JournalAccess.NoMatches",
    "io.systemd.JournalAccess.NoEntries",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a syslog priority value
pub fn is_valid_priority(priority: i64) -> bool {
    (PRIORITY_MIN..=PRIORITY_MAX).contains(&priority)
}

/// Clamp a limit value to the valid range
pub fn clamp_limit(limit: i64) -> i64 {
    limit.clamp(1, MAX_ENTRY_LIMIT)
}

/// Parse a syslog priority name to its numeric value
pub fn priority_from_name(name: &str) -> Option<i64> {
    match name {
        "emerg" => Some(0),
        "alert" => Some(1),
        "crit" => Some(2),
        "err" | "error" => Some(3),
        "warning" | "warn" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        _ => None,
    }
}

/// Convert a numeric priority to its name
pub fn priority_to_name(priority: i64) -> Option<&'static str> {
    match priority {
        0 => Some("emerg"),
        1 => Some("alert"),
        2 => Some("crit"),
        3 => Some("err"),
        4 => Some("warning"),
        5 => Some("notice"),
        6 => Some("info"),
        7 => Some("debug"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.JournalAccess");
    }

    #[test]
    fn test_default_limit_constants() {
        assert_eq!(DEFAULT_ENTRY_LIMIT, 100);
        assert_eq!(MAX_ENTRY_LIMIT, 10000);
        assert!(DEFAULT_ENTRY_LIMIT <= MAX_ENTRY_LIMIT);
    }

    #[test]
    fn test_get_entries_input_validate_success() {
        let input = GetEntriesInput {
            units: vec!["sshd.service".into()],
            ..Default::default()
        };
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_get_entries_input_validate_no_filters() {
        let input = GetEntriesInput::new();
        assert_eq!(input.validate(), Err(JournalAccessError::NoMatches));
    }

    #[test]
    fn test_get_entries_input_validate_bad_priority() {
        let input = GetEntriesInput {
            units: vec!["test.service".into()],
            priority: Some(9),
            ..Default::default()
        };
        assert_eq!(input.validate(), Err(JournalAccessError::NoEntries));
    }

    #[test]
    fn test_get_entries_input_validate_negative_limit() {
        let input = GetEntriesInput {
            units: vec!["test.service".into()],
            limit: Some(-1),
            ..Default::default()
        };
        assert_eq!(input.validate(), Err(JournalAccessError::NoEntries));
    }

    #[test]
    fn test_effective_limit() {
        let input = GetEntriesInput {
            limit: None,
            ..Default::default()
        };
        assert_eq!(input.effective_limit(), DEFAULT_ENTRY_LIMIT);

        let input2 = GetEntriesInput {
            limit: Some(50000),
            ..Default::default()
        };
        assert_eq!(input2.effective_limit(), MAX_ENTRY_LIMIT);

        let input3 = GetEntriesInput {
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(input3.effective_limit(), 50);
    }

    #[test]
    fn test_journal_entry_lookup() {
        let entry = JournalEntry::new(vec![
            ("MESSAGE".into(), "hello world".into()),
            ("_PID".into(), "1234".into()),
        ]);
        assert_eq!(entry.get("MESSAGE"), Some("hello world"));
        assert_eq!(entry.get("_PID"), Some("1234"));
        assert_eq!(entry.get("NONEXISTENT"), None);
    }

    #[test]
    fn test_journal_entry_has_field() {
        let entry = JournalEntry::new(vec![("KEY".into(), "val".into())]);
        assert!(entry.has_field("KEY"));
        assert!(!entry.has_field("MISSING"));
    }

    #[test]
    fn test_is_valid_priority() {
        assert!(is_valid_priority(0));
        assert!(is_valid_priority(7));
        assert!(is_valid_priority(3));
        assert!(!is_valid_priority(-1));
        assert!(!is_valid_priority(8));
    }

    #[test]
    fn test_clamp_limit() {
        assert_eq!(clamp_limit(50), 50);
        assert_eq!(clamp_limit(0), 1);
        assert_eq!(clamp_limit(100000), MAX_ENTRY_LIMIT);
        assert_eq!(clamp_limit(1), 1);
    }

    #[test]
    fn test_priority_roundtrip() {
        for p in 0..=7 {
            let name = priority_to_name(p).unwrap();
            assert_eq!(priority_from_name(name), Some(p));
        }
    }

    #[test]
    fn test_priority_from_name_aliases() {
        assert_eq!(priority_from_name("error"), Some(3));
        assert_eq!(priority_from_name("warn"), Some(4));
        assert_eq!(priority_from_name("unknown"), None);
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 2);
        assert!(
            JournalAccessError::NoMatches
                .error_id()
                .contains("NoMatches")
        );
        assert!(
            JournalAccessError::NoEntries
                .error_id()
                .contains("NoEntries")
        );
    }
}
