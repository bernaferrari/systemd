// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.PCRLock.c
//
// Varlink interface definition for io.systemd.PCRLock.
//
// TPM PCR lock management. Provides methods to read the event log,
// create a policy, and remove a policy.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.PCRLock";

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_READ_EVENT_LOG: &str = "ReadEventLog";
pub const METHOD_MAKE_POLICY: &str = "MakePolicy";
pub const METHOD_REMOVE_POLICY: &str = "RemovePolicy";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_READ_EVENT_LOG,
        METHOD_MAKE_POLICY,
        METHOD_REMOVE_POLICY,
    ]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrLockMethod {
    ReadEventLog,
    MakePolicy,
    RemovePolicy,
}

impl PcrLockMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadEventLog => METHOD_READ_EVENT_LOG,
            Self::MakePolicy => METHOD_MAKE_POLICY,
            Self::RemovePolicy => METHOD_REMOVE_POLICY,
        }
    }

    /// Whether the method uses the "more" flag (streaming).
    pub fn requires_more(&self) -> bool {
        matches!(self, Self::ReadEventLog)
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<PcrLockMethod, String> {
    match name {
        METHOD_READ_EVENT_LOG => Ok(PcrLockMethod::ReadEventLog),
        METHOD_MAKE_POLICY => Ok(PcrLockMethod::MakePolicy),
        METHOD_REMOVE_POLICY => Ok(PcrLockMethod::RemovePolicy),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Input parameters for the MakePolicy method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakePolicyInput {
    /// Whether to force policy creation.
    pub force: Option<bool>,
}

impl MakePolicyInput {
    /// Create a new MakePolicyInput with force unset.
    pub fn new() -> Self {
        Self { force: None }
    }

    /// Create a new MakePolicyInput with force set.
    pub fn from_force(force: bool) -> Self {
        Self { force: Some(force) }
    }

    /// Set the force flag.
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = Some(force);
        self
    }
}

impl Default for MakePolicyInput {
    fn default() -> Self {
        Self::new()
    }
}

/// The RemovePolicy method takes no input parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovePolicyInput;

/// The ReadEventLog method takes no input parameters.
/// It streams output records using the "more" flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadEventLogInput;

/// A single record from the event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLogRecord {
    /// The record data as a structured object.
    pub record: String,
}

impl EventLogRecord {
    /// Create a new EventLogRecord.
    pub fn new(record: &str) -> Self {
        Self {
            record: record.to_string(),
        }
    }
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors defined by this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrLockError {
    /// No change was detected (policy unchanged).
    NoChange,
}

impl PcrLockError {
    /// Parse from the varlink error string.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "NoChange" => Ok(Self::NoChange),
            _ => Err(format!("unknown error: {s}")),
        }
    }

    /// Return the varlink error string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoChange => "NoChange",
        }
    }
}

/// All error names.
pub fn error_names() -> &'static [&'static str] {
    &["NoChange"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.PCRLock");
    }

    #[test]
    fn test_method_names_count() {
        assert_eq!(method_names().len(), 3);
    }

    #[test]
    fn test_has_method() {
        assert!(has_method("ReadEventLog"));
        assert!(has_method("MakePolicy"));
        assert!(has_method("RemovePolicy"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_all() {
        assert_eq!(
            parse_method("ReadEventLog"),
            Ok(PcrLockMethod::ReadEventLog)
        );
        assert_eq!(parse_method("MakePolicy"), Ok(PcrLockMethod::MakePolicy));
        assert_eq!(
            parse_method("RemovePolicy"),
            Ok(PcrLockMethod::RemovePolicy)
        );
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_requires_more() {
        assert!(PcrLockMethod::ReadEventLog.requires_more());
        assert!(!PcrLockMethod::MakePolicy.requires_more());
        assert!(!PcrLockMethod::RemovePolicy.requires_more());
    }

    #[test]
    fn test_make_policy_input_new() {
        let input = MakePolicyInput::new();
        assert_eq!(input.force, None);
    }

    #[test]
    fn test_make_policy_input_from_force() {
        let input = MakePolicyInput::from_force(true);
        assert_eq!(input.force, Some(true));
    }

    #[test]
    fn test_make_policy_input_with_force() {
        let input = MakePolicyInput::new().with_force(false);
        assert_eq!(input.force, Some(false));
    }

    #[test]
    fn test_make_policy_input_default() {
        let input = MakePolicyInput::default();
        assert_eq!(input.force, None);
    }

    #[test]
    fn test_event_log_record() {
        let rec = EventLogRecord::new("test-data");
        assert_eq!(rec.record, "test-data");
    }

    #[test]
    fn test_error_roundtrip() {
        assert_eq!(
            PcrLockError::from_str("NoChange"),
            Ok(PcrLockError::NoChange)
        );
        assert!(PcrLockError::from_str("bogus").is_err());
        assert_eq!(PcrLockError::NoChange.as_str(), "NoChange");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(error_names().len(), 1);
        assert!(error_names().contains(&"NoChange"));
    }
}
