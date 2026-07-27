// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Journal.c
//
// Varlink interface definition for io.systemd.Journal.
//
// Journal control APIs for synchronization, rotation, flushing,
// and relinquishing runtime journal data.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Journal";

pub const METHOD_SYNCHRONIZE: &str = "Synchronize";
pub const METHOD_ROTATE: &str = "Rotate";
pub const METHOD_FLUSH_TO_VAR: &str = "FlushToVar";
pub const METHOD_RELINQUISH_VAR: &str = "RelinquishVar";

pub const METHODS: &[&str] = &[
    METHOD_SYNCHRONIZE,
    METHOD_ROTATE,
    METHOD_FLUSH_TO_VAR,
    METHOD_RELINQUISH_VAR,
];

// ── Structs ────────────────────────────────────────────────────────────────

/// Input parameters for the Synchronize method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynchronizeInput {
    /// Controls whether to offline the journal files as part of synchronization
    pub offline: Option<bool>,
}

impl SynchronizeInput {
    pub fn new(offline: bool) -> Self {
        Self {
            offline: Some(offline),
        }
    }

    pub fn default_sync() -> Self {
        Self { offline: None }
    }
}

/// Output from journal operations that return no structured data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEmptyOutput;

// ── Error types ────────────────────────────────────────────────────────────

/// Errors for the io.systemd.Journal interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    /// Journal service running as per-namespace instance, operation not supported
    NotSupportedByNamespaces,
}

impl JournalError {
    pub fn error_id(&self) -> &'static str {
        match self {
            JournalError::NotSupportedByNamespaces => "io.systemd.Journal.NotSupportedByNamespaces",
        }
    }
}

pub const ERROR_IDS: &[&str] = &["io.systemd.Journal.NotSupportedByNamespaces"];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a journal method name against this interface
pub fn is_valid_method(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Parse a method name to its canonical form
pub fn parse_method_name(name: &str) -> Option<&'static str> {
    match name {
        "Synchronize" | "synchronize" => Some(METHOD_SYNCHRONIZE),
        "Rotate" | "rotate" => Some(METHOD_ROTATE),
        "FlushToVar" | "flushToVar" | "flush_to_var" => Some(METHOD_FLUSH_TO_VAR),
        "RelinquishVar" | "relinquishVar" | "relinquish_var" => Some(METHOD_RELINQUISH_VAR),
        _ => None,
    }
}

/// Check if a method requires additional input parameters
pub fn method_has_input(method: &str) -> bool {
    method == METHOD_SYNCHRONIZE
}

/// Check if a method modifies journal state (write operations)
pub fn is_write_method(method: &str) -> bool {
    matches!(
        method,
        METHOD_SYNCHRONIZE | METHOD_ROTATE | METHOD_FLUSH_TO_VAR | METHOD_RELINQUISH_VAR
    )
}

/// Describe what a journal method does
pub fn describe_method(method: &str) -> Option<&'static str> {
    match method {
        METHOD_SYNCHRONIZE => {
            Some("Write out all pending log messages to disk, reply only after complete")
        }
        METHOD_ROTATE => Some("Rotate journal files, close existing and start new ones"),
        METHOD_FLUSH_TO_VAR => Some("Flush runtime logs to persistent logs from /run/ into /var/"),
        METHOD_RELINQUISH_VAR => {
            Some("Relinquish use of /var/ and return to runtime logging into /run/ only")
        }
        _ => None,
    }
}

/// Validate offline parameter semantics
pub fn validate_offline_param(offline: Option<bool>) -> Result<bool, JournalError> {
    Ok(offline.unwrap_or(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Journal");
    }

    #[test]
    fn test_methods_constant() {
        assert_eq!(METHODS.len(), 4);
        assert!(METHODS.contains(&METHOD_SYNCHRONIZE));
        assert!(METHODS.contains(&METHOD_ROTATE));
        assert!(METHODS.contains(&METHOD_FLUSH_TO_VAR));
        assert!(METHODS.contains(&METHOD_RELINQUISH_VAR));
    }

    #[test]
    fn test_synchronize_input_new() {
        let input = SynchronizeInput::new(true);
        assert_eq!(input.offline, Some(true));

        let input2 = SynchronizeInput::new(false);
        assert_eq!(input2.offline, Some(false));
    }

    #[test]
    fn test_synchronize_input_default() {
        let input = SynchronizeInput::default_sync();
        assert_eq!(input.offline, None);
    }

    #[test]
    fn test_journal_error_error_id() {
        let err = JournalError::NotSupportedByNamespaces;
        assert!(err.error_id().contains("NotSupportedByNamespaces"));
        assert!(err.error_id().starts_with("io.systemd.Journal"));
    }

    #[test]
    fn test_error_ids_constant() {
        assert_eq!(ERROR_IDS.len(), 1);
        assert_eq!(ERROR_IDS[0], "io.systemd.Journal.NotSupportedByNamespaces");
    }

    #[test]
    fn test_is_valid_method() {
        assert!(is_valid_method(METHOD_SYNCHRONIZE));
        assert!(is_valid_method(METHOD_ROTATE));
        assert!(is_valid_method(METHOD_FLUSH_TO_VAR));
        assert!(is_valid_method(METHOD_RELINQUISH_VAR));
        assert!(!is_valid_method("Unknown"));
        assert!(!is_valid_method(""));
    }

    #[test]
    fn test_parse_method_name() {
        assert_eq!(parse_method_name("Synchronize"), Some(METHOD_SYNCHRONIZE));
        assert_eq!(parse_method_name("synchronize"), Some(METHOD_SYNCHRONIZE));
        assert_eq!(parse_method_name("Rotate"), Some(METHOD_ROTATE));
        assert_eq!(parse_method_name("FlushToVar"), Some(METHOD_FLUSH_TO_VAR));
        assert_eq!(parse_method_name("flushToVar"), Some(METHOD_FLUSH_TO_VAR));
        assert_eq!(
            parse_method_name("RelinquishVar"),
            Some(METHOD_RELINQUISH_VAR)
        );
        assert_eq!(parse_method_name("bogus"), None);
    }

    #[test]
    fn test_method_has_input() {
        assert!(method_has_input(METHOD_SYNCHRONIZE));
        assert!(!method_has_input(METHOD_ROTATE));
        assert!(!method_has_input(METHOD_FLUSH_TO_VAR));
        assert!(!method_has_input(METHOD_RELINQUISH_VAR));
    }

    #[test]
    fn test_is_write_method() {
        assert!(is_write_method(METHOD_SYNCHRONIZE));
        assert!(is_write_method(METHOD_ROTATE));
        assert!(is_write_method(METHOD_FLUSH_TO_VAR));
        assert!(is_write_method(METHOD_RELINQUISH_VAR));
        assert!(!is_write_method("ReadEntries"));
    }

    #[test]
    fn test_describe_method() {
        let desc = describe_method(METHOD_SYNCHRONIZE).unwrap();
        assert!(desc.contains("pending"));

        let desc = describe_method(METHOD_ROTATE).unwrap();
        assert!(desc.contains("Rotate"));

        let desc = describe_method(METHOD_FLUSH_TO_VAR).unwrap();
        assert!(desc.contains("/var/"));

        let desc = describe_method(METHOD_RELINQUISH_VAR).unwrap();
        assert!(desc.contains("/run/"));

        assert!(describe_method("unknown").is_none());
    }

    #[test]
    fn test_validate_offline_param() {
        assert_eq!(validate_offline_param(Some(true)), Ok(true));
        assert_eq!(validate_offline_param(Some(false)), Ok(false));
        assert_eq!(validate_offline_param(None), Ok(true)); // defaults to true
    }

    #[test]
    fn test_journal_empty_output() {
        let output = JournalEmptyOutput;
        assert_eq!(output, JournalEmptyOutput);
    }
}
