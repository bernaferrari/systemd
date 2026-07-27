// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Journal.c
//
// Varlink interface definition for io.systemd.Journal.
//
// Journal control APIs for synchronization, rotation, and flushing
// between runtime (/run) and persistent (/var) storage.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Journal service.
pub const INTERFACE_NAME: &str = "io.systemd.Journal";

/// Method name for Synchronize.
pub const METHOD_SYNCHRONIZE: &str = "io.systemd.Journal.Synchronize";

/// Method name for Rotate.
pub const METHOD_ROTATE: &str = "io.systemd.Journal.Rotate";

/// Method name for FlushToVar.
pub const METHOD_FLUSH_TO_VAR: &str = "io.systemd.Journal.FlushToVar";

/// Method name for RelinquishVar.
pub const METHOD_RELINQUISH_VAR: &str = "io.systemd.Journal.RelinquishVar";

/// Error: operation not supported for namespaced journal.
pub const ERROR_NOT_SUPPORTED_BY_NAMESPACES: &str = "io.systemd.Journal.NotSupportedByNamespaces";

/// Input parameter name for Synchronize: offline.
pub const PARAM_OFFLINE: &str = "offline";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Enum representing the different journal operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalOperation {
    /// Write out all pending log messages to disk.
    Synchronize,
    /// Rotate journal files (close existing, start new ones).
    Rotate,
    /// Flush runtime logs from /run/ into /var/.
    FlushToVar,
    /// Relinquish /var/, return to runtime logging in /run/ only.
    RelinquishVar,
}

impl JournalOperation {
    /// Get the fully qualified method name for this operation.
    pub fn method_name(&self) -> &'static str {
        match self {
            JournalOperation::Synchronize => METHOD_SYNCHRONIZE,
            JournalOperation::Rotate => METHOD_ROTATE,
            JournalOperation::FlushToVar => METHOD_FLUSH_TO_VAR,
            JournalOperation::RelinquishVar => METHOD_RELINQUISH_VAR,
        }
    }

    /// Get the short method name for this operation.
    pub fn short_name(&self) -> &'static str {
        match self {
            JournalOperation::Synchronize => "Synchronize",
            JournalOperation::Rotate => "Rotate",
            JournalOperation::FlushToVar => "FlushToVar",
            JournalOperation::RelinquishVar => "RelinquishVar",
        }
    }

    /// Parse a journal operation from a short method name.
    pub fn from_short_name(name: &str) -> Result<JournalOperation, i32> {
        match name {
            "Synchronize" => Ok(JournalOperation::Synchronize),
            "Rotate" => Ok(JournalOperation::Rotate),
            "FlushToVar" => Ok(JournalOperation::FlushToVar),
            "RelinquishVar" => Ok(JournalOperation::RelinquishVar),
            _ => Err(-22),
        }
    }

    /// Parse a journal operation from a fully qualified method name.
    pub fn from_qualified_name(name: &str) -> Result<JournalOperation, i32> {
        match name {
            METHOD_SYNCHRONIZE => Ok(JournalOperation::Synchronize),
            METHOD_ROTATE => Ok(JournalOperation::Rotate),
            METHOD_FLUSH_TO_VAR => Ok(JournalOperation::FlushToVar),
            METHOD_RELINQUISH_VAR => Ok(JournalOperation::RelinquishVar),
            _ => Err(-22),
        }
    }

    /// Check if this operation takes any input parameters.
    pub fn has_parameters(&self) -> bool {
        matches!(self, JournalOperation::Synchronize)
    }

    /// Check if this operation modifies journal files on disk.
    pub fn modifies_disk(&self) -> bool {
        matches!(
            self,
            JournalOperation::Synchronize | JournalOperation::Rotate
        )
    }

    /// All variants in definition order.
    pub fn all_variants() -> &'static [JournalOperation] {
        &[
            JournalOperation::Synchronize,
            JournalOperation::Rotate,
            JournalOperation::FlushToVar,
            JournalOperation::RelinquishVar,
        ]
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for the Synchronize method.
#[derive(Debug, Clone, Default)]
pub struct SynchronizeParams {
    /// Whether to offline journal files as part of synchronization.
    pub offline: Option<bool>,
}

impl SynchronizeParams {
    /// Create new SynchronizeParams with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the offline option using builder pattern.
    pub fn offline(mut self, value: bool) -> Self {
        self.offline = Some(value);
        self
    }

    /// Validate that the parameters are valid.
    pub fn validate(&self) -> Result<(), i32> {
        // SynchronizeParams is always valid; offline is optional.
        Ok(())
    }
}

// ── Interface definition ──────────────────────────────────────────────────

/// Returns the Varlink interface definition as a JSON string.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [],
  "methods": {
    "Synchronize": {
      "description": "Write out all pending log messages out to disk, and reply only after that's complete.",
      "parameters": {
        "offline": {
          "type": "bool",
          "nullable": true,
          "description": "Controls whether to offline the journal files as part of the synchronization operation."
        }
      },
      "return": {}
    },
    "Rotate": {
      "description": "Rotate journal files, i.e. close existing files, start new ones.",
      "parameters": {},
      "return": {}
    },
    "FlushToVar": {
      "description": "Flush runtime logs to persistent logs, i.e. flush log data from /run/ into /var/, and continue writing future log data to the latter location.",
      "parameters": {},
      "return": {}
    },
    "RelinquishVar": {
      "description": "Relinquish use of /var/ again, return to do runtime logging into /run/ only.",
      "parameters": {},
      "return": {}
    }
  },
  "errors": {
    "NotSupportedByNamespaces": {
      "description": "Journal service running as per-namespace instance, and requested operation is not supported for namespaced journal."
    }
  },
  "interface": "io.systemd.Journal",
  "description": "Journal control APIs"
}"#
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a short method name belongs to this interface.
pub fn is_method(name: &str) -> bool {
    matches!(
        name,
        "Synchronize" | "Rotate" | "FlushToVar" | "RelinquishVar"
    )
}

/// Look up the fully qualified method name from a short name.
pub fn qualified_method(short: &str) -> Result<&'static str, i32> {
    match short {
        "Synchronize" => Ok(METHOD_SYNCHRONIZE),
        "Rotate" => Ok(METHOD_ROTATE),
        "FlushToVar" => Ok(METHOD_FLUSH_TO_VAR),
        "RelinquishVar" => Ok(METHOD_RELINQUISH_VAR),
        _ => Err(-22),
    }
}

/// Look up the short method name from a fully qualified one.
pub fn short_method(qualified: &str) -> Result<&'static str, i32> {
    match qualified {
        METHOD_SYNCHRONIZE => Ok("Synchronize"),
        METHOD_ROTATE => Ok("Rotate"),
        METHOD_FLUSH_TO_VAR => Ok("FlushToVar"),
        METHOD_RELINQUISH_VAR => Ok("RelinquishVar"),
        _ => Err(-22),
    }
}

/// Check if a fully qualified error name belongs to this interface.
pub fn is_error(name: &str) -> bool {
    matches!(name, ERROR_NOT_SUPPORTED_BY_NAMESPACES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Journal");
    }

    #[test]
    fn test_method_constants() {
        assert_eq!(METHOD_SYNCHRONIZE, "io.systemd.Journal.Synchronize");
        assert_eq!(METHOD_ROTATE, "io.systemd.Journal.Rotate");
        assert_eq!(METHOD_FLUSH_TO_VAR, "io.systemd.Journal.FlushToVar");
        assert_eq!(METHOD_RELINQUISH_VAR, "io.systemd.Journal.RelinquishVar");
    }

    #[test]
    fn test_error_constant() {
        assert_eq!(
            ERROR_NOT_SUPPORTED_BY_NAMESPACES,
            "io.systemd.Journal.NotSupportedByNamespaces"
        );
    }

    #[test]
    fn test_param_offline() {
        assert_eq!(PARAM_OFFLINE, "offline");
    }

    #[test]
    fn test_journal_operation_method_names() {
        assert_eq!(
            JournalOperation::Synchronize.method_name(),
            METHOD_SYNCHRONIZE
        );
        assert_eq!(JournalOperation::Rotate.method_name(), METHOD_ROTATE);
        assert_eq!(
            JournalOperation::FlushToVar.method_name(),
            METHOD_FLUSH_TO_VAR
        );
        assert_eq!(
            JournalOperation::RelinquishVar.method_name(),
            METHOD_RELINQUISH_VAR
        );
    }

    #[test]
    fn test_journal_operation_short_names() {
        assert_eq!(JournalOperation::Synchronize.short_name(), "Synchronize");
        assert_eq!(JournalOperation::Rotate.short_name(), "Rotate");
        assert_eq!(JournalOperation::FlushToVar.short_name(), "FlushToVar");
        assert_eq!(
            JournalOperation::RelinquishVar.short_name(),
            "RelinquishVar"
        );
    }

    #[test]
    fn test_journal_operation_from_short_name() {
        assert_eq!(
            JournalOperation::from_short_name("Synchronize"),
            Ok(JournalOperation::Synchronize)
        );
        assert_eq!(
            JournalOperation::from_short_name("Rotate"),
            Ok(JournalOperation::Rotate)
        );
        assert_eq!(
            JournalOperation::from_short_name("FlushToVar"),
            Ok(JournalOperation::FlushToVar)
        );
        assert_eq!(
            JournalOperation::from_short_name("RelinquishVar"),
            Ok(JournalOperation::RelinquishVar)
        );
        assert!(JournalOperation::from_short_name("invalid").is_err());
    }

    #[test]
    fn test_journal_operation_from_qualified_name() {
        assert_eq!(
            JournalOperation::from_qualified_name(METHOD_SYNCHRONIZE),
            Ok(JournalOperation::Synchronize)
        );
        assert_eq!(
            JournalOperation::from_qualified_name(METHOD_ROTATE),
            Ok(JournalOperation::Rotate)
        );
        assert!(JournalOperation::from_qualified_name("unknown").is_err());
    }

    #[test]
    fn test_journal_operation_roundtrip() {
        for op in JournalOperation::all_variants() {
            let qualified = op.method_name();
            let back = JournalOperation::from_qualified_name(qualified);
            assert_eq!(back, Ok(*op));

            let short = op.short_name();
            let back2 = JournalOperation::from_short_name(short);
            assert_eq!(back2, Ok(*op));
        }
    }

    #[test]
    fn test_journal_operation_has_parameters() {
        assert!(JournalOperation::Synchronize.has_parameters());
        assert!(!JournalOperation::Rotate.has_parameters());
        assert!(!JournalOperation::FlushToVar.has_parameters());
        assert!(!JournalOperation::RelinquishVar.has_parameters());
    }

    #[test]
    fn test_journal_operation_modifies_disk() {
        assert!(JournalOperation::Synchronize.modifies_disk());
        assert!(JournalOperation::Rotate.modifies_disk());
        assert!(!JournalOperation::FlushToVar.modifies_disk());
        assert!(!JournalOperation::RelinquishVar.modifies_disk());
    }

    #[test]
    fn test_journal_operation_equality() {
        assert_eq!(JournalOperation::Synchronize, JournalOperation::Synchronize);
        assert_ne!(JournalOperation::Synchronize, JournalOperation::Rotate);
    }

    #[test]
    fn test_synchronize_params_default() {
        let params = SynchronizeParams::new();
        assert!(params.offline.is_none());
    }

    #[test]
    fn test_synchronize_params_builder() {
        let params = SynchronizeParams::new().offline(true);
        assert_eq!(params.offline, Some(true));
    }

    #[test]
    fn test_synchronize_params_clone() {
        let params = SynchronizeParams::new().offline(false);
        let cloned = params.clone();
        assert_eq!(params.offline, cloned.offline);
    }

    #[test]
    fn test_synchronize_params_validate() {
        let params = SynchronizeParams::new();
        assert!(params.validate().is_ok());

        let params_with_offline = SynchronizeParams::new().offline(true);
        assert!(params_with_offline.validate().is_ok());
    }

    #[test]
    fn test_interface_definition_contents() {
        let def = get_interface_definition();
        assert!(def.contains("io.systemd.Journal"));
        assert!(def.contains("Synchronize"));
        assert!(def.contains("Rotate"));
        assert!(def.contains("FlushToVar"));
        assert!(def.contains("RelinquishVar"));
        assert!(def.contains("NotSupportedByNamespaces"));
        assert!(def.contains("offline"));
    }

    #[test]
    fn test_is_method() {
        assert!(is_method("Synchronize"));
        assert!(is_method("Rotate"));
        assert!(is_method("FlushToVar"));
        assert!(is_method("RelinquishVar"));
        assert!(!is_method("synchronize"));
        assert!(!is_method("Ping"));
    }

    #[test]
    fn test_qualified_method() {
        assert_eq!(qualified_method("Synchronize"), Ok(METHOD_SYNCHRONIZE));
        assert_eq!(qualified_method("Rotate"), Ok(METHOD_ROTATE));
        assert_eq!(qualified_method("FlushToVar"), Ok(METHOD_FLUSH_TO_VAR));
        assert_eq!(qualified_method("RelinquishVar"), Ok(METHOD_RELINQUISH_VAR));
        assert!(qualified_method("Ping").is_err());
    }

    #[test]
    fn test_short_method() {
        assert_eq!(short_method(METHOD_SYNCHRONIZE), Ok("Synchronize"));
        assert_eq!(short_method(METHOD_ROTATE), Ok("Rotate"));
        assert_eq!(short_method(METHOD_FLUSH_TO_VAR), Ok("FlushToVar"));
        assert_eq!(short_method(METHOD_RELINQUISH_VAR), Ok("RelinquishVar"));
        assert!(short_method("io.systemd.Journal.Unknown").is_err());
    }

    #[test]
    fn test_is_error() {
        assert!(is_error(ERROR_NOT_SUPPORTED_BY_NAMESPACES));
        assert!(!is_error("io.systemd.Journal.Unknown"));
    }
}
