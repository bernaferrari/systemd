// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.MuteConsole.c
//
// Varlink interface definition for io.systemd.MuteConsole.
//
// API for temporarily muting noisy output to the main kernel console.
// The Mute method mutes kernel and PID 1 output to the main kernel console.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.MuteConsole";

/// Method name for muting console output.
pub const METHOD_MUTE: &str = "Mute";

// ── Method: Mute ──────────────────────────────────────────────────────────

/// Input parameters for the Mute method.
///
/// Mutes kernel and PID 1 output to the main kernel console.
/// Both fields default to `true` when `None` is supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuteParameters {
    /// Whether to mute the kernel's output to the console (defaults to true).
    pub kernel: Option<bool>,
    /// Whether to mute PID1's output to the console (defaults to true).
    pub pid1: Option<bool>,
}

impl MuteParameters {
    /// Create a new MuteParameters with all fields unset (will default to true).
    pub fn new() -> Self {
        Self {
            kernel: None,
            pid1: None,
        }
    }

    /// Create a new MuteParameters with both fields explicitly set.
    pub fn from_values(kernel: bool, pid1: bool) -> Self {
        Self {
            kernel: Some(kernel),
            pid1: Some(pid1),
        }
    }

    /// Set the kernel mute flag.
    pub fn with_kernel(mut self, kernel: bool) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Set the pid1 mute flag.
    pub fn with_pid1(mut self, pid1: bool) -> Self {
        self.pid1 = Some(pid1);
        self
    }

    /// Resolve the kernel flag, defaulting to true when unset.
    pub fn kernel_resolved(&self) -> bool {
        self.kernel.unwrap_or(true)
    }

    /// Resolve the pid1 flag, defaulting to true when unset.
    pub fn pid1_resolved(&self) -> bool {
        self.pid1.unwrap_or(true)
    }

    /// Validate the parameters. Currently always succeeds since both fields
    /// are nullable booleans with sensible defaults.
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

impl Default for MuteParameters {
    fn default() -> Self {
        Self::new()
    }
}

// ── Interface metadata ────────────────────────────────────────────────────

/// Returns the list of method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_MUTE]
}

/// Returns the list of error names defined by this interface.
pub fn error_names() -> &'static [&'static str] {
    &[]
}

/// Check whether the given method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Parse a method name and return a typed identifier.
pub fn parse_method(name: &str) -> Result<MuteMethod, String> {
    match name {
        METHOD_MUTE => Ok(MuteMethod::Mute),
        _ => Err(format!("unknown method: {name}")),
    }
}

/// Typed identifier for methods on this interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuteMethod {
    Mute,
}

impl MuteMethod {
    /// Return the string name used in varlink protocol.
    pub fn name(&self) -> &'static str {
        match self {
            MuteMethod::Mute => METHOD_MUTE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Interface metadata tests ──────────────────────────────────────

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.MuteConsole");
    }

    #[test]
    fn test_method_names_contains_mute() {
        assert!(method_names().contains(&METHOD_MUTE));
        assert_eq!(method_names().len(), 1);
    }

    #[test]
    fn test_error_names_is_empty() {
        assert!(error_names().is_empty());
    }

    #[test]
    fn test_has_method_mute() {
        assert!(has_method("Mute"));
        assert!(!has_method("Unknown"));
    }

    // ── Method parsing tests ──────────────────────────────────────────

    #[test]
    fn test_parse_method_mute() {
        assert_eq!(parse_method("Mute"), Ok(MuteMethod::Mute));
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("Unknown").is_err());
    }

    #[test]
    fn test_mute_method_name() {
        assert_eq!(MuteMethod::Mute.name(), "Mute");
    }

    // ── MuteParameters tests ──────────────────────────────────────────

    #[test]
    fn test_mute_parameters_new() {
        let params = MuteParameters::new();
        assert_eq!(params.kernel, None);
        assert_eq!(params.pid1, None);
    }

    #[test]
    fn test_mute_parameters_default() {
        let params = MuteParameters::default();
        assert_eq!(params.kernel, None);
        assert_eq!(params.pid1, None);
    }

    #[test]
    fn test_mute_parameters_from_values() {
        let params = MuteParameters::from_values(false, true);
        assert_eq!(params.kernel, Some(false));
        assert_eq!(params.pid1, Some(true));
    }

    #[test]
    fn test_mute_parameters_with_builder() {
        let params = MuteParameters::new().with_kernel(false).with_pid1(true);
        assert_eq!(params.kernel, Some(false));
        assert_eq!(params.pid1, Some(true));
    }

    #[test]
    fn test_mute_parameters_resolved_defaults() {
        let params = MuteParameters::new();
        assert!(params.kernel_resolved());
        assert!(params.pid1_resolved());
    }

    #[test]
    fn test_mute_parameters_resolved_explicit() {
        let params = MuteParameters::from_values(false, false);
        assert!(!params.kernel_resolved());
        assert!(!params.pid1_resolved());
    }

    #[test]
    fn test_mute_parameters_validate() {
        let params = MuteParameters::new();
        assert!(params.validate().is_ok());
    }
}
