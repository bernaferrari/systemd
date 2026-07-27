// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.MuteConsole.c
//
// Varlink interface definition for io.systemd.MuteConsole
// API for temporarily muting noisy output to the main kernel console.

/// Interface name for the MuteConsole service
pub const INTERFACE_NAME: &str = "io.systemd.MuteConsole";

/// Method name for the Mute operation
pub const METHOD_MUTE: &str = "io.systemd.MuteConsole.Mute";

/// Input parameter: kernel - Whether to mute the kernel's output to the console (defaults to true)
pub const PARAM_KERNEL: &str = "kernel";

/// Input parameter: pid1 - Whether to mute PID1's output to the console (defaults to true)
pub const PARAM_PID1: &str = "pid1";

/// Error type for MuteConsole operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuteConsoleError {
    /// Invalid parameter combination
    InvalidParams(String),
}

impl std::fmt::Display for MuteConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MuteConsoleError::InvalidParams(msg) => write!(f, "invalid params: {msg}"),
        }
    }
}

impl std::error::Error for MuteConsoleError {}

/// Returns the Varlink interface definition as a JSON string
pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [],
  "methods": {
    "Mute": {
      "description": "Mute kernel and PID 1 output to the main kernel console",
      "parameters": {
        "kernel": {
          "type": "bool",
          "nullable": true,
          "description": "Whether to mute the kernel's output to the console (defaults to true)"
        },
        "pid1": {
          "type": "bool",
          "nullable": true,
          "description": "Whether to mute PID1's output to the console (defaults to true)"
        }
      },
      "return": {},
      "flags": ["more"]
    }
  },
  "interface": "io.systemd.MuteConsole",
  "description": "API for temporarily muting noisy output to the main kernel console"
}"#
}

/// Parameters for the Mute method
#[derive(Debug, Clone, Default)]
pub struct MuteParams {
    /// Whether to mute kernel output
    pub kernel: Option<bool>,
    /// Whether to mute PID1 output
    pub pid1: Option<bool>,
}

impl MuteParams {
    /// Create new MuteParams with defaults (None = use default behavior)
    pub fn new() -> Self {
        Self::default()
    }

    /// Set kernel mute option
    pub fn kernel(mut self, value: bool) -> Self {
        self.kernel = Some(value);
        self
    }

    /// Set pid1 mute option
    pub fn pid1(mut self, value: bool) -> Self {
        self.pid1 = Some(value);
        self
    }

    /// Validate the parameters. Both None means mute everything (valid default).
    /// Returns Ok(()) if valid, Err with description otherwise.
    pub fn validate(&self) -> Result<(), MuteConsoleError> {
        // All parameter combinations are valid for MuteConsole.
        // None means "use default (true)", so every combination is acceptable.
        Ok(())
    }

    /// Returns true if kernel muting is explicitly enabled or defaults to enabled.
    pub fn is_kernel_muted(&self) -> bool {
        self.kernel.unwrap_or(true)
    }

    /// Returns true if PID1 muting is explicitly enabled or defaults to enabled.
    pub fn is_pid1_muted(&self) -> bool {
        self.pid1.unwrap_or(true)
    }

    /// Returns true if at least one target is muted.
    pub fn is_any_muted(&self) -> bool {
        self.is_kernel_muted() || self.is_pid1_muted()
    }

    /// Returns true if both targets are muted.
    pub fn is_all_muted(&self) -> bool {
        self.is_kernel_muted() && self.is_pid1_muted()
    }
}

/// Validate that a method name belongs to this interface.
pub fn validate_method_name(method: &str) -> Result<&str, MuteConsoleError> {
    if method == METHOD_MUTE {
        Ok(method)
    } else {
        Err(MuteConsoleError::InvalidParams(format!(
            "unknown method: {method}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.MuteConsole");
    }

    #[test]
    fn test_method_name() {
        assert_eq!(METHOD_MUTE, "io.systemd.MuteConsole.Mute");
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_KERNEL, "kernel");
        assert_eq!(PARAM_PID1, "pid1");
    }

    #[test]
    fn test_interface_definition_valid_json() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.MuteConsole"));
        assert!(json.contains("Mute"));
        assert!(json.contains("kernel"));
        assert!(json.contains("pid1"));
    }

    #[test]
    fn test_interface_definition_contains_more_flag() {
        let json = get_interface_definition();
        assert!(json.contains("\"more\""));
    }

    #[test]
    fn test_mute_params_default() {
        let params = MuteParams::new();
        assert!(params.kernel.is_none());
        assert!(params.pid1.is_none());
    }

    #[test]
    fn test_mute_params_builder() {
        let params = MuteParams::new().kernel(true).pid1(false);
        assert_eq!(params.kernel, Some(true));
        assert_eq!(params.pid1, Some(false));
    }

    #[test]
    fn test_mute_params_clone() {
        let params = MuteParams::new().kernel(true);
        let cloned = params.clone();
        assert_eq!(params.kernel, cloned.kernel);
        assert_eq!(params.pid1, cloned.pid1);
    }

    #[test]
    fn test_mute_params_validate_ok() {
        let params = MuteParams::new();
        assert!(params.validate().is_ok());

        let params = MuteParams::new().kernel(true).pid1(false);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_mute_params_default_muting() {
        let params = MuteParams::new();
        assert!(params.is_kernel_muted());
        assert!(params.is_pid1_muted());
        assert!(params.is_all_muted());
        assert!(params.is_any_muted());
    }

    #[test]
    fn test_mute_params_explicit_unmute() {
        let params = MuteParams::new().kernel(false).pid1(false);
        assert!(!params.is_kernel_muted());
        assert!(!params.is_pid1_muted());
        assert!(!params.is_any_muted());
        assert!(!params.is_all_muted());
    }

    #[test]
    fn test_mute_params_partial_mute() {
        let params = MuteParams::new().kernel(true).pid1(false);
        assert!(params.is_kernel_muted());
        assert!(!params.is_pid1_muted());
        assert!(params.is_any_muted());
        assert!(!params.is_all_muted());
    }

    #[test]
    fn test_validate_method_name_ok() {
        assert_eq!(
            validate_method_name("io.systemd.MuteConsole.Mute"),
            Ok("io.systemd.MuteConsole.Mute")
        );
    }

    #[test]
    fn test_validate_method_name_unknown() {
        let result = validate_method_name("io.systemd.MuteConsole.Unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_mute_params_debug_format() {
        let params = MuteParams::new().kernel(true);
        let debug_str = format!("{params:?}");
        assert!(debug_str.contains("kernel"));
        assert!(debug_str.contains("Some(true)"));
    }
}
