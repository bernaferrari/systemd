// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.AskPassword.c
//
// Varlink interface definition for io.systemd.AskPassword.
//
// Provides an interface for interactively asking the user for a password,
// or answering from a previously cached entry in the kernel keyring.

// ── Constants ─────────────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.AskPassword";

pub const METHOD_ASK: &str = "io.systemd.AskPassword.Ask";

pub const ERROR_NO_PASSWORD_AVAILABLE: &str = "io.systemd.AskPassword.NoPasswordAvailable";
pub const ERROR_TIMEOUT_REACHED: &str = "io.systemd.AskPassword.TimeoutReached";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Controls visual feedback when typing in a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMode {
    /// No visual feedback while typing.
    Off,
    /// Show password in plaintext as it is typed.
    On,
    /// Show visual feedback but mask the actual characters.
    Masked,
}

impl EchoMode {
    /// Parse an echo mode from its varlink string representation.
    pub fn from_str(s: &str) -> Result<EchoMode, i32> {
        match s {
            "off" => Ok(EchoMode::Off),
            "on" => Ok(EchoMode::On),
            "masked" => Ok(EchoMode::Masked),
            _ => Err(-22), // -EINVAL
        }
    }

    /// Convert to the varlink string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            EchoMode::Off => "off",
            EchoMode::On => "on",
            EchoMode::Masked => "masked",
        }
    }

    /// All variant names in varlink order.
    pub fn all_variants() -> &'static [EchoMode] {
        &[EchoMode::Off, EchoMode::On, EchoMode::Masked]
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for the Ask method.
#[derive(Debug, Clone, Default)]
pub struct AskParams {
    /// The message to show when prompting for the password.
    pub message: Option<String>,
    /// The name for the kernel keyring entry used for caching.
    pub keyname: Option<String>,
    /// The icon name to display (freedesktop.org icon naming spec).
    pub icon: Option<String>,
    /// A recognizable id for the password prompt.
    pub id: Option<String>,
    /// Timeout in µs (relative, CLOCK_MONOTONIC).
    pub timeout_usec: Option<i64>,
    /// Timeout in µs (absolute, CLOCK_MONOTONIC).
    pub until_usec: Option<i64>,
    /// Whether to accept cached passwords from the kernel keyring.
    pub accept_cached: Option<bool>,
    /// Whether to push acquired passwords into the kernel keyring.
    pub push_cache: Option<bool>,
    /// Whether to give visual feedback when typing in the password.
    pub echo: Option<EchoMode>,
}

impl AskParams {
    /// Create a new empty AskParams.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prompt message.
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Set the keyring key name.
    pub fn keyname(mut self, name: impl Into<String>) -> Self {
        self.keyname = Some(name.into());
        self
    }

    /// Set the icon name.
    pub fn icon(mut self, name: impl Into<String>) -> Self {
        self.icon = Some(name.into());
        self
    }

    /// Set the prompt id.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set relative timeout in µs.
    pub fn timeout_usec(mut self, v: i64) -> Self {
        self.timeout_usec = Some(v);
        self
    }

    /// Set absolute timeout in µs.
    pub fn until_usec(mut self, v: i64) -> Self {
        self.until_usec = Some(v);
        self
    }

    /// Set whether to accept cached passwords.
    pub fn accept_cached(mut self, v: bool) -> Self {
        self.accept_cached = Some(v);
        self
    }

    /// Set whether to push passwords to cache.
    pub fn push_cache(mut self, v: bool) -> Self {
        self.push_cache = Some(v);
        self
    }

    /// Set the echo mode.
    pub fn echo(mut self, mode: EchoMode) -> Self {
        self.echo = Some(mode);
        self
    }

    /// Validate that at least a message or id is provided for meaningful prompting.
    pub fn validate(&self) -> Result<(), i32> {
        if self.message.is_none() && self.id.is_none() {
            return Err(-22); // -EINVAL: need at least message or id
        }
        if let (Some(t), Some(u)) = (self.timeout_usec, self.until_usec) {
            if t == 0 && u == 0 {
                // Both zero means only check cache; that's valid but unusual
            }
        }
        Ok(())
    }
}

/// Result of the Ask method.
#[derive(Debug, Clone)]
pub struct AskResult {
    /// List of acquired passwords. Typically one, but may contain more
    /// when multiple passwords were previously cached.
    pub passwords: Vec<String>,
}

impl AskResult {
    /// Create a new AskResult with a single password.
    pub fn single(password: impl Into<String>) -> Self {
        Self {
            passwords: vec![password.into()],
        }
    }

    /// Create a new AskResult with multiple passwords.
    pub fn multiple(passwords: Vec<String>) -> Self {
        Self { passwords }
    }

    /// Create an empty AskResult (no passwords available).
    pub fn empty() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }

    /// Check if any passwords are available.
    pub fn has_passwords(&self) -> bool {
        !self.passwords.is_empty()
    }
}

// ── Interface definition ──────────────────────────────────────────────────

/// Returns the Varlink interface definition as a JSON string.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "EchoMode",
      "type": "enum",
      "values": ["off", "on", "masked"]
    }
  ],
  "methods": {
    "Ask": {
      "parameters": {
        "message": { "type": "string", "nullable": true },
        "keyname": { "type": "string", "nullable": true },
        "icon": { "type": "string", "nullable": true },
        "id": { "type": "string", "nullable": true },
        "timeoutUSec": { "type": "int", "nullable": true },
        "untilUSec": { "type": "int", "nullable": true },
        "acceptCached": { "type": "bool", "nullable": true },
        "pushCache": { "type": "bool", "nullable": true },
        "echo": { "type": "EchoMode", "nullable": true }
      },
      "return": {
        "passwords": { "type": "[]string" }
      }
    }
  },
  "errors": {
    "NoPasswordAvailable": { "description": "No password available." },
    "TimeoutReached": { "description": "Query timeout reached." }
  },
  "interface": "io.systemd.AskPassword",
  "description": "An interface for interactively asking the user for a password."
}"#
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if a method name belongs to this interface.
pub fn is_method(name: &str) -> bool {
    matches!(name, "Ask")
}

/// Look up the fully qualified method name from a short name.
pub fn qualified_method(short: &str) -> Result<&'static str, i32> {
    match short {
        "Ask" => Ok(METHOD_ASK),
        _ => Err(-22),
    }
}

/// Look up the short method name from a fully qualified one.
pub fn short_method(qualified: &str) -> Result<&'static str, i32> {
    match qualified {
        METHOD_ASK => Ok("Ask"),
        _ => Err(-22),
    }
}

/// Check if a fully qualified error name belongs to this interface.
pub fn is_error(name: &str) -> bool {
    matches!(name, ERROR_NO_PASSWORD_AVAILABLE | ERROR_TIMEOUT_REACHED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.AskPassword");
    }

    #[test]
    fn test_method_constants() {
        assert_eq!(METHOD_ASK, "io.systemd.AskPassword.Ask");
    }

    #[test]
    fn test_error_constants() {
        assert_eq!(
            ERROR_NO_PASSWORD_AVAILABLE,
            "io.systemd.AskPassword.NoPasswordAvailable"
        );
        assert_eq!(
            ERROR_TIMEOUT_REACHED,
            "io.systemd.AskPassword.TimeoutReached"
        );
    }

    #[test]
    fn test_echo_mode_from_str() {
        assert_eq!(EchoMode::from_str("off"), Ok(EchoMode::Off));
        assert_eq!(EchoMode::from_str("on"), Ok(EchoMode::On));
        assert_eq!(EchoMode::from_str("masked"), Ok(EchoMode::Masked));
        assert!(EchoMode::from_str("invalid").is_err());
        assert!(EchoMode::from_str("").is_err());
    }

    #[test]
    fn test_echo_mode_as_str() {
        assert_eq!(EchoMode::Off.as_str(), "off");
        assert_eq!(EchoMode::On.as_str(), "on");
        assert_eq!(EchoMode::Masked.as_str(), "masked");
    }

    #[test]
    fn test_echo_mode_roundtrip() {
        for mode in EchoMode::all_variants() {
            assert_eq!(EchoMode::from_str(mode.as_str()), Ok(*mode));
        }
    }

    #[test]
    fn test_echo_mode_equality() {
        assert_eq!(EchoMode::Off, EchoMode::Off);
        assert_ne!(EchoMode::Off, EchoMode::On);
        assert_ne!(EchoMode::On, EchoMode::Masked);
    }

    #[test]
    fn test_ask_params_default() {
        let p = AskParams::new();
        assert!(p.message.is_none());
        assert!(p.keyname.is_none());
        assert!(p.icon.is_none());
        assert!(p.id.is_none());
        assert!(p.timeout_usec.is_none());
        assert!(p.until_usec.is_none());
        assert!(p.accept_cached.is_none());
        assert!(p.push_cache.is_none());
        assert!(p.echo.is_none());
    }

    #[test]
    fn test_ask_params_builder() {
        let p = AskParams::new()
            .message("Enter password:")
            .keyname("test-key")
            .icon("dialog-password")
            .id("test-id")
            .timeout_usec(90_000_000)
            .accept_cached(true)
            .push_cache(false)
            .echo(EchoMode::Masked);

        assert_eq!(p.message.as_deref(), Some("Enter password:"));
        assert_eq!(p.keyname.as_deref(), Some("test-key"));
        assert_eq!(p.icon.as_deref(), Some("dialog-password"));
        assert_eq!(p.id.as_deref(), Some("test-id"));
        assert_eq!(p.timeout_usec, Some(90_000_000));
        assert_eq!(p.accept_cached, Some(true));
        assert_eq!(p.push_cache, Some(false));
        assert_eq!(p.echo, Some(EchoMode::Masked));
    }

    #[test]
    fn test_ask_params_validate_with_message() {
        let p = AskParams::new().message("hello");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_ask_params_validate_with_id() {
        let p = AskParams::new().id("test");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_ask_params_validate_empty_fails() {
        let p = AskParams::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_ask_result_single() {
        let r = AskResult::single("secret");
        assert_eq!(r.passwords, vec!["secret"]);
        assert!(r.has_passwords());
    }

    #[test]
    fn test_ask_result_multiple() {
        let r = AskResult::multiple(vec!["a".into(), "b".into()]);
        assert_eq!(r.passwords.len(), 2);
        assert!(r.has_passwords());
    }

    #[test]
    fn test_ask_result_empty() {
        let r = AskResult::empty();
        assert!(r.passwords.is_empty());
        assert!(!r.has_passwords());
    }

    #[test]
    fn test_interface_definition_contents() {
        let def = get_interface_definition();
        assert!(def.contains("io.systemd.AskPassword"));
        assert!(def.contains("EchoMode"));
        assert!(def.contains("\"Ask\""));
        assert!(def.contains("NoPasswordAvailable"));
        assert!(def.contains("TimeoutReached"));
        assert!(def.contains("off"));
        assert!(def.contains("on"));
        assert!(def.contains("masked"));
    }

    #[test]
    fn test_is_method() {
        assert!(is_method("Ask"));
        assert!(!is_method("Ping"));
        assert!(!is_method("ask"));
    }

    #[test]
    fn test_qualified_method() {
        assert_eq!(qualified_method("Ask"), Ok(METHOD_ASK));
        assert!(qualified_method("Ping").is_err());
    }

    #[test]
    fn test_short_method() {
        assert_eq!(short_method(METHOD_ASK), Ok("Ask"));
        assert!(short_method("io.systemd.AskPassword.Unknown").is_err());
    }

    #[test]
    fn test_is_error() {
        assert!(is_error(ERROR_NO_PASSWORD_AVAILABLE));
        assert!(is_error(ERROR_TIMEOUT_REACHED));
        assert!(!is_error("io.systemd.AskPassword.Unknown"));
    }
}
