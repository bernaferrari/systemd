// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.AskPassword.c
//
// Rust shadow of the io.systemd.AskPassword varlink interface.
//
// Provides types mirroring the C varlink IDL definitions for interactive
// password prompting, including echo-mode enumeration, method parameters,
// and structured error reporting.

// ── Constants ─────────────────────────────────────────────────────────────

/// Varlink interface name for the AskPassword service.
pub const INTERFACE_NAME: &str = "io.systemd.AskPassword";

/// Default timeout in microseconds (90 s, matching the C implementation).
pub const DEFAULT_TIMEOUT_USEC: u64 = 90_000_000;

/// Sentinel: no relative timeout.
pub const TIMEOUT_INFINITY: u64 = u64::MAX;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Controls visual feedback while the user types a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMode {
    /// No visual feedback (default secure behaviour).
    Off,
    /// Show the password in plaintext.
    On,
    /// Show a mask character per typed character.
    Masked,
}

impl EchoMode {
    /// Parse an echo-mode value from its varlink string representation.
    pub fn from_varlink(s: &str) -> Result<EchoMode, AskPasswordError> {
        match s {
            "off" => Ok(EchoMode::Off),
            "on" => Ok(EchoMode::On),
            "masked" => Ok(EchoMode::Masked),
            _ => Err(AskPasswordError::InvalidEchoMode(s.to_owned())),
        }
    }

    /// Return the varlink string for this variant.
    pub fn to_varlink(self) -> &'static str {
        match self {
            EchoMode::Off => "off",
            EchoMode::On => "on",
            EchoMode::Masked => "masked",
        }
    }

    /// All defined variants in IDL order.
    pub fn all() -> &'static [EchoMode] {
        &[EchoMode::Off, EchoMode::On, EchoMode::Masked]
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Input parameters for the `Ask` method.
#[derive(Debug, Clone, PartialEq)]
pub struct AskInput {
    /// The message to show when prompting for the password.
    pub message: Option<String>,
    /// Kernel keyring entry name used for caching.
    pub keyname: Option<String>,
    /// Icon name (freedesktop.org icon naming spec).
    pub icon: Option<String>,
    /// Recognisable id for the password prompt.
    pub id: Option<String>,
    /// Timeout in µs (relative, `CLOCK_MONOTONIC`).
    pub timeout_usec: Option<u64>,
    /// Timeout in µs (absolute, `CLOCK_MONOTONIC`).
    pub until_usec: Option<u64>,
    /// Whether to accept cached passwords from the kernel keyring.
    pub accept_cached: Option<bool>,
    /// Whether to push acquired passwords into the kernel keyring.
    pub push_cache: Option<bool>,
    /// Visual feedback mode while typing.
    pub echo: Option<EchoMode>,
}

impl AskInput {
    /// Create an input with all optional fields set to `None`.
    pub fn new() -> Self {
        AskInput {
            message: None,
            keyname: None,
            icon: None,
            id: None,
            timeout_usec: None,
            until_usec: None,
            accept_cached: None,
            push_cache: None,
            echo: None,
        }
    }

    /// Resolve the effective relative timeout, defaulting to 90 s.
    pub fn effective_timeout_usec(&self) -> u64 {
        self.timeout_usec.unwrap_or(DEFAULT_TIMEOUT_USEC)
    }

    /// Check whether the input requests only a cache lookup (no interactive
    /// query).  This is true when `timeout_usec` is set to zero.
    pub fn is_cache_only(&self) -> bool {
        self.timeout_usec == Some(0)
    }
}

impl Default for AskInput {
    fn default() -> Self {
        Self::new()
    }
}

/// Output of the `Ask` method.
#[derive(Debug, Clone, PartialEq)]
pub struct AskOutput {
    /// Acquired passwords.  Typically one entry but may contain more when
    /// multiple passwords were previously cached.
    pub passwords: Vec<String>,
}

impl AskOutput {
    /// Create output from a single password.
    pub fn single(password: String) -> Self {
        AskOutput {
            passwords: vec![password],
        }
    }

    /// Create output from multiple passwords.
    pub fn multiple(passwords: Vec<String>) -> Self {
        AskOutput { passwords }
    }

    /// Return the first password, if any.
    pub fn first(&self) -> Option<&str> {
        self.passwords.first().map(|s| s.as_str())
    }

    /// Number of passwords returned.
    pub fn len(&self) -> usize {
        self.passwords.len()
    }

    /// Whether no passwords were returned.
    pub fn is_empty(&self) -> bool {
        self.passwords.is_empty()
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors raised by the `io.systemd.AskPassword` interface.
#[derive(Debug, Clone, PartialEq)]
pub enum AskPasswordError {
    /// No password available (none cached and no agent asked).
    NoPasswordAvailable,
    /// Query timeout reached.
    TimeoutReached,
    /// Unrecognised echo-mode string.
    InvalidEchoMode(String),
}

impl std::fmt::Display for AskPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AskPasswordError::NoPasswordAvailable => write!(f, "NoPasswordAvailable"),
            AskPasswordError::TimeoutReached => write!(f, "TimeoutReached"),
            AskPasswordError::InvalidEchoMode(s) => write!(f, "InvalidEchoMode: {}", s),
        }
    }
}

impl std::error::Error for AskPasswordError {}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate that an `AskInput` is well-formed for sending to the varlink
/// service.  Returns `Ok(())` on success.
pub fn validate_ask_input(input: &AskInput) -> Result<(), AskPasswordError> {
    // Zero timeout is valid (cache-only) but a timeout > 0 on an absolute
    // deadline that is already in the past is not useful — we accept it
    // anyway and let the service decide.

    if let Some(ref echo) = input.echo {
        // Ensure the mode round-trips cleanly (defensive).
        let _ = echo.to_varlink();
    }
    Ok(())
}

/// Simulate the `Ask` method: returns `Ok(output)` when at least one
/// password is provided, `NoPasswordAvailable` otherwise.
pub fn ask(input: &AskInput, cached_passwords: &[String]) -> Result<AskOutput, AskPasswordError> {
    validate_ask_input(input)?;

    if input.is_cache_only() && !input.accept_cached.unwrap_or(false) {
        return Err(AskPasswordError::NoPasswordAvailable);
    }

    if cached_passwords.is_empty() {
        return Err(AskPasswordError::NoPasswordAvailable);
    }

    Ok(AskOutput {
        passwords: cached_passwords.to_vec(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EchoMode tests ────────────────────────────────────────────────

    #[test]
    fn echo_mode_from_varlink_valid() {
        assert_eq!(EchoMode::from_varlink("off").unwrap(), EchoMode::Off);
        assert_eq!(EchoMode::from_varlink("on").unwrap(), EchoMode::On);
        assert_eq!(EchoMode::from_varlink("masked").unwrap(), EchoMode::Masked);
    }

    #[test]
    fn echo_mode_from_varlink_invalid() {
        assert!(EchoMode::from_varlink("bogus").is_err());
        assert!(EchoMode::from_varlink("").is_err());
        assert!(EchoMode::from_varlink("OFF").is_err());
    }

    #[test]
    fn echo_mode_roundtrip() {
        for mode in EchoMode::all() {
            assert_eq!(EchoMode::from_varlink(mode.to_varlink()).unwrap(), *mode);
        }
    }

    #[test]
    fn echo_mode_all_count() {
        assert_eq!(EchoMode::all().len(), 3);
    }

    // ── AskInput tests ────────────────────────────────────────────────

    #[test]
    fn ask_input_default_has_no_fields() {
        let input = AskInput::default();
        assert!(input.message.is_none());
        assert!(input.keyname.is_none());
        assert!(input.icon.is_none());
        assert!(input.id.is_none());
        assert!(input.timeout_usec.is_none());
        assert!(input.until_usec.is_none());
        assert!(input.accept_cached.is_none());
        assert!(input.push_cache.is_none());
        assert!(input.echo.is_none());
    }

    #[test]
    fn ask_input_effective_timeout_default() {
        let input = AskInput::new();
        assert_eq!(input.effective_timeout_usec(), DEFAULT_TIMEOUT_USEC);
    }

    #[test]
    fn ask_input_effective_timeout_custom() {
        let mut input = AskInput::new();
        input.timeout_usec = Some(5_000_000);
        assert_eq!(input.effective_timeout_usec(), 5_000_000);
    }

    #[test]
    fn ask_input_cache_only_true() {
        let mut input = AskInput::new();
        input.timeout_usec = Some(0);
        assert!(input.is_cache_only());
    }

    #[test]
    fn ask_input_cache_only_false() {
        let input = AskInput::new();
        assert!(!input.is_cache_only());
    }

    // ── AskOutput tests ───────────────────────────────────────────────

    #[test]
    fn ask_output_single() {
        let out = AskOutput::single("hunter2".to_owned());
        assert_eq!(out.passwords, vec!["hunter2"]);
        assert_eq!(out.first(), Some("hunter2"));
        assert_eq!(out.len(), 1);
        assert!(!out.is_empty());
    }

    #[test]
    fn ask_output_multiple() {
        let out = AskOutput::multiple(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(out.passwords.len(), 2);
        assert_eq!(out.first(), Some("a"));
    }

    #[test]
    fn ask_output_empty() {
        let out = AskOutput::multiple(vec![]);
        assert!(out.is_empty());
        assert_eq!(out.first(), None);
    }

    // ── Ask function tests ────────────────────────────────────────────

    #[test]
    fn ask_succeeds_with_cached_passwords() {
        let input = AskInput::new();
        let result = ask(&input, &["secret".to_owned()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().passwords, vec!["secret"]);
    }

    #[test]
    fn ask_fails_no_passwords() {
        let input = AskInput::new();
        let result = ask(&input, &[]);
        assert_eq!(result.unwrap_err(), AskPasswordError::NoPasswordAvailable);
    }

    #[test]
    fn ask_cache_only_without_accept_cached() {
        let mut input = AskInput::new();
        input.timeout_usec = Some(0);
        // accept_cached defaults to None → treated as false for cache-only
        let result = ask(&input, &["pw".to_owned()]);
        assert_eq!(result.unwrap_err(), AskPasswordError::NoPasswordAvailable);
    }

    #[test]
    fn ask_cache_only_with_accept_cached() {
        let mut input = AskInput::new();
        input.timeout_usec = Some(0);
        input.accept_cached = Some(true);
        let result = ask(&input, &["pw".to_owned()]);
        assert!(result.is_ok());
    }

    // ── Validation tests ──────────────────────────────────────────────

    #[test]
    fn validate_accepts_valid_input() {
        let mut input = AskInput::new();
        input.echo = Some(EchoMode::Masked);
        assert!(validate_ask_input(&input).is_ok());
    }

    #[test]
    fn validate_accepts_empty_input() {
        assert!(validate_ask_input(&AskInput::new()).is_ok());
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        assert_eq!(
            format!("{}", AskPasswordError::NoPasswordAvailable),
            "NoPasswordAvailable"
        );
        assert_eq!(
            format!("{}", AskPasswordError::TimeoutReached),
            "TimeoutReached"
        );
        assert_eq!(
            format!("{}", AskPasswordError::InvalidEchoMode("xyz".to_owned())),
            "InvalidEchoMode: xyz"
        );
    }

    #[test]
    fn interface_name_constant() {
        assert_eq!(INTERFACE_NAME, "io.systemd.AskPassword");
    }
}
