// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/log-assert-critical.c, src/shared/log-assert-critical.h
//
// Log assertion criticality configuration.
//
// Controls whether assert_return() failures are logged at LOG_CRIT level
// (critical mode) or LOG_DEBUG level. In developer builds, critical mode
// is enabled by default. In production builds, it defaults to off.
//
// The behavior can be overridden at runtime via the
// $SYSTEMD_ASSERT_RETURN_IS_CRITICAL environment variable, which accepts
// the same boolean strings as systemd's parse_boolean()
// ("1", "yes", "y", "true", "t", "on" / "0", "no", "n", "false", "f", "off").

use std::env;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

// ── Build configuration ────────────────────────────────────────────────────

/// Whether this is a developer build. In developer mode, assert_return()
/// failures default to critical (LOG_CRIT) logging.
#[cfg(feature = "developer-mode")]
const BUILD_MODE_DEVELOPER: bool = true;

#[cfg(not(feature = "developer-mode"))]
const BUILD_MODE_DEVELOPER: bool = false;

// ── Constants ──────────────────────────────────────────────────────────────

/// Sentinel value indicating the environment cache has not been populated.
const ENV_CACHE_UNSET: i32 = i32::MIN;

/// Environment variable name for controlling assert criticality.
const ENV_VAR_ASSERT_RETURN_IS_CRITICAL: &str = "SYSTEMD_ASSERT_RETURN_IS_CRITICAL";

/// -ENXIO: environment variable not set.
const ENXIO: i32 = -6;

/// -EINVAL: invalid boolean value.
const EINVAL: i32 = -22;

// ── Error types ────────────────────────────────────────────────────────────

/// Errors that can occur when parsing a boolean string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseBoolError {
    /// The string is not a recognized boolean value.
    InvalidValue(String),
}

impl std::fmt::Display for ParseBoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseBoolError::InvalidValue(v) => write!(f, "invalid boolean value: {v}"),
        }
    }
}

impl std::error::Error for ParseBoolError {}

// ── Global state ───────────────────────────────────────────────────────────

/// Whether assert_return() failures are logged at critical level.
/// Defaults to BUILD_MODE_DEVELOPER.
static ASSERT_RETURN_IS_CRITICAL: AtomicBool = AtomicBool::new(BUILD_MODE_DEVELOPER);

/// Cached result of parsing the environment variable.
///
/// * `ENV_CACHE_UNSET` — not yet read
/// * `>= 0` — parsed boolean (0 = false, 1 = true)
/// * `ENXIO` — variable not set
/// * other negative — parse error
static ENV_CACHE: AtomicI32 = AtomicI32::new(ENV_CACHE_UNSET);

// ── Public API ─────────────────────────────────────────────────────────────

/// Get whether assert_return() failures are logged at critical level.
///
/// When `true`, failed `assert_return()` calls produce `LOG_CRIT` messages.
/// When `false`, they produce `LOG_DEBUG` messages instead.
pub fn log_get_assert_return_is_critical() -> bool {
    ASSERT_RETURN_IS_CRITICAL.load(Ordering::Relaxed)
}

/// Set whether assert_return() failures are logged at critical level.
///
/// This overrides the build-time default and any environment variable setting.
pub fn log_set_assert_return_is_critical(critical: bool) {
    ASSERT_RETURN_IS_CRITICAL.store(critical, Ordering::Relaxed);
}

/// Configure assert_return criticality from the environment variable.
///
/// Reads `$SYSTEMD_ASSERT_RETURN_IS_CRITICAL`. If set to a recognized boolean
/// value, updates the critical flag accordingly. If unset, the current default
/// is kept. Parse errors are silently ignored (matching the C behavior of
/// logging at debug level and continuing).
///
/// The result is cached after the first call; subsequent calls re-apply the
/// cached value idempotently.
pub fn log_set_assert_return_is_critical_from_env() {
    let cached = ENV_CACHE.load(Ordering::Relaxed);

    if cached == ENV_CACHE_UNSET {
        // First call — read and parse the environment variable.
        let cache_value = match read_env_bool(ENV_VAR_ASSERT_RETURN_IS_CRITICAL) {
            Ok(Some(true)) => 1,
            Ok(Some(false)) => 0,
            Ok(None) => ENXIO,
            Err(_) => EINVAL,
        };

        // Store cache value before applying so concurrent callers see it.
        ENV_CACHE.store(cache_value, Ordering::Relaxed);

        if cache_value >= 0 {
            ASSERT_RETURN_IS_CRITICAL.store(cache_value != 0, Ordering::Relaxed);
        }
    } else if cached >= 0 {
        // Cached and valid — re-apply idempotently.
        ASSERT_RETURN_IS_CRITICAL.store(cached != 0, Ordering::Relaxed);
    }
    // If cached < 0 (ENXIO or EINVAL), do nothing — keep current default.
}

// ── Environment parsing ────────────────────────────────────────────────────

/// Read a boolean environment variable.
///
/// Returns `Ok(Some(bool))` for recognized values, `Ok(None)` if unset,
/// or `Err(ParseBoolError)` if the value is not a valid boolean string.
fn read_env_bool(var_name: &str) -> Result<Option<bool>, ParseBoolError> {
    match env::var(var_name) {
        Ok(value) => parse_boolean(&value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(ParseBoolError::InvalidValue("(non-UTF-8)".to_string()))
        }
    }
}

/// Parse a string as a boolean, matching systemd's `parse_boolean()`.
///
/// Recognized true values (case-insensitive): `"1"`, `"yes"`, `"y"`,
/// `"true"`, `"t"`, `"on"`.
///
/// Recognized false values (case-insensitive): `"0"`, `"no"`, `"n"`,
/// `"false"`, `"f"`, `"off"`.
///
/// Empty string is treated as unset and returns `Err(ParseBoolError)`
/// (matching C behavior where empty string is not a valid boolean).
pub fn parse_boolean(s: &str) -> Result<bool, ParseBoolError> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Ok(false),
        other => Err(ParseBoolError::InvalidValue(other.to_string())),
    }
}

// ── Test helpers ───────────────────────────────────────────────────────────

/// Reset global state to build defaults. Only available in test builds.
#[cfg(test)]
fn reset_state() {
    ASSERT_RETURN_IS_CRITICAL.store(BUILD_MODE_DEVELOPER, Ordering::Relaxed);
    ENV_CACHE.store(ENV_CACHE_UNSET, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Getter / setter tests ──────────────────────────────────────────────

    #[test]
    fn test_default_matches_build_mode() {
        reset_state();
        assert_eq!(log_get_assert_return_is_critical(), BUILD_MODE_DEVELOPER);
    }

    #[test]
    fn test_set_critical_true() {
        reset_state();
        log_set_assert_return_is_critical(true);
        assert!(log_get_assert_return_is_critical());
    }

    #[test]
    fn test_set_critical_false() {
        reset_state();
        log_set_assert_return_is_critical(false);
        assert!(!log_get_assert_return_is_critical());
    }

    #[test]
    fn test_toggle_critical() {
        reset_state();
        let initial = log_get_assert_return_is_critical();
        log_set_assert_return_is_critical(!initial);
        assert_ne!(log_get_assert_return_is_critical(), initial);
        log_set_assert_return_is_critical(initial);
        assert_eq!(log_get_assert_return_is_critical(), initial);
    }

    // ── parse_boolean tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_boolean_true_values() {
        for val in &["1", "yes", "y", "true", "t", "on"] {
            assert_eq!(parse_boolean(val), Ok(true), "expected true for {val:?}");
        }
    }

    #[test]
    fn test_parse_boolean_true_case_insensitive() {
        for val in &["YES", "Yes", "TRUE", "True", "ON", "On", "Y", "T"] {
            assert_eq!(parse_boolean(val), Ok(true), "expected true for {val:?}");
        }
    }

    #[test]
    fn test_parse_boolean_false_values() {
        for val in &["0", "no", "n", "false", "f", "off"] {
            assert_eq!(parse_boolean(val), Ok(false), "expected false for {val:?}");
        }
    }

    #[test]
    fn test_parse_boolean_false_case_insensitive() {
        for val in &["NO", "No", "FALSE", "False", "OFF", "Off", "N", "F"] {
            assert_eq!(parse_boolean(val), Ok(false), "expected false for {val:?}");
        }
    }

    #[test]
    fn test_parse_boolean_invalid() {
        assert!(parse_boolean("").is_err());
        assert!(parse_boolean("maybe").is_err());
        assert!(parse_boolean("2").is_err());
        assert!(parse_boolean("enabled").is_err());
        assert!(parse_boolean("  yes  ").is_err());
    }

    #[test]
    fn test_parse_boolean_error_preserves_value() {
        let err = parse_boolean("garbage").unwrap_err();
        assert_eq!(err, ParseBoolError::InvalidValue("garbage".to_string()));
        assert!(err.to_string().contains("garbage"));
    }

    // ── from_env tests ────────────────────────────────────────────────────

    #[test]
    fn test_from_env_all() {
        reset_state();
        env::remove_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL);
        log_set_assert_return_is_critical_from_env();
        assert_eq!(log_get_assert_return_is_critical(), BUILD_MODE_DEVELOPER);

        reset_state();
        env::set_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL, "1");
        log_set_assert_return_is_critical_from_env();
        assert!(log_get_assert_return_is_critical());

        reset_state();
        env::set_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL, "no");
        log_set_assert_return_is_critical_from_env();
        assert!(!log_get_assert_return_is_critical());

        reset_state();
        env::set_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL, "garbage");
        log_set_assert_return_is_critical_from_env();
        assert_eq!(log_get_assert_return_is_critical(), BUILD_MODE_DEVELOPER);

        reset_state();
        env::set_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL, "true");
        log_set_assert_return_is_critical_from_env();
        env::remove_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL);
        log_set_assert_return_is_critical_from_env();
        assert!(log_get_assert_return_is_critical());

        reset_state();
        log_set_assert_return_is_critical(false);
        env::set_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL, "yes");
        log_set_assert_return_is_critical_from_env();
        assert!(log_get_assert_return_is_critical());

        env::remove_var(ENV_VAR_ASSERT_RETURN_IS_CRITICAL);
    }

    // ── Constants / type tests ─────────────────────────────────────────────

    #[test]
    fn test_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ParseBoolError::InvalidValue("x".into()));
        assert!(err.to_string().contains("x"));
    }
}
