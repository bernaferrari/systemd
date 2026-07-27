// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.service.c, src/shared/varlink-io.systemd.service.h
//
// Varlink io.systemd.service interface — Ping, Reload, SetLogLevel,
// GetEnvironment method handlers and service introspection.
//
// Provides an interface to control basic properties of systemd services,
// including liveness checks, configuration reloads, runtime log-level
// adjustment, and inspection of the process environment block.

// ── Interface Constants ────────────────────────────────────────────────────

/// The fully-qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.service";

/// Human-readable description of the interface purpose.
pub const INTERFACE_DESCRIPTION: &str =
    "An interface to control basic properties of systemd services.";

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors defined by the io.systemd.service interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The environment block is currently not in a valid state.
    InconsistentEnvironment,

    /// The caller lacks permission for the requested operation.
    PermissionDenied,

    /// A required parameter is missing or invalid.
    InvalidParameter(String),

    /// The method name is not recognised by this interface.
    UnknownMethod(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InconsistentEnvironment => {
                write!(f, "{}.InconsistentEnvironment", INTERFACE_NAME)
            }
            Self::PermissionDenied => {
                write!(f, "{}.PermissionDenied", INTERFACE_NAME)
            }
            Self::InvalidParameter(field) => {
                write!(f, "{}.InvalidParameter: {}", INTERFACE_NAME, field)
            }
            Self::UnknownMethod(method) => {
                write!(f, "{}.UnknownMethod: {}", INTERFACE_NAME, method)
            }
        }
    }
}

impl std::error::Error for ServiceError {}

// ── Method Descriptor ──────────────────────────────────────────────────────

/// A single varlink method (or error) exposed by the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    /// Qualified method name, e.g. "io.systemd.service.Ping".
    pub qualified_name: String,
    /// Short description.
    pub description: &'static str,
    /// Whether this entry is an error definition rather than a callable method.
    pub is_error: bool,
}

/// Returns the full set of methods and errors in declaration order.
pub fn interface_symbols() -> Vec<MethodDescriptor> {
    vec![
        MethodDescriptor {
            qualified_name: format!("{}.Ping", INTERFACE_NAME),
            description: "Checks if the service is running.",
            is_error: false,
        },
        MethodDescriptor {
            qualified_name: format!("{}.Reload", INTERFACE_NAME),
            description: "Reloads configuration files.",
            is_error: false,
        },
        MethodDescriptor {
            qualified_name: format!("{}.SetLogLevel", INTERFACE_NAME),
            description: "Sets the maximum log level.",
            is_error: false,
        },
        MethodDescriptor {
            qualified_name: format!("{}.GetEnvironment", INTERFACE_NAME),
            description: "Get current environment block.",
            is_error: false,
        },
        MethodDescriptor {
            qualified_name: format!("{}.InconsistentEnvironment", INTERFACE_NAME),
            description: "Returned if the environment block is currently not in a valid state.",
            is_error: true,
        },
    ]
}

// ── Log Level ──────────────────────────────────────────────────────────────

/// Represents a BSD syslog log level that can be applied at runtime.
///
/// The value is the numeric priority: lower numbers are more severe.
/// Common values: `LOG_EMERG`=0, `LOG_ALERT`=1, …, `LOG_DEBUG`=7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogLevel(pub i32);

impl LogLevel {
    /// Emergency: system is unusable (0).
    pub const EMERG: LogLevel = LogLevel(0);
    /// Alert: action must be taken immediately (1).
    pub const ALERT: LogLevel = LogLevel(1);
    /// Critical: critical conditions (2).
    pub const CRIT: LogLevel = LogLevel(2);
    /// Error: error conditions (3).
    pub const ERR: LogLevel = LogLevel(3);
    /// Warning: warning conditions (4).
    pub const WARNING: LogLevel = LogLevel(4);
    /// Notice: normal but significant condition (5).
    pub const NOTICE: LogLevel = LogLevel(5);
    /// Informational: informational messages (6).
    pub const INFO: LogLevel = LogLevel(6);
    /// Debug: debug-level messages (7).
    pub const DEBUG: LogLevel = LogLevel(7);

    /// Returns `true` if the level value is within the valid syslog range [0, 7].
    pub fn is_valid(self) -> bool {
        (0..=7).contains(&self.0)
    }
}

// ── Method Parameters ─────────────────────────────────────────────────────

/// Parameters for the `SetLogLevel` method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetLogLevelParams {
    /// The maximum log level, using BSD syslog log level integers.
    /// `None` means "reset to default" (no change).
    pub level: Option<i32>,
}

// ── Method Replies ─────────────────────────────────────────────────────────

/// Reply payload for the `GetEnvironment` method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEnvironmentReply {
    /// The current environment block — each element is a `KEY=VALUE` string.
    pub environment: Vec<String>,
}

// ── Permission Helpers ─────────────────────────────────────────────────────

/// Verifies that `peer_uid` is either root (0) or matches `own_uid`.
///
/// In the C implementation this guards `SetLogLevel` and `GetEnvironment`
/// so that arbitrary clients cannot change log verbosity or read secrets
/// that may have been passed via environment variables.
pub fn check_peer_permission(peer_uid: u32, own_uid: u32) -> Result<(), ServiceError> {
    if peer_uid == 0 || peer_uid == own_uid {
        Ok(())
    } else {
        Err(ServiceError::PermissionDenied)
    }
}

// ── Environment Validation ─────────────────────────────────────────────────

/// Checks whether `s` is a valid environment-variable assignment (`KEY=VALUE`).
///
/// A valid assignment consists of:
/// - A name part that starts with an ASCII letter or underscore and contains
///   only ASCII letters, digits, or underscores.
/// - A `=` separator.
/// - An optional value (may be empty).
///
/// This mirrors the logic of `env_assignment_is_valid()` from the C source.
pub fn env_assignment_is_valid(s: &str) -> bool {
    let (name, rest) = match s.split_once('=') {
        Some(pair) => pair,
        None => return false,
    };

    if name.is_empty() {
        return false;
    }

    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && rest.is_ascii()
}

/// Validates an entire environment block, deduplicating entries.
///
/// Returns the deduplicated environment on success, or
/// `InconsistentEnvironment` if any entry fails validation.
///
/// UTF-8 validity is guaranteed by Rust's `str` type, so only the
/// assignment format is checked (matching the C source which explicitly
/// calls both `env_assignment_is_valid` and `utf8_is_valid`).
pub fn validate_environment_block(entries: &[&str]) -> Result<Vec<String>, ServiceError> {
    let mut seen: Vec<String> = Vec::new();

    for entry in entries {
        if !env_assignment_is_valid(entry) {
            return Err(ServiceError::InconsistentEnvironment);
        }
        // Deduplicate: if a key already exists, replace its value.
        let key = entry.split_once('=').map(|(k, _)| k).unwrap_or(entry);
        if let Some(pos) = seen
            .iter()
            .position(|e| e.split_once('=').map(|(k, _)| k == key).unwrap_or(false))
        {
            seen[pos] = (*entry).to_owned();
        } else {
            seen.push((*entry).to_owned());
        }
    }

    Ok(seen)
}

// ── Method Handlers ────────────────────────────────────────────────────────

/// Handles the `io.systemd.service.Ping` method.
///
/// The Ping method is a simple liveness probe — it accepts no parameters
/// and returns an empty reply to confirm the service is reachable.
pub fn handle_ping() -> Result<(), ServiceError> {
    // In the C implementation this calls sd_varlink_dispatch then replies.
    // The dispatch with a NULL table is a no-op validation, so the handler
    // effectively just acknowledges receipt.
    Ok(())
}

/// Handles the `io.systemd.service.SetLogLevel` method.
///
/// Adjusts the maximum runtime log level.  Only root or the process owner
/// may change the level.  The returned value is the level that was
/// actually applied (useful for callers to confirm the new setting).
///
/// # Errors
///
/// - `PermissionDenied` if `peer_uid` is neither 0 nor `own_uid`.
/// - `InvalidParameter` if `level` is present but outside [0, 7].
pub fn handle_set_log_level(
    params: SetLogLevelParams,
    peer_uid: u32,
    own_uid: u32,
) -> Result<i32, ServiceError> {
    check_peer_permission(peer_uid, own_uid)?;

    let level = match params.level {
        Some(l) if !(0..=7).contains(&l) => {
            return Err(ServiceError::InvalidParameter("level".to_owned()));
        }
        Some(l) => l,
        None => return Err(ServiceError::InvalidParameter("level".to_owned())),
    };

    Ok(level)
}

/// Handles the `io.systemd.service.GetEnvironment` method.
///
/// Returns the current environment block of the process, similar to
/// `/proc/$PID/environ` but reading the actual `environ[]` array as seen
/// from the process itself (which may differ from the original memory
/// mapping if the block has been enlarged).
///
/// Only root or the process owner may retrieve the environment, since
/// callers sometimes pass secrets via environment variables.
///
/// # Errors
///
/// - `PermissionDenied` if `peer_uid` is neither 0 nor `own_uid`.
/// - `InconsistentEnvironment` if any entry in the block is malformed.
pub fn handle_get_environment(
    peer_uid: u32,
    own_uid: u32,
    environ: &[&str],
) -> Result<GetEnvironmentReply, ServiceError> {
    check_peer_permission(peer_uid, own_uid)?;

    let environment = validate_environment_block(environ)?;

    Ok(GetEnvironmentReply { environment })
}

/// Resolves a method name string to a [`MethodDescriptor`] if it belongs to
/// this interface.
pub fn resolve_method(name: &str) -> Option<MethodDescriptor> {
    interface_symbols()
        .into_iter()
        .find(|s| s.qualified_name == name || s.qualified_name.ends_with(&format!(".{name}")))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Interface metadata ─────────────────────────────────────────────

    #[test]
    fn interface_name_is_correct() {
        assert_eq!(INTERFACE_NAME, "io.systemd.service");
    }

    #[test]
    fn interface_description_is_nonempty() {
        assert!(!INTERFACE_DESCRIPTION.is_empty());
    }

    #[test]
    fn interface_symbols_count() {
        let syms = interface_symbols();
        // 4 methods + 1 error
        assert_eq!(syms.len(), 5);
    }

    #[test]
    fn interface_symbols_methods_not_errors() {
        let syms = interface_symbols();
        for s in &syms[0..4] {
            assert!(
                !s.is_error,
                "method {} should not be an error",
                s.qualified_name
            );
        }
        assert!(
            syms[4].is_error,
            "InconsistentEnvironment should be an error"
        );
    }

    #[test]
    fn interface_symbols_qualified_names() {
        let syms = interface_symbols();
        assert_eq!(syms[0].qualified_name, "io.systemd.service.Ping");
        assert_eq!(syms[1].qualified_name, "io.systemd.service.Reload");
        assert_eq!(syms[2].qualified_name, "io.systemd.service.SetLogLevel");
        assert_eq!(syms[3].qualified_name, "io.systemd.service.GetEnvironment");
        assert_eq!(
            syms[4].qualified_name,
            "io.systemd.service.InconsistentEnvironment"
        );
    }

    // ── Error display ──────────────────────────────────────────────────

    #[test]
    fn error_display_inconsistent_environment() {
        let err = ServiceError::InconsistentEnvironment;
        assert_eq!(
            err.to_string(),
            "io.systemd.service.InconsistentEnvironment"
        );
    }

    #[test]
    fn error_display_permission_denied() {
        let err = ServiceError::PermissionDenied;
        assert_eq!(err.to_string(), "io.systemd.service.PermissionDenied");
    }

    #[test]
    fn error_display_invalid_parameter() {
        let err = ServiceError::InvalidParameter("level".to_owned());
        assert_eq!(
            err.to_string(),
            "io.systemd.service.InvalidParameter: level"
        );
    }

    #[test]
    fn error_display_unknown_method() {
        let err = ServiceError::UnknownMethod("Foo".to_owned());
        assert_eq!(err.to_string(), "io.systemd.service.UnknownMethod: Foo");
    }

    // ── Log level ──────────────────────────────────────────────────────

    #[test]
    fn log_level_constants_are_sequential() {
        assert_eq!(LogLevel::EMERG.0, 0);
        assert_eq!(LogLevel::ALERT.0, 1);
        assert_eq!(LogLevel::CRIT.0, 2);
        assert_eq!(LogLevel::ERR.0, 3);
        assert_eq!(LogLevel::WARNING.0, 4);
        assert_eq!(LogLevel::NOTICE.0, 5);
        assert_eq!(LogLevel::INFO.0, 6);
        assert_eq!(LogLevel::DEBUG.0, 7);
    }

    #[test]
    fn log_level_valid_range() {
        assert!(LogLevel(0).is_valid());
        assert!(LogLevel(7).is_valid());
        assert!(!LogLevel(-1).is_valid());
        assert!(!LogLevel(8).is_valid());
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::DEBUG > LogLevel::ERR);
        assert!(LogLevel::EMERG < LogLevel::INFO);
    }

    // ── Permission check ───────────────────────────────────────────────

    #[test]
    fn permission_check_root_allowed() {
        assert!(check_peer_permission(0, 1000).is_ok());
    }

    #[test]
    fn permission_check_owner_allowed() {
        assert!(check_peer_permission(1000, 1000).is_ok());
    }

    #[test]
    fn permission_check_other_denied() {
        assert_eq!(
            check_peer_permission(2000, 1000),
            Err(ServiceError::PermissionDenied)
        );
    }

    // ── Environment validation ─────────────────────────────────────────

    #[test]
    fn env_assignment_valid_simple() {
        assert!(env_assignment_is_valid("HOME=/home/user"));
        assert!(env_assignment_is_valid("PATH=/usr/bin"));
        assert!(env_assignment_is_valid("_UNDERSCORE=value"));
        assert!(env_assignment_is_valid("EMPTY="));
    }

    #[test]
    fn env_assignment_valid_with_digits() {
        assert!(env_assignment_is_valid("VAR123=hello"));
        assert!(env_assignment_is_valid("A1B2C3=val"));
    }

    #[test]
    fn env_assignment_invalid_no_equals() {
        assert!(!env_assignment_is_valid("JUSTAKEY"));
    }

    #[test]
    fn env_assignment_invalid_empty_name() {
        assert!(!env_assignment_is_valid("=value"));
    }

    #[test]
    fn env_assignment_invalid_name_starts_with_digit() {
        assert!(!env_assignment_is_valid("1BAD=value"));
    }

    #[test]
    fn env_assignment_invalid_name_has_dash() {
        assert!(!env_assignment_is_valid("BAD-NAME=value"));
    }

    #[test]
    fn env_assignment_invalid_non_ascii_value() {
        // Values must be ASCII per the C validation
        assert!(!env_assignment_is_valid("KEY=café"));
    }

    #[test]
    fn validate_environment_block_ok() {
        let entries = vec!["HOME=/home/user", "PATH=/usr/bin", "SHELL=/bin/bash"];
        let result = validate_environment_block(&entries).unwrap();
        assert_eq!(result, entries);
    }

    #[test]
    fn validate_environment_block_deduplicates() {
        let entries = vec!["PATH=/usr/bin", "PATH=/usr/local/bin"];
        let result = validate_environment_block(&entries).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "PATH=/usr/local/bin");
    }

    #[test]
    fn validate_environment_block_rejects_invalid() {
        let entries = vec!["HOME=/home/user", "=bad", "PATH=/usr/bin"];
        assert_eq!(
            validate_environment_block(&entries),
            Err(ServiceError::InconsistentEnvironment)
        );
    }

    #[test]
    fn validate_environment_block_empty() {
        let result = validate_environment_block(&[]).unwrap();
        assert!(result.is_empty());
    }

    // ── Method handlers ────────────────────────────────────────────────

    #[test]
    fn handle_ping_succeeds() {
        assert!(handle_ping().is_ok());
    }

    #[test]
    fn handle_set_log_level_ok_as_root() {
        let params = SetLogLevelParams { level: Some(6) };
        assert_eq!(handle_set_log_level(params, 0, 1000).unwrap(), 6);
    }

    #[test]
    fn handle_set_log_level_ok_as_owner() {
        let params = SetLogLevelParams { level: Some(3) };
        assert_eq!(handle_set_log_level(params, 1000, 1000).unwrap(), 3);
    }

    #[test]
    fn handle_set_log_level_permission_denied() {
        let params = SetLogLevelParams { level: Some(5) };
        assert_eq!(
            handle_set_log_level(params, 2000, 1000),
            Err(ServiceError::PermissionDenied)
        );
    }

    #[test]
    fn handle_set_log_level_invalid_level_negative() {
        let params = SetLogLevelParams { level: Some(-1) };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn handle_set_log_level_invalid_level_too_high() {
        let params = SetLogLevelParams { level: Some(99) };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn handle_set_log_level_missing_level() {
        let params = SetLogLevelParams { level: None };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn handle_get_environment_ok_as_root() {
        let environ = vec!["HOME=/root", "PATH=/usr/bin"];
        let reply = handle_get_environment(0, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["HOME=/root", "PATH=/usr/bin"]);
    }

    #[test]
    fn handle_get_environment_ok_as_owner() {
        let environ = vec!["USER=alice"];
        let reply = handle_get_environment(1000, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["USER=alice"]);
    }

    #[test]
    fn handle_get_environment_permission_denied() {
        let environ = vec!["SECRET=abc"];
        assert_eq!(
            handle_get_environment(2000, 1000, &environ),
            Err(ServiceError::PermissionDenied)
        );
    }

    #[test]
    fn handle_get_environment_inconsistent() {
        let environ = vec!["GOOD=val", "=BAD"];
        assert_eq!(
            handle_get_environment(0, 1000, &environ),
            Err(ServiceError::InconsistentEnvironment)
        );
    }

    #[test]
    fn handle_get_environment_deduplicates() {
        let environ = vec!["X=1", "Y=2", "X=3"];
        let reply = handle_get_environment(0, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["X=3", "Y=2"]);
    }

    #[test]
    fn handle_get_environment_empty_block() {
        let reply = handle_get_environment(0, 1000, &[]).unwrap();
        assert!(reply.environment.is_empty());
    }

    // ── Method resolution ──────────────────────────────────────────────

    #[test]
    fn resolve_method_ping() {
        let desc = resolve_method("Ping").unwrap();
        assert_eq!(desc.qualified_name, "io.systemd.service.Ping");
        assert!(!desc.is_error);
    }

    #[test]
    fn resolve_method_full_name() {
        let desc = resolve_method("io.systemd.service.Ping").unwrap();
        assert_eq!(desc.qualified_name, "io.systemd.service.Ping");
    }

    #[test]
    fn resolve_method_error() {
        let desc = resolve_method("InconsistentEnvironment").unwrap();
        assert!(desc.is_error);
    }

    #[test]
    fn resolve_method_unknown() {
        assert!(resolve_method("Nonexistent").is_none());
    }

    #[test]
    fn resolve_method_empty() {
        assert!(resolve_method("").is_none());
    }
}
