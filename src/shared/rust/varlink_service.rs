// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.service.c,
//           src/shared/varlink-io.systemd.service.h
//
// Varlink interface definition for io.systemd.service.
//
// An interface to control basic properties of systemd services.
// Provides liveness probes (Ping), configuration reloads (Reload),
// runtime log-level adjustment (SetLogLevel), and inspection of
// the process environment block (GetEnvironment).

// ── Interface Constants ────────────────────────────────────────────────────

/// The fully-qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.service";

/// Human-readable description of the interface purpose.
pub const INTERFACE_DESCRIPTION: &str =
    "An interface to control basic properties of systemd services.";

/// Fully-qualified method name for Ping.
pub const METHOD_PING: &str = "io.systemd.service.Ping";

/// Fully-qualified method name for Reload.
pub const METHOD_RELOAD: &str = "io.systemd.service.Reload";

/// Fully-qualified method name for SetLogLevel.
pub const METHOD_SET_LOG_LEVEL: &str = "io.systemd.service.SetLogLevel";

/// Fully-qualified method name for GetEnvironment.
pub const METHOD_GET_ENVIRONMENT: &str = "io.systemd.service.GetEnvironment";

/// Fully-qualified error name for InconsistentEnvironment.
pub const ERROR_INCONSISTENT_ENVIRONMENT: &str = "io.systemd.service.InconsistentEnvironment";

/// Parameter name: level (SetLogLevel input).
pub const PARAM_LEVEL: &str = "level";

/// Parameter name: environment (GetEnvironment output).
pub const PARAM_ENVIRONMENT: &str = "environment";

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
                write!(f, "org.varlink.service.PermissionDenied")
            }
            Self::InvalidParameter(field) => {
                write!(f, "org.varlink.service.InvalidParameter: {}", field)
            }
            Self::UnknownMethod(method) => {
                write!(f, "org.varlink.service.MethodNotFound: {}", method)
            }
        }
    }
}

impl std::error::Error for ServiceError {}

// ── Method Descriptor ──────────────────────────────────────────────────────

/// Describes a single varlink method or error exposed by the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    /// Fully-qualified name, e.g. "io.systemd.service.Ping".
    pub qualified_name: String,
    /// Short human-readable description.
    pub description: &'static str,
    /// `true` if this entry is an error definition rather than a callable method.
    pub is_error: bool,
}

/// Returns the full set of methods and errors in declaration order,
/// matching the C `SD_VARLINK_DEFINE_INTERFACE` macro expansion.
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

// ── Interface Definition (JSON) ────────────────────────────────────────────

/// Returns the varlink interface definition as a JSON string.
///
/// This corresponds to the `SD_VARLINK_DEFINE_INTERFACE(io_systemd_service, …)`
/// macro expansion in the C source, which builds the method/error descriptors
/// that varlink clients use for introspection.
pub fn get_interface_definition() -> &'static str {
    r#"{
  "methods": {
    "Ping": {
      "description": "Checks if the service is running."
    },
    "Reload": {
      "description": "Reloads configuration files."
    },
    "SetLogLevel": {
      "description": "Sets the maximum log level.",
      "parameters": {
        "level": {
          "type": "int",
          "nullable": true,
          "description": "The maximum log level, using BSD syslog log level integers."
        }
      }
    },
    "GetEnvironment": {
      "description": "Get current environment block.",
      "return": {
        "environment": {
          "type": "[]string",
          "nullable": true,
          "description": "Returns the current environment block, i.e. the contents of environ[]."
        }
      }
    }
  },
  "errors": {
    "InconsistentEnvironment": {
      "description": "Returned if the environment block is currently not in a valid state."
    }
  },
  "interface": "io.systemd.service",
  "description": "An interface to control basic properties of systemd services."
}"#
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

/// Parses a log level from an integer, returning `None` for out-of-range values.
///
/// Mirrors the `json_dispatch_log_level` dispatch used in the C implementation
/// to validate the `level` parameter of SetLogLevel.
pub fn parse_log_level(value: i32) -> Option<LogLevel> {
    let level = LogLevel(value);
    if level.is_valid() {
        Some(level)
    } else {
        None
    }
}

// ── Method Parameters & Replies ────────────────────────────────────────────

/// Parameters for the `SetLogLevel` method.
///
/// The `level` field uses `Option<i32>` to represent the varlink `nullable int`.
/// In the C source this is dispatched as a mandatory field via `SD_JSON_MANDATORY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetLogLevelParams {
    /// The maximum log level, using BSD syslog log level integers.
    /// `Some(v)` for a valid level, `None` if not provided.
    pub level: Option<i32>,
}

impl SetLogLevelParams {
    /// Create new `SetLogLevelParams` with no level set.
    pub fn new() -> Self {
        Self { level: None }
    }

    /// Set the log level (builder pattern).
    pub fn level(mut self, level: i32) -> Self {
        self.level = Some(level);
        self
    }
}

impl Default for SetLogLevelParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Reply payload for the `GetEnvironment` method.
///
/// Each element is a `KEY=VALUE` string from the process environment block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEnvironmentResult {
    /// The environment block entries.
    pub environment: Vec<String>,
}

/// Parameters for the `Ping` method (accepts no parameters).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PingParams;

/// Parameters for the `Reload` method (accepts no parameters).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadParams;

/// Empty reply for methods that return no data (Ping, Reload).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmptyReply;

// ── Permission Helpers ─────────────────────────────────────────────────────

/// Verifies that `peer_uid` is either root (0) or matches `own_uid`.
///
/// In the C implementation this guards `SetLogLevel` and `GetEnvironment`
/// so that arbitrary clients cannot change log verbosity or read secrets
/// that may have been passed via environment variables.
///
/// Returns `Ok(())` if the caller is authorised, or `Err(ServiceError::PermissionDenied)`.
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
/// - An optional value (may be empty, but must be ASCII).
///
/// Mirrors `env_assignment_is_valid()` from the C source.
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

    // Name characters must be alphanumeric or underscore
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }

    // Value must be pure ASCII (the C code calls utf8_is_valid separately,
    // but Rust's str is always valid UTF-8, so we only need the ASCII check
    // which the C env_assignment_is_valid also performs).
    rest.is_ascii()
}

/// Validates an entire environment block, deduplicating entries by key.
///
/// Returns the deduplicated environment on success, or
/// `InconsistentEnvironment` if any entry fails validation.
///
/// This mirrors the loop in `varlink_method_get_environment()` which
/// iterates `environ[]`, calling both `env_assignment_is_valid()` and
/// `utf8_is_valid()` on each entry, and using `strv_env_replace_strdup()`
/// for deduplication.
pub fn validate_environment_block(entries: &[&str]) -> Result<Vec<String>, ServiceError> {
    let mut result: Vec<String> = Vec::new();

    for entry in entries {
        if !env_assignment_is_valid(entry) {
            return Err(ServiceError::InconsistentEnvironment);
        }

        // Deduplicate: if a key already exists, replace its value.
        // This mirrors strv_env_replace_strdup() from the C source.
        let key = entry.split_once('=').map(|(k, _)| k).unwrap_or(entry);
        if let Some(pos) = result
            .iter()
            .position(|e| e.split_once('=').map(|(k, _)| k == key).unwrap_or(false))
        {
            result[pos] = (*entry).to_owned();
        } else {
            result.push((*entry).to_owned());
        }
    }

    Ok(result)
}

// ── Method Handlers ────────────────────────────────────────────────────────

/// Handles the `io.systemd.service.Ping` method.
///
/// A simple liveness probe — accepts no parameters and returns an empty
/// reply to confirm the service is reachable.
///
/// In the C implementation this calls `sd_varlink_dispatch(link, parameters, NULL, NULL)`
/// (a no-op validation) then `sd_varlink_reply(link, NULL)`.
pub fn handle_ping(_params: PingParams) -> Result<EmptyReply, ServiceError> {
    Ok(EmptyReply)
}

/// Handles the `io.systemd.service.Reload` method.
///
/// Signals that the service should reload its configuration files.
/// The C implementation defines this with `VARLINK_DEFINE_POLKIT_INPUT`
/// for PolicyKit authorisation.
pub fn handle_reload(_params: ReloadParams) -> Result<EmptyReply, ServiceError> {
    Ok(EmptyReply)
}

/// Handles the `io.systemd.service.SetLogLevel` method.
///
/// Adjusts the maximum runtime log level.  Only root or the process owner
/// may change the level.
///
/// # Errors
///
/// - `PermissionDenied` if `peer_uid` is neither 0 nor `own_uid`.
/// - `InvalidParameter` if `level` is `None` or outside the valid range [0, 7].
pub fn handle_set_log_level(
    params: SetLogLevelParams,
    peer_uid: u32,
    own_uid: u32,
) -> Result<LogLevel, ServiceError> {
    check_peer_permission(peer_uid, own_uid)?;

    let raw_level = params
        .level
        .ok_or_else(|| ServiceError::InvalidParameter(PARAM_LEVEL.to_owned()))?;

    let level = parse_log_level(raw_level)
        .ok_or_else(|| ServiceError::InvalidParameter(PARAM_LEVEL.to_owned()))?;

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
) -> Result<GetEnvironmentResult, ServiceError> {
    check_peer_permission(peer_uid, own_uid)?;

    let environment = validate_environment_block(environ)?;

    Ok(GetEnvironmentResult { environment })
}

/// Resolves a method name string to a [`MethodDescriptor`] if it belongs to
/// this interface.  Accepts both short names ("Ping") and fully-qualified
/// names ("io.systemd.service.Ping").
pub fn resolve_method(name: &str) -> Option<MethodDescriptor> {
    interface_symbols()
        .into_iter()
        .find(|s| s.qualified_name == name || s.qualified_name.ends_with(&format!(".{name}")))
}

/// Returns `true` if `name` is a known method of this interface.
pub fn is_known_method(name: &str) -> bool {
    resolve_method(name).is_some()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Interface constants ─────────────────────────────────────────────

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.service");
    }

    #[test]
    fn test_interface_description() {
        assert!(!INTERFACE_DESCRIPTION.is_empty());
        assert!(INTERFACE_DESCRIPTION.contains("systemd"));
    }

    #[test]
    fn test_method_names() {
        assert_eq!(METHOD_PING, "io.systemd.service.Ping");
        assert_eq!(METHOD_RELOAD, "io.systemd.service.Reload");
        assert_eq!(METHOD_SET_LOG_LEVEL, "io.systemd.service.SetLogLevel");
        assert_eq!(METHOD_GET_ENVIRONMENT, "io.systemd.service.GetEnvironment");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(
            ERROR_INCONSISTENT_ENVIRONMENT,
            "io.systemd.service.InconsistentEnvironment"
        );
    }

    #[test]
    fn test_param_names() {
        assert_eq!(PARAM_LEVEL, "level");
        assert_eq!(PARAM_ENVIRONMENT, "environment");
    }

    // ── Interface definition JSON ───────────────────────────────────────

    #[test]
    fn test_interface_definition_contains_interface_name() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.service"));
    }

    #[test]
    fn test_interface_definition_contains_all_methods() {
        let json = get_interface_definition();
        assert!(json.contains("\"Ping\""));
        assert!(json.contains("\"Reload\""));
        assert!(json.contains("\"SetLogLevel\""));
        assert!(json.contains("\"GetEnvironment\""));
    }

    #[test]
    fn test_interface_definition_contains_error() {
        let json = get_interface_definition();
        assert!(json.contains("\"InconsistentEnvironment\""));
    }

    #[test]
    fn test_interface_definition_contains_level_parameter() {
        let json = get_interface_definition();
        assert!(json.contains("\"level\""));
        assert!(json.contains("BSD syslog"));
    }

    #[test]
    fn test_interface_definition_contains_environment_output() {
        let json = get_interface_definition();
        assert!(json.contains("\"environment\""));
        assert!(json.contains("[]string"));
    }

    // ── Interface symbols ───────────────────────────────────────────────

    #[test]
    fn test_interface_symbols_count() {
        let syms = interface_symbols();
        assert_eq!(syms.len(), 5); // 4 methods + 1 error
    }

    #[test]
    fn test_interface_symbols_methods_not_errors() {
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
    fn test_interface_symbols_qualified_names() {
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

    // ── Error display ───────────────────────────────────────────────────

    #[test]
    fn test_error_display_inconsistent_environment() {
        let err = ServiceError::InconsistentEnvironment;
        assert_eq!(
            err.to_string(),
            "io.systemd.service.InconsistentEnvironment"
        );
    }

    #[test]
    fn test_error_display_permission_denied() {
        let err = ServiceError::PermissionDenied;
        assert_eq!(err.to_string(), "org.varlink.service.PermissionDenied");
    }

    #[test]
    fn test_error_display_invalid_parameter() {
        let err = ServiceError::InvalidParameter("level".to_owned());
        assert_eq!(
            err.to_string(),
            "org.varlink.service.InvalidParameter: level"
        );
    }

    #[test]
    fn test_error_display_unknown_method() {
        let err = ServiceError::UnknownMethod("Foo".to_owned());
        assert_eq!(err.to_string(), "org.varlink.service.MethodNotFound: Foo");
    }

    // ── Log level ───────────────────────────────────────────────────────

    #[test]
    fn test_log_level_constants() {
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
    fn test_log_level_valid_range() {
        assert!(LogLevel(0).is_valid());
        assert!(LogLevel(7).is_valid());
        assert!(!LogLevel(-1).is_valid());
        assert!(!LogLevel(8).is_valid());
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::DEBUG > LogLevel::ERR);
        assert!(LogLevel::EMERG < LogLevel::INFO);
    }

    #[test]
    fn test_parse_log_level_valid() {
        assert_eq!(parse_log_level(0), Some(LogLevel::EMERG));
        assert_eq!(parse_log_level(7), Some(LogLevel::DEBUG));
        assert_eq!(parse_log_level(3), Some(LogLevel::ERR));
    }

    #[test]
    fn test_parse_log_level_invalid() {
        assert_eq!(parse_log_level(-1), None);
        assert_eq!(parse_log_level(8), None);
        assert_eq!(parse_log_level(100), None);
    }

    // ── SetLogLevel params ──────────────────────────────────────────────

    #[test]
    fn test_set_log_level_params_builder() {
        let params = SetLogLevelParams::new().level(6);
        assert_eq!(params.level, Some(6));
    }

    #[test]
    fn test_set_log_level_params_default() {
        let params = SetLogLevelParams::default();
        assert_eq!(params.level, None);
    }

    // ── Permission check ────────────────────────────────────────────────

    #[test]
    fn test_permission_check_root_allowed() {
        assert!(check_peer_permission(0, 1000).is_ok());
    }

    #[test]
    fn test_permission_check_owner_allowed() {
        assert!(check_peer_permission(1000, 1000).is_ok());
    }

    #[test]
    fn test_permission_check_other_denied() {
        assert_eq!(
            check_peer_permission(2000, 1000),
            Err(ServiceError::PermissionDenied)
        );
    }

    // ── Environment validation ──────────────────────────────────────────

    #[test]
    fn test_env_assignment_valid_simple() {
        assert!(env_assignment_is_valid("HOME=/home/user"));
        assert!(env_assignment_is_valid("PATH=/usr/bin"));
        assert!(env_assignment_is_valid("_UNDERSCORE=value"));
        assert!(env_assignment_is_valid("EMPTY="));
    }

    #[test]
    fn test_env_assignment_valid_with_digits() {
        assert!(env_assignment_is_valid("VAR123=hello"));
        assert!(env_assignment_is_valid("A1B2C3=val"));
    }

    #[test]
    fn test_env_assignment_invalid_no_equals() {
        assert!(!env_assignment_is_valid("JUSTAKEY"));
    }

    #[test]
    fn test_env_assignment_invalid_empty_name() {
        assert!(!env_assignment_is_valid("=value"));
    }

    #[test]
    fn test_env_assignment_invalid_name_starts_with_digit() {
        assert!(!env_assignment_is_valid("1BAD=value"));
    }

    #[test]
    fn test_env_assignment_invalid_name_has_dash() {
        assert!(!env_assignment_is_valid("BAD-NAME=value"));
    }

    #[test]
    fn test_env_assignment_invalid_non_ascii_value() {
        assert!(!env_assignment_is_valid("KEY=café"));
    }

    #[test]
    fn test_validate_environment_block_ok() {
        let entries = vec!["HOME=/home/user", "PATH=/usr/bin", "SHELL=/bin/bash"];
        let result = validate_environment_block(&entries).unwrap();
        assert_eq!(result, entries);
    }

    #[test]
    fn test_validate_environment_block_deduplicates() {
        let entries = vec!["PATH=/usr/bin", "PATH=/usr/local/bin"];
        let result = validate_environment_block(&entries).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "PATH=/usr/local/bin");
    }

    #[test]
    fn test_validate_environment_block_rejects_invalid() {
        let entries = vec!["HOME=/home/user", "=bad", "PATH=/usr/bin"];
        assert_eq!(
            validate_environment_block(&entries),
            Err(ServiceError::InconsistentEnvironment)
        );
    }

    #[test]
    fn test_validate_environment_block_empty() {
        let result = validate_environment_block(&[]).unwrap();
        assert!(result.is_empty());
    }

    // ── Method handlers ────────────────────────────────────────────────

    #[test]
    fn test_handle_ping_succeeds() {
        assert!(handle_ping(PingParams).is_ok());
    }

    #[test]
    fn test_handle_reload_succeeds() {
        assert!(handle_reload(ReloadParams).is_ok());
    }

    #[test]
    fn test_handle_set_log_level_ok_as_root() {
        let params = SetLogLevelParams { level: Some(6) };
        assert_eq!(handle_set_log_level(params, 0, 1000).unwrap(), LogLevel(6));
    }

    #[test]
    fn test_handle_set_log_level_ok_as_owner() {
        let params = SetLogLevelParams { level: Some(3) };
        assert_eq!(
            handle_set_log_level(params, 1000, 1000).unwrap(),
            LogLevel(3)
        );
    }

    #[test]
    fn test_handle_set_log_level_permission_denied() {
        let params = SetLogLevelParams { level: Some(5) };
        assert_eq!(
            handle_set_log_level(params, 2000, 1000),
            Err(ServiceError::PermissionDenied)
        );
    }

    #[test]
    fn test_handle_set_log_level_invalid_negative() {
        let params = SetLogLevelParams { level: Some(-1) };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn test_handle_set_log_level_invalid_too_high() {
        let params = SetLogLevelParams { level: Some(99) };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn test_handle_set_log_level_missing_level() {
        let params = SetLogLevelParams { level: None };
        assert_eq!(
            handle_set_log_level(params, 0, 1000),
            Err(ServiceError::InvalidParameter("level".to_owned()))
        );
    }

    #[test]
    fn test_handle_get_environment_ok_as_root() {
        let environ = vec!["HOME=/root", "PATH=/usr/bin"];
        let reply = handle_get_environment(0, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["HOME=/root", "PATH=/usr/bin"]);
    }

    #[test]
    fn test_handle_get_environment_ok_as_owner() {
        let environ = vec!["USER=alice"];
        let reply = handle_get_environment(1000, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["USER=alice"]);
    }

    #[test]
    fn test_handle_get_environment_permission_denied() {
        let environ = vec!["SECRET=abc"];
        assert_eq!(
            handle_get_environment(2000, 1000, &environ),
            Err(ServiceError::PermissionDenied)
        );
    }

    #[test]
    fn test_handle_get_environment_inconsistent() {
        let environ = vec!["GOOD=val", "=BAD"];
        assert_eq!(
            handle_get_environment(0, 1000, &environ),
            Err(ServiceError::InconsistentEnvironment)
        );
    }

    #[test]
    fn test_handle_get_environment_deduplicates() {
        let environ = vec!["X=1", "Y=2", "X=3"];
        let reply = handle_get_environment(0, 1000, &environ).unwrap();
        assert_eq!(reply.environment, vec!["X=3", "Y=2"]);
    }

    #[test]
    fn test_handle_get_environment_empty_block() {
        let reply = handle_get_environment(0, 1000, &[]).unwrap();
        assert!(reply.environment.is_empty());
    }

    // ── Method resolution ───────────────────────────────────────────────

    #[test]
    fn test_resolve_method_ping() {
        let desc = resolve_method("Ping").unwrap();
        assert_eq!(desc.qualified_name, "io.systemd.service.Ping");
        assert!(!desc.is_error);
    }

    #[test]
    fn test_resolve_method_full_name() {
        let desc = resolve_method("io.systemd.service.Ping").unwrap();
        assert_eq!(desc.qualified_name, "io.systemd.service.Ping");
    }

    #[test]
    fn test_resolve_method_error() {
        let desc = resolve_method("InconsistentEnvironment").unwrap();
        assert!(desc.is_error);
    }

    #[test]
    fn test_resolve_method_unknown() {
        assert!(resolve_method("Nonexistent").is_none());
    }

    #[test]
    fn test_resolve_method_empty() {
        assert!(resolve_method("").is_none());
    }

    #[test]
    fn test_is_known_method() {
        assert!(is_known_method("Ping"));
        assert!(is_known_method("io.systemd.service.Reload"));
        assert!(is_known_method("SetLogLevel"));
        assert!(!is_known_method("Bogus"));
    }
}
