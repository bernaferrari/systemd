// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-varlink.c
//
// Varlink server method dispatch for the udev daemon.
//
// Defines the varlink address, method name constants, dispatch table
// structure, and method handler logic used by udevd to expose runtime
// control over the device manager via varlink RPC.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default varlink socket address for udevd.
pub const UDEV_VARLINK_ADDRESS: &str = "/run/udev/io.systemd.Udev";

/// Default timeout for varlink connections (in microseconds).
pub const DEFAULT_VARLINK_TIMEOUT_USEC: u64 = 60_000_000; // 60 seconds

// ── Method name constants ─────────────────────────────────────────────────

pub const METHOD_PING: &str = "io.systemd.service.Ping";
pub const METHOD_RELOAD: &str = "io.systemd.service.Reload";
pub const METHOD_SET_LOG_LEVEL: &str = "io.systemd.service.SetLogLevel";
pub const METHOD_GET_ENVIRONMENT: &str = "io.systemd.service.GetEnvironment";
pub const METHOD_SET_TRACE: &str = "io.systemd.Udev.SetTrace";
pub const METHOD_SET_CHILDREN_MAX: &str = "io.systemd.Udev.SetChildrenMax";
pub const METHOD_SET_ENVIRONMENT: &str = "io.systemd.Udev.SetEnvironment";
pub const METHOD_REVERT: &str = "io.systemd.Udev.Revert";
pub const METHOD_START_EXEC_QUEUE: &str = "io.systemd.Udev.StartExecQueue";
pub const METHOD_STOP_EXEC_QUEUE: &str = "io.systemd.Udev.StopExecQueue";
pub const METHOD_EXIT: &str = "io.systemd.Udev.Exit";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Varlink method identifiers known to udevd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarlinkMethod {
    Ping,
    Reload,
    SetLogLevel,
    GetEnvironment,
    SetTrace,
    SetChildrenMax,
    SetEnvironment,
    Revert,
    StartExecQueue,
    StopExecQueue,
    Exit,
}

impl VarlinkMethod {
    /// Convert from the string method name to the enum variant.
    pub fn from_method_name(name: &str) -> Option<VarlinkMethod> {
        match name {
            METHOD_PING => Some(VarlinkMethod::Ping),
            METHOD_RELOAD => Some(VarlinkMethod::Reload),
            METHOD_SET_LOG_LEVEL => Some(VarlinkMethod::SetLogLevel),
            METHOD_GET_ENVIRONMENT => Some(VarlinkMethod::GetEnvironment),
            METHOD_SET_TRACE => Some(VarlinkMethod::SetTrace),
            METHOD_SET_CHILDREN_MAX => Some(VarlinkMethod::SetChildrenMax),
            METHOD_SET_ENVIRONMENT => Some(VarlinkMethod::SetEnvironment),
            METHOD_REVERT => Some(VarlinkMethod::Revert),
            METHOD_START_EXEC_QUEUE => Some(VarlinkMethod::StartExecQueue),
            METHOD_STOP_EXEC_QUEUE => Some(VarlinkMethod::StopExecQueue),
            METHOD_EXIT => Some(VarlinkMethod::Exit),
            _ => None,
        }
    }

    /// Convert the enum variant to its canonical string method name.
    pub fn to_method_name(self) -> &'static str {
        match self {
            VarlinkMethod::Ping => METHOD_PING,
            VarlinkMethod::Reload => METHOD_RELOAD,
            VarlinkMethod::SetLogLevel => METHOD_SET_LOG_LEVEL,
            VarlinkMethod::GetEnvironment => METHOD_GET_ENVIRONMENT,
            VarlinkMethod::SetTrace => METHOD_SET_TRACE,
            VarlinkMethod::SetChildrenMax => METHOD_SET_CHILDREN_MAX,
            VarlinkMethod::SetEnvironment => METHOD_SET_ENVIRONMENT,
            VarlinkMethod::Revert => METHOD_REVERT,
            VarlinkMethod::StartExecQueue => METHOD_START_EXEC_QUEUE,
            VarlinkMethod::StopExecQueue => METHOD_STOP_EXEC_QUEUE,
            VarlinkMethod::Exit => METHOD_EXIT,
        }
    }

    /// Return all known method names.
    pub fn all_methods() -> &'static [VarlinkMethod] {
        &[
            VarlinkMethod::Ping,
            VarlinkMethod::Reload,
            VarlinkMethod::SetLogLevel,
            VarlinkMethod::GetEnvironment,
            VarlinkMethod::SetTrace,
            VarlinkMethod::SetChildrenMax,
            VarlinkMethod::SetEnvironment,
            VarlinkMethod::Revert,
            VarlinkMethod::StartExecQueue,
            VarlinkMethod::StopExecQueue,
            VarlinkMethod::Exit,
        ]
    }
}

// ── JSON dispatch field ───────────────────────────────────────────────────

/// Represents a JSON dispatch field used for varlink parameter parsing.
/// Mirrors the C `sd_json_dispatch_field` structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchField {
    pub name: &'static str,
    pub type_hint: DispatchType,
    pub mandatory: bool,
}

/// Expected JSON type for a dispatch field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchType {
    Invalid,
    Boolean,
    Integer,
    Unsigned,
    String,
    Array,
}

// ── Dispatch tables for each method ───────────────────────────────────────

/// Returns the dispatch fields for SetLogLevel: one mandatory "level" integer.
pub fn dispatch_set_log_level() -> Vec<DispatchField> {
    vec![DispatchField {
        name: "level",
        type_hint: DispatchType::Integer,
        mandatory: true,
    }]
}

/// Returns the dispatch fields for SetTrace: one mandatory "enable" boolean.
pub fn dispatch_set_trace() -> Vec<DispatchField> {
    vec![DispatchField {
        name: "enable",
        type_hint: DispatchType::Boolean,
        mandatory: true,
    }]
}

/// Returns the dispatch fields for SetChildrenMax: one mandatory "number" unsigned.
pub fn dispatch_set_children_max() -> Vec<DispatchField> {
    vec![DispatchField {
        name: "number",
        type_hint: DispatchType::Unsigned,
        mandatory: true,
    }]
}

/// Returns the dispatch fields for SetEnvironment: one mandatory "assignments" array.
pub fn dispatch_set_environment() -> Vec<DispatchField> {
    vec![DispatchField {
        name: "assignments",
        type_hint: DispatchType::Array,
        mandatory: true,
    }]
}

// ── Method dispatch logic ─────────────────────────────────────────────────

/// Errors that can occur during varlink method dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarlinkError {
    /// The method name is not recognized.
    UnknownMethod(String),
    /// A required parameter is missing.
    MissingParameter(&'static str),
    /// A parameter has the wrong type.
    InvalidParameterType(&'static str, DispatchType),
    /// The log level value is out of range.
    InvalidLogLevel(i32),
    /// The children max value is invalid.
    InvalidChildrenMax(u64),
    /// An environment assignment string is malformed (missing '=').
    MalformedEnvironment(String),
    /// Generic dispatch failure.
    DispatchFailed(String),
}

impl std::fmt::Display for VarlinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarlinkError::UnknownMethod(m) => write!(f, "Unknown varlink method: {m}"),
            VarlinkError::MissingParameter(p) => write!(f, "Missing required parameter: {p}"),
            VarlinkError::InvalidParameterType(p, t) => {
                write!(f, "Parameter '{p}' has wrong type, expected {t:?}")
            }
            VarlinkError::InvalidLogLevel(l) => write!(f, "Invalid log level: {l}"),
            VarlinkError::InvalidChildrenMax(n) => write!(f, "Invalid children max: {n}"),
            VarlinkError::MalformedEnvironment(s) => {
                write!(f, "Malformed environment assignment: {s}")
            }
            VarlinkError::DispatchFailed(msg) => write!(f, "Dispatch failed: {msg}"),
        }
    }
}

impl std::error::Error for VarlinkError {}

/// Result type for varlink operations.
pub type VarlinkResult<T> = Result<T, VarlinkError>;

/// Validates that environment assignment strings contain an '=' character.
pub fn validate_environment_assignments(assignments: &[&str]) -> VarlinkResult<()> {
    for a in assignments {
        if !a.contains('=') {
            return Err(VarlinkError::MalformedEnvironment(a.to_string()));
        }
    }
    Ok(())
}

/// Validates a log level value. Valid syslog levels are 0 (emerg) through 7 (debug).
pub fn validate_log_level(level: i32) -> VarlinkResult<()> {
    if (0..=7).contains(&level) {
        Ok(())
    } else {
        Err(VarlinkError::InvalidLogLevel(level))
    }
}

/// Validates that a children-max value is reasonable (fits in u32).
pub fn validate_children_max(n: u64) -> VarlinkResult<()> {
    if n <= u32::MAX as u64 {
        Ok(())
    } else {
        Err(VarlinkError::InvalidChildrenMax(n))
    }
}

/// Determines whether a method affects the exec queue state.
/// Returns `Some(true)` for StartExecQueue, `Some(false)` for StopExecQueue, `None` otherwise.
pub fn exec_queue_action(method: &VarlinkMethod) -> Option<bool> {
    match method {
        VarlinkMethod::StartExecQueue => Some(true),
        VarlinkMethod::StopExecQueue => Some(false),
        _ => None,
    }
}

/// Determines whether a method requires no parameters.
pub fn method_needs_no_params(method: &VarlinkMethod) -> bool {
    matches!(
        method,
        VarlinkMethod::Ping
            | VarlinkMethod::Reload
            | VarlinkMethod::Revert
            | VarlinkMethod::StartExecQueue
            | VarlinkMethod::StopExecQueue
            | VarlinkMethod::Exit
    )
}

/// Lookup table: method name → dispatch table generator.
/// Returns the dispatch fields required for a given method, or None if no params.
pub fn method_dispatch_table(method: &VarlinkMethod) -> Option<Vec<DispatchField>> {
    match method {
        VarlinkMethod::SetLogLevel => Some(dispatch_set_log_level()),
        VarlinkMethod::SetTrace => Some(dispatch_set_trace()),
        VarlinkMethod::SetChildrenMax => Some(dispatch_set_children_max()),
        VarlinkMethod::SetEnvironment => Some(dispatch_set_environment()),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varlink_address_constant() {
        assert!(UDEV_VARLINK_ADDRESS.starts_with("/run/udev/"));
        assert!(UDEV_VARLINK_ADDRESS.contains("io.systemd.Udev"));
    }

    #[test]
    fn test_method_name_roundtrip() {
        for m in VarlinkMethod::all_methods() {
            let name = m.to_method_name();
            assert!(
                VarlinkMethod::from_method_name(name).is_some(),
                "Method {:?} name {} should roundtrip",
                m,
                name
            );
            assert_eq!(VarlinkMethod::from_method_name(name), Some(*m));
        }
    }

    #[test]
    fn test_from_method_name_unknown() {
        assert_eq!(VarlinkMethod::from_method_name("io.systemd.Unknown"), None);
        assert_eq!(VarlinkMethod::from_method_name(""), None);
        assert_eq!(
            VarlinkMethod::from_method_name("io.systemd.Udev.Nonexistent"),
            None
        );
    }

    #[test]
    fn test_dispatch_set_log_level_fields() {
        let fields = dispatch_set_log_level();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "level");
        assert_eq!(fields[0].type_hint, DispatchType::Integer);
        assert!(fields[0].mandatory);
    }

    #[test]
    fn test_dispatch_set_trace_fields() {
        let fields = dispatch_set_trace();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "enable");
        assert_eq!(fields[0].type_hint, DispatchType::Boolean);
        assert!(fields[0].mandatory);
    }

    #[test]
    fn test_validate_environment_assignments_valid() {
        assert!(validate_environment_assignments(&["KEY=value", "FOO=bar"]).is_ok());
        assert!(validate_environment_assignments(&[]).is_ok());
    }

    #[test]
    fn test_validate_environment_assignments_invalid() {
        let result = validate_environment_assignments(&["NOEQUALSSIGN"]);
        assert!(result.is_err());
        if let Err(VarlinkError::MalformedEnvironment(s)) = result {
            assert_eq!(s, "NOEQUALSSIGN");
        } else {
            panic!("Expected MalformedEnvironment error");
        }
    }

    #[test]
    fn test_validate_log_level() {
        assert!(validate_log_level(0).is_ok()); // emerg
        assert!(validate_log_level(7).is_ok()); // debug
        assert!(validate_log_level(3).is_ok()); // err
        assert!(validate_log_level(-1).is_err());
        assert!(validate_log_level(8).is_err());
        assert!(validate_log_level(100).is_err());
    }

    #[test]
    fn test_validate_children_max() {
        assert!(validate_children_max(0).is_ok());
        assert!(validate_children_max(128).is_ok());
        assert!(validate_children_max(u32::MAX as u64).is_ok());
        assert!(validate_children_max(u32::MAX as u64 + 1).is_err());
    }

    #[test]
    fn test_exec_queue_action() {
        assert_eq!(
            exec_queue_action(&VarlinkMethod::StartExecQueue),
            Some(true)
        );
        assert_eq!(
            exec_queue_action(&VarlinkMethod::StopExecQueue),
            Some(false)
        );
        assert_eq!(exec_queue_action(&VarlinkMethod::Ping), None);
        assert_eq!(exec_queue_action(&VarlinkMethod::Reload), None);
    }

    #[test]
    fn test_method_needs_no_params() {
        assert!(method_needs_no_params(&VarlinkMethod::Ping));
        assert!(method_needs_no_params(&VarlinkMethod::Reload));
        assert!(method_needs_no_params(&VarlinkMethod::Exit));
        assert!(method_needs_no_params(&VarlinkMethod::Revert));
        assert!(!method_needs_no_params(&VarlinkMethod::SetLogLevel));
        assert!(!method_needs_no_params(&VarlinkMethod::SetTrace));
        assert!(!method_needs_no_params(&VarlinkMethod::SetChildrenMax));
        assert!(!method_needs_no_params(&VarlinkMethod::SetEnvironment));
    }

    #[test]
    fn test_method_dispatch_table_coverage() {
        // Methods that need params
        assert!(method_dispatch_table(&VarlinkMethod::SetLogLevel).is_some());
        assert!(method_dispatch_table(&VarlinkMethod::SetTrace).is_some());
        assert!(method_dispatch_table(&VarlinkMethod::SetChildrenMax).is_some());
        assert!(method_dispatch_table(&VarlinkMethod::SetEnvironment).is_some());

        // Methods that need no params
        assert!(method_dispatch_table(&VarlinkMethod::Ping).is_none());
        assert!(method_dispatch_table(&VarlinkMethod::Reload).is_none());
        assert!(method_dispatch_table(&VarlinkMethod::Exit).is_none());
    }

    #[test]
    fn test_all_methods_count() {
        // The C code binds 11 methods
        assert_eq!(VarlinkMethod::all_methods().len(), 11);
    }
}
