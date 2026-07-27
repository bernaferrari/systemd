// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-scope.c
//
// D-Bus property access and transient property management for scope units.
//
// Provides scope-specific enums with string tables, the abandon-state
// and the RequestStop signal emission logic.

// ── Scope result enum ─────────────────────────────────────────────────────

/// Scope result types, corresponding to ScopeResult in scope.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeResult {
    Success,
    Abandoned,
    Timeout,
    Failure,
}

static SCOPE_RESULT_TABLE: &[&str] = &["success", "abandoned", "timeout", "failure"];

// ── OOM policy enum ───────────────────────────────────────────────────────

/// OOM policy for scope units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OOMPolicy {
    Continue,
    Stop,
    Kill,
}

static OOM_POLICY_TABLE: &[&str] = &["continue", "stop", "kill"];

// ── Scope state ───────────────────────────────────────────────────────────

/// Runtime state tracked for a scope unit.
///
/// Port of the Scope struct fields used in dbus-scope.c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeState {
    /// Bus name of the controlling process.
    pub controller: Option<String>,
    /// Timeout for stopping the scope, in microseconds.
    pub timeout_stop_usec: u64,
    /// Maximum runtime in microseconds.
    pub runtime_max_usec: u64,
    /// Randomized extra runtime in microseconds.
    pub runtime_rand_extra_usec: u64,
    /// OOM policy.
    pub oom_policy: OOMPolicy,
    /// Current result.
    pub result: ScopeResult,
    /// Whether the scope has been abandoned.
    pub abandoned: bool,
}

impl ScopeState {
    /// Create a new scope state with default values.
    pub fn new() -> Self {
        Self {
            controller: None,
            timeout_stop_usec: 0,
            runtime_max_usec: 0,
            runtime_rand_extra_usec: 0,
            oom_policy: OOMPolicy::Continue,
            result: ScopeResult::Success,
            abandoned: false,
        }
    }
}

impl Default for ScopeState {
    fn default() -> Self {
        Self::new()
    }
}

// ── String table helpers ──────────────────────────────────────────────────

const EINVAL: i32 = -22;

fn table_to_string<'a>(table: &'a [&'a str], idx: usize) -> Result<&'a str, i32> {
    table.get(idx).copied().ok_or(EINVAL)
}

fn table_from_string(table: &[&str], s: &str) -> Result<usize, i32> {
    table.iter().position(|entry| *entry == s).ok_or(EINVAL)
}

// ── Scope result helpers ──────────────────────────────────────────────────

/// Convert a ScopeResult to its string representation.
pub fn scope_result_to_string(v: ScopeResult) -> Result<&'static str, i32> {
    table_to_string(SCOPE_RESULT_TABLE, v as usize)
}

/// Parse a ScopeResult from its string representation.
pub fn scope_result_from_string(s: &str) -> Result<ScopeResult, i32> {
    let idx = table_from_string(SCOPE_RESULT_TABLE, s)?;
    Ok(match idx {
        0 => ScopeResult::Success,
        1 => ScopeResult::Abandoned,
        2 => ScopeResult::Timeout,
        3 => ScopeResult::Failure,
        _ => return Err(EINVAL),
    })
}

// ── OOM policy helpers ────────────────────────────────────────────────────

/// Convert an OOMPolicy to its string representation.
pub fn oom_policy_to_string(v: OOMPolicy) -> Result<&'static str, i32> {
    table_to_string(OOM_POLICY_TABLE, v as usize)
}

/// Parse an OOMPolicy from its string representation.
pub fn oom_policy_from_string(s: &str) -> Result<OOMPolicy, i32> {
    let idx = table_from_string(OOM_POLICY_TABLE, s)?;
    Ok(match idx {
        0 => OOMPolicy::Continue,
        1 => OOMPolicy::Stop,
        2 => OOMPolicy::Kill,
        _ => return Err(EINVAL),
    })
}

// ── Abandon logic ─────────────────────────────────────────────────────────

/// Abandon state machine result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonResult {
    /// Scope was successfully abandoned.
    Abandoned,
    /// Scope is not running (stale).
    NotRunning,
    /// Access denied.
    AccessDenied,
}

/// Attempt to abandon a scope.
///
/// Port of `bus_scope_method_abandon()` from dbus-scope.c.
/// In the C code this involves D-Bus access checks and async polkit;
/// here we model the core abandon logic.
pub fn scope_abandon(state: &mut ScopeState) -> Result<AbandonResult, i32> {
    if state.abandoned {
        return Err(EINVAL);
    }

    // If no controller and already abandoned, the scope is not running
    if state.controller.is_none() {
        return Ok(AbandonResult::NotRunning);
    }

    state.abandoned = true;
    state.result = ScopeResult::Abandoned;
    Ok(AbandonResult::Abandoned)
}

// ── Transient property dispatch ───────────────────────────────────────────

/// Categories of transient properties for scope units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeTransientPropertyKind {
    TimeoutStopUSec,
    RuntimeMaxUSec,
    RuntimeRandomizedExtraUSec,
    OOMPolicy,
    PIDs,
    PIDFDs,
    Controller,
    User,
    Group,
    Unknown,
}

/// Classify a transient property name for scope units.
///
/// Port of the dispatch logic in `bus_scope_set_transient_property()`
/// and `bus_scope_set_property()`.
pub fn classify_scope_transient_property(name: &str) -> ScopeTransientPropertyKind {
    match name {
        "TimeoutStopUSec" => ScopeTransientPropertyKind::TimeoutStopUSec,
        "RuntimeMaxUSec" => ScopeTransientPropertyKind::RuntimeMaxUSec,
        "RuntimeRandomizedExtraUSec" => ScopeTransientPropertyKind::RuntimeRandomizedExtraUSec,
        "OOMPolicy" => ScopeTransientPropertyKind::OOMPolicy,
        "PIDs" => ScopeTransientPropertyKind::PIDs,
        "PIDFDs" => ScopeTransientPropertyKind::PIDFDs,
        "Controller" => ScopeTransientPropertyKind::Controller,
        "User" => ScopeTransientPropertyKind::User,
        "Group" => ScopeTransientPropertyKind::Group,
        _ => ScopeTransientPropertyKind::Unknown,
    }
}

// ── Controller tracking ───────────────────────────────────────────────────

/// State machine for controller bus name tracking.
///
/// Port of `bus_scope_track_controller()` and `on_controller_gone()`
/// from dbus-scope.c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerTracker {
    /// Whether we are actively tracking a controller.
    pub tracking: bool,
}

impl ControllerTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self { tracking: false }
    }

    /// Begin tracking a controller bus name.
    ///
    /// Returns Ok(()) if tracking was set up, or an error if the
    /// controller name is missing or already tracked.
    pub fn track(&mut self, controller: Option<&str>) -> Result<(), i32> {
        let name = controller.ok_or(EINVAL)?;
        if name.is_empty() {
            return Err(EINVAL);
        }
        if self.tracking {
            return Err(EINVAL);
        }
        self.tracking = true;
        Ok(())
    }

    /// Handle the controller disappearing from the bus.
    ///
    /// Port of `on_controller_gone()`. Clears the tracking state
    /// and returns the name of the controller that disappeared.
    pub fn controller_gone(&mut self) -> bool {
        if self.tracking {
            self.tracking = false;
            true
        } else {
            false
        }
    }
}

impl Default for ControllerTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request stop signal ───────────────────────────────────────────────────

/// Build the data needed to emit a RequestStop signal.
///
/// Port of `bus_scope_send_request_stop()` from dbus-scope.c.
/// Returns None if no controller is set, or Some(controller_name) if
/// a signal should be sent.
pub fn build_request_stop(state: &ScopeState) -> Option<&str> {
    state.controller.as_deref()
}

// ── Set controller ────────────────────────────────────────────────────────

/// Validate and set the controller bus name.
///
/// Port of the "Controller" branch in `bus_scope_set_transient_property()`.
/// The controller must be a valid bus name (non-empty unless clearing).
pub fn validate_controller_name(name: &str) -> Result<(), i32> {
    if name.is_empty() {
        // Clearing the controller is always valid
        return Ok(());
    }

    // A valid bus service name: non-empty, dot-separated, alphanumeric + _ -
    if name.len() > 255 {
        return Err(EINVAL);
    }

    for c in name.chars() {
        if !c.is_alphanumeric() && c != '.' && c != '_' && c != '-' {
            return Err(EINVAL);
        }
    }

    // Must not start or end with a dot
    if name.starts_with('.') || name.ends_with('.') {
        return Err(EINVAL);
    }

    Ok(())
}

/// Set the controller on scope state, validating the name first.
pub fn set_controller(state: &mut ScopeState, name: &str) -> Result<(), i32> {
    validate_controller_name(name)?;
    if name.is_empty() {
        state.controller = None;
    } else {
        state.controller = Some(name.to_string());
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_result_roundtrip() {
        let all = [
            ScopeResult::Success,
            ScopeResult::Abandoned,
            ScopeResult::Timeout,
            ScopeResult::Failure,
        ];
        for variant in &all {
            let s = scope_result_to_string(*variant).unwrap();
            let back = scope_result_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_scope_result_invalid() {
        assert!(scope_result_from_string("nonexistent").is_err());
    }

    #[test]
    fn test_oom_policy_roundtrip() {
        let all = [OOMPolicy::Continue, OOMPolicy::Stop, OOMPolicy::Kill];
        for variant in &all {
            let s = oom_policy_to_string(*variant).unwrap();
            let back = oom_policy_from_string(s).unwrap();
            assert_eq!(back, *variant);
        }
    }

    #[test]
    fn test_oom_policy_invalid() {
        assert!(oom_policy_from_string("nonexistent").is_err());
    }

    #[test]
    fn test_scope_abandon_success() {
        let mut state = ScopeState::new();
        state.controller = Some("org.example".to_string());
        let result = scope_abandon(&mut state).unwrap();
        assert_eq!(result, AbandonResult::Abandoned);
        assert!(state.abandoned);
        assert_eq!(state.result, ScopeResult::Abandoned);
    }

    #[test]
    fn test_scope_abandon_no_controller() {
        let mut state = ScopeState::new();
        state.controller = None;
        let result = scope_abandon(&mut state).unwrap();
        assert_eq!(result, AbandonResult::NotRunning);
    }

    #[test]
    fn test_scope_abandon_already_abandoned() {
        let mut state = ScopeState::new();
        state.controller = Some("org.example".to_string());
        state.abandoned = true;
        assert!(scope_abandon(&mut state).is_err());
    }

    #[test]
    fn test_classify_scope_transient_property() {
        assert_eq!(
            classify_scope_transient_property("TimeoutStopUSec"),
            ScopeTransientPropertyKind::TimeoutStopUSec
        );
        assert_eq!(
            classify_scope_transient_property("RuntimeMaxUSec"),
            ScopeTransientPropertyKind::RuntimeMaxUSec
        );
        assert_eq!(
            classify_scope_transient_property("OOMPolicy"),
            ScopeTransientPropertyKind::OOMPolicy
        );
        assert_eq!(
            classify_scope_transient_property("PIDs"),
            ScopeTransientPropertyKind::PIDs
        );
        assert_eq!(
            classify_scope_transient_property("Controller"),
            ScopeTransientPropertyKind::Controller
        );
        assert_eq!(
            classify_scope_transient_property("User"),
            ScopeTransientPropertyKind::User
        );
        assert_eq!(
            classify_scope_transient_property("Group"),
            ScopeTransientPropertyKind::Group
        );
        assert_eq!(
            classify_scope_transient_property("Unknown"),
            ScopeTransientPropertyKind::Unknown
        );
    }

    #[test]
    fn test_controller_tracker_track() {
        let mut tracker = ControllerTracker::new();
        assert!(!tracker.tracking);
        tracker.track(Some("org.example")).unwrap();
        assert!(tracker.tracking);
    }

    #[test]
    fn test_controller_tracker_track_none() {
        let mut tracker = ControllerTracker::new();
        assert!(tracker.track(None).is_err());
    }

    #[test]
    fn test_controller_tracker_track_empty() {
        let mut tracker = ControllerTracker::new();
        assert!(tracker.track(Some("")).is_err());
    }

    #[test]
    fn test_controller_tracker_track_already_tracking() {
        let mut tracker = ControllerTracker::new();
        tracker.track(Some("org.example")).unwrap();
        assert!(tracker.track(Some("org.other")).is_err());
    }

    #[test]
    fn test_controller_tracker_gone() {
        let mut tracker = ControllerTracker::new();
        tracker.track(Some("org.example")).unwrap();
        assert!(tracker.controller_gone());
        assert!(!tracker.tracking);
    }

    #[test]
    fn test_controller_tracker_gone_not_tracking() {
        let mut tracker = ControllerTracker::new();
        assert!(!tracker.controller_gone());
    }

    #[test]
    fn test_build_request_stop_with_controller() {
        let mut state = ScopeState::new();
        state.controller = Some("org.example".to_string());
        assert_eq!(build_request_stop(&state), Some("org.example"));
    }

    #[test]
    fn test_build_request_stop_no_controller() {
        let state = ScopeState::new();
        assert_eq!(build_request_stop(&state), None);
    }

    #[test]
    fn test_validate_controller_name_valid() {
        assert!(validate_controller_name("org.example.Service").is_ok());
        assert!(validate_controller_name("a.b").is_ok());
        assert!(validate_controller_name("my_service-1.0").is_ok());
    }

    #[test]
    fn test_validate_controller_name_empty() {
        // Empty means clearing the controller
        assert!(validate_controller_name("").is_ok());
    }

    #[test]
    fn test_validate_controller_name_invalid_chars() {
        assert!(validate_controller_name("has space").is_err());
        assert!(validate_controller_name("has/slash").is_err());
        assert!(validate_controller_name(".starts.dot").is_err());
        assert!(validate_controller_name("ends.dot.").is_err());
    }

    #[test]
    fn test_set_controller() {
        let mut state = ScopeState::new();
        set_controller(&mut state, "org.example").unwrap();
        assert_eq!(state.controller, Some("org.example".to_string()));

        set_controller(&mut state, "").unwrap();
        assert_eq!(state.controller, None);
    }

    #[test]
    fn test_scope_state_default() {
        let state = ScopeState::default();
        assert_eq!(state.controller, None);
        assert_eq!(state.oom_policy, OOMPolicy::Continue);
        assert_eq!(state.result, ScopeResult::Success);
        assert!(!state.abandoned);
    }
}
