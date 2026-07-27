// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/scope.c
//

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/scope.c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeState {
    Dead,
    StartChown,
    Running,
    Abandoned,
    StopSigterm,
    StopSigkill,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeResult {
    Success,
    Resources,
    Timeout,
    OomKill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    MissingPids,
    TimeOverflow,
}

impl ScopeError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::MissingPids => Errno::ENOENT.to_neg_errno(),
            Self::TimeOverflow => Errno::EOVERFLOW.to_neg_errno(),
        }
    }
}

pub const STATE_TRANSLATION_TABLE: [UnitActiveState; 7] = [
    UnitActiveState::Inactive,
    UnitActiveState::Activating,
    UnitActiveState::Active,
    UnitActiveState::Active,
    UnitActiveState::Deactivating,
    UnitActiveState::Deactivating,
    UnitActiveState::Failed,
];

pub const fn active_state(state: ScopeState) -> UnitActiveState {
    STATE_TRANSLATION_TABLE[state as usize]
}

pub const fn result_to_string(result: ScopeResult) -> &'static str {
    match result {
        ScopeResult::Success => "success",
        ScopeResult::Resources => "resources",
        ScopeResult::Timeout => "timeout",
        ScopeResult::OomKill => "oom-kill",
    }
}

pub const fn state_to_string(state: ScopeState) -> &'static str {
    match state {
        ScopeState::Dead => "dead",
        ScopeState::StartChown => "start-chown",
        ScopeState::Running => "running",
        ScopeState::Abandoned => "abandoned",
        ScopeState::StopSigterm => "stop-sigterm",
        ScopeState::StopSigkill => "stop-sigkill",
        ScopeState::Failed => "failed",
    }
}

pub fn verify_scope(
    has_pids: bool,
    manager_is_reloading: bool,
    is_init_scope: bool,
) -> Result<(), ScopeError> {
    if !has_pids && !manager_is_reloading && !is_init_scope {
        return Err(ScopeError::MissingPids);
    }

    Ok(())
}

pub fn scope_running_timeout(
    active_enter_timestamp_monotonic: u64,
    runtime_max_usec: u64,
    random_extra_usec: u64,
) -> Result<u64, ScopeError> {
    active_enter_timestamp_monotonic
        .checked_add(runtime_max_usec)
        .and_then(|t| t.checked_add(random_extra_usec))
        .ok_or(ScopeError::TimeOverflow)
}

pub fn scope_coldplug_timeout(
    deserialized_state: ScopeState,
    active_enter_timestamp_monotonic: u64,
    runtime_max_usec: u64,
    random_extra_usec: u64,
    state_change_timestamp_monotonic: u64,
    timeout_stop_usec: u64,
) -> Result<Option<u64>, ScopeError> {
    match deserialized_state {
        ScopeState::Running => scope_running_timeout(
            active_enter_timestamp_monotonic,
            runtime_max_usec,
            random_extra_usec,
        )
        .map(Some),
        ScopeState::StopSigkill | ScopeState::StopSigterm => state_change_timestamp_monotonic
            .checked_add(timeout_stop_usec)
            .map(Some)
            .ok_or(ScopeError::TimeOverflow),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_table_matches_c_order() {
        assert_eq!(STATE_TRANSLATION_TABLE.len(), 7);
        assert_eq!(active_state(ScopeState::Dead), UnitActiveState::Inactive);
        assert_eq!(
            active_state(ScopeState::StartChown),
            UnitActiveState::Activating
        );
        assert_eq!(active_state(ScopeState::Running), UnitActiveState::Active);
        assert_eq!(active_state(ScopeState::Abandoned), UnitActiveState::Active);
        assert_eq!(
            active_state(ScopeState::StopSigterm),
            UnitActiveState::Deactivating
        );
        assert_eq!(
            active_state(ScopeState::StopSigkill),
            UnitActiveState::Deactivating
        );
        assert_eq!(active_state(ScopeState::Failed), UnitActiveState::Failed);
    }

    #[test]
    fn result_names_match_scope_tables() {
        assert_eq!(result_to_string(ScopeResult::Success), "success");
        assert_eq!(result_to_string(ScopeResult::Resources), "resources");
        assert_eq!(result_to_string(ScopeResult::Timeout), "timeout");
        assert_eq!(result_to_string(ScopeResult::OomKill), "oom-kill");
    }

    #[test]
    fn state_names_match_c_strings() {
        assert_eq!(state_to_string(ScopeState::Dead), "dead");
        assert_eq!(state_to_string(ScopeState::Running), "running");
        assert_eq!(state_to_string(ScopeState::Failed), "failed");
    }

    #[test]
    fn verify_scope_rejects_empty_non_special_scope() {
        assert_eq!(
            verify_scope(false, false, false),
            Err(ScopeError::MissingPids)
        );
    }

    #[test]
    fn verify_scope_allows_reloading_without_pids() {
        assert_eq!(verify_scope(false, true, false), Ok(()));
    }

    #[test]
    fn verify_scope_allows_init_scope_without_pids() {
        assert_eq!(verify_scope(false, false, true), Ok(()));
    }

    #[test]
    fn running_timeout_adds_all_components() {
        assert_eq!(scope_running_timeout(10, 20, 7), Ok(37));
    }

    #[test]
    fn running_timeout_reports_overflow() {
        assert_eq!(
            scope_running_timeout(u64::MAX, 1, 0),
            Err(ScopeError::TimeOverflow)
        );
    }

    #[test]
    fn coldplug_timeout_uses_running_deadline() {
        assert_eq!(
            scope_coldplug_timeout(ScopeState::Running, 100, 50, 3, 200, 10),
            Ok(Some(153))
        );
    }

    #[test]
    fn coldplug_timeout_uses_stop_deadline() {
        assert_eq!(
            scope_coldplug_timeout(ScopeState::StopSigterm, 100, 50, 3, 200, 10),
            Ok(Some(210))
        );
        assert_eq!(
            scope_coldplug_timeout(ScopeState::StopSigkill, 100, 50, 3, 200, 10),
            Ok(Some(210))
        );
    }

    #[test]
    fn coldplug_timeout_is_infinite_for_other_states() {
        assert_eq!(
            scope_coldplug_timeout(ScopeState::Dead, 100, 50, 3, 200, 10),
            Ok(None)
        );
    }

    #[test]
    fn scope_error_maps_to_errno() {
        assert_eq!(
            ScopeError::MissingPids.errno(),
            Errno::ENOENT.to_neg_errno()
        );
        assert_eq!(
            ScopeError::TimeOverflow.errno(),
            Errno::EOVERFLOW.to_neg_errno()
        );
    }
}
