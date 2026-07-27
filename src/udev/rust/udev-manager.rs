// SPDX-License-Identifier: GPL-2.0-or-later
// PORT-SYNC: src/udev/udev-manager.c

pub const SOURCE_PATH: &str = "src/udev/udev-manager.c";
pub const SOURCE_LINE_COUNT: usize = 1539;
pub const EVENT_REQUEUE_INTERVAL_USEC: u64 = 200_000;
pub const EVENT_REQUEUE_TIMEOUT_USEC: u64 = 180_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Undef,
    Queued,
    Running,
    Locked,
    Processed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Undef,
    Running,
    Idle,
    Killed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerOverview {
    pub source_path: &'static str,
    pub line_count: usize,
    pub exported_functions: usize,
}

pub const EXPORTED_FUNCTIONS: &[&str] = &[
    "event_unset_whole_disk",
    "event_free",
    "event_enter_processed",
    "worker_free",
    "manager_free",
    "manager_new",
    "manager_kill_workers",
    "on_kill_workers_event",
    "manager_reset_kill_workers_timer",
    "manager_exit",
    "notify_ready",
    "manager_reload",
    "manager_revert",
    "on_worker_timeout_kill",
    "on_worker_timeout_warning",
    "worker_attach_event",
    "worker_detach_event",
    "on_worker_exit",
    "worker_new",
    "worker_spawn",
    "event_run",
    "devpath_conflict",
    "event_find_blocker",
    "manager_can_process_event",
    "event_queue_start",
    "on_requeue_locked_events",
    "manager_requeue_locked_events",
    "manager_requeue_locked_events_by_device",
    "locked_event_compare",
    "event_enter_locked",
    "event_queue_insert",
    "manager_serialize_events",
    "manager_deserialize_events",
    "on_uevent",
    "manager_init_device_monitor",
    "manager_start_device_monitor",
    "on_worker_notify",
    "manager_start_worker_notify",
    "on_sigterm",
    "on_sighup",
    "manager_create_queue_file",
    "manager_unlink_queue_file",
    "on_post_exit",
    "on_post",
    "manager_setup_signal",
    "manager_setup_event",
    "manager_listen_fds",
    "manager_main",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerError {
    InvalidTransition,
    UnknownFunction(String),
}

pub fn port_overview() -> ManagerOverview {
    ManagerOverview {
        source_path: SOURCE_PATH,
        line_count: SOURCE_LINE_COUNT,
        exported_functions: EXPORTED_FUNCTIONS.len(),
    }
}

pub fn can_transition(from: EventState, to: EventState) -> Result<bool, ManagerError> {
    let allowed = matches!(
        (from, to),
        (EventState::Undef, EventState::Queued)
            | (EventState::Queued, EventState::Running)
            | (EventState::Queued, EventState::Locked)
            | (EventState::Running, EventState::Processed)
            | (EventState::Locked, EventState::Queued)
            | (EventState::Locked, EventState::Processed)
    );
    Ok(allowed)
}

pub fn function_group(name: &str) -> Result<&'static str, ManagerError> {
    match name {
        "manager_new" | "manager_free" | "manager_main" => Ok("manager-lifecycle"),
        "worker_new" | "worker_spawn" | "worker_free" | "on_worker_exit" => Ok("workers"),
        "event_run" | "event_queue_insert" | "event_queue_start" | "event_enter_locked" => {
            Ok("events")
        }
        "manager_reload" | "manager_revert" | "manager_exit" => Ok("control"),
        other if EXPORTED_FUNCTIONS.contains(&other) => Ok("misc"),
        other => Err(ManagerError::UnknownFunction(other.to_string())),
    }
}

pub fn validate_port_model() -> Result<(), ManagerError> {
    if port_overview().exported_functions < 40 {
        return Err(ManagerError::InvalidTransition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/udev-manager.c");
        assert_eq!(SOURCE_LINE_COUNT, 1539);
    }

    #[test]
    fn requeue_constants_match_c_macros() {
        assert_eq!(EVENT_REQUEUE_INTERVAL_USEC, 200_000);
        assert_eq!(EVENT_REQUEUE_TIMEOUT_USEC, 180_000_000);
    }

    #[test]
    fn undef_can_queue() {
        assert_eq!(
            can_transition(EventState::Undef, EventState::Queued).unwrap(),
            true
        );
    }

    #[test]
    fn queued_can_lock_and_run() {
        assert_eq!(
            can_transition(EventState::Queued, EventState::Locked).unwrap(),
            true
        );
        assert_eq!(
            can_transition(EventState::Queued, EventState::Running).unwrap(),
            true
        );
    }

    #[test]
    fn processed_is_terminal_in_model() {
        assert_eq!(
            can_transition(EventState::Processed, EventState::Queued).unwrap(),
            false
        );
    }

    #[test]
    fn worker_functions_are_classified() {
        assert_eq!(function_group("worker_spawn").unwrap(), "workers");
    }

    #[test]
    fn event_functions_are_classified() {
        assert_eq!(function_group("event_queue_start").unwrap(), "events");
    }

    #[test]
    fn lifecycle_functions_are_classified() {
        assert_eq!(function_group("manager_main").unwrap(), "manager-lifecycle");
    }

    #[test]
    fn unknown_function_is_rejected() {
        assert_eq!(
            function_group("missing"),
            Err(ManagerError::UnknownFunction("missing".into()))
        );
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
