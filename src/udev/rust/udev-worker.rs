// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udev-worker.c
//
// Udev worker process logic for handling device events.
//
// Defines device exclusion lists, whole-disk detection helpers,
// lock status tracking, and worker configuration structures used
// when processing uevents in forked worker processes.

use crate::udev_rule_engine::{
    DeviceEvent, DeviceNodeSpec, EngineError, EngineOutput, Rule, process_device_event,
};

// ── Device exclusion lists ────────────────────────────────────────────────

/// Device sysname prefixes that should be excluded from whole-disk locking.
/// See C comments in udev_get_whole_disk() for rationale.
pub const EXCLUDED_SYSNAME_PREFIXES_LOCK: &[&str] = &["dm-", "md", "drbd"];

/// Device sysname prefixes excluded from read-only marking.
/// Broader than the lock exclusion: adds synthetic devices.
pub const EXCLUDED_SYSNAME_PREFIXES_READONLY: &[&str] =
    &["dm-", "md", "drbd", "loop", "nbd", "zram"];

// ── Lock result ───────────────────────────────────────────────────────────

/// Result of attempting to lock a block device for event processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResult {
    /// Lock acquired successfully.
    Acquired,
    /// Device is locked by another process; event should be requeued.
    LockedByOther,
    /// No lock needed (not a block device, or remove action).
    NoLockNeeded,
    /// Failed to lock with a non-retryable error.
    Failed(i32),
}

// ── Worker configuration ──────────────────────────────────────────────────

/// Configuration for a udev worker, passed from the manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    pub log_level: i32,
    pub blockdev_read_only: bool,
    pub trace: bool,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            log_level: 6, // LOG_INFO
            blockdev_read_only: false,
            trace: false,
        }
    }
}

// ── Device classification helpers ─────────────────────────────────────────

/// Device action types relevant to worker processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
    Other,
}

impl DeviceAction {
    pub fn from_action_string(s: &str) -> DeviceAction {
        match s {
            "add" => DeviceAction::Add,
            "remove" => DeviceAction::Remove,
            "change" => DeviceAction::Change,
            "move" => DeviceAction::Move,
            "online" => DeviceAction::Online,
            "offline" => DeviceAction::Offline,
            "bind" => DeviceAction::Bind,
            "unbind" => DeviceAction::Unbind,
            _ => DeviceAction::Other,
        }
    }

    pub fn to_action_string(self) -> &'static str {
        match self {
            DeviceAction::Add => "add",
            DeviceAction::Remove => "remove",
            DeviceAction::Change => "change",
            DeviceAction::Move => "move",
            DeviceAction::Online => "online",
            DeviceAction::Offline => "offline",
            DeviceAction::Bind => "bind",
            DeviceAction::Unbind => "unbind",
            DeviceAction::Other => "other",
        }
    }
}

/// Check if a device sysname matches any of the excluded prefixes.
/// Mirrors `device_sysname_startswith(dev, "dm-", "md", "drbd")` in C.
pub fn is_excluded_sysname(sysname: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| sysname.starts_with(prefix))
}

/// Determine if locking should be skipped for this action.
/// Locking is skipped for remove actions since the device node is already gone.
pub fn should_skip_lock(action: DeviceAction) -> bool {
    action == DeviceAction::Remove
}

/// Determine if read-only marking applies for this action and subsystem.
/// Only applies on add action, for block devices, excluding synthetic devices.
pub fn should_mark_readonly(action: DeviceAction, subsystem: &str, sysname: &str) -> bool {
    action == DeviceAction::Add
        && subsystem == "block"
        && !is_excluded_sysname(sysname, EXCLUDED_SYSNAME_PREFIXES_READONLY)
}

/// Classify whether a device needs whole-disk resolution.
/// Returns true if the device is a block device that isn't in the exclusion list.
pub fn needs_whole_disk(action: DeviceAction, sysname: &str, is_block: bool) -> bool {
    if should_skip_lock(action) {
        return false;
    }
    if !is_block {
        return false;
    }
    !is_excluded_sysname(sysname, EXCLUDED_SYSNAME_PREFIXES_LOCK)
}

// ── Notification messages ─────────────────────────────────────────────────

/// Build the TRY_AGAIN notification message for requeuing.
pub fn try_again_message(whole_disk: &str) -> String {
    format!("TRY_AGAIN=1\nWHOLE_DISK={whole_disk}")
}

/// Build the PROCESSED notification message.
pub fn processed_message() -> &'static str {
    "PROCESSED=1"
}

/// Build an ERRNO notification message.
pub fn errno_message(errno_val: i32, errno_name: Option<&str>) -> String {
    match errno_name {
        Some(name) => format!("ERRNO={}\nERRNO_NAME={name}", -errno_val),
        None => format!("ERRNO={}", -errno_val),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkerNotifyPayload {
    pub inotify_watch_add: bool,
    pub inotify_watch_remove: bool,
    pub try_again: bool,
    pub whole_disk: Option<String>,
    pub processed: bool,
    pub errno: Option<i32>,
    pub errno_name: Option<String>,
}

pub fn parse_worker_notify_payload(payload: &str) -> WorkerNotifyPayload {
    let mut parsed = WorkerNotifyPayload::default();

    for line in payload
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "INOTIFY_WATCH_ADD" => parsed.inotify_watch_add = value == "1",
            "INOTIFY_WATCH_REMOVE" => parsed.inotify_watch_remove = value == "1",
            "TRY_AGAIN" => parsed.try_again = value == "1",
            "WHOLE_DISK" => parsed.whole_disk = Some(value.to_string()),
            "PROCESSED" => parsed.processed = value == "1",
            "ERRNO" => parsed.errno = value.parse::<i32>().ok(),
            "ERRNO_NAME" => parsed.errno_name = Some(value.to_string()),
            _ => {}
        }
    }

    parsed
}

// ── Rules engine integration ─────────────────────────────────────────────

/// Execute the Rust rules engine and optional node/symlink operations
/// for one worker event.
pub fn process_worker_event(
    event: &DeviceEvent,
    rules: &[Rule],
    node_spec: Option<&DeviceNodeSpec>,
    execute_external_run: bool,
) -> Result<EngineOutput, EngineError> {
    process_device_event(event, rules, node_spec, execute_external_run)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udev_rule_engine::{AssignToken, MatchToken};

    #[test]
    fn test_excluded_sysname_lock() {
        assert!(is_excluded_sysname("dm-0", EXCLUDED_SYSNAME_PREFIXES_LOCK));
        assert!(is_excluded_sysname("md127", EXCLUDED_SYSNAME_PREFIXES_LOCK));
        assert!(is_excluded_sysname("drbd0", EXCLUDED_SYSNAME_PREFIXES_LOCK));
        assert!(!is_excluded_sysname("sda", EXCLUDED_SYSNAME_PREFIXES_LOCK));
        assert!(!is_excluded_sysname(
            "nvme0n1",
            EXCLUDED_SYSNAME_PREFIXES_LOCK
        ));
    }

    #[test]
    fn test_excluded_sysname_readonly() {
        assert!(is_excluded_sysname(
            "loop0",
            EXCLUDED_SYSNAME_PREFIXES_READONLY
        ));
        assert!(is_excluded_sysname(
            "zram0",
            EXCLUDED_SYSNAME_PREFIXES_READONLY
        ));
        assert!(is_excluded_sysname(
            "nbd0",
            EXCLUDED_SYSNAME_PREFIXES_READONLY
        ));
        assert!(is_excluded_sysname(
            "dm-0",
            EXCLUDED_SYSNAME_PREFIXES_READONLY
        ));
        assert!(!is_excluded_sysname(
            "sda",
            EXCLUDED_SYSNAME_PREFIXES_READONLY
        ));
    }

    #[test]
    fn test_device_action_roundtrip() {
        let actions = [
            DeviceAction::Add,
            DeviceAction::Remove,
            DeviceAction::Change,
            DeviceAction::Move,
            DeviceAction::Online,
            DeviceAction::Offline,
            DeviceAction::Bind,
            DeviceAction::Unbind,
        ];
        for a in &actions {
            assert_eq!(DeviceAction::from_action_string(a.to_action_string()), *a);
        }
    }

    #[test]
    fn test_device_action_unknown() {
        assert_eq!(
            DeviceAction::from_action_string("unknown_action"),
            DeviceAction::Other
        );
    }

    #[test]
    fn test_should_skip_lock() {
        assert!(should_skip_lock(DeviceAction::Remove));
        assert!(!should_skip_lock(DeviceAction::Add));
        assert!(!should_skip_lock(DeviceAction::Change));
    }

    #[test]
    fn test_should_mark_readonly() {
        assert!(should_mark_readonly(DeviceAction::Add, "block", "sda"));
        assert!(!should_mark_readonly(DeviceAction::Change, "block", "sda"));
        assert!(!should_mark_readonly(DeviceAction::Add, "net", "eth0"));
        assert!(!should_mark_readonly(DeviceAction::Add, "block", "dm-0"));
        assert!(!should_mark_readonly(DeviceAction::Add, "block", "loop0"));
    }

    #[test]
    fn test_needs_whole_disk() {
        assert!(needs_whole_disk(DeviceAction::Add, "sda", true));
        assert!(!needs_whole_disk(DeviceAction::Remove, "sda", true));
        assert!(!needs_whole_disk(DeviceAction::Add, "sda", false));
        assert!(!needs_whole_disk(DeviceAction::Add, "dm-0", true));
        assert!(needs_whole_disk(DeviceAction::Change, "nvme0n1", true));
    }

    #[test]
    fn test_notification_messages() {
        assert_eq!(
            try_again_message("/dev/sda"),
            "TRY_AGAIN=1\nWHOLE_DISK=/dev/sda"
        );
        assert_eq!(processed_message(), "PROCESSED=1");
        assert_eq!(
            errno_message(-16, Some("EBUSY")),
            "ERRNO=16\nERRNO_NAME=EBUSY"
        );
        assert_eq!(errno_message(-16, None), "ERRNO=16");
    }

    #[test]
    fn worker_notify_parser_extracts_try_again_and_whole_disk() {
        let parsed = parse_worker_notify_payload("TRY_AGAIN=1\nWHOLE_DISK=/dev/sda");
        assert!(parsed.try_again);
        assert_eq!(parsed.whole_disk.as_deref(), Some("/dev/sda"));
    }

    #[test]
    fn worker_notify_parser_extracts_watch_and_errno_fields() {
        let parsed = parse_worker_notify_payload("INOTIFY_WATCH_ADD=1\nERRNO=16\nERRNO_NAME=EBUSY");
        assert!(parsed.inotify_watch_add);
        assert_eq!(parsed.errno, Some(16));
        assert_eq!(parsed.errno_name.as_deref(), Some("EBUSY"));
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.log_level, 6);
        assert!(!config.blockdev_read_only);
        assert!(!config.trace);
    }

    #[test]
    fn test_lock_result_variants() {
        assert_eq!(LockResult::Acquired, LockResult::Acquired);
        assert_ne!(LockResult::Acquired, LockResult::LockedByOther);
        assert_ne!(LockResult::NoLockNeeded, LockResult::Failed(-1));
    }

    #[test]
    fn worker_can_execute_rule_engine_path() {
        let event = DeviceEvent {
            action: "add".into(),
            devpath: "/devices/mock0".into(),
            kernel: "mock0".into(),
            subsystem: "block".into(),
            env: Default::default(),
            tags: Default::default(),
        };
        let rules = vec![Rule {
            matches: vec![MatchToken::Action("add".into())],
            assigns: vec![AssignToken::Tag("systemd".into())],
        }];

        let out = process_worker_event(&event, &rules, None, false).unwrap();
        assert!(out.assignment.tags.contains("systemd"));
    }
}
