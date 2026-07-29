// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-wait-for-units.c, src/shared/bus-wait-for-units.h
//
// D-Bus unit state waiting — monitor multiple systemd units and detect when
// they reach their target state (active, inactive, maintenance-end, or
// job-free) via D-Bus PropertiesChanged signals and GetAll method replies.
//
// This is the pure-state-machine core. The actual D-Bus interaction
// (signal matching, bus process/wait loops, Ref/Unref calls) is left to
// the caller; this module tracks which units are pending, feeds property
// updates into the readiness logic, and reports completion.

use std::collections::HashMap;
use std::fmt;

use systemd_basic_rs::bus_label::bus_label_escape_bytes;

// ── State ──────────────────────────────────────────────────────────────────

/// Overall state of the unit-waiting operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusWaitForUnitsState {
    /// Nothing to wait for anymore and nothing failed.
    Success,
    /// Nothing to wait for, but at least one unit failed.
    Failure,
    /// Still waiting for one or more units.
    Running,
}

impl Default for BusWaitForUnitsState {
    fn default() -> Self {
        Self::Success
    }
}

impl BusWaitForUnitsState {
    /// Returns `true` if waiting has finished (success or failure).
    pub fn is_finished(self) -> bool {
        !matches!(self, BusWaitForUnitsState::Running)
    }
}

// ── Flags ──────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling what condition each tracked unit must satisfy
    /// before it is considered ready.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct WaitForUnitsFlags: u32 {
        /// Wait until the unit leaves "maintenance" state and both
        /// CleanResult and LiveMountResult are "success".
        const FOR_MAINTENANCE_END = 1 << 0;
        /// Wait until the unit enters "inactive" state.  If it enters
        /// "failed" instead the overall wait is marked as failed but the
        /// item is still considered complete.
        const FOR_INACTIVE        = 1 << 1;
        /// Wait until no job is pending on the unit (Job id == 0).
        const NO_JOB              = 1 << 2;
        /// The caller already holds a Ref on the unit; do not call Ref.
        const REFFED              = 1 << 3;
    }
}

impl WaitForUnitsFlags {
    /// At least one of these flags must be set for a valid wait condition.
    pub const TARGET_MASK: WaitForUnitsFlags = WaitForUnitsFlags::union(
        WaitForUnitsFlags::FOR_MAINTENANCE_END,
        WaitForUnitsFlags::union(WaitForUnitsFlags::FOR_INACTIVE, WaitForUnitsFlags::NO_JOB),
    );
}

// ── Error ──────────────────────────────────────────────────────────────────

/// Errors produced while adding or tracking units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitWaitError {
    /// The unit name is invalid (e.g. empty).
    InvalidUnit(String),
    /// No target flag was specified.
    InvalidFlags,
    /// The GetAll method call for this unit returned a D-Bus error.
    GetAllFailed { bus_path: String, message: String },
    /// The D-Bus connection was terminated while waiting.
    Disconnected,
    /// Memory allocation failure.
    OutOfMemory,
}

impl fmt::Display for UnitWaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnitWaitError::InvalidUnit(u) => write!(f, "Invalid unit name: {u}"),
            UnitWaitError::InvalidFlags => write!(f, "No target wait flag specified"),
            UnitWaitError::GetAllFailed { bus_path, message } => {
                write!(f, "GetAll() failed for {bus_path}: {message}")
            }
            UnitWaitError::Disconnected => {
                write!(f, "D-Bus connection terminated while waiting for units")
            }
            UnitWaitError::OutOfMemory => write!(f, "Out of memory"),
        }
    }
}

impl std::error::Error for UnitWaitError {}

// ── Property data ──────────────────────────────────────────────────────────

/// Parsed unit properties extracted from a D-Bus GetAll reply or
/// PropertiesChanged signal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitProperties {
    /// Current ActiveState (e.g. "active", "inactive", "failed",
    /// "maintenance").
    pub active_state: Option<String>,
    /// Pending job id.  `Some(0)` means no job; `None` means the
    /// property was absent from the message.
    pub job_id: Option<u32>,
    /// Result of the last Clean operation (maintenance-end mode).
    pub clean_result: Option<String>,
    /// Result of the last LiveMount operation (maintenance-end mode).
    pub live_mount_result: Option<String>,
}

/// A unit that has finished waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedUnit {
    /// D-Bus object path of the unit.
    pub bus_path: String,
    /// `true` if the unit reached its target state, `false` if it was
    /// removed due to an error or disconnection.
    pub good: bool,
}

// ── Internal: WaitForItem ─────────────────────────────────────────────────

/// Per-unit tracking state.
#[derive(Debug, Clone)]
struct WaitForItem {
    bus_path: String,
    flags: WaitForUnitsFlags,
    active_state: Option<String>,
    job_id: Option<u32>,
    clean_result: Option<String>,
    live_mount_result: Option<String>,
}

impl WaitForItem {
    fn new(bus_path: String, flags: WaitForUnitsFlags) -> Self {
        Self {
            bus_path,
            flags,
            active_state: None,
            job_id: None,
            clean_result: None,
            live_mount_result: None,
        }
    }

    /// Merge a batch of parsed properties into this item.
    fn apply_properties(&mut self, props: &UnitProperties) {
        if let Some(ref s) = props.active_state {
            self.active_state = Some(s.clone());
        }
        if props.job_id.is_some() {
            self.job_id = props.job_id;
        }
        if let Some(ref cr) = props.clean_result {
            self.clean_result = Some(cr.clone());
        }
        if let Some(ref lmr) = props.live_mount_result {
            self.live_mount_result = Some(lmr.clone());
        }
    }

    /// Evaluate the readiness condition described in the C
    /// `wait_for_item_check_ready()`.
    ///
    /// Returns `(is_ready, encountered_failure)`.
    fn check_ready(&self) -> (bool, bool) {
        let mut failure = false;
        let flags = self.flags;

        // ── FOR_MAINTENANCE_END ─────────────────────────────────────
        if flags.contains(WaitForUnitsFlags::FOR_MAINTENANCE_END) {
            if let Some(ref cr) = self.clean_result {
                if cr != "success" {
                    failure = true;
                }
            }
            if let Some(ref lmr) = self.live_mount_result {
                if lmr != "success" {
                    failure = true;
                }
            }
            // Still in maintenance (or state unknown yet) → not ready
            if self.active_state.is_none() || self.active_state.as_deref() == Some("maintenance") {
                return (false, failure);
            }
        }

        // ── NO_JOB ──────────────────────────────────────────────────
        if flags.contains(WaitForUnitsFlags::NO_JOB) && self.job_id != Some(0) {
            return (false, failure);
        }

        // ── FOR_INACTIVE ────────────────────────────────────────────
        if flags.contains(WaitForUnitsFlags::FOR_INACTIVE) {
            match self.active_state.as_deref() {
                Some("failed") => {
                    failure = true;
                    // fall through — item IS done, just failed
                }
                Some("inactive") => {
                    // fall through — item is ready
                }
                _ => return (false, failure),
            }
        }

        (true, failure)
    }
}

// ── BusWaitForUnits ────────────────────────────────────────────────────────

/// Tracks multiple systemd units and detects when they all reach their
/// requested target state.
///
/// Usage pattern (mirrors the C `bus_wait_for_units_run` loop):
///
/// 1. Create with [`BusWaitForUnits::new`].
/// 2. Register units with [`BusWaitForUnits::add_unit`].
/// 3. In the D-Bus event loop, feed updates via
///    [`handle_properties_changed`], [`handle_get_all_reply`], or
///    [`handle_get_all_error`].
/// 4. Poll [`state`] after each round; when it is no longer
///    [`Running`], waiting is done.
///
/// [`Running`]: BusWaitForUnitsState::Running
/// [`state`]: BusWaitForUnits::state
#[derive(Debug, Clone)]
pub struct BusWaitForUnits {
    items: HashMap<String, WaitForItem>,
    state: BusWaitForUnitsState,
    has_failed: bool,
    disconnected: bool,
    completed: Vec<CompletedUnit>,
}

impl Default for BusWaitForUnits {
    fn default() -> Self {
        Self::new()
    }
}

impl BusWaitForUnits {
    /// Create a new, empty unit waiter in the [`Success`] state.
    ///
    /// [`Success`]: BusWaitForUnitsState::Success
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
            state: BusWaitForUnitsState::Success,
            has_failed: false,
            disconnected: false,
            completed: Vec::new(),
        }
    }

    // ── Adding units ────────────────────────────────────────────────

    /// Register a unit for monitoring.
    ///
    /// `name` is the unit name (e.g. `"sshd.service"`).  At least one
    /// flag in [`WaitForUnitsFlags::TARGET_MASK`] must be set.
    ///
    /// Returns the computed D-Bus object path of the unit on success.
    /// Returns `Ok(None)` if the unit was already being tracked.
    pub fn add_unit(
        &mut self,
        name: &str,
        flags: WaitForUnitsFlags,
    ) -> Result<Option<String>, UnitWaitError> {
        if name.is_empty() {
            return Err(UnitWaitError::InvalidUnit(name.to_owned()));
        }
        if flags.intersects(WaitForUnitsFlags::TARGET_MASK) == false {
            return Err(UnitWaitError::InvalidFlags);
        }

        let bus_path = unit_dbus_path_from_name(name);

        if self.items.contains_key(&bus_path) {
            return Ok(None);
        }

        let item = WaitForItem::new(bus_path.clone(), flags);
        self.items.insert(bus_path.clone(), item);
        self.state = BusWaitForUnitsState::Running;

        Ok(Some(bus_path))
    }

    // ── Feeding D-Bus events ────────────────────────────────────────

    /// Process a `PropertiesChanged` signal for a tracked unit.
    ///
    /// `interface` must be `"org.freedesktop.systemd1.Unit"` for the
    /// update to be applied; other interfaces are silently ignored.
    pub fn handle_properties_changed(
        &mut self,
        bus_path: &str,
        interface: &str,
        props: &UnitProperties,
    ) {
        if interface != "org.freedesktop.systemd1.Unit" {
            return;
        }
        self.update_item(bus_path, props);
    }

    /// Process a successful `GetAll` method reply for a tracked unit.
    pub fn handle_get_all_reply(&mut self, bus_path: &str, props: &UnitProperties) {
        self.update_item(bus_path, props);
    }

    /// Process a `GetAll` method error for a tracked unit.
    ///
    /// Marks the overall wait as failed and removes the item.
    pub fn handle_get_all_error(&mut self, bus_path: &str, error_message: &str) {
        if self.items.remove(bus_path).is_some() {
            self.has_failed = true;
            self.completed.push(CompletedUnit {
                bus_path: bus_path.to_owned(),
                good: false,
            });
        }
        self.refresh_state();
    }

    /// Mark the D-Bus connection as terminated.
    ///
    /// All pending items are immediately removed with `good = false`,
    /// and the state transitions to [`Failure`].
    ///
    /// [`Failure`]: BusWaitForUnitsState::Failure
    pub fn set_disconnected(&mut self) {
        if self.disconnected {
            return;
        }
        self.disconnected = true;
        self.has_failed = true;
        for path in self.items.keys() {
            self.completed.push(CompletedUnit {
                bus_path: path.clone(),
                good: false,
            });
        }
        self.items.clear();
        self.refresh_state();
    }

    // ── Querying ────────────────────────────────────────────────────

    /// Current overall state.
    pub fn state(&self) -> BusWaitForUnitsState {
        self.state
    }

    /// Returns `true` when no items remain (success or failure).
    pub fn is_ready(&self) -> bool {
        if self.disconnected {
            return true;
        }
        self.items.is_empty()
    }

    /// Number of units still being tracked.
    pub fn pending_count(&self) -> usize {
        self.items.len()
    }

    /// Whether any tracked unit has recorded a failure.
    pub fn has_failed(&self) -> bool {
        self.has_failed
    }

    /// Whether the bus has been disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.disconnected
    }

    /// Drain and return the list of units that completed since the last
    /// call.
    pub fn drain_completed(&mut self) -> Vec<CompletedUnit> {
        std::mem::take(&mut self.completed)
    }

    /// Remove all tracked items, invoking completion with `good = false`.
    pub fn clear(&mut self) {
        for path in self.items.keys() {
            self.completed.push(CompletedUnit {
                bus_path: path.clone(),
                good: false,
            });
        }
        self.items.clear();
        self.refresh_state();
    }

    // ── Internal ────────────────────────────────────────────────────

    /// Merge properties and possibly remove a ready item.
    fn update_item(&mut self, bus_path: &str, props: &UnitProperties) {
        let (ready, failure) = {
            let item = match self.items.get_mut(bus_path) {
                Some(i) => i,
                None => return,
            };
            item.apply_properties(props);
            item.check_ready()
        };

        if failure {
            self.has_failed = true;
        }

        if ready {
            self.items.remove(bus_path);
            self.completed.push(CompletedUnit {
                bus_path: bus_path.to_owned(),
                good: true,
            });
            self.refresh_state();
        }
    }

    /// Recompute `self.state` from `self.has_failed` and emptiness.
    fn refresh_state(&mut self) {
        if !self.is_ready() {
            return;
        }
        self.state = if self.has_failed {
            BusWaitForUnitsState::Failure
        } else {
            BusWaitForUnitsState::Success
        };
    }
}

// ── D-Bus path helpers ─────────────────────────────────────────────────────

/// Escape a unit name for use as a D-Bus path label.
///
/// This delegates the byte policy to the basic Rust mirror of C's
/// `bus_label_escape()`: ASCII letters are preserved, later digits remain
/// literal, and every other byte is encoded as lowercase `_xx`.
fn bus_label_escape(s: &str) -> String {
    let escaped = bus_label_escape_bytes(s.as_bytes())
        .expect("String allocation is the API's established out-of-memory behavior");
    // `bus_label_escape_bytes()` only emits ASCII labels, regardless of the
    // UTF-8 input bytes, so this conversion cannot fail.
    String::from_utf8(escaped).expect("bus label escape output is ASCII")
}

/// Build the D-Bus object path for a systemd unit name.
///
/// ```ignore
/// assert_eq!(
///     unit_dbus_path_from_name("sshd.service"),
///     "/org/freedesktop/systemd1/unit/sshd_2eservice"
/// );
/// ```
pub fn unit_dbus_path_from_name(name: &str) -> String {
    let escaped = bus_label_escape(name);
    format!("/org/freedesktop/systemd1/unit/{escaped}")
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── State enum ─────────────────────────────────────────────────

    #[test]
    fn test_state_default_is_success() {
        assert_eq!(
            BusWaitForUnitsState::default(),
            BusWaitForUnitsState::Success
        );
    }

    #[test]
    fn test_state_is_finished() {
        assert!(BusWaitForUnitsState::Success.is_finished());
        assert!(BusWaitForUnitsState::Failure.is_finished());
        assert!(!BusWaitForUnitsState::Running.is_finished());
    }

    // ── Flags ──────────────────────────────────────────────────────

    #[test]
    fn test_flag_values_match_c() {
        assert_eq!(WaitForUnitsFlags::FOR_MAINTENANCE_END.bits(), 1);
        assert_eq!(WaitForUnitsFlags::FOR_INACTIVE.bits(), 2);
        assert_eq!(WaitForUnitsFlags::NO_JOB.bits(), 4);
        assert_eq!(WaitForUnitsFlags::REFFED.bits(), 8);
    }

    #[test]
    fn test_target_mask() {
        let mask = WaitForUnitsFlags::TARGET_MASK;
        assert!(mask.contains(WaitForUnitsFlags::FOR_MAINTENANCE_END));
        assert!(mask.contains(WaitForUnitsFlags::FOR_INACTIVE));
        assert!(mask.contains(WaitForUnitsFlags::NO_JOB));
        assert!(!mask.contains(WaitForUnitsFlags::REFFED));
    }

    #[test]
    fn test_flags_empty_intersects_target_mask_is_false() {
        assert!(!WaitForUnitsFlags::empty().intersects(WaitForUnitsFlags::TARGET_MASK));
    }

    #[test]
    fn test_reffed_alone_does_not_intersect_target_mask() {
        assert!(!WaitForUnitsFlags::REFFED.intersects(WaitForUnitsFlags::TARGET_MASK));
    }

    // ── Construction ──────────────────────────────────────────────

    #[test]
    fn test_new() {
        let mut w = BusWaitForUnits::new();
        assert_eq!(w.state(), BusWaitForUnitsState::Success);
        assert!(w.is_ready());
        assert_eq!(w.pending_count(), 0);
        assert!(!w.has_failed());
        assert!(!w.is_disconnected());
        assert!(w.drain_completed().is_empty());
    }

    #[test]
    fn test_default() {
        let w = BusWaitForUnits::default();
        assert_eq!(w.state(), BusWaitForUnitsState::Success);
    }

    // ── add_unit ──────────────────────────────────────────────────

    #[test]
    fn test_add_unit_basic() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("sshd.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();
        assert_eq!(path, "/org/freedesktop/systemd1/unit/sshd_2eservice");
        assert_eq!(w.state(), BusWaitForUnitsState::Running);
        assert_eq!(w.pending_count(), 1);
        assert!(!w.is_ready());
    }

    #[test]
    fn test_add_unit_duplicate_returns_none() {
        let mut w = BusWaitForUnits::new();
        w.add_unit("sshd.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        let result = w
            .add_unit("sshd.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        assert!(result.is_none());
        assert_eq!(w.pending_count(), 1);
    }

    #[test]
    fn test_add_unit_empty_name_rejected() {
        let mut w = BusWaitForUnits::new();
        let err = w.add_unit("", WaitForUnitsFlags::FOR_INACTIVE).unwrap_err();
        assert!(matches!(err, UnitWaitError::InvalidUnit(_)));
    }

    #[test]
    fn test_add_unit_no_target_flags_rejected() {
        let mut w = BusWaitForUnits::new();
        let err = w
            .add_unit("a.service", WaitForUnitsFlags::REFFED)
            .unwrap_err();
        assert_eq!(err, UnitWaitError::InvalidFlags);
    }

    #[test]
    fn test_add_unit_empty_flags_rejected() {
        let mut w = BusWaitForUnits::new();
        let err = w
            .add_unit("a.service", WaitForUnitsFlags::empty())
            .unwrap_err();
        assert_eq!(err, UnitWaitError::InvalidFlags);
    }

    #[test]
    fn test_add_multiple_units() {
        let mut w = BusWaitForUnits::new();
        w.add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        w.add_unit("b.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        assert_eq!(w.pending_count(), 2);
        assert_eq!(w.state(), BusWaitForUnitsState::Running);
    }

    // ── D-Bus path helper ─────────────────────────────────────────

    #[test]
    fn test_unit_dbus_path_from_name_simple() {
        assert_eq!(
            unit_dbus_path_from_name("sshd.service"),
            "/org/freedesktop/systemd1/unit/sshd_2eservice"
        );
    }

    #[test]
    fn test_unit_dbus_path_from_name_with_dash() {
        assert_eq!(
            unit_dbus_path_from_name("systemd-journald.service"),
            "/org/freedesktop/systemd1/unit/systemd_2djournald_2eservice"
        );
    }

    #[test]
    fn test_unit_dbus_path_from_name_with_at() {
        assert_eq!(
            unit_dbus_path_from_name("getty@tty2.service"),
            "/org/freedesktop/systemd1/unit/getty_40tty2_2eservice"
        );
    }

    #[test]
    fn test_unit_dbus_path_from_name_leading_digit() {
        // Leading digit gets underscore prefix
        assert_eq!(
            unit_dbus_path_from_name("50-ssh.socket"),
            "/org/freedesktop/systemd1/unit/_350_2dssh_2esocket"
        );
    }

    #[test]
    fn test_bus_label_escape() {
        assert_eq!(bus_label_escape("abc"), "abc");
        assert_eq!(bus_label_escape("a.b"), "a_2eb");
        assert_eq!(bus_label_escape("a-b"), "a_2db");
        assert_eq!(bus_label_escape("a@b"), "a_40b");
        assert_eq!(bus_label_escape("a\\b"), "a_5cb");
        assert_eq!(bus_label_escape("123"), "_3123");
        assert_eq!(bus_label_escape("_"), "_5f");
        assert_eq!(bus_label_escape(""), "_");
        assert_eq!(bus_label_escape("é"), "_c3_a9");
    }

    // ── handle_get_all_error ──────────────────────────────────────

    #[test]
    fn test_get_all_error_marks_failed_and_completes() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        w.handle_get_all_error(&path, "UnknownUnit");

        assert!(w.has_failed());
        assert_eq!(w.pending_count(), 0);
        assert!(w.is_ready());
        assert_eq!(w.state(), BusWaitForUnitsState::Failure);

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].bus_path, path);
        assert!(!completed[0].good);
    }

    #[test]
    fn test_get_all_error_for_unknown_path_is_noop() {
        let mut w = BusWaitForUnits::new();
        w.handle_get_all_error("/nonexistent", "error");
        assert!(!w.has_failed());
    }

    // ── handle_get_all_reply / FOR_INACTIVE ───────────────────────

    #[test]
    fn test_get_all_reply_inactive_completes_item() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("inactive".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert_eq!(w.pending_count(), 0);
        assert!(w.is_ready());
        assert!(!w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Success);

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].good);
    }

    #[test]
    fn test_get_all_reply_failed_marks_failed_but_completes() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("failed".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert_eq!(w.pending_count(), 0);
        assert!(w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Failure);

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].good); // item reached terminal state
    }

    #[test]
    fn test_get_all_reply_active_keeps_waiting() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("active".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert_eq!(w.pending_count(), 1);
        assert_eq!(w.state(), BusWaitForUnitsState::Running);
    }

    #[test]
    fn test_get_all_reply_no_state_keeps_waiting() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        w.handle_get_all_reply(&path, &UnitProperties::default());

        assert_eq!(w.pending_count(), 1);
        assert_eq!(w.state(), BusWaitForUnitsState::Running);
    }

    // ── handle_properties_changed ─────────────────────────────────

    #[test]
    fn test_properties_changed_wrong_interface_ignored() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("inactive".to_owned()),
            ..Default::default()
        };
        w.handle_properties_changed(&path, "org.freedesktop.DBus.Properties", &props);

        assert_eq!(w.pending_count(), 1); // still waiting
    }

    #[test]
    fn test_properties_changed_unit_interface_applied() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("inactive".to_owned()),
            ..Default::default()
        };
        w.handle_properties_changed(&path, "org.freedesktop.systemd1.Unit", &props);

        assert_eq!(w.pending_count(), 0);
        assert!(w.is_ready());
    }

    // ── FOR_MAINTENANCE_END ───────────────────────────────────────

    #[test]
    fn test_maintenance_end_waits_for_non_maintenance() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_MAINTENANCE_END)
            .unwrap()
            .unwrap();

        // Still in maintenance → not ready
        let props = UnitProperties {
            active_state: Some("maintenance".to_owned()),
            clean_result: Some("success".to_owned()),
            live_mount_result: Some("success".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);
        assert_eq!(w.pending_count(), 1);

        // No active_state yet → not ready
        let props2 = UnitProperties {
            active_state: None,
            ..Default::default()
        };
        w.handle_properties_changed(&path, "org.freedesktop.systemd1.Unit", &props2);
        assert_eq!(w.pending_count(), 1);
    }

    #[test]
    fn test_maintenance_end_completes_on_active() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_MAINTENANCE_END)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("active".to_owned()),
            clean_result: Some("success".to_owned()),
            live_mount_result: Some("success".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert_eq!(w.pending_count(), 0);
        assert!(!w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Success);
    }

    #[test]
    fn test_maintenance_end_non_success_clean_result_fails() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_MAINTENANCE_END)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("active".to_owned()),
            clean_result: Some("resources".to_owned()),
            live_mount_result: Some("success".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert!(w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Failure);
    }

    #[test]
    fn test_maintenance_end_non_success_live_mount_result_fails() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_MAINTENANCE_END)
            .unwrap()
            .unwrap();

        let props = UnitProperties {
            active_state: Some("active".to_owned()),
            clean_result: Some("success".to_owned()),
            live_mount_result: Some("timeout".to_owned()),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);

        assert!(w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Failure);
    }

    // ── NO_JOB ────────────────────────────────────────────────────

    #[test]
    fn test_no_job_waits_for_job_zero() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::NO_JOB)
            .unwrap()
            .unwrap();

        // Job still pending → not ready
        let props = UnitProperties {
            job_id: Some(42),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);
        assert_eq!(w.pending_count(), 1);

        // Job gone → ready
        let props2 = UnitProperties {
            job_id: Some(0),
            ..Default::default()
        };
        w.handle_properties_changed(&path, "org.freedesktop.systemd1.Unit", &props2);
        assert_eq!(w.pending_count(), 0);
        assert_eq!(w.state(), BusWaitForUnitsState::Success);
    }

    #[test]
    fn test_no_job_no_job_id_yet_keeps_waiting() {
        let mut w = BusWaitForUnits::new();
        let path = w
            .add_unit("a.service", WaitForUnitsFlags::NO_JOB)
            .unwrap()
            .unwrap();

        w.handle_get_all_reply(&path, &UnitProperties::default());
        assert_eq!(w.pending_count(), 1);
    }

    // ── Combined flags ────────────────────────────────────────────

    #[test]
    fn test_combined_inactive_and_no_job() {
        let mut w = BusWaitForUnits::new();
        let flags = WaitForUnitsFlags::FOR_INACTIVE | WaitForUnitsFlags::NO_JOB;
        let path = w.add_unit("a.service", flags).unwrap().unwrap();

        // Inactive but job still pending → not ready
        let props = UnitProperties {
            active_state: Some("inactive".to_owned()),
            job_id: Some(1),
            ..Default::default()
        };
        w.handle_get_all_reply(&path, &props);
        assert_eq!(w.pending_count(), 1);

        // Job now gone → ready
        let props2 = UnitProperties {
            job_id: Some(0),
            ..Default::default()
        };
        w.handle_properties_changed(&path, "org.freedesktop.systemd1.Unit", &props2);
        assert_eq!(w.pending_count(), 0);
        assert_eq!(w.state(), BusWaitForUnitsState::Success);
    }

    // ── Multiple units ────────────────────────────────────────────

    #[test]
    fn test_multiple_units_all_complete_success() {
        let mut w = BusWaitForUnits::new();
        let p1 = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();
        let p2 = w
            .add_unit("b.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        // First completes
        w.handle_get_all_reply(
            &p1,
            &UnitProperties {
                active_state: Some("inactive".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(w.pending_count(), 1);
        assert_eq!(w.state(), BusWaitForUnitsState::Running);

        // Second completes
        w.handle_get_all_reply(
            &p2,
            &UnitProperties {
                active_state: Some("inactive".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(w.pending_count(), 0);
        assert_eq!(w.state(), BusWaitForUnitsState::Success);

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 2);
        assert!(completed.iter().all(|c| c.good));
    }

    #[test]
    fn test_multiple_units_one_fails_overall_failure() {
        let mut w = BusWaitForUnits::new();
        let p1 = w
            .add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();
        let p2 = w
            .add_unit("b.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap()
            .unwrap();

        // First fails
        w.handle_get_all_reply(
            &p1,
            &UnitProperties {
                active_state: Some("failed".to_owned()),
                ..Default::default()
            },
        );
        assert!(w.has_failed());
        assert_eq!(w.state(), BusWaitForUnitsState::Running); // still one pending

        // Second succeeds
        w.handle_get_all_reply(
            &p2,
            &UnitProperties {
                active_state: Some("inactive".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(w.state(), BusWaitForUnitsState::Failure); // has_failed
    }

    // ── Disconnected ──────────────────────────────────────────────

    #[test]
    fn test_set_disconnected_clears_all() {
        let mut w = BusWaitForUnits::new();
        w.add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        w.add_unit("b.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();

        w.set_disconnected();

        assert!(w.is_disconnected());
        assert!(w.has_failed());
        assert_eq!(w.pending_count(), 0);
        assert!(w.is_ready());
        assert_eq!(w.state(), BusWaitForUnitsState::Failure);

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 2);
        assert!(completed.iter().all(|c| !c.good));
    }

    #[test]
    fn test_set_disconnected_idempotent() {
        let mut w = BusWaitForUnits::new();
        w.set_disconnected();
        w.set_disconnected(); // should not panic or double-count
        assert_eq!(w.drain_completed().len(), 0); // already drained by first call... actually no
    }

    #[test]
    fn test_set_disconnected_no_units() {
        let mut w = BusWaitForUnits::new();
        w.set_disconnected();
        assert!(w.is_disconnected());
        // State stays Success because no items to fail
        assert_eq!(w.state(), BusWaitForUnitsState::Failure); // C sets has_failed = true
    }

    // ── clear ─────────────────────────────────────────────────────

    #[test]
    fn test_clear_removes_all_with_good_false() {
        let mut w = BusWaitForUnits::new();
        w.add_unit("a.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();
        w.add_unit("b.service", WaitForUnitsFlags::FOR_INACTIVE)
            .unwrap();

        w.clear();

        assert_eq!(w.pending_count(), 0);
        assert!(w.is_ready());

        let completed = w.drain_completed();
        assert_eq!(completed.len(), 2);
        assert!(completed.iter().all(|c| !c.good));
    }

    // ── Error Display ─────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert!(!UnitWaitError::InvalidFlags.to_string().is_empty());
        assert!(!UnitWaitError::Disconnected.to_string().is_empty());
        assert!(!UnitWaitError::OutOfMemory.to_string().is_empty());
        assert!(
            !UnitWaitError::InvalidUnit("x".into())
                .to_string()
                .is_empty()
        );
        assert!(
            !UnitWaitError::GetAllFailed {
                bus_path: "/p".into(),
                message: "err".into(),
            }
            .to_string()
            .is_empty()
        );
    }

    #[test]
    fn test_get_all_failed_error_contains_path_and_message() {
        let err = UnitWaitError::GetAllFailed {
            bus_path: "/org/freedesktop/systemd1/unit/a_2eservice".into(),
            message: "UnknownUnit".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("a_2eservice"));
        assert!(msg.contains("UnknownUnit"));
    }

    // ── WaitForItem check_ready (unit tests for internal logic) ──

    #[test]
    fn test_item_check_ready_inactive_flag() {
        let item = WaitForItem::new("/unit/a".into(), WaitForUnitsFlags::FOR_INACTIVE);
        // No state yet → not ready
        assert_eq!(item.check_ready(), (false, false));

        // Active → not ready
        let mut item = item;
        item.active_state = Some("active".into());
        assert_eq!(item.check_ready(), (false, false));

        // Inactive → ready
        item.active_state = Some("inactive".into());
        assert_eq!(item.check_ready(), (true, false));

        // Failed → ready + failure
        item.active_state = Some("failed".into());
        assert_eq!(item.check_ready(), (true, true));
    }

    #[test]
    fn test_item_check_ready_no_job_flag() {
        let item = WaitForItem::new("/unit/a".into(), WaitForUnitsFlags::NO_JOB);
        // No job id → not ready (None ≠ Some(0))
        assert_eq!(item.check_ready(), (false, false));

        let mut item = item;
        item.job_id = Some(42);
        assert_eq!(item.check_ready(), (false, false));

        item.job_id = Some(0);
        assert_eq!(item.check_ready(), (true, false));
    }

    #[test]
    fn test_item_check_ready_maintenance_end_flag() {
        let item = WaitForItem::new("/unit/a".into(), WaitForUnitsFlags::FOR_MAINTENANCE_END);
        // No state → not ready
        assert_eq!(item.check_ready(), (false, false));

        let mut item = item;
        item.active_state = Some("maintenance".into());
        assert_eq!(item.check_ready(), (false, false));

        // Active with success results → ready
        item.active_state = Some("active".into());
        item.clean_result = Some("success".into());
        item.live_mount_result = Some("success".into());
        assert_eq!(item.check_ready(), (true, false));

        // Non-success clean result → failure
        item.clean_result = Some("resources".into());
        assert_eq!(item.check_ready(), (true, true));
    }

    #[test]
    fn test_item_apply_properties() {
        let mut item = WaitForItem::new("/unit/a".into(), WaitForUnitsFlags::FOR_INACTIVE);
        item.apply_properties(&UnitProperties {
            active_state: Some("active".into()),
            job_id: Some(5),
            clean_result: Some("success".into()),
            live_mount_result: Some("success".into()),
        });
        assert_eq!(item.active_state.as_deref(), Some("active"));
        assert_eq!(item.job_id, Some(5));
        assert_eq!(item.clean_result.as_deref(), Some("success"));

        // Partial update: only changes what's Some
        item.apply_properties(&UnitProperties {
            active_state: Some("inactive".into()),
            ..Default::default()
        });
        assert_eq!(item.active_state.as_deref(), Some("inactive"));
        assert_eq!(item.job_id, Some(5)); // unchanged
    }
}
