// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c (PID watch ownership)
//
//! Manager-owned PID identity indexes.
//!
//! Keeping numeric compatibility indexes and their reassignment cleanup out
//! of service command execution makes the ownership boundary explicit. The
//! `Unit` PID slots and `ProcessTracker` identity remain authoritative; these
//! maps only route a reaper/notify event to that owner.

use super::{RuntimeManager, TrackedPidRole};

impl RuntimeManager {
    pub(super) fn track_pid(&mut self, unit_name: &str, pid: u32, role: TrackedPidRole) {
        // A numeric PID may be reused only after the previous identity has
        // left the manager. If a caller presents a replacement identity
        // before the old reverse index was reaped, detach every compatibility
        // reference first. Otherwise a later kill/notify lookup could steer
        // the new process through the old unit's main/control slot.
        if let Some(previous_unit) = self.pid_to_unit_map.get(&pid).cloned()
            && previous_unit != unit_name
        {
            if self.unit_pid_map.get(&previous_unit).copied() == Some(pid) {
                self.unit_pid_map.remove(&previous_unit);
            }
            if let Some(unit) = self.units.get_mut(&previous_unit) {
                if unit.main_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.main_pid = None;
                }
                if unit.control_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.control_pid = None;
                }
                unit.watched_pids.retain(|pid_ref| pid_ref.0 != pid);
            }
        }

        // This compatibility index cannot represent main and control children
        // concurrently. Preserve a main PID once one exists; lifecycle code
        // uses Unit's two PID slots and the reverse maps below.
        if role == TrackedPidRole::Main || !self.unit_pid_map.contains_key(unit_name) {
            self.unit_pid_map.insert(unit_name.to_string(), pid);
        }
        self.pid_to_unit_map.insert(pid, unit_name.to_string());
        self.pid_role_map.insert(pid, role);
        self.update_unit_cgroup_population_from_tracking(unit_name);
    }

    pub(super) fn untrack_pid(&mut self, pid: u32) {
        #[cfg(target_os = "linux")]
        self.pending_exec_confirmations.remove(&pid);
        let reverse_owner = self.pid_to_unit_map.remove(&pid);
        self.pid_role_map.remove(&pid);

        // C's unit_unwatch_pidref() clears both the Unit-local PID set and
        // the manager reverse indexes. Clear the known owner directly. If a
        // repeated/late call arrives after the reverse index was already
        // consumed, scan for stale local slots as a defensive fallback. Do
        // not scan when an owner is known: a newly tracked process may reuse
        // the same numeric PID in another unit and must remain untouched.
        let mut owners = Vec::new();
        if let Some(unit_name) = reverse_owner {
            if let Some(unit) = self.units.get_mut(&unit_name) {
                if unit.main_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.main_pid = None;
                }
                if unit.control_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.control_pid = None;
                }
                unit.watched_pids.retain(|pid_ref| pid_ref.0 != pid);
            }
            owners.push(unit_name);
        } else {
            for (unit_name, unit) in &mut self.units {
                let matches = unit.main_pid.map(|pid_ref| pid_ref.0) == Some(pid)
                    || unit.control_pid.map(|pid_ref| pid_ref.0) == Some(pid)
                    || unit.watched_pids.iter().any(|pid_ref| pid_ref.0 == pid);
                if !matches {
                    continue;
                }
                if unit.main_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.main_pid = None;
                }
                if unit.control_pid.map(|pid_ref| pid_ref.0) == Some(pid) {
                    unit.control_pid = None;
                }
                unit.watched_pids.retain(|pid_ref| pid_ref.0 != pid);
                owners.push(unit_name.clone());
            }
        }
        for unit_name in owners {
            if self.unit_pid_map.get(&unit_name).copied() == Some(pid) {
                self.unit_pid_map.remove(&unit_name);
            }
        }
    }
}
