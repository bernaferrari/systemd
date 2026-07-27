// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/manager.c, src/core/manager.h
//
// Manager state, objective, and timestamp string table conversions.
//
// Provides safe Rust equivalents for the DEFINE_STRING_TABLE_LOOKUP
// string tables in manager.c (manager_state_table,
// manager_objective_table, manager_timestamp_table).

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerState {
    Initializing,
    Starting,
    Running,
    Degraded,
    Maintenance,
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerObjective {
    Ok,
    Exit,
    Reload,
    Reexecute,
    Reboot,
    SoftReboot,
    Poweroff,
    Halt,
    Kexec,
    SwitchRoot,
}

impl ManagerObjective {
    /// Return the spelling used by the manager's varlink objective methods.
    ///
    /// Varlink can request only externally actionable objectives. `Ok`, `Exit`,
    /// and `SwitchRoot` are internal lifecycle outcomes and deliberately have
    /// no varlink method spelling.
    pub const fn varlink_method_name(self) -> Option<&'static str> {
        match self {
            Self::Reload => Some("Reload"),
            Self::Reexecute => Some("Reexecute"),
            Self::Poweroff => Some("PowerOff"),
            Self::Reboot => Some("Reboot"),
            Self::Halt => Some("Halt"),
            Self::Kexec => Some("KExec"),
            Self::SoftReboot => Some("SoftReboot"),
            Self::Ok | Self::Exit | Self::SwitchRoot => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerTimestamp {
    Firmware,
    Loader,
    Kernel,
    Initrd,
    Userspace,
    Finish,
    SecurityStart,
    SecurityFinish,
    GeneratorsStart,
    GeneratorsFinish,
    UnitsLoadStart,
    UnitsLoadFinish,
    UnitsLoad,
    InitrdSecurityStart,
    InitrdSecurityFinish,
    InitrdGeneratorsStart,
    InitrdGeneratorsFinish,
    InitrdUnitsLoadStart,
    InitrdUnitsLoadFinish,
    ShutdownStart,
    ShutdownFinish,
    PreviousShutdownStart,
    PreviousShutdownFinish,
    PreviousShutdownLateStart,
    PreviousShutdownLateFinish,
}

// ── Error ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableError;

const EINVAL: i32 = -22;

// ── ManagerState table ────────────────────────────────────────────────────

static MANAGER_STATE_TABLE: &[(ManagerState, &str)] = &[
    (ManagerState::Initializing, "initializing"),
    (ManagerState::Starting, "starting"),
    (ManagerState::Running, "running"),
    (ManagerState::Degraded, "degraded"),
    (ManagerState::Maintenance, "maintenance"),
    (ManagerState::Stopping, "stopping"),
];

pub fn manager_state_to_string(state: ManagerState) -> Option<&'static str> {
    MANAGER_STATE_TABLE
        .iter()
        .find(|(s, _)| *s == state)
        .map(|(_, name)| *name)
}

pub fn manager_state_from_string(name: &str) -> Result<ManagerState, TableError> {
    MANAGER_STATE_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(state, _)| *state)
        .ok_or(TableError)
}

// ── ManagerObjective table ────────────────────────────────────────────────

static MANAGER_OBJECTIVE_TABLE: &[(ManagerObjective, &str)] = &[
    (ManagerObjective::Ok, "ok"),
    (ManagerObjective::Exit, "exit"),
    (ManagerObjective::Reload, "reload"),
    (ManagerObjective::Reexecute, "reexecute"),
    (ManagerObjective::Reboot, "reboot"),
    (ManagerObjective::SoftReboot, "soft-reboot"),
    (ManagerObjective::Poweroff, "poweroff"),
    (ManagerObjective::Halt, "halt"),
    (ManagerObjective::Kexec, "kexec"),
    (ManagerObjective::SwitchRoot, "switch-root"),
];

pub fn manager_objective_to_string(obj: ManagerObjective) -> Option<&'static str> {
    MANAGER_OBJECTIVE_TABLE
        .iter()
        .find(|(o, _)| *o == obj)
        .map(|(_, name)| *name)
}

pub fn manager_objective_from_string(name: &str) -> Result<ManagerObjective, TableError> {
    MANAGER_OBJECTIVE_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(obj, _)| *obj)
        .ok_or(TableError)
}

// ── ManagerTimestamp table ────────────────────────────────────────────────

static MANAGER_TIMESTAMP_TABLE: &[(ManagerTimestamp, &str)] = &[
    (ManagerTimestamp::Firmware, "firmware"),
    (ManagerTimestamp::Loader, "loader"),
    (ManagerTimestamp::Kernel, "kernel"),
    (ManagerTimestamp::Initrd, "initrd"),
    (ManagerTimestamp::Userspace, "userspace"),
    (ManagerTimestamp::Finish, "finish"),
    (ManagerTimestamp::SecurityStart, "security-start"),
    (ManagerTimestamp::SecurityFinish, "security-finish"),
    (ManagerTimestamp::GeneratorsStart, "generators-start"),
    (ManagerTimestamp::GeneratorsFinish, "generators-finish"),
    (ManagerTimestamp::UnitsLoadStart, "units-load-start"),
    (ManagerTimestamp::UnitsLoadFinish, "units-load-finish"),
    (ManagerTimestamp::UnitsLoad, "units-load"),
    (
        ManagerTimestamp::InitrdSecurityStart,
        "initrd-security-start",
    ),
    (
        ManagerTimestamp::InitrdSecurityFinish,
        "initrd-security-finish",
    ),
    (
        ManagerTimestamp::InitrdGeneratorsStart,
        "initrd-generators-start",
    ),
    (
        ManagerTimestamp::InitrdGeneratorsFinish,
        "initrd-generators-finish",
    ),
    (
        ManagerTimestamp::InitrdUnitsLoadStart,
        "initrd-units-load-start",
    ),
    (
        ManagerTimestamp::InitrdUnitsLoadFinish,
        "initrd-units-load-finish",
    ),
    (ManagerTimestamp::ShutdownStart, "shutdown-start"),
    (ManagerTimestamp::ShutdownFinish, "shutdown-finish"),
    (
        ManagerTimestamp::PreviousShutdownStart,
        "previous-shutdown-start",
    ),
    (
        ManagerTimestamp::PreviousShutdownFinish,
        "previous-shutdown-finish",
    ),
    (
        ManagerTimestamp::PreviousShutdownLateStart,
        "previous-shutdown-late-start",
    ),
    (
        ManagerTimestamp::PreviousShutdownLateFinish,
        "previous-shutdown-late-finish",
    ),
];

pub fn manager_timestamp_to_string(ts: ManagerTimestamp) -> Option<&'static str> {
    MANAGER_TIMESTAMP_TABLE
        .iter()
        .find(|(t, _)| *t == ts)
        .map(|(_, name)| *name)
}

pub fn manager_timestamp_from_string(name: &str) -> Result<ManagerTimestamp, TableError> {
    MANAGER_TIMESTAMP_TABLE
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(ts, _)| *ts)
        .ok_or(TableError)
}

// ── Generic helpers ───────────────────────────────────────────────────────

pub fn table_to_string_raw<'a>(table: &'a [&'a str], v: i32) -> Option<&'a str> {
    if v < 0 {
        return None;
    }
    let idx = v as usize;
    if idx >= table.len() {
        return None;
    }
    Some(table[idx])
}

pub fn table_from_string_raw(table: &[&str], s: &str) -> Result<i32, TableError> {
    table
        .iter()
        .position(|item| *item == s)
        .map(|idx| idx as i32)
        .ok_or(TableError)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_state_roundtrip() {
        for state in [
            ManagerState::Initializing,
            ManagerState::Starting,
            ManagerState::Running,
            ManagerState::Degraded,
            ManagerState::Maintenance,
            ManagerState::Stopping,
        ] {
            let name = manager_state_to_string(state).unwrap();
            let back = manager_state_from_string(name).unwrap();
            assert_eq!(back, state);
        }
    }

    #[test]
    fn test_manager_state_from_string_invalid() {
        assert!(manager_state_from_string("nonexistent").is_err());
    }

    #[test]
    fn test_manager_state_to_string_known_values() {
        assert_eq!(
            manager_state_to_string(ManagerState::Initializing),
            Some("initializing")
        );
        assert_eq!(
            manager_state_to_string(ManagerState::Running),
            Some("running")
        );
        assert_eq!(
            manager_state_to_string(ManagerState::Stopping),
            Some("stopping")
        );
    }

    #[test]
    fn test_manager_objective_roundtrip() {
        for obj in [
            ManagerObjective::Ok,
            ManagerObjective::Exit,
            ManagerObjective::Reload,
            ManagerObjective::Reexecute,
            ManagerObjective::Reboot,
            ManagerObjective::SoftReboot,
            ManagerObjective::Poweroff,
            ManagerObjective::Halt,
            ManagerObjective::Kexec,
            ManagerObjective::SwitchRoot,
        ] {
            let name = manager_objective_to_string(obj).unwrap();
            let back = manager_objective_from_string(name).unwrap();
            assert_eq!(back, obj);
        }
    }

    #[test]
    fn test_manager_objective_from_string_invalid() {
        assert!(manager_objective_from_string("nope").is_err());
    }

    #[test]
    fn test_manager_objective_known_values() {
        assert_eq!(
            manager_objective_to_string(ManagerObjective::Ok),
            Some("ok")
        );
        assert_eq!(
            manager_objective_to_string(ManagerObjective::SoftReboot),
            Some("soft-reboot")
        );
        assert_eq!(
            manager_objective_to_string(ManagerObjective::SwitchRoot),
            Some("switch-root")
        );
    }

    #[test]
    fn manager_objective_varlink_names_cover_only_externally_actionable_values() {
        assert_eq!(
            ManagerObjective::Reload.varlink_method_name(),
            Some("Reload")
        );
        assert_eq!(
            ManagerObjective::SoftReboot.varlink_method_name(),
            Some("SoftReboot")
        );
        assert_eq!(ManagerObjective::Ok.varlink_method_name(), None);
        assert_eq!(ManagerObjective::Exit.varlink_method_name(), None);
        assert_eq!(ManagerObjective::SwitchRoot.varlink_method_name(), None);
    }

    #[test]
    fn test_manager_timestamp_roundtrip() {
        for ts in [
            ManagerTimestamp::Firmware,
            ManagerTimestamp::Loader,
            ManagerTimestamp::Kernel,
            ManagerTimestamp::Initrd,
            ManagerTimestamp::Userspace,
            ManagerTimestamp::Finish,
            ManagerTimestamp::SecurityStart,
            ManagerTimestamp::SecurityFinish,
            ManagerTimestamp::GeneratorsStart,
            ManagerTimestamp::GeneratorsFinish,
            ManagerTimestamp::UnitsLoadStart,
            ManagerTimestamp::UnitsLoadFinish,
            ManagerTimestamp::UnitsLoad,
            ManagerTimestamp::InitrdSecurityStart,
            ManagerTimestamp::InitrdSecurityFinish,
            ManagerTimestamp::InitrdGeneratorsStart,
            ManagerTimestamp::InitrdGeneratorsFinish,
            ManagerTimestamp::InitrdUnitsLoadStart,
            ManagerTimestamp::InitrdUnitsLoadFinish,
            ManagerTimestamp::ShutdownStart,
            ManagerTimestamp::ShutdownFinish,
            ManagerTimestamp::PreviousShutdownStart,
            ManagerTimestamp::PreviousShutdownFinish,
            ManagerTimestamp::PreviousShutdownLateStart,
            ManagerTimestamp::PreviousShutdownLateFinish,
        ] {
            let name = manager_timestamp_to_string(ts).unwrap();
            let back = manager_timestamp_from_string(name).unwrap();
            assert_eq!(back, ts);
        }
    }

    #[test]
    fn test_manager_timestamp_count() {
        assert_eq!(MANAGER_TIMESTAMP_TABLE.len(), 25);
    }

    #[test]
    fn test_manager_timestamp_known_values() {
        assert_eq!(
            manager_timestamp_to_string(ManagerTimestamp::Firmware),
            Some("firmware")
        );
        assert_eq!(
            manager_timestamp_to_string(ManagerTimestamp::ShutdownStart),
            Some("shutdown-start")
        );
        assert_eq!(
            manager_timestamp_to_string(ManagerTimestamp::PreviousShutdownLateFinish),
            Some("previous-shutdown-late-finish")
        );
        assert_eq!(
            manager_timestamp_to_string(ManagerTimestamp::UnitsLoad),
            Some("units-load")
        );
    }

    #[test]
    fn test_table_to_string_raw_valid() {
        let table: &[&str] = &["alpha", "beta", "gamma"];
        assert_eq!(table_to_string_raw(table, 0), Some("alpha"));
        assert_eq!(table_to_string_raw(table, 2), Some("gamma"));
    }

    #[test]
    fn test_table_to_string_raw_out_of_range() {
        let table: &[&str] = &["alpha", "beta"];
        assert_eq!(table_to_string_raw(table, -1), None);
        assert_eq!(table_to_string_raw(table, 5), None);
    }

    #[test]
    fn test_table_from_string_raw_valid() {
        let table: &[&str] = &["alpha", "beta", "gamma"];
        assert_eq!(table_from_string_raw(table, "beta"), Ok(1));
    }

    #[test]
    fn test_table_from_string_raw_not_found() {
        let table: &[&str] = &["alpha", "beta"];
        assert!(table_from_string_raw(table, "gamma").is_err());
    }
}
