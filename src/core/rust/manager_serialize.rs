// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/manager-serialize.c

//! Scalar parsing model for the manager serialization format.
//!
//! This is compiled-but-disconnected from the live manager owner.
//!
//! This is not a live PID 1 reexec snapshot. It deliberately owns no units,
//! jobs, event sources, or file descriptors and must not be used to construct
//! a replacement [`crate::runtime_manager::RuntimeManager`]. A real lifecycle
//! handoff must consume or retain that exact manager owner and transfer every
//! owned descriptor explicitly.

use std::collections::BTreeMap;
use std::fmt;

use crate::manager_tables::{ManagerObjective, ManagerTimestamp};

pub const SOURCE_PATH: &str = "src/core/manager-serialize.c";
pub const DESTROY_IPC_FLAG: u32 = 1 << 31;

pub type Result<T> = std::result::Result<T, ManagerSerializeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerSerializeError {
    InvalidLine(String),
    InvalidNumber(String),
    InvalidBoolean(String),
}

impl fmt::Display for ManagerSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine(line) => write!(f, "invalid serialization line: {line}"),
            Self::InvalidNumber(value) => write!(f, "invalid numeric value: {value}"),
            Self::InvalidBoolean(value) => write!(f, "invalid boolean value: {value}"),
        }
    }
}

impl std::error::Error for ManagerSerializeError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagerScalarState {
    pub last_transaction_id: u64,
    pub current_job_id: u32,
    pub n_installed_jobs: u32,
    pub n_failed_jobs: u32,
    pub taint_logged: bool,
    pub service_watchdogs: bool,
    pub client_environment: Vec<String>,
    pub notify_socket: Option<String>,
    pub uid_refs: BTreeMap<u32, u32>,
    pub gid_refs: BTreeMap<u32, u32>,
}

pub fn manager_timestamp_shall_serialize(timestamp: ManagerTimestamp, in_initrd: bool) -> bool {
    if !in_initrd {
        return true;
    }

    !matches!(
        timestamp,
        ManagerTimestamp::Userspace
            | ManagerTimestamp::Finish
            | ManagerTimestamp::SecurityStart
            | ManagerTimestamp::SecurityFinish
            | ManagerTimestamp::GeneratorsStart
            | ManagerTimestamp::GeneratorsFinish
            | ManagerTimestamp::UnitsLoadStart
            | ManagerTimestamp::UnitsLoadFinish
    )
}

pub fn map_timestamp_serialization(
    previous_objective: ManagerObjective,
    timestamp: ManagerTimestamp,
) -> Option<ManagerTimestamp> {
    if matches!(
        previous_objective,
        ManagerObjective::SoftReboot | ManagerObjective::SwitchRoot
    ) && matches!(
        timestamp,
        ManagerTimestamp::Userspace
            | ManagerTimestamp::Finish
            | ManagerTimestamp::SecurityStart
            | ManagerTimestamp::SecurityFinish
            | ManagerTimestamp::GeneratorsStart
            | ManagerTimestamp::GeneratorsFinish
            | ManagerTimestamp::UnitsLoadStart
            | ManagerTimestamp::UnitsLoadFinish
    ) {
        return None;
    }

    if previous_objective == ManagerObjective::SoftReboot {
        return Some(match timestamp {
            ManagerTimestamp::ShutdownStart => ManagerTimestamp::PreviousShutdownStart,
            ManagerTimestamp::ShutdownFinish => ManagerTimestamp::PreviousShutdownFinish,
            other => other,
        });
    }

    Some(timestamp)
}

pub fn manager_serialize_uid_refs_internal(
    refs: &BTreeMap<u32, u32>,
    field_name: &str,
) -> Result<Vec<String>> {
    if field_name.is_empty() {
        return Err(ManagerSerializeError::InvalidLine(
            "empty field name".into(),
        ));
    }

    Ok(refs
        .iter()
        .filter(|(_, flags)| *flags & DESTROY_IPC_FLAG != 0)
        .map(|(uid, _)| format!("{field_name}={uid}"))
        .collect())
}

pub fn manager_serialize(state: &ManagerScalarState, switching_root: bool) -> Result<String> {
    let mut lines = vec![
        format!("last-transaction-id={}", state.last_transaction_id),
        format!("current-job-id={}", state.current_job_id),
        format!("n-installed-jobs={}", state.n_installed_jobs),
        format!("n-failed-jobs={}", state.n_failed_jobs),
        format!(
            "taint-logged={}",
            if state.taint_logged { "yes" } else { "no" }
        ),
        format!(
            "service-watchdogs={}",
            if state.service_watchdogs { "yes" } else { "no" }
        ),
    ];

    if !switching_root {
        lines.extend(
            state
                .client_environment
                .iter()
                .map(|entry| format!("env={entry}")),
        );
    }

    if let Some(socket) = &state.notify_socket {
        lines.push(format!("notify-socket={socket}"));
    }

    lines.extend(manager_serialize_uid_refs_internal(
        &state.uid_refs,
        "destroy-ipc-uid",
    )?);
    lines.extend(manager_serialize_uid_refs_internal(
        &state.gid_refs,
        "destroy-ipc-gid",
    )?);

    Ok(lines.join("\n"))
}

pub fn manager_deserialize(state: &mut ManagerScalarState, input: &str) -> Result<()> {
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        if let Some(value) = line.strip_prefix("last-transaction-id=") {
            let parsed = parse_u64(value)?;
            state.last_transaction_id = state.last_transaction_id.max(parsed);
        } else if let Some(value) = line.strip_prefix("current-job-id=") {
            let parsed = parse_u32(value)?;
            state.current_job_id = state.current_job_id.max(parsed);
        } else if let Some(value) = line.strip_prefix("n-installed-jobs=") {
            state.n_installed_jobs = state.n_installed_jobs.saturating_add(parse_u32(value)?);
        } else if let Some(value) = line.strip_prefix("n-failed-jobs=") {
            state.n_failed_jobs = state.n_failed_jobs.saturating_add(parse_u32(value)?);
        } else if let Some(value) = line.strip_prefix("taint-logged=") {
            state.taint_logged |= parse_boolean(value)?;
        } else if let Some(value) = line.strip_prefix("service-watchdogs=") {
            state.service_watchdogs = parse_boolean(value)?;
        } else if let Some(value) = line.strip_prefix("env=") {
            state.client_environment.push(value.to_string());
        } else if let Some(value) = line.strip_prefix("notify-socket=") {
            state.notify_socket = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("destroy-ipc-uid=") {
            manager_deserialize_uid_refs_one_internal(&mut state.uid_refs, value)?;
        } else if let Some(value) = line.strip_prefix("destroy-ipc-gid=") {
            manager_deserialize_uid_refs_one_internal(&mut state.gid_refs, value)?;
        } else {
            return Err(ManagerSerializeError::InvalidLine(line.to_string()));
        }
    }

    Ok(())
}

pub fn manager_deserialize_uid_refs_one_internal(
    refs: &mut BTreeMap<u32, u32>,
    value: &str,
) -> Result<()> {
    let id = parse_u32(value)?;
    if id == 0 {
        return Ok(());
    }

    let flags = refs.entry(id).or_insert(0);
    *flags |= DESTROY_IPC_FLAG;
    Ok(())
}

fn parse_u32(value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| ManagerSerializeError::InvalidNumber(value.into()))
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| ManagerSerializeError::InvalidNumber(value.into()))
}

fn parse_boolean(value: &str) -> Result<bool> {
    match value {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        other => Err(ManagerSerializeError::InvalidBoolean(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_policy_matches_initrd_rules() {
        assert!(manager_timestamp_shall_serialize(
            ManagerTimestamp::Userspace,
            false
        ));
        assert!(!manager_timestamp_shall_serialize(
            ManagerTimestamp::Userspace,
            true
        ));
        assert!(manager_timestamp_shall_serialize(
            ManagerTimestamp::Firmware,
            true
        ));
    }

    #[test]
    fn timestamp_mapping_matches_soft_reboot_and_switch_root_rules() {
        assert_eq!(
            map_timestamp_serialization(ManagerObjective::SoftReboot, ManagerTimestamp::Userspace),
            None
        );
        assert_eq!(
            map_timestamp_serialization(
                ManagerObjective::SwitchRoot,
                ManagerTimestamp::UnitsLoadFinish
            ),
            None
        );
        assert_eq!(
            map_timestamp_serialization(
                ManagerObjective::SoftReboot,
                ManagerTimestamp::ShutdownStart
            ),
            Some(ManagerTimestamp::PreviousShutdownStart)
        );
        assert_eq!(
            map_timestamp_serialization(
                ManagerObjective::SoftReboot,
                ManagerTimestamp::ShutdownFinish
            ),
            Some(ManagerTimestamp::PreviousShutdownFinish)
        );
        assert_eq!(
            map_timestamp_serialization(
                ManagerObjective::Reexecute,
                ManagerTimestamp::ShutdownFinish
            ),
            Some(ManagerTimestamp::ShutdownFinish)
        );
    }

    #[test]
    fn serializes_destroy_ipc_uid_entries_only() {
        let refs = BTreeMap::from([(1000, DESTROY_IPC_FLAG), (1001, 0)]);
        assert_eq!(
            manager_serialize_uid_refs_internal(&refs, "destroy-ipc-uid").unwrap(),
            vec!["destroy-ipc-uid=1000".to_string()]
        );
    }

    #[test]
    fn serializes_basic_manager_state() {
        let mut state = ManagerScalarState {
            taint_logged: true,
            service_watchdogs: true,
            notify_socket: Some("/run/systemd/notify".into()),
            client_environment: vec!["A=B".into()],
            ..ManagerScalarState::default()
        };
        state.uid_refs.insert(42, DESTROY_IPC_FLAG);

        let serialized = manager_serialize(&state, false).unwrap();
        assert!(serialized.contains("taint-logged=yes"));
        assert!(serialized.contains("env=A=B"));
        assert!(serialized.contains("destroy-ipc-uid=42"));
    }

    #[test]
    fn switching_root_skips_environment() {
        let state = ManagerScalarState {
            client_environment: vec!["A=B".into()],
            ..ManagerScalarState::default()
        };
        let serialized = manager_serialize(&state, true).unwrap();
        assert!(!serialized.contains("env=A=B"));
    }

    #[test]
    fn deserialization_merges_counters_and_boolean_state() {
        let mut state = ManagerScalarState {
            last_transaction_id: 10,
            current_job_id: 2,
            ..ManagerScalarState::default()
        };
        manager_deserialize(
            &mut state,
            "last-transaction-id=8\ncurrent-job-id=4\nn-installed-jobs=3\ntaint-logged=yes\n",
        )
        .unwrap();

        assert_eq!(state.last_transaction_id, 10);
        assert_eq!(state.current_job_id, 4);
        assert_eq!(state.n_installed_jobs, 3);
        assert!(state.taint_logged);
    }

    #[test]
    fn deserializes_uid_and_gid_destroy_ipc_refs() {
        let mut state = ManagerScalarState::default();
        manager_deserialize(&mut state, "destroy-ipc-uid=1000\ndestroy-ipc-gid=2000\n").unwrap();

        assert_eq!(state.uid_refs.get(&1000), Some(&DESTROY_IPC_FLAG));
        assert_eq!(state.gid_refs.get(&2000), Some(&DESTROY_IPC_FLAG));
    }

    #[test]
    fn uid_zero_is_ignored_during_deserialization() {
        let mut refs = BTreeMap::new();
        manager_deserialize_uid_refs_one_internal(&mut refs, "0").unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn deserialize_rejects_unknown_lines() {
        let mut state = ManagerScalarState::default();
        assert!(matches!(
            manager_deserialize(&mut state, "mystery=value\n"),
            Err(ManagerSerializeError::InvalidLine(_))
        ));
    }

    #[test]
    fn deserialize_rejects_invalid_numbers() {
        let mut state = ManagerScalarState::default();
        assert!(matches!(
            manager_deserialize(&mut state, "current-job-id=nope\n"),
            Err(ManagerSerializeError::InvalidNumber(_))
        ));
    }
}
