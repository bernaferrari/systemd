// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-container.c
//
// Container leader lookup helpers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    HostDown,
    InvalidMachineName,
    MissingLeader,
    WrongClass(Option<String>),
    InvalidLeader,
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostDown => f.write_str("container unavailable"),
            Self::InvalidMachineName => f.write_str("invalid machine name"),
            Self::MissingLeader => f.write_str("missing LEADER entry"),
            Self::WrongClass(_) => f.write_str("machine is not a container"),
            Self::InvalidLeader => f.write_str("invalid LEADER entry"),
            Self::Io(kind) => write!(f, "i/o error: {kind:?}"),
        }
    }
}

impl std::error::Error for ContainerError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRecord {
    entries: HashMap<String, String>,
}

impl MachineRecord {
    pub fn parse(env: &str) -> Self {
        let mut entries = HashMap::new();
        for line in env.lines() {
            if let Some((key, value)) = line.split_once('=') {
                entries.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Self { entries }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }
}

pub fn hostname_is_valid(machine: &str) -> bool {
    !machine.is_empty()
        && machine.len() <= 255
        && machine
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn runtime_machine_path(runtime_dir: &Path, scope: RuntimeScope, machine: &str) -> PathBuf {
    match scope {
        RuntimeScope::System => runtime_dir.join("systemd/machines").join(machine),
        RuntimeScope::User => runtime_dir.join("user/systemd/machines").join(machine),
    }
}

pub fn container_get_leader_from_record(
    scope: RuntimeScope,
    machine: &str,
    record: &MachineRecord,
) -> Result<u32, ContainerError> {
    if machine == ".host" {
        return match scope {
            RuntimeScope::System => Ok(1),
            RuntimeScope::User => Err(ContainerError::HostDown),
        };
    }

    if !hostname_is_valid(machine) {
        return Err(ContainerError::InvalidMachineName);
    }

    let leader = record.get("LEADER").ok_or(ContainerError::MissingLeader)?;
    let class = record.get("CLASS");
    if class != Some("container") {
        return Err(ContainerError::WrongClass(class.map(str::to_string)));
    }

    let leader: i64 = leader.parse().map_err(|_| ContainerError::InvalidLeader)?;
    if leader <= 1 {
        return Err(ContainerError::InvalidLeader);
    }

    Ok(leader as u32)
}

pub fn container_get_leader_from_env(
    scope: RuntimeScope,
    machine: &str,
    env: &str,
) -> Result<u32, ContainerError> {
    container_get_leader_from_record(scope, machine, &MachineRecord::parse(env))
}

pub fn container_get_leader_in(
    runtime_dir: &Path,
    scope: RuntimeScope,
    machine: &str,
) -> Result<u32, ContainerError> {
    if machine == ".host" {
        return match scope {
            RuntimeScope::System => Ok(1),
            RuntimeScope::User => Err(ContainerError::HostDown),
        };
    }

    if !hostname_is_valid(machine) {
        return Err(ContainerError::InvalidMachineName);
    }

    let path = runtime_machine_path(runtime_dir, scope, machine);
    let content = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ContainerError::HostDown
        } else {
            ContainerError::Io(e.kind())
        }
    })?;

    container_get_leader_from_env(scope, machine, &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_in_system_scope_maps_to_pid_one() {
        assert_eq!(
            container_get_leader_from_env(RuntimeScope::System, ".host", "").unwrap(),
            1
        );
    }

    #[test]
    fn host_in_user_scope_is_down() {
        assert_eq!(
            container_get_leader_from_env(RuntimeScope::User, ".host", "").unwrap_err(),
            ContainerError::HostDown
        );
    }

    #[test]
    fn invalid_machine_name_is_rejected() {
        assert_eq!(
            container_get_leader_from_env(
                RuntimeScope::System,
                "bad/name",
                "LEADER=2\nCLASS=container\n"
            )
            .unwrap_err(),
            ContainerError::InvalidMachineName
        );
    }

    #[test]
    fn missing_leader_matches_c_esrch_case() {
        assert_eq!(
            container_get_leader_from_env(RuntimeScope::System, "demo", "CLASS=container\n")
                .unwrap_err(),
            ContainerError::MissingLeader
        );
    }

    #[test]
    fn class_must_be_container() {
        assert_eq!(
            container_get_leader_from_env(RuntimeScope::System, "demo", "LEADER=42\nCLASS=vm\n")
                .unwrap_err(),
            ContainerError::WrongClass(Some("vm".into()))
        );
    }

    #[test]
    fn leader_must_parse() {
        assert_eq!(
            container_get_leader_from_env(
                RuntimeScope::System,
                "demo",
                "LEADER=abc\nCLASS=container\n"
            )
            .unwrap_err(),
            ContainerError::InvalidLeader
        );
    }

    #[test]
    fn leader_must_be_greater_than_one() {
        assert_eq!(
            container_get_leader_from_env(
                RuntimeScope::System,
                "demo",
                "LEADER=1\nCLASS=container\n"
            )
            .unwrap_err(),
            ContainerError::InvalidLeader
        );
    }

    #[test]
    fn valid_record_returns_leader() {
        assert_eq!(
            container_get_leader_from_env(
                RuntimeScope::System,
                "demo",
                "LEADER=123\nCLASS=container\n"
            )
            .unwrap(),
            123
        );
    }

    #[test]
    fn path_layout_matches_scope() {
        let base = Path::new("/run");
        assert_eq!(
            runtime_machine_path(base, RuntimeScope::System, "m"),
            PathBuf::from("/run/systemd/machines/m")
        );
        assert_eq!(
            runtime_machine_path(base, RuntimeScope::User, "m"),
            PathBuf::from("/run/user/systemd/machines/m")
        );
    }
}
