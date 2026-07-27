// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Minimal runtime helpers for systemd-networkd.
//
// The helpers in this module are intentionally deterministic and testable:
// they discover interfaces from sysfs, normalize link state, and render a
// stable runtime-state file under /run/systemd/network/.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

const RUNTIME_STATE_FILENAME: &str = "networkd-runtime.state";

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to read sysfs root {path}: {source}")]
    ReadSysfsRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read sysfs entry under {path}: {source}")]
    ReadSysfsEntry {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to read interface {interface} from {path}: {source}")]
    ReadInterface {
        interface: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to create runtime directory {path}: {source}")]
    CreateRuntimeDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write runtime state file {path}: {source}")]
    WriteRuntimeState {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperState {
    Unknown,
    NotPresent,
    Down,
    LowerLayerDown,
    Testing,
    Dormant,
    Up,
}

impl OperState {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "notpresent" => Self::NotPresent,
            "down" => Self::Down,
            "lowerlayerdown" => Self::LowerLayerDown,
            "testing" => Self::Testing,
            "dormant" => Self::Dormant,
            "up" => Self::Up,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotPresent => "notpresent",
            Self::Down => "down",
            Self::LowerLayerDown => "lowerlayerdown",
            Self::Testing => "testing",
            Self::Dormant => "dormant",
            Self::Up => "up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierState {
    Unknown,
    Down,
    Up,
}

impl CarrierState {
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "0" => Self::Down,
            "1" => Self::Up,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Down => "down",
            Self::Up => "up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Online,
    Degraded,
    Down,
    Unknown,
}

impl LinkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    pub name: String,
    pub oper_state: OperState,
    pub carrier_state: CarrierState,
    pub status: LinkStatus,
}

impl InterfaceState {
    pub fn new(name: String, oper_state: OperState, carrier_state: CarrierState) -> Self {
        let status = match (oper_state, carrier_state) {
            (OperState::Up, CarrierState::Up) => LinkStatus::Online,
            (OperState::Up, CarrierState::Unknown) => LinkStatus::Degraded,
            (OperState::Up, CarrierState::Down) => LinkStatus::Down,
            (OperState::LowerLayerDown, _) => LinkStatus::Degraded,
            (OperState::Dormant, _) | (OperState::Testing, _) => LinkStatus::Degraded,
            (OperState::Down, CarrierState::Up) => LinkStatus::Degraded,
            (OperState::Down, CarrierState::Down) => LinkStatus::Down,
            (OperState::Down, CarrierState::Unknown) => LinkStatus::Down,
            (OperState::NotPresent, _) => LinkStatus::Down,
            (OperState::Unknown, CarrierState::Unknown) => LinkStatus::Unknown,
            (OperState::Unknown, CarrierState::Up) => LinkStatus::Degraded,
            (OperState::Unknown, CarrierState::Down) => LinkStatus::Down,
        };

        Self {
            name,
            oper_state,
            carrier_state,
            status,
        }
    }
}

pub fn default_sysfs_root() -> PathBuf {
    PathBuf::from("/sys/class/net")
}

pub fn default_runtime_dir() -> PathBuf {
    PathBuf::from("/run/systemd/network")
}

pub fn collect_interface_states(sysfs_root: &Path) -> Result<Vec<InterfaceState>, RuntimeError> {
    let mut states = Vec::new();
    let entries = fs::read_dir(sysfs_root).map_err(|source| RuntimeError::ReadSysfsRoot {
        path: sysfs_root.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| RuntimeError::ReadSysfsEntry {
            path: sysfs_root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let interface_path = entry.path();
        let oper_state = read_state_file(&interface_path, "operstate", &name)
            .map(|value| OperState::parse(&value))
            .unwrap_or(OperState::Unknown);
        let carrier_state = read_state_file(&interface_path, "carrier", &name)
            .map(|value| CarrierState::parse(&value))
            .unwrap_or(CarrierState::Unknown);

        states.push(InterfaceState::new(name, oper_state, carrier_state));
    }

    states.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(states)
}

pub fn render_runtime_state(states: &[InterfaceState]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# systemd-networkd runtime state");
    let _ = writeln!(output, "interface_count={}", states.len());

    for state in states {
        let _ = writeln!(
            output,
            "{} operstate={} carrier={} status={}",
            state.name,
            state.oper_state.as_str(),
            state.carrier_state.as_str(),
            state.status.as_str()
        );
    }

    output
}

pub fn write_runtime_state(
    runtime_dir: &Path,
    states: &[InterfaceState],
) -> Result<PathBuf, RuntimeError> {
    fs::create_dir_all(runtime_dir).map_err(|source| RuntimeError::CreateRuntimeDir {
        path: runtime_dir.to_path_buf(),
        source,
    })?;

    let state_path = runtime_dir.join(RUNTIME_STATE_FILENAME);
    let payload = render_runtime_state(states);

    fs::write(&state_path, payload).map_err(|source| RuntimeError::WriteRuntimeState {
        path: state_path.clone(),
        source,
    })?;

    Ok(state_path)
}

fn read_state_file(
    interface_path: &Path,
    file_name: &str,
    interface: &str,
) -> Result<String, RuntimeError> {
    let path = interface_path.join(file_name);
    let value = fs::read_to_string(&path).map_err(|source| RuntimeError::ReadInterface {
        interface: interface.to_string(),
        path: path.clone(),
        source,
    })?;
    Ok(value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, oper_state: OperState, carrier_state: CarrierState) -> InterfaceState {
        InterfaceState::new(name.to_string(), oper_state, carrier_state)
    }

    #[test]
    fn parse_operstate_and_carrier_values() {
        assert_eq!(OperState::parse("up"), OperState::Up);
        assert_eq!(
            OperState::parse(" lowerlayerdown "),
            OperState::LowerLayerDown
        );
        assert_eq!(OperState::parse("unexpected"), OperState::Unknown);

        assert_eq!(CarrierState::parse("1"), CarrierState::Up);
        assert_eq!(CarrierState::parse("0"), CarrierState::Down);
        assert_eq!(CarrierState::parse("n/a"), CarrierState::Unknown);
    }

    #[test]
    fn render_runtime_state_is_sorted_and_stable() {
        let mut states = vec![
            interface("wlan0", OperState::Down, CarrierState::Up),
            interface("eth0", OperState::Up, CarrierState::Up),
        ];
        states.sort_by(|left, right| left.name.cmp(&right.name));

        let rendered = render_runtime_state(&states);
        assert_eq!(
            rendered,
            "# systemd-networkd runtime state\n\
             interface_count=2\n\
             eth0 operstate=up carrier=up status=online\n\
             wlan0 operstate=down carrier=up status=degraded\n"
        );
    }

    #[test]
    fn collect_interface_states_reads_temp_sysfs_tree() {
        let tempdir = tempfile::tempdir().unwrap();
        let sysfs_root = tempdir.path().join("class").join("net");
        fs::create_dir_all(&sysfs_root).unwrap();

        let lo = sysfs_root.join("lo");
        fs::create_dir(&lo).unwrap();
        fs::write(lo.join("operstate"), "unknown\n").unwrap();
        fs::write(lo.join("carrier"), "0\n").unwrap();

        let eth0 = sysfs_root.join("eth0");
        fs::create_dir(&eth0).unwrap();
        fs::write(eth0.join("operstate"), "up\n").unwrap();
        fs::write(eth0.join("carrier"), "1\n").unwrap();

        let states = collect_interface_states(&sysfs_root).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].name, "eth0");
        assert_eq!(states[0].status, LinkStatus::Online);
        assert_eq!(states[1].name, "lo");
        assert_eq!(states[1].carrier_state, CarrierState::Down);
    }

    #[test]
    fn write_runtime_state_creates_the_state_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let runtime_dir = tempdir.path().join("run").join("systemd").join("network");
        let states = vec![interface("eth0", OperState::Up, CarrierState::Up)];

        let path = write_runtime_state(&runtime_dir, &states).unwrap();
        assert_eq!(path, runtime_dir.join(RUNTIME_STATE_FILENAME));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            render_runtime_state(&states)
        );
    }
}
