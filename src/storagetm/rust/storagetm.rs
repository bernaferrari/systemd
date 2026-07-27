// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/storagetm/storagetm.c
//
pub const NVME_MODEL_MAX_LEN: usize = 40;
pub const NVME_FIRMWARE_MAX_LEN: usize = 8;
pub const NVME_SERIAL_MAX_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub devices: Vec<String>,
    pub nqn: String,
    pub all: bool,
    pub list_devices: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoragetmError {
    InvalidNqn,
    InvalidPath,
    MissingDevice,
    DevicesNotAllowedWithAll,
}

impl std::fmt::Display for StoragetmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoragetmError {}

pub fn is_valid_filename_like(value: &str) -> bool {
    !value.is_empty() && !value.contains('/') && !value.contains('\0')
}

pub fn is_valid_path(value: &str) -> bool {
    value.starts_with('/') && !value.contains('\0')
}

pub fn truncate_nvme_field(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

pub fn default_nqn(machine_app_id: &str) -> String {
    format!("nqn.2023-10.io.systemd:storagetm.{machine_app_id}")
}

pub fn build_subsystem_name(nqn: &str, node: &str) -> String {
    let file = node.rsplit('/').next().unwrap_or(node);
    format!("{nqn}.{file}")
}

pub fn deterministic_port(seed: u64, family: IpFamily) -> u16 {
    let base = 1024 + (seed % ((u16::MAX - 1024) as u64)) as u16;
    base | match family {
        IpFamily::V4 => 0,
        IpFamily::V6 => 1,
    }
}

pub fn parse_args(args: &[&str], machine_app_id: &str) -> Result<Config, StoragetmError> {
    let mut nqn = None;
    let mut all = false;
    let mut list_devices = false;
    let mut devices = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--nqn" => {
                i += 1;
                let value = args.get(i).ok_or(StoragetmError::InvalidNqn)?;
                if !is_valid_filename_like(value) {
                    return Err(StoragetmError::InvalidNqn);
                }
                nqn = Some((*value).to_string());
            }
            s if s.starts_with("--nqn=") => {
                let value = &s[6..];
                if !is_valid_filename_like(value) {
                    return Err(StoragetmError::InvalidNqn);
                }
                nqn = Some(value.to_string());
            }
            "-a" | "--all" => all = true,
            "--list-devices" => list_devices = true,
            s if s.starts_with('-') => return Err(StoragetmError::InvalidPath),
            other => devices.push(other.to_string()),
        }
        i += 1;
    }
    if list_devices {
        return Ok(Config {
            devices,
            nqn: nqn.unwrap_or_else(|| default_nqn(machine_app_id)),
            all,
            list_devices,
        });
    }
    if all && !devices.is_empty() {
        return Err(StoragetmError::DevicesNotAllowedWithAll);
    }
    if !all && devices.is_empty() {
        return Err(StoragetmError::MissingDevice);
    }
    if devices.iter().any(|d| !is_valid_path(d)) {
        return Err(StoragetmError::InvalidPath);
    }
    Ok(Config {
        devices,
        nqn: nqn.unwrap_or_else(|| default_nqn(machine_app_id)),
        all,
        list_devices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_default_nqn() {
        assert!(default_nqn("abc").contains("abc"));
    }

    #[test]
    fn rejects_invalid_nqn() {
        assert_eq!(
            parse_args(&["--nqn=a/b", "/dev/sda"], "m").unwrap_err(),
            StoragetmError::InvalidNqn
        );
    }

    #[test]
    fn rejects_invalid_path() {
        assert_eq!(
            parse_args(&["relative"], "m").unwrap_err(),
            StoragetmError::InvalidPath
        );
    }

    #[test]
    fn rejects_missing_device_without_all() {
        assert_eq!(
            parse_args(&[], "m").unwrap_err(),
            StoragetmError::MissingDevice
        );
    }

    #[test]
    fn rejects_devices_with_all() {
        assert_eq!(
            parse_args(&["--all", "/dev/sda"], "m").unwrap_err(),
            StoragetmError::DevicesNotAllowedWithAll
        );
    }

    #[test]
    fn builds_subsystem_name() {
        assert_eq!(build_subsystem_name("nqn.x", "/dev/sda"), "nqn.x.sda");
    }

    #[test]
    fn truncates_nvme_fields() {
        assert_eq!(truncate_nvme_field("abcdefghijk", 4), "abcd");
    }

    #[test]
    fn deterministic_port_differs_by_family() {
        assert_ne!(
            deterministic_port(1, IpFamily::V4),
            deterministic_port(1, IpFamily::V6)
        );
    }
}
