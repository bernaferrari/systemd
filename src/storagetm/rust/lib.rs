// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/storagetm/storagetm.c
//
// NVMe-TCP storage target mode daemon.
//
// Exposes block devices or regular files as NVMe-TCP volumes.
// Manages NVMe subsystems, ports, and device monitoring via udev.

// ── Constants ─────────────────────────────────────────────────────────────

/// NVMe configfs subsystems path.
pub const NVME_SUBSYSTEMS_PATH: &str = "/sys/kernel/config/nvmet/subsystems";

/// NVMe configfs ports path.
pub const NVME_PORTS_PATH: &str = "/sys/kernel/config/nvmet/ports";

/// Minimum port number for NVMe-TCP.
pub const NVME_PORT_MIN: u16 = 1024;

/// Maximum port number for NVMe-TCP.
pub const NVME_PORT_MAX: u16 = 0xFFFF;

/// Maximum number of port allocation attempts.
pub const NVME_PORT_MAX_ATTEMPTS: u32 = 16;

/// Maximum model name length (per NVMe spec).
pub const NVME_MODEL_MAX_LEN: usize = 40;

/// Maximum firmware revision length (per NVMe spec).
pub const NVME_FIRMWARE_MAX_LEN: usize = 8;

/// Maximum serial number length (per NVMe spec).
pub const NVME_SERIAL_MAX_LEN: usize = 20;

// ── Enums ─────────────────────────────────────────────────────────────────

/// IP family for NVMe port addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    /// Convert to the address family integer constant.
    pub fn to_af(self) -> i32 {
        match self {
            IpFamily::V4 => 2,  // AF_INET
            IpFamily::V6 => 10, // AF_INET6
        }
    }

    /// Get the wildcard address string.
    pub fn wildcard_addr(self) -> &'static str {
        match self {
            IpFamily::V4 => "0.0.0.0",
            IpFamily::V6 => "::",
        }
    }

    /// Get the address family name for configfs.
    pub fn adrfam(self) -> &'static str {
        match self {
            IpFamily::V4 => "ipv4",
            IpFamily::V6 => "ipv6",
        }
    }

    /// Get the lowest-bit flag value.
    pub fn lowest_bit_flag(self) -> u16 {
        match self {
            IpFamily::V4 => 0,
            IpFamily::V6 => 1,
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// An NVMe subsystem representing an exposed device.
#[derive(Debug, Clone)]
pub struct NvmeSubsystemInfo {
    /// Subsystem name (nqn.2023-10.io.systemd:storagetm.<id>.<filename>).
    pub name: String,
    /// The device path being exposed.
    pub device: String,
}

/// An NVMe port for TCP connectivity.
#[derive(Debug, Clone)]
pub struct NvmePortInfo {
    /// Port number (both IP and NVMe).
    pub portnr: u16,
    /// IP family.
    pub ip_family: IpFamily,
}

/// Port calculation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortCalculation {
    /// The calculated port number.
    pub port: u16,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from storagetm operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoragetmError {
    /// Configfs not mounted.
    ConfigfsNotMounted,
    /// Invalid NQN.
    InvalidNqn(String),
    /// Invalid device path.
    InvalidPath(String),
    /// Failed to allocate port.
    PortAllocationFailed(u32),
    /// NVMe subsystem operation failed.
    SubsystemError(String),
    /// Port operation failed.
    PortError(String),
    /// Device not allowed (root disk).
    DeviceNotAllowed(String),
    /// Event loop error.
    EventLoopError(String),
}

impl std::fmt::Display for StoragetmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoragetmError::ConfigfsNotMounted => {
                write!(
                    f,
                    "The configfs filesystem must be mounted at /sys/kernel/config/"
                )
            }
            StoragetmError::InvalidNqn(nqn) => write!(f, "NQN invalid: {}", nqn),
            StoragetmError::InvalidPath(path) => write!(f, "Invalid path: {}", path),
            StoragetmError::PortAllocationFailed(attempts) => {
                write!(f, "Can't find free NVME port after {} attempts.", attempts)
            }
            StoragetmError::SubsystemError(msg) => {
                write!(f, "Subsystem error: {}", msg)
            }
            StoragetmError::PortError(msg) => write!(f, "Port error: {}", msg),
            StoragetmError::DeviceNotAllowed(dev) => {
                write!(f, "Not exposing device '{}', backed by root disk", dev)
            }
            StoragetmError::EventLoopError(msg) => {
                write!(f, "Event loop error: {}", msg)
            }
        }
    }
}

impl std::error::Error for StoragetmError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Calculate the starting port number for a given name and IP family.
/// Uses a deterministic hash-based approach.
///
/// Mirrors the C `calculate_start_port()`.
pub fn calculate_start_port(name: &str, ip_family: IpFamily) -> u16 {
    // Simple deterministic hash (FNV-like)
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in name.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    // Mix in family
    hash ^= ip_family.to_af() as u64;
    hash = hash.wrapping_mul(0x100000001b3);

    let mut port = NVME_PORT_MIN + ((hash % (NVME_PORT_MAX as u64 - NVME_PORT_MIN as u64)) as u16);
    // Set lowest bit based on family
    port = (port & !1) | ip_family.lowest_bit_flag();
    port
}

/// Check if a sysname should be ignored (loop, zram devices).
pub fn should_ignore_sysname(sysname: &str) -> bool {
    sysname.starts_with("loop") || sysname.starts_with("zram")
}

/// Truncate a string to a maximum length for NVMe spec compliance.
pub fn truncate_for_nvme(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len { s } else { &s[..max_len] }
}

/// Build a subsystem name from NQN and device filename.
pub fn build_subsystem_name(nqn: &str, device_path: &str) -> String {
    let filename = device_path.rsplit('/').next().unwrap_or(device_path);
    format!("{}.{}", nqn, filename)
}

/// Build a port directory name from port number.
pub fn port_dir_name(portnr: u16) -> String {
    format!("{}", portnr)
}

/// Build the subsystem target path for port linking.
pub fn subsystem_target_path(subsystem_name: &str) -> String {
    format!("{}/{}", NVME_SUBSYSTEMS_PATH, subsystem_name)
}

/// Build the subsystem link name for a port.
pub fn subsystem_link_name(subsystem_name: &str) -> String {
    format!("subsystems/{}", subsystem_name)
}

/// Check if the `--all` flag count means all devices are allowed.
/// When all >= 2, even the root filesystem is allowed.
pub fn all_devices_allowed(all_count: i32) -> bool {
    all_count >= 2
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_family_wildcard() {
        assert_eq!(IpFamily::V4.wildcard_addr(), "0.0.0.0");
        assert_eq!(IpFamily::V6.wildcard_addr(), "::");
    }

    #[test]
    fn test_ip_family_adrfam() {
        assert_eq!(IpFamily::V4.adrfam(), "ipv4");
        assert_eq!(IpFamily::V6.adrfam(), "ipv6");
    }

    #[test]
    fn test_ip_family_af() {
        assert_eq!(IpFamily::V4.to_af(), 2);
        assert_eq!(IpFamily::V6.to_af(), 10);
    }

    #[test]
    fn test_calculate_start_port_deterministic() {
        let p1 = calculate_start_port("test-device", IpFamily::V4);
        let p2 = calculate_start_port("test-device", IpFamily::V4);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_calculate_start_port_different_family() {
        let p4 = calculate_start_port("test", IpFamily::V4);
        let p6 = calculate_start_port("test", IpFamily::V6);
        assert_ne!(p4, p6);
    }

    #[test]
    fn test_calculate_start_port_in_range() {
        let port = calculate_start_port("some-device", IpFamily::V4);
        assert!(port >= NVME_PORT_MIN);
        assert!(port <= NVME_PORT_MAX);
    }

    #[test]
    fn test_calculate_start_port_ipv4_even() {
        let port = calculate_start_port("device", IpFamily::V4);
        assert_eq!(port % 2, 0);
    }

    #[test]
    fn test_calculate_start_port_ipv6_odd() {
        let port = calculate_start_port("device", IpFamily::V6);
        assert_eq!(port % 2, 1);
    }

    #[test]
    fn test_should_ignore_sysname() {
        assert!(should_ignore_sysname("loop0"));
        assert!(should_ignore_sysname("zram0"));
        assert!(!should_ignore_sysname("sda"));
        assert!(!should_ignore_sysname("nvme0n1"));
    }

    #[test]
    fn test_truncate_for_nvme_short() {
        assert_eq!(truncate_for_nvme("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_for_nvme_long() {
        let long = "a_very_long_model_name_that_exceeds_the_limit";
        assert_eq!(
            truncate_for_nvme(long, NVME_MODEL_MAX_LEN).len(),
            NVME_MODEL_MAX_LEN
        );
    }

    #[test]
    fn test_build_subsystem_name() {
        let name = build_subsystem_name("nqn.2023-10.io.systemd:storagetm.abc", "/dev/sda");
        assert_eq!(name, "nqn.2023-10.io.systemd:storagetm.abc.sda");
    }

    #[test]
    fn test_port_dir_name() {
        assert_eq!(port_dir_name(4444), "4444");
    }

    #[test]
    fn test_subsystem_target_path() {
        let path = subsystem_target_path("my.subsystem");
        assert_eq!(path, "/sys/kernel/config/nvmet/subsystems/my.subsystem");
    }

    #[test]
    fn test_subsystem_link_name() {
        let name = subsystem_link_name("my.subsystem");
        assert_eq!(name, "subsystems/my.subsystem");
    }

    #[test]
    fn test_all_devices_allowed() {
        assert!(!all_devices_allowed(0));
        assert!(!all_devices_allowed(1));
        assert!(all_devices_allowed(2));
        assert!(all_devices_allowed(3));
    }

    #[test]
    fn test_error_display() {
        let err = StoragetmError::ConfigfsNotMounted;
        assert!(format!("{}", err).contains("configfs"));
    }
}
