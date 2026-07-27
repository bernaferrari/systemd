// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Unit.c
//
// Varlink interface definition for io.systemd.Unit
// CGroup and Exec context types for unit resource control.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name
pub const INTERFACE_NAME: &str = "io.systemd.Unit";

/// Device policy options
pub const DEVICE_POLICY_AUTO: &str = "auto";
pub const DEVICE_POLICY_CLOSED: &str = "closed";
pub const DEVICE_POLICY_STRICT: &str = "strict";

/// ManagedOOM swap options
pub const MANAGED_OOM_SWAP_AUTO: &str = "auto";
pub const MANAGED_OOM_SWAP_KILL: &str = "kill";

/// ManagedOOM preference options
pub const MANAGED_OOM_PREFERENCE_NONE: &str = "none";
pub const MANAGED_OOM_PREFERENCE_AVOID: &str = "avoid";
pub const MANAGED_OOM_PREFERENCE_OMIT: &str = "omit";

// ── Structs ───────────────────────────────────────────────────────────────

/// CGroup tasks max configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupTasksMax {
    /// Maximum amount of tasks
    pub value: i64,
    /// Scaling factor
    pub scale: i64,
}

impl CGroupTasksMax {
    /// Create a new CGroupTasksMax
    pub fn new(value: i64, scale: i64) -> Self {
        Self { value, scale }
    }

    /// Check if this represents an unlimited value
    pub fn is_unlimited(&self) -> bool {
        self.value == i64::MAX
    }
}

/// CGroup IO device weight
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupIODeviceWeight {
    /// Device path
    pub path: String,
    /// IO weight
    pub weight: i64,
}

impl CGroupIODeviceWeight {
    /// Create a new CGroupIODeviceWeight
    pub fn new(path: impl Into<String>, weight: i64) -> Self {
        Self {
            path: path.into(),
            weight,
        }
    }
}

/// CGroup IO device limit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupIODeviceLimit {
    /// Device path
    pub path: String,
    /// IO limit
    pub limit: i64,
}

impl CGroupIODeviceLimit {
    /// Create a new CGroupIODeviceLimit
    pub fn new(path: impl Into<String>, limit: i64) -> Self {
        Self {
            path: path.into(),
            limit,
        }
    }
}

/// CGroup IO device latency
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupIODeviceLatency {
    /// Device path
    pub path: String,
    /// Target latency in microseconds
    pub target_usec: Option<i64>,
}

impl CGroupIODeviceLatency {
    /// Create a new CGroupIODeviceLatency
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            target_usec: None,
        }
    }

    /// Set target latency
    pub fn with_target(mut self, target_usec: i64) -> Self {
        self.target_usec = Some(target_usec);
        self
    }
}

/// CGroup address prefix (for IP allow/deny)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupAddressPrefix {
    /// Address family
    pub family: i64,
    /// Address as integer array
    pub address: Vec<i64>,
    /// Prefix length
    pub prefix_length: i64,
}

impl CGroupAddressPrefix {
    /// Create a new CGroupAddressPrefix
    pub fn new(family: i64, address: Vec<i64>, prefix_length: i64) -> Self {
        Self {
            family,
            address,
            prefix_length,
        }
    }
}

/// CGroup socket bind rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupSocketBind {
    /// Address family
    pub family: i64,
    /// Protocol name
    pub protocol: String,
    /// Number of ports
    pub number_of_ports: i64,
    /// Minimum port number
    pub minimum_port: i64,
}

impl CGroupSocketBind {
    /// Create a new CGroupSocketBind
    pub fn new(
        family: i64,
        protocol: impl Into<String>,
        number_of_ports: i64,
        minimum_port: i64,
    ) -> Self {
        Self {
            family,
            protocol: protocol.into(),
            number_of_ports,
            minimum_port,
        }
    }
}

/// CGroup network interface restriction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupRestrictNetworkInterfaces {
    /// Whether this is an allow list
    pub is_allow_list: bool,
    /// List of interface names
    pub interfaces: Vec<String>,
}

impl CGroupRestrictNetworkInterfaces {
    /// Create an allow list
    pub fn allow(interfaces: Vec<String>) -> Self {
        Self {
            is_allow_list: true,
            interfaces,
        }
    }

    /// Create a deny list
    pub fn deny(interfaces: Vec<String>) -> Self {
        Self {
            is_allow_list: false,
            interfaces,
        }
    }
}

/// CGroup NFT set rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupNFTSet {
    /// Source
    pub source: String,
    /// Protocol
    pub protocol: String,
    /// Table name
    pub table: String,
    /// Set name
    pub set: String,
}

impl CGroupNFTSet {
    /// Create a new CGroupNFTSet
    pub fn new(
        source: impl Into<String>,
        protocol: impl Into<String>,
        table: impl Into<String>,
        set: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            protocol: protocol.into(),
            table: table.into(),
            set: set.into(),
        }
    }
}

/// CGroup device allow rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupDeviceAllow {
    /// Device path
    pub path: String,
    /// Permissions (e.g. "rwm")
    pub permissions: String,
}

impl CGroupDeviceAllow {
    /// Create a new CGroupDeviceAllow
    pub fn new(path: impl Into<String>, permissions: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            permissions: permissions.into(),
        }
    }
}

/// Working directory specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingDirectory {
    /// Path to working directory
    pub path: String,
    /// Whether missing directory is OK
    pub missing_ok: bool,
}

impl WorkingDirectory {
    /// Create a new WorkingDirectory
    pub fn new(path: impl Into<String>, missing_ok: bool) -> Self {
        Self {
            path: path.into(),
            missing_ok,
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Validate a device policy string
pub fn is_valid_device_policy(s: &str) -> bool {
    matches!(s, "auto" | "closed" | "strict")
}

/// Validate a ManagedOOM swap mode string
pub fn is_valid_managed_oom_swap(s: &str) -> bool {
    matches!(s, "auto" | "kill")
}

/// Validate a ManagedOOM preference string
pub fn is_valid_managed_oom_preference(s: &str) -> bool {
    matches!(s, "none" | "avoid" | "omit")
}

/// Validate device permission string (r/w/m combinations)
pub fn is_valid_device_permissions(s: &str) -> bool {
    s.chars().all(|c| matches!(c, 'r' | 'w' | 'm')) && !s.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Unit");
    }

    #[test]
    fn test_cgroup_tasks_max() {
        let tm = CGroupTasksMax::new(100, 1);
        assert_eq!(tm.value, 100);
        assert_eq!(tm.scale, 1);
        assert!(!tm.is_unlimited());

        let unlimited = CGroupTasksMax::new(i64::MAX, 0);
        assert!(unlimited.is_unlimited());
    }

    #[test]
    fn test_cgroup_io_device_weight() {
        let w = CGroupIODeviceWeight::new("/dev/sda", 100);
        assert_eq!(w.path, "/dev/sda");
        assert_eq!(w.weight, 100);
    }

    #[test]
    fn test_cgroup_io_device_limit() {
        let l = CGroupIODeviceLimit::new("/dev/sda", 1048576);
        assert_eq!(l.path, "/dev/sda");
        assert_eq!(l.limit, 1048576);
    }

    #[test]
    fn test_cgroup_io_device_latency() {
        let l = CGroupIODeviceLatency::new("/dev/sda").with_target(5000);
        assert_eq!(l.path, "/dev/sda");
        assert_eq!(l.target_usec, Some(5000));

        let l_no_target = CGroupIODeviceLatency::new("/dev/sda");
        assert!(l_no_target.target_usec.is_none());
    }

    #[test]
    fn test_cgroup_address_prefix() {
        let ap = CGroupAddressPrefix::new(2, vec![192, 168, 1, 0], 24);
        assert_eq!(ap.family, 2);
        assert_eq!(ap.prefix_length, 24);
        assert_eq!(ap.address.len(), 4);
    }

    #[test]
    fn test_cgroup_socket_bind() {
        let sb = CGroupSocketBind::new(2, "tcp", 1, 80);
        assert_eq!(sb.family, 2);
        assert_eq!(sb.protocol, "tcp");
        assert_eq!(sb.number_of_ports, 1);
        assert_eq!(sb.minimum_port, 80);
    }

    #[test]
    fn test_cgroup_restrict_network_interfaces() {
        let allow = CGroupRestrictNetworkInterfaces::allow(vec!["eth0".to_string()]);
        assert!(allow.is_allow_list);
        assert_eq!(allow.interfaces.len(), 1);

        let deny = CGroupRestrictNetworkInterfaces::deny(vec!["lo".to_string()]);
        assert!(!deny.is_allow_list);
    }

    #[test]
    fn test_cgroup_nft_set() {
        let nft = CGroupNFTSet::new("cgroup", "inet", "filter", "myset");
        assert_eq!(nft.source, "cgroup");
        assert_eq!(nft.protocol, "inet");
        assert_eq!(nft.table, "filter");
        assert_eq!(nft.set, "myset");
    }

    #[test]
    fn test_cgroup_device_allow() {
        let da = CGroupDeviceAllow::new("/dev/sda", "rwm");
        assert_eq!(da.path, "/dev/sda");
        assert_eq!(da.permissions, "rwm");
    }

    #[test]
    fn test_working_directory() {
        let wd = WorkingDirectory::new("/opt/app", true);
        assert_eq!(wd.path, "/opt/app");
        assert!(wd.missing_ok);
    }

    #[test]
    fn test_is_valid_device_policy() {
        assert!(is_valid_device_policy("auto"));
        assert!(is_valid_device_policy("closed"));
        assert!(is_valid_device_policy("strict"));
        assert!(!is_valid_device_policy("invalid"));
    }

    #[test]
    fn test_is_valid_managed_oom_swap() {
        assert!(is_valid_managed_oom_swap("auto"));
        assert!(is_valid_managed_oom_swap("kill"));
        assert!(!is_valid_managed_oom_swap("invalid"));
    }

    #[test]
    fn test_is_valid_device_permissions() {
        assert!(is_valid_device_permissions("r"));
        assert!(is_valid_device_permissions("rw"));
        assert!(is_valid_device_permissions("rwm"));
        assert!(!is_valid_device_permissions(""));
        assert!(!is_valid_device_permissions("x"));
    }

    #[test]
    fn test_is_valid_managed_oom_preference() {
        assert!(is_valid_managed_oom_preference("none"));
        assert!(is_valid_managed_oom_preference("avoid"));
        assert!(is_valid_managed_oom_preference("omit"));
        assert!(!is_valid_managed_oom_preference("invalid"));
    }
}
