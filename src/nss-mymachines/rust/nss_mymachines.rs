// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nss-mymachines/nss-mymachines.c
//
// NSS module for resolving local container hostnames via machined.
//
// Provides hostname classification for machine names, address family
/// helpers, and deadlock detection to avoid circular activation of
// `systemd-machined.service` during NSS lookups.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── NSS status ────────────────────────────────────────────────────────────

/// NSS lookup return status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success = 0,
    NotFound = 1,
    TryAgain = 2,
    Unavail = 3,
}

// ── Address family ────────────────────────────────────────────────────────

/// Socket address family values matching the C `AF_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec = 0,
    Inet = 2,
    Inet6 = 10,
}

impl AddressFamily {
    /// Parse an address family from its integer value.
    pub fn from_c_int(val: i32) -> Option<Self> {
        match val {
            0 => Some(AddressFamily::Unspec),
            2 => Some(AddressFamily::Inet),
            10 => Some(AddressFamily::Inet6),
            _ => None,
        }
    }

    /// Address size in bytes.
    pub fn address_size(&self) -> usize {
        match self {
            AddressFamily::Inet => 4,
            AddressFamily::Inet6 => 16,
            AddressFamily::Unspec => 0,
        }
    }
}

// ── Machine address ───────────────────────────────────────────────────────

/// A network address associated with a local machine (container/VM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAddress {
    /// Network interface index.
    pub ifindex: i32,
    /// Address as a string (e.g. "10.0.0.1" or "fd00::1").
    pub address: String,
    /// Address family.
    pub family: AddressFamily,
}

impl MachineAddress {
    pub fn new(ifindex: i32, address: &str, family: AddressFamily) -> Self {
        Self {
            ifindex,
            address: address.to_string(),
            family,
        }
    }

    /// Check whether this is a link-local IPv6 address (fe80::/10).
    pub fn is_link_local_ipv6(&self) -> bool {
        self.family == AddressFamily::Inet6 && self.address.starts_with("fe80:")
    }

    /// Check whether this is an IPv4 address.
    pub fn is_ipv4(&self) -> bool {
        self.family == AddressFamily::Inet
    }

    /// Check whether this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        self.family == AddressFamily::Inet6
    }
}

// ── Machine name classification ───────────────────────────────────────────

/// Category of a machine hostname for NSS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineNameClass {
    /// Name ends with `.machine`.
    Machine,
    /// Name ends with `.mymachines`.
    MyMachines,
    /// Any other name.
    Other,
}

/// Classify a machine name by its suffix.
///
/// Mirrors the lookup logic in the C NSS module.
pub fn classify_machine_name(name: &str) -> MachineNameClass {
    if name.ends_with(".machine") {
        MachineNameClass::Machine
    } else if name.ends_with(".mymachines") {
        MachineNameClass::MyMachines
    } else {
        MachineNameClass::Other
    }
}

/// Strip the `.machine` or `.mymachines` suffix from a name.
pub fn machine_name_without_suffix(name: &str) -> &str {
    name.strip_suffix(".machine")
        .or_else(|| name.strip_suffix(".mymachines"))
        .unwrap_or(name)
}

// ── Deadlock detection ────────────────────────────────────────────────────

/// Check whether the current process is inside the activation path of
/// `systemd-machined.service`, which would cause a deadlock if we tried
/// to do a synchronous D-Bus lookup.
///
/// Mirrors `avoid_deadlock()` in the C source.
pub fn avoid_deadlock(activation_unit: Option<&str>, activation_scope: Option<&str>) -> bool {
    activation_unit == Some("systemd-machined.service") && activation_scope == Some("system")
}

// ── Machine class check ───────────────────────────────────────────────────

/// Check whether a machine class string represents a container.
pub fn is_container_class(class: &str) -> bool {
    class == "container"
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_machine() {
        assert_eq!(
            classify_machine_name("web.machine"),
            MachineNameClass::Machine
        );
        assert_eq!(
            classify_machine_name("web.mymachines"),
            MachineNameClass::MyMachines
        );
        assert_eq!(classify_machine_name("localhost"), MachineNameClass::Other);
        assert_eq!(classify_machine_name("web.other"), MachineNameClass::Other);
    }

    #[test]
    fn strip_suffix_machine() {
        assert_eq!(machine_name_without_suffix("web.machine"), "web");
    }

    #[test]
    fn strip_suffix_mymachines() {
        assert_eq!(machine_name_without_suffix("db.mymachines"), "db");
    }

    #[test]
    fn strip_suffix_none() {
        assert_eq!(machine_name_without_suffix("host"), "host");
    }

    #[test]
    fn machine_address_link_local() {
        let ma = MachineAddress::new(1, "fe80::1", AddressFamily::Inet6);
        assert!(ma.is_link_local_ipv6());
    }

    #[test]
    fn machine_address_not_link_local() {
        let ma = MachineAddress::new(1, "2001:db8::1", AddressFamily::Inet6);
        assert!(!ma.is_link_local_ipv6());
    }

    #[test]
    fn machine_address_family_checks() {
        let v4 = MachineAddress::new(1, "10.0.0.1", AddressFamily::Inet);
        assert!(v4.is_ipv4());
        assert!(!v4.is_ipv6());
        let v6 = MachineAddress::new(1, "::1", AddressFamily::Inet6);
        assert!(v6.is_ipv6());
        assert!(!v6.is_ipv4());
    }

    #[test]
    fn avoid_deadlock_true() {
        assert!(avoid_deadlock(
            Some("systemd-machined.service"),
            Some("system")
        ));
    }

    #[test]
    fn avoid_deadlock_wrong_unit() {
        assert!(!avoid_deadlock(Some("other.service"), Some("system")));
    }

    #[test]
    fn avoid_deadlock_wrong_scope() {
        assert!(!avoid_deadlock(
            Some("systemd-machined.service"),
            Some("user")
        ));
    }

    #[test]
    fn avoid_deadlock_none() {
        assert!(!avoid_deadlock(None, None));
    }

    #[test]
    fn is_container_class() {
        assert!(is_container_class("container"));
        assert!(!is_container_class("vm"));
        assert!(!is_container_class("host"));
    }

    #[test]
    fn address_family_from_c_int() {
        assert_eq!(AddressFamily::from_c_int(0), Some(AddressFamily::Unspec));
        assert_eq!(AddressFamily::from_c_int(2), Some(AddressFamily::Inet));
        assert_eq!(AddressFamily::from_c_int(10), Some(AddressFamily::Inet6));
        assert_eq!(AddressFamily::from_c_int(99), None);
    }

    #[test]
    fn address_family_sizes() {
        assert_eq!(AddressFamily::Inet.address_size(), 4);
        assert_eq!(AddressFamily::Inet6.address_size(), 16);
        assert_eq!(AddressFamily::Unspec.address_size(), 0);
    }
}
