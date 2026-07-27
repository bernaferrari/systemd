// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-locator.c, src/shared/bus-locator.h
//
// D-Bus service locator definitions and convenience helpers.
//
// Provides a BusLocator struct encapsulating the three D-Bus identifiers
// (destination, path, interface) used to address a specific service object
// on the bus. Static instances cover all well-known systemd manager services.

// ── BusLocator ────────────────────────────────────────────────────────────

/// A D-Bus service locator combining the destination (well-known bus name),
/// object path, and interface name needed to address a specific service.
///
/// This is the Rust equivalent of the C `BusLocator` struct from bus-locator.h.
/// All fields are static string references, making this type `Copy`, `Send`, and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusLocator {
    pub destination: &'static str,
    pub path: &'static str,
    pub interface: &'static str,
}

impl BusLocator {
    /// Create a new BusLocator from static string slices.
    pub const fn new(
        destination: &'static str,
        path: &'static str,
        interface: &'static str,
    ) -> Self {
        Self {
            destination,
            path,
            interface,
        }
    }

    /// Returns the destination (well-known bus name) as a byte slice.
    pub fn destination_bytes(&self) -> &'static [u8] {
        self.destination.as_bytes()
    }

    /// Returns the object path as a byte slice.
    pub fn path_bytes(&self) -> &'static [u8] {
        self.path.as_bytes()
    }

    /// Returns the interface name as a byte slice.
    pub fn interface_bytes(&self) -> &'static [u8] {
        self.interface.as_bytes()
    }

    /// Returns true if this locator uses the `.Manager` interface convention.
    pub fn has_manager_interface(&self) -> bool {
        self.interface.ends_with(".Manager")
    }

    /// Returns true if the destination follows the `org.freedesktop.` naming convention.
    pub fn is_freedesktop_service(&self) -> bool {
        self.destination.starts_with("org.freedesktop.")
    }

    /// Extracts the service short name from the destination.
    ///
    /// For example, `org.freedesktop.systemd1` yields `systemd1`.
    /// Returns `None` if the destination does not start with `org.freedesktop.`.
    pub fn service_short_name(&self) -> Option<&'static str> {
        self.destination
            .strip_prefix("org.freedesktop.")
            .or_else(|| self.destination.strip_prefix("org.freedesktop.login1."))
            .or_else(|| self.destination.strip_prefix("org.freedesktop.systemd1."))
    }
}

impl std::fmt::Display for BusLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BusLocator(dest={}, path={}, iface={})",
            self.destination, self.path, self.interface
        )
    }
}

// ── Static service locators ───────────────────────────────────────────────

/// Home directory manager (`homectl` / `pam_systemd_home`)
pub const BUS_HOME_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.home1",
    "/org/freedesktop/home1",
    "org.freedesktop.home1.Manager",
);

/// Import/export manager (`machinectl pull`, `importctl`)
pub const BUS_IMPORT_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.import1",
    "/org/freedesktop/import1",
    "org.freedesktop.import1.Manager",
);

/// Locale manager (`localectl`)
pub const BUS_LOCALE: BusLocator = BusLocator::new(
    "org.freedesktop.locale1",
    "/org/freedesktop/locale1",
    "org.freedesktop.locale1",
);

/// Login manager (`loginctl` / `pam_systemd`)
pub const BUS_LOGIN_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.login1",
    "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager",
);

/// Machine manager (`machinectl`)
pub const BUS_MACHINE_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.machine1",
    "/org/freedesktop/machine1",
    "org.freedesktop.machine1.Manager",
);

/// Network manager (`networkctl`)
pub const BUS_NETWORK_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.network1",
    "/org/freedesktop/network1",
    "org.freedesktop.network1.Manager",
);

/// OOM (out-of-memory) manager (`systemd-oomd`)
pub const BUS_OOM_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.oom1",
    "/org/freedesktop/oom1",
    "org.freedesktop.oom1.Manager",
);

/// Portable service manager (`portablectl`)
pub const BUS_PORTABLE_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.portable1",
    "/org/freedesktop/portable1",
    "org.freedesktop.portable1.Manager",
);

/// DNS resolver manager (`resolvectl`)
pub const BUS_RESOLVE_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.resolve1",
    "/org/freedesktop/resolve1",
    "org.freedesktop.resolve1.Manager",
);

/// System/service manager (`systemctl`, `systemd` itself)
pub const BUS_SYSTEMD_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
);

/// System update manager (`sysupdatectl`)
pub const BUS_SYSUPDATE_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.sysupdate1",
    "/org/freedesktop/sysupdate1",
    "org.freedesktop.sysupdate1.Manager",
);

/// Time/date manager (`timedatectl`)
pub const BUS_TIMEDATE: BusLocator = BusLocator::new(
    "org.freedesktop.timedate1",
    "/org/freedesktop/timedate1",
    "org.freedesktop.timedate1",
);

/// Network time synchronization manager (`systemd-timesyncd`)
pub const BUS_TIMESYNC_MGR: BusLocator = BusLocator::new(
    "org.freedesktop.timesync1",
    "/org/freedesktop/timesync1",
    "org.freedesktop.timesync1.Manager",
);

/// Hostname manager (`hostnamectl`)
pub const BUS_HOSTNAME: BusLocator = BusLocator::new(
    "org.freedesktop.hostname1",
    "/org/freedesktop/hostname1",
    "org.freedesktop.hostname1",
);

/// All well-known systemd bus locators, in canonical order.
pub const ALL_BUS_LOCATORS: &[BusLocator] = &[
    BUS_HOME_MGR,
    BUS_HOSTNAME,
    BUS_IMPORT_MGR,
    BUS_LOCALE,
    BUS_LOGIN_MGR,
    BUS_MACHINE_MGR,
    BUS_NETWORK_MGR,
    BUS_OOM_MGR,
    BUS_PORTABLE_MGR,
    BUS_RESOLVE_MGR,
    BUS_SYSTEMD_MGR,
    BUS_SYSUPDATE_MGR,
    BUS_TIMEDATE,
    BUS_TIMESYNC_MGR,
];

// ── Lookup helpers ────────────────────────────────────────────────────────

/// Look up a BusLocator by its destination (well-known bus name).
/// Returns a reference to the matching static locator, or `None`.
pub fn find_by_destination(destination: &str) -> Option<&'static BusLocator> {
    ALL_BUS_LOCATORS
        .iter()
        .find(|loc| loc.destination == destination)
}

/// Look up a BusLocator by its object path.
/// Returns a reference to the matching static locator, or `None`.
pub fn find_by_path(path: &str) -> Option<&'static BusLocator> {
    ALL_BUS_LOCATORS.iter().find(|loc| loc.path == path)
}

/// Look up a BusLocator by its interface name.
/// Returns a reference to the matching static locator, or `None`.
pub fn find_by_interface(interface: &str) -> Option<&'static BusLocator> {
    ALL_BUS_LOCATORS
        .iter()
        .find(|loc| loc.interface == interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bus_locator_new() {
        let loc = BusLocator::new(
            "org.example.Foo",
            "/org/example/Foo",
            "org.example.Foo.Iface",
        );
        assert_eq!(loc.destination, "org.example.Foo");
        assert_eq!(loc.path, "/org/example/Foo");
        assert_eq!(loc.interface, "org.example.Foo.Iface");
    }

    #[test]
    fn test_bus_locator_copy() {
        let original = BUS_SYSTEMD_MGR;
        let copy = original;
        assert_eq!(original, copy);
    }

    #[test]
    fn test_bus_locator_debug() {
        let loc = BUS_SYSTEMD_MGR;
        let debug_str = format!("{:?}", loc);
        assert!(debug_str.contains("org.freedesktop.systemd1"));
    }

    #[test]
    fn test_bus_locator_display() {
        let loc = BUS_LOGIN_MGR;
        let display = format!("{}", loc);
        assert!(display.contains("org.freedesktop.login1"));
        assert!(display.contains("/org/freedesktop/login1"));
        assert!(display.contains("org.freedesktop.login1.Manager"));
    }

    #[test]
    fn test_home_mgr_fields() {
        assert_eq!(BUS_HOME_MGR.destination, "org.freedesktop.home1");
        assert_eq!(BUS_HOME_MGR.path, "/org/freedesktop/home1");
        assert_eq!(BUS_HOME_MGR.interface, "org.freedesktop.home1.Manager");
    }

    #[test]
    fn test_systemd_mgr_fields() {
        assert_eq!(BUS_SYSTEMD_MGR.destination, "org.freedesktop.systemd1");
        assert_eq!(BUS_SYSTEMD_MGR.path, "/org/freedesktop/systemd1");
        assert_eq!(
            BUS_SYSTEMD_MGR.interface,
            "org.freedesktop.systemd1.Manager"
        );
    }

    #[test]
    fn test_locale_fields() {
        assert_eq!(BUS_LOCALE.destination, "org.freedesktop.locale1");
        assert_eq!(BUS_LOCALE.interface, "org.freedesktop.locale1");
    }

    #[test]
    fn test_hostname_fields() {
        assert_eq!(BUS_HOSTNAME.destination, "org.freedesktop.hostname1");
        assert_eq!(BUS_HOSTNAME.path, "/org/freedesktop/hostname1");
        assert_eq!(BUS_HOSTNAME.interface, "org.freedesktop.hostname1");
    }

    #[test]
    fn test_has_manager_interface() {
        assert!(BUS_SYSTEMD_MGR.has_manager_interface());
        assert!(BUS_LOGIN_MGR.has_manager_interface());
        assert!(BUS_NETWORK_MGR.has_manager_interface());
        assert!(!BUS_LOCALE.has_manager_interface());
        assert!(!BUS_HOSTNAME.has_manager_interface());
        assert!(!BUS_TIMEDATE.has_manager_interface());
    }

    #[test]
    fn test_is_freedesktop_service() {
        assert!(BUS_SYSTEMD_MGR.is_freedesktop_service());
        assert!(BUS_LOGIN_MGR.is_freedesktop_service());
    }

    #[test]
    fn test_service_short_name() {
        assert_eq!(BUS_SYSTEMD_MGR.service_short_name(), Some("systemd1"));
        assert_eq!(BUS_LOGIN_MGR.service_short_name(), Some("login1"));
        assert_eq!(BUS_LOCALE.service_short_name(), Some("locale1"));
        assert_eq!(BUS_HOSTNAME.service_short_name(), Some("hostname1"));
    }

    #[test]
    fn test_destination_bytes() {
        assert_eq!(
            BUS_SYSTEMD_MGR.destination_bytes(),
            b"org.freedesktop.systemd1"
        );
    }

    #[test]
    fn test_path_bytes() {
        assert_eq!(BUS_SYSTEMD_MGR.path_bytes(), b"/org/freedesktop/systemd1");
    }

    #[test]
    fn test_interface_bytes() {
        assert_eq!(
            BUS_SYSTEMD_MGR.interface_bytes(),
            b"org.freedesktop.systemd1.Manager"
        );
    }

    #[test]
    fn test_all_locators_count() {
        assert_eq!(ALL_BUS_LOCATORS.len(), 14);
    }

    #[test]
    fn test_find_by_destination() {
        let found = find_by_destination("org.freedesktop.systemd1");
        assert_eq!(found, Some(&BUS_SYSTEMD_MGR));

        let not_found = find_by_destination("org.example.nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_find_by_path() {
        let found = find_by_path("/org/freedesktop/login1");
        assert_eq!(found, Some(&BUS_LOGIN_MGR));

        let not_found = find_by_path("/org/example/nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_find_by_interface() {
        let found = find_by_interface("org.freedesktop.resolve1.Manager");
        assert_eq!(found, Some(&BUS_RESOLVE_MGR));

        let not_found = find_by_interface("org.example.Nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_all_locators_are_freedesktop() {
        for loc in ALL_BUS_LOCATORS {
            assert!(
                loc.is_freedesktop_service(),
                "locator {} is not a freedesktop service",
                loc.destination
            );
        }
    }

    #[test]
    fn test_all_locators_path_matches_destination() {
        for loc in ALL_BUS_LOCATORS {
            let expected_path = format!("/{}", loc.destination.replace('.', "/"));
            assert_eq!(
                loc.path, expected_path,
                "path mismatch for {}",
                loc.destination
            );
        }
    }

    #[test]
    fn test_partial_eq_different_locators() {
        assert_ne!(BUS_SYSTEMD_MGR, BUS_LOGIN_MGR);
        assert_ne!(BUS_LOCALE, BUS_HOSTNAME);
    }
}
