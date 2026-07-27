// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-common-errors.c, src/libsystemd/sd-bus/bus-common-errors.h

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusErrorMap {
    pub name: &'static str,
    pub errno: i32,
}

pub const BUS_COMMON_ERRORS: &[BusErrorMap] = &[
    BusErrorMap {
        name: "org.freedesktop.systemd1.NoSuchUnit",
        errno: 2,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.NoSuchProcess",
        errno: 3,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.NoUnitForPID",
        errno: 3,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.NoUnitForInvocationID",
        errno: 2,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.UnitExists",
        errno: 17,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.LoadFailed",
        errno: 5,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.BadUnitSetting",
        errno: 8,
    },
    BusErrorMap {
        name: "org.freedesktop.systemd1.JobFailed",
        errno: 121,
    },
    BusErrorMap {
        name: "org.freedesktop.resolve1.NoSuchService",
        errno: 49,
    },
    BusErrorMap {
        name: "org.freedesktop.resolve1.NetworkDown",
        errno: 100,
    },
    BusErrorMap {
        name: "org.freedesktop.resolve1.InvalidReply",
        errno: 22,
    },
    BusErrorMap {
        name: "org.freedesktop.home1.BadPassword",
        errno: 126,
    },
    BusErrorMap {
        name: "org.freedesktop.home1.HomeLocked",
        errno: 8,
    },
    BusErrorMap {
        name: "org.freedesktop.home1.TooManyOperations",
        errno: 105,
    },
    BusErrorMap {
        name: "org.freedesktop.portable1.NoMatchingUnitFiles",
        errno: 2,
    },
    BusErrorMap {
        name: "org.freedesktop.sysupdate1.NoCandidate",
        errno: 114,
    },
];

pub fn common_error_to_errno(name: &str) -> Result<i32, i32> {
    BUS_COMMON_ERRORS
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.errno)
        .ok_or(-5)
}

pub fn errno_to_common_error(errno: i32) -> Option<&'static str> {
    let normalized = errno.abs();
    BUS_COMMON_ERRORS
        .iter()
        .find(|entry| entry.errno == normalized)
        .map(|entry| entry.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_no_such_unit() {
        assert_eq!(
            common_error_to_errno("org.freedesktop.systemd1.NoSuchUnit"),
            Ok(2)
        );
    }

    #[test]
    fn resolves_bad_password() {
        assert_eq!(
            common_error_to_errno("org.freedesktop.home1.BadPassword"),
            Ok(126)
        );
    }

    #[test]
    fn returns_eio_for_unknown_name() {
        assert_eq!(common_error_to_errno("missing.error"), Err(-5));
    }

    #[test]
    fn resolves_errno_to_first_matching_name() {
        assert_eq!(
            errno_to_common_error(17),
            Some("org.freedesktop.systemd1.UnitExists")
        );
    }

    #[test]
    fn accepts_negative_errno() {
        assert_eq!(
            errno_to_common_error(-100),
            Some("org.freedesktop.resolve1.NetworkDown")
        );
    }

    #[test]
    fn unknown_errno_returns_none() {
        assert_eq!(errno_to_common_error(9999), None);
    }

    #[test]
    fn map_contains_sysupdate_entry() {
        assert!(BUS_COMMON_ERRORS
            .iter()
            .any(|entry| entry.name == "org.freedesktop.sysupdate1.NoCandidate"));
    }

    #[test]
    fn map_contains_resolve_service_entry() {
        assert!(BUS_COMMON_ERRORS.iter().any(|entry| entry.name
            == "org.freedesktop.resolve1.NoSuchService"
            && entry.errno == 49));
    }

    #[test]
    fn map_contains_portable_no_matching_unit_files_entry() {
        assert!(BUS_COMMON_ERRORS.iter().any(|entry| entry.name
            == "org.freedesktop.portable1.NoMatchingUnitFiles"
            && entry.errno == 2));
    }

    #[test]
    fn map_contains_home_locked_entry() {
        assert!(BUS_COMMON_ERRORS
            .iter()
            .any(|entry| entry.name == "org.freedesktop.home1.HomeLocked" && entry.errno == 8));
    }
}
