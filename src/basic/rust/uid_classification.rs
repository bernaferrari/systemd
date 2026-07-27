// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/uid-classification.h (uid_is_greeter, uid_is_dynamic, etc.)
//
// The ranges are Meson options, not universal protocol constants. The Meson
// Cargo wrapper supplies their configured values as compile-time environment
// variables. Direct Cargo use intentionally falls back to upstream defaults.

const fn configured_u32(value: Option<&str>, default: u32) -> u32 {
    let text = match value {
        Some(value) => value,
        None => return default,
    };
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        panic!("empty configured UID boundary");
    }

    let mut parsed = 0_u32;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte < b'0' || byte > b'9' {
            panic!("configured UID boundary is not decimal");
        }
        let digit = (byte - b'0') as u32;
        if parsed > (u32::MAX - digit) / 10 {
            panic!("configured UID boundary overflows uid_t");
        }
        parsed = parsed * 10 + digit;
        index += 1;
    }
    parsed
}

pub const GREETER_UID_MIN: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_GREETER_UID_MIN"), 0x0000_ECA2);
pub const GREETER_UID_MAX: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_GREETER_UID_MAX"), 0x0000_ED21);

pub const DYNAMIC_UID_MIN: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_DYNAMIC_UID_MIN"), 0x0000_EF00);
pub const DYNAMIC_UID_MAX: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_DYNAMIC_UID_MAX"), 0x0000_FFEF);

pub const CONTAINER_UID_MIN: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_CONTAINER_UID_MIN"), 0x0008_0000);
pub const CONTAINER_UID_MAX: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_CONTAINER_UID_MAX"), 0x6FFF_FFFF);

pub const FOREIGN_UID_MIN: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_FOREIGN_UID_MIN"), 0x7FFE_0000);
pub const FOREIGN_UID_MAX: libc::uid_t =
    configured_u32(option_env!("SYSTEMD_FOREIGN_UID_MAX"), 0x7FFE_FFFF);

const _: () = {
    assert!(GREETER_UID_MIN <= GREETER_UID_MAX);
    assert!(DYNAMIC_UID_MIN <= DYNAMIC_UID_MAX);
    assert!(CONTAINER_UID_MIN <= CONTAINER_UID_MAX);
    assert!(FOREIGN_UID_MIN <= FOREIGN_UID_MAX);
    assert!(CONTAINER_UID_MIN & 0xffff == 0);
    assert!(CONTAINER_UID_MAX & 0xffff == 0xffff);
    assert!(FOREIGN_UID_MIN & 0xffff == 0);
    assert!(FOREIGN_UID_MAX & 0xffff == 0xffff);
};

fn in_range(id: libc::uid_t, min: libc::uid_t, max: libc::uid_t) -> bool {
    min <= id && id <= max
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_uid_is_greeter(uid: libc::uid_t) -> bool {
    in_range(uid, GREETER_UID_MIN, GREETER_UID_MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_uid_is_dynamic(uid: libc::uid_t) -> bool {
    in_range(uid, DYNAMIC_UID_MIN, DYNAMIC_UID_MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_gid_is_dynamic(gid: libc::gid_t) -> bool {
    rs_uid_is_dynamic(gid as libc::uid_t)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_uid_is_container(uid: libc::uid_t) -> bool {
    in_range(uid, CONTAINER_UID_MIN, CONTAINER_UID_MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_gid_is_container(gid: libc::gid_t) -> bool {
    rs_uid_is_container(gid as libc::uid_t)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_uid_is_foreign(uid: libc::uid_t) -> bool {
    in_range(uid, FOREIGN_UID_MIN, FOREIGN_UID_MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_gid_is_foreign(gid: libc::gid_t) -> bool {
    rs_uid_is_foreign(gid as libc::uid_t)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_uid_is_transient(uid: libc::uid_t) -> bool {
    rs_uid_is_container(uid) || rs_uid_is_dynamic(uid)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_gid_is_transient(gid: libc::gid_t) -> bool {
    rs_uid_is_container(gid as libc::uid_t) || rs_uid_is_dynamic(gid as libc::uid_t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeter_range_is_inclusive() {
        assert!(rs_uid_is_greeter(GREETER_UID_MIN));
        assert!(rs_uid_is_greeter(
            GREETER_UID_MIN + (GREETER_UID_MAX - GREETER_UID_MIN) / 2
        ));
        assert!(rs_uid_is_greeter(GREETER_UID_MAX));
    }

    #[test]
    fn greeter_range_rejects_outside_values() {
        if GREETER_UID_MIN > 0 {
            assert!(!rs_uid_is_greeter(GREETER_UID_MIN - 1));
        }
        if GREETER_UID_MAX < libc::uid_t::MAX {
            assert!(!rs_uid_is_greeter(GREETER_UID_MAX + 1));
        }
    }

    #[test]
    fn dynamic_range_is_inclusive() {
        assert!(rs_uid_is_dynamic(DYNAMIC_UID_MIN));
        assert!(rs_uid_is_dynamic(
            DYNAMIC_UID_MIN + (DYNAMIC_UID_MAX - DYNAMIC_UID_MIN) / 2
        ));
        assert!(rs_uid_is_dynamic(DYNAMIC_UID_MAX));
    }

    #[test]
    fn dynamic_gid_matches_uid_logic() {
        assert_eq!(
            rs_gid_is_dynamic(DYNAMIC_UID_MIN),
            rs_uid_is_dynamic(DYNAMIC_UID_MIN)
        );
        assert_eq!(
            rs_gid_is_dynamic(DYNAMIC_UID_MAX),
            rs_uid_is_dynamic(DYNAMIC_UID_MAX)
        );
        assert!(!rs_gid_is_dynamic(1000));
    }

    #[test]
    fn container_range_is_inclusive() {
        assert!(rs_uid_is_container(CONTAINER_UID_MIN));
        assert!(rs_uid_is_container(
            CONTAINER_UID_MIN + (CONTAINER_UID_MAX - CONTAINER_UID_MIN) / 2
        ));
        assert!(rs_uid_is_container(CONTAINER_UID_MAX));
    }

    #[test]
    fn container_gid_matches_uid_logic() {
        assert!(rs_gid_is_container(CONTAINER_UID_MIN));
        assert!(rs_gid_is_container(CONTAINER_UID_MAX));
        if CONTAINER_UID_MIN > 0 {
            assert!(!rs_gid_is_container(CONTAINER_UID_MIN - 1));
        }
    }

    #[test]
    fn foreign_range_is_inclusive() {
        assert!(rs_uid_is_foreign(FOREIGN_UID_MIN));
        assert!(rs_uid_is_foreign(
            FOREIGN_UID_MIN + (FOREIGN_UID_MAX - FOREIGN_UID_MIN) / 2
        ));
        assert!(rs_uid_is_foreign(FOREIGN_UID_MAX));
    }

    #[test]
    fn foreign_range_rejects_outside_values() {
        if FOREIGN_UID_MIN > 0 {
            assert!(!rs_uid_is_foreign(FOREIGN_UID_MIN - 1));
        }
        if FOREIGN_UID_MAX < libc::uid_t::MAX {
            assert!(!rs_uid_is_foreign(FOREIGN_UID_MAX + 1));
        }
    }

    #[test]
    fn transient_is_union_of_dynamic_and_container() {
        assert!(rs_uid_is_transient(DYNAMIC_UID_MIN));
        assert!(rs_uid_is_transient(CONTAINER_UID_MIN));
        assert_eq!(
            rs_uid_is_transient(GREETER_UID_MIN),
            rs_uid_is_dynamic(GREETER_UID_MIN) || rs_uid_is_container(GREETER_UID_MIN)
        );
        assert_eq!(
            rs_uid_is_transient(1000),
            rs_uid_is_dynamic(1000) || rs_uid_is_container(1000)
        );
    }

    #[test]
    fn transient_gid_matches_uid_logic() {
        assert_eq!(
            rs_gid_is_transient(DYNAMIC_UID_MAX),
            rs_uid_is_transient(DYNAMIC_UID_MAX)
        );
        assert_eq!(
            rs_gid_is_transient(CONTAINER_UID_MIN),
            rs_uid_is_transient(CONTAINER_UID_MIN)
        );
    }
}
