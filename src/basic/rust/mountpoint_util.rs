// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/mountpoint-util.c (mount_propagation_flag_to_string/from_string,
//            mount_propagation_flag_is_valid, is_name_to_handle_at_fatal_error,
//            file_handle_equal)
//
// Mount propagation flag conversion and mountpoint utility functions.
// Pure Rust — no FFI. Uses safe idiomatic Rust with enums and Result types.

use libc::c_ulong;

// ── Constants ─────────────────────────────────────────────────────────────

pub const MS_SHARED: u64 = 1 << 20;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_PRIVATE: u64 = 1 << 18;

const PROPAGATION_MASK: u64 = MS_SHARED | MS_SLAVE | MS_PRIVATE;

const EOPNOTSUPP: i32 = 95;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 38;
const EAFNOSUPPORT: i32 = 97;
const EPFNOSUPPORT: i32 = 96;
const EPROTONOSUPPORT: i32 = 93;
const ESOCKTNOSUPPORT: i32 = 94;
const ENOPROTOOPT: i32 = 92;
const EACCES: i32 = 13;
const EPERM: i32 = 1;
const EOVERFLOW: i32 = 75;
const EINVAL: i32 = 22;

// ── Enums ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountPropagationFlag {
    None,
    Shared,
    Slave,
    Private,
}

impl MountPropagationFlag {
    pub fn from_raw_flags(flags: u64) -> Option<Self> {
        match flags & PROPAGATION_MASK {
            0 => Some(Self::None),
            MS_SHARED => Some(Self::Shared),
            MS_SLAVE => Some(Self::Slave),
            MS_PRIVATE => Some(Self::Private),
            _ => None,
        }
    }

    pub fn to_raw_flag(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Shared => MS_SHARED,
            Self::Slave => MS_SLAVE,
            Self::Private => MS_PRIVATE,
        }
    }
}

// ── Propagation flag string conversion ─────────────────────────────────────

pub fn mount_propagation_flag_to_string(flag: MountPropagationFlag) -> &'static str {
    match flag {
        MountPropagationFlag::None => "",
        MountPropagationFlag::Shared => "shared",
        MountPropagationFlag::Slave => "slave",
        MountPropagationFlag::Private => "private",
    }
}

pub fn mount_propagation_flag_from_string(name: &str) -> Result<MountPropagationFlag, i32> {
    let flag = if name.is_empty() {
        MountPropagationFlag::None
    } else if name == "shared" {
        MountPropagationFlag::Shared
    } else if name == "slave" {
        MountPropagationFlag::Slave
    } else if name == "private" {
        MountPropagationFlag::Private
    } else {
        return Err(-EINVAL);
    };
    Ok(flag)
}

pub fn mount_propagation_flag_is_valid(flag: MountPropagationFlag) -> bool {
    true
}

pub fn mount_propagation_flag_raw_is_valid(flag: u64) -> bool {
    matches!(flag, 0 | MS_SHARED | MS_PRIVATE | MS_SLAVE)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_mount_propagation_flag_is_valid(flag: c_ulong) -> bool {
    mount_propagation_flag_raw_is_valid(flag as u64)
}

// ── Error classification helpers ──────────────────────────────────────────

pub fn errno_is_neg_not_supported(r: i32) -> bool {
    r == -EOPNOTSUPP
        || r == -ENOTTY
        || r == -ENOSYS
        || r == -EAFNOSUPPORT
        || r == -EPFNOSUPPORT
        || r == -EPROTONOSUPPORT
        || r == -ESOCKTNOSUPPORT
        || r == -ENOPROTOOPT
}

pub fn errno_is_neg_privilege(r: i32) -> bool {
    r == -EACCES || r == -EPERM
}

// ── is_name_to_handle_at_fatal_error ──────────────────────────────────────

pub fn is_name_to_handle_at_fatal_error(err: i32) -> bool {
    if err >= 0 {
        return true;
    }

    if errno_is_neg_not_supported(err) {
        return false;
    }
    if errno_is_neg_privilege(err) {
        return false;
    }

    !(err == -EOVERFLOW || err == -EINVAL)
}

// ── File handle comparison ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub handle_type: i32,
    pub handle_bytes: Vec<u8>,
}

impl FileHandle {
    pub fn new(handle_type: i32, handle_bytes: Vec<u8>) -> Self {
        Self {
            handle_type,
            handle_bytes,
        }
    }
}

pub fn file_handle_equal(a: Option<&FileHandle>, b: Option<&FileHandle>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
        (Some(a_val), Some(b_val)) => {
            a_val.handle_type == b_val.handle_type && a_val.handle_bytes == b_val.handle_bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_propagation_flag_to_string_none() {
        assert_eq!(
            mount_propagation_flag_to_string(MountPropagationFlag::None),
            ""
        );
    }

    #[test]
    fn test_mount_propagation_flag_to_string_shared() {
        assert_eq!(
            mount_propagation_flag_to_string(MountPropagationFlag::Shared),
            "shared"
        );
    }

    #[test]
    fn test_mount_propagation_flag_to_string_slave() {
        assert_eq!(
            mount_propagation_flag_to_string(MountPropagationFlag::Slave),
            "slave"
        );
    }

    #[test]
    fn test_mount_propagation_flag_to_string_private() {
        assert_eq!(
            mount_propagation_flag_to_string(MountPropagationFlag::Private),
            "private"
        );
    }

    #[test]
    fn test_mount_propagation_flag_from_string_empty() {
        assert_eq!(
            mount_propagation_flag_from_string(""),
            Ok(MountPropagationFlag::None)
        );
    }

    #[test]
    fn test_mount_propagation_flag_from_string_shared() {
        assert_eq!(
            mount_propagation_flag_from_string("shared"),
            Ok(MountPropagationFlag::Shared)
        );
    }

    #[test]
    fn test_mount_propagation_flag_from_string_slave() {
        assert_eq!(
            mount_propagation_flag_from_string("slave"),
            Ok(MountPropagationFlag::Slave)
        );
    }

    #[test]
    fn test_mount_propagation_flag_from_string_private() {
        assert_eq!(
            mount_propagation_flag_from_string("private"),
            Ok(MountPropagationFlag::Private)
        );
    }

    #[test]
    fn test_mount_propagation_flag_from_string_invalid() {
        assert_eq!(mount_propagation_flag_from_string("invalid"), Err(-22));
    }

    #[test]
    fn test_mount_propagation_flag_from_string_case_sensitive() {
        assert_eq!(mount_propagation_flag_from_string("Shared"), Err(-22));
        assert_eq!(mount_propagation_flag_from_string("SHARED"), Err(-22));
        assert_eq!(mount_propagation_flag_from_string("Private"), Err(-22));
    }

    #[test]
    fn test_from_raw_flags_zero() {
        assert_eq!(
            MountPropagationFlag::from_raw_flags(0),
            Some(MountPropagationFlag::None)
        );
    }

    #[test]
    fn test_from_raw_flags_shared() {
        assert_eq!(
            MountPropagationFlag::from_raw_flags(MS_SHARED),
            Some(MountPropagationFlag::Shared)
        );
    }

    #[test]
    fn test_from_raw_flags_slave() {
        assert_eq!(
            MountPropagationFlag::from_raw_flags(MS_SLAVE),
            Some(MountPropagationFlag::Slave)
        );
    }

    #[test]
    fn test_from_raw_flags_private() {
        assert_eq!(
            MountPropagationFlag::from_raw_flags(MS_PRIVATE),
            Some(MountPropagationFlag::Private)
        );
    }

    #[test]
    fn test_from_raw_flags_combined_is_invalid() {
        assert!(MountPropagationFlag::from_raw_flags(MS_SHARED | MS_SLAVE).is_none());
        assert!(MountPropagationFlag::from_raw_flags(MS_SHARED | MS_PRIVATE).is_none());
        assert!(MountPropagationFlag::from_raw_flags(MS_SLAVE | MS_PRIVATE).is_none());
        assert!(MountPropagationFlag::from_raw_flags(MS_SHARED | MS_SLAVE | MS_PRIVATE).is_none());
    }

    #[test]
    fn test_from_raw_flags_ignores_other_bits() {
        assert_eq!(
            MountPropagationFlag::from_raw_flags(MS_SHARED | 0xFFFF),
            Some(MountPropagationFlag::Shared)
        );
    }

    #[test]
    fn test_roundtrip_shared() {
        let flag = mount_propagation_flag_from_string("shared").unwrap();
        assert_eq!(flag.to_raw_flag(), MS_SHARED);
        assert_eq!(mount_propagation_flag_to_string(flag), "shared");
    }

    #[test]
    fn test_roundtrip_slave() {
        let flag = mount_propagation_flag_from_string("slave").unwrap();
        assert_eq!(flag.to_raw_flag(), MS_SLAVE);
        assert_eq!(mount_propagation_flag_to_string(flag), "slave");
    }

    #[test]
    fn test_roundtrip_private() {
        let flag = mount_propagation_flag_from_string("private").unwrap();
        assert_eq!(flag.to_raw_flag(), MS_PRIVATE);
        assert_eq!(mount_propagation_flag_to_string(flag), "private");
    }

    #[test]
    fn test_roundtrip_none() {
        let flag = mount_propagation_flag_from_string("").unwrap();
        assert_eq!(flag.to_raw_flag(), 0);
        assert_eq!(mount_propagation_flag_to_string(flag), "");
    }

    #[test]
    fn test_mount_propagation_flag_is_valid_all() {
        assert!(mount_propagation_flag_is_valid(MountPropagationFlag::None));
        assert!(mount_propagation_flag_is_valid(
            MountPropagationFlag::Shared
        ));
        assert!(mount_propagation_flag_is_valid(MountPropagationFlag::Slave));
        assert!(mount_propagation_flag_is_valid(
            MountPropagationFlag::Private
        ));
    }

    #[test]
    fn test_mount_propagation_flag_raw_is_valid() {
        assert!(mount_propagation_flag_raw_is_valid(0));
        assert!(mount_propagation_flag_raw_is_valid(MS_SHARED));
        assert!(mount_propagation_flag_raw_is_valid(MS_SLAVE));
        assert!(mount_propagation_flag_raw_is_valid(MS_PRIVATE));
        assert!(!mount_propagation_flag_raw_is_valid(MS_SHARED | MS_SLAVE));
        assert!(!mount_propagation_flag_raw_is_valid(42));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_positive() {
        assert!(is_name_to_handle_at_fatal_error(1));
        assert!(is_name_to_handle_at_fatal_error(0));
        assert!(is_name_to_handle_at_fatal_error(100));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_not_supported() {
        assert!(!is_name_to_handle_at_fatal_error(-95));
        assert!(!is_name_to_handle_at_fatal_error(-25));
        assert!(!is_name_to_handle_at_fatal_error(-38));
        assert!(!is_name_to_handle_at_fatal_error(-97));
        assert!(!is_name_to_handle_at_fatal_error(-96));
        assert!(!is_name_to_handle_at_fatal_error(-93));
        assert!(!is_name_to_handle_at_fatal_error(-94));
        assert!(!is_name_to_handle_at_fatal_error(-92));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_privilege() {
        assert!(!is_name_to_handle_at_fatal_error(-13));
        assert!(!is_name_to_handle_at_fatal_error(-1));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_eoverflow() {
        assert!(!is_name_to_handle_at_fatal_error(-75));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_einval() {
        assert!(!is_name_to_handle_at_fatal_error(-22));
    }

    #[test]
    fn test_is_name_to_handle_at_fatal_error_other_fatal() {
        assert!(is_name_to_handle_at_fatal_error(-5));
        assert!(is_name_to_handle_at_fatal_error(-100));
        assert!(is_name_to_handle_at_fatal_error(-2));
    }

    #[test]
    fn test_errno_is_neg_not_supported_all_values() {
        assert!(errno_is_neg_not_supported(-95));
        assert!(errno_is_neg_not_supported(-25));
        assert!(errno_is_neg_not_supported(-38));
        assert!(errno_is_neg_not_supported(-97));
        assert!(errno_is_neg_not_supported(-96));
        assert!(errno_is_neg_not_supported(-93));
        assert!(errno_is_neg_not_supported(-94));
        assert!(errno_is_neg_not_supported(-92));
    }

    #[test]
    fn test_errno_is_neg_not_supported_negative() {
        assert!(!errno_is_neg_not_supported(0));
        assert!(!errno_is_neg_not_supported(95));
        assert!(!errno_is_neg_not_supported(-1));
        assert!(!errno_is_neg_not_supported(-13));
    }

    #[test]
    fn test_errno_is_neg_privilege_all_values() {
        assert!(errno_is_neg_privilege(-13));
        assert!(errno_is_neg_privilege(-1));
    }

    #[test]
    fn test_errno_is_neg_privilege_negative() {
        assert!(!errno_is_neg_privilege(0));
        assert!(!errno_is_neg_privilege(13));
        assert!(!errno_is_neg_privilege(-95));
    }

    #[test]
    fn test_file_handle_equal_both_none() {
        assert!(file_handle_equal(None, None));
    }

    #[test]
    fn test_file_handle_equal_one_none() {
        let fh = FileHandle::new(1, vec![1, 2, 3]);
        assert!(!file_handle_equal(Some(&fh), None));
        assert!(!file_handle_equal(None, Some(&fh)));
    }

    #[test]
    fn test_file_handle_equal_same() {
        let fh = FileHandle::new(1, vec![1, 2, 3]);
        assert!(file_handle_equal(Some(&fh), Some(&fh)));
    }

    #[test]
    fn test_file_handle_equal_identical() {
        let a = FileHandle::new(1, vec![1, 2, 3]);
        let b = FileHandle::new(1, vec![1, 2, 3]);
        assert!(file_handle_equal(Some(&a), Some(&b)));
    }

    #[test]
    fn test_file_handle_equal_different_type() {
        let a = FileHandle::new(1, vec![1, 2, 3]);
        let b = FileHandle::new(2, vec![1, 2, 3]);
        assert!(!file_handle_equal(Some(&a), Some(&b)));
    }

    #[test]
    fn test_file_handle_equal_different_bytes() {
        let a = FileHandle::new(1, vec![1, 2, 3]);
        let b = FileHandle::new(1, vec![1, 2, 4]);
        assert!(!file_handle_equal(Some(&a), Some(&b)));
    }

    #[test]
    fn test_file_handle_equal_different_length() {
        let a = FileHandle::new(1, vec![1, 2, 3]);
        let b = FileHandle::new(1, vec![1, 2]);
        assert!(!file_handle_equal(Some(&a), Some(&b)));
    }

    #[test]
    fn test_file_handle_equal_empty_bytes() {
        let a = FileHandle::new(0, vec![]);
        let b = FileHandle::new(0, vec![]);
        assert!(file_handle_equal(Some(&a), Some(&b)));
    }
}
