// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.namespace-util; authority=src/basic/namespace-util.c,src/basic/namespace-util.h,src/include/override/sched.h
//
// Namespace type lookup from clone flags and userns range validation.

use crate::ffi::Errno;
use libc::{c_int, c_ulong, uid_t};

// ── Constants ──────────────────────────────────────────────────────────────

// Namespace clone flags from Linux UAPI <sched.h>. The project override
// additionally pins CLONE_NEWTIME for older libc header sets.
const CLONE_NEWCGROUP: c_ulong = 0x02000000;
const CLONE_NEWIPC: c_ulong = 0x08000000;
const CLONE_NEWNET: c_ulong = 0x40000000;
const CLONE_NEWNS: c_ulong = 0x00020000;
const CLONE_NEWPID: c_ulong = 0x20000000;
const CLONE_NEWUSER: c_ulong = 0x10000000;
const CLONE_NEWUTS: c_ulong = 0x04000000;
const CLONE_NEWTIME: c_ulong = 0x00000080;

const NAMESPACE_TYPE_MAX: usize = 8;
const NAMESPACE_TYPE_INVALID: i32 = Errno::EINVAL.to_neg_errno();

// Mask of all valid namespace clone flags
const ALL_CLONE_NEW_FLAGS: c_ulong = CLONE_NEWCGROUP
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWUSER
    | CLONE_NEWUTS
    | CLONE_NEWTIME;

// clone_flag values indexed by NamespaceType enum (0-7)
static CLONE_FLAGS: [c_ulong; 8] = [
    CLONE_NEWCGROUP, // 0: NAMESPACE_CGROUP
    CLONE_NEWIPC,    // 1: NAMESPACE_IPC
    CLONE_NEWNET,    // 2: NAMESPACE_NET
    CLONE_NEWNS,     // 3: NAMESPACE_MOUNT
    CLONE_NEWPID,    // 4: NAMESPACE_PID
    CLONE_NEWUSER,   // 5: NAMESPACE_USER
    CLONE_NEWUTS,    // 6: NAMESPACE_UTS
    CLONE_NEWTIME,   // 7: NAMESPACE_TIME
];

// ── Public API ─────────────────────────────────────────────────────────────

/// Namespace type indices matching the C NamespaceType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NamespaceType {
    Cgroup = 0,
    Ipc = 1,
    Net = 2,
    Mount = 3,
    Pid = 4,
    User = 5,
    Uts = 6,
    Time = 7,
}

/// Look up NamespaceType from a clone flag value.
///
/// Port of `clone_flag_to_namespace_type()` from namespace-util.c.
/// Returns `Ok(NamespaceType)` when exactly one namespace-selection bit is
/// set, ignoring unrelated clone(2) flags; otherwise returns `Err(EINVAL)`.
pub fn clone_flag_to_namespace_type(clone_flag: c_ulong) -> Result<NamespaceType, Errno> {
    for i in 0..NAMESPACE_TYPE_MAX {
        // Match the C implementation exactly: only namespace-selection bits
        // participate in the comparison. Other clone(2) flags are ignored.
        if (CLONE_FLAGS[i] ^ clone_flag) & ALL_CLONE_NEW_FLAGS == 0 {
            return Ok(match i {
                0 => NamespaceType::Cgroup,
                1 => NamespaceType::Ipc,
                2 => NamespaceType::Net,
                3 => NamespaceType::Mount,
                4 => NamespaceType::Pid,
                5 => NamespaceType::User,
                6 => NamespaceType::Uts,
                7 => NamespaceType::Time,
                _ => unreachable!(),
            });
        }
    }
    Err(Errno::EINVAL)
}

/// Check that a userns UID/GID shift range is valid: at least one UID
/// and the end doesn't overflow uid_t.
///
/// Port of `userns_shift_range_valid()` from namespace-util.h.
pub fn userns_shift_range_valid(shift: uid_t, range: uid_t) -> bool {
    if range == 0 {
        return false;
    }
    if shift > uid_t::MAX - range {
        return false;
    }
    true
}

/// C ABI facade for `clone_flag_to_namespace_type()`.
///
/// `unsigned long` is represented by `c_ulong`, rather than assuming the
/// LP64 width used by the supported Linux builds.
#[unsafe(no_mangle)]
pub extern "C" fn rs_clone_flag_to_namespace_type(clone_flag: c_ulong) -> c_int {
    clone_flag_to_namespace_type(clone_flag)
        .map(|namespace_type| namespace_type as c_int)
        .unwrap_or(NAMESPACE_TYPE_INVALID)
}

/// C ABI facade for the inline `userns_shift_range_valid()` predicate.
#[unsafe(no_mangle)]
pub extern "C" fn rs_userns_shift_range_valid(shift: uid_t, range: uid_t) -> bool {
    userns_shift_range_valid(shift, range)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── clone_flag_to_namespace_type tests ───────────────────────────────

    #[test]
    fn test_clone_flag_cgroup() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWCGROUP),
            Ok(NamespaceType::Cgroup)
        );
    }

    #[test]
    fn test_clone_flag_ipc() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWIPC),
            Ok(NamespaceType::Ipc)
        );
    }

    #[test]
    fn test_clone_flag_net() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWNET),
            Ok(NamespaceType::Net)
        );
    }

    #[test]
    fn test_clone_flag_mount() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWNS),
            Ok(NamespaceType::Mount)
        );
    }

    #[test]
    fn test_clone_flag_pid() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWPID),
            Ok(NamespaceType::Pid)
        );
    }

    #[test]
    fn test_clone_flag_user() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWUSER),
            Ok(NamespaceType::User)
        );
    }

    #[test]
    fn test_clone_flag_uts() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWUTS),
            Ok(NamespaceType::Uts)
        );
    }

    #[test]
    fn test_clone_flag_time() {
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWTIME),
            Ok(NamespaceType::Time)
        );
    }

    #[test]
    fn test_clone_flag_zero_is_invalid() {
        assert_eq!(clone_flag_to_namespace_type(0), Err(Errno::EINVAL));
    }

    #[test]
    fn test_clone_flag_random_is_invalid() {
        assert_eq!(clone_flag_to_namespace_type(0xDEADBEEF), Err(Errno::EINVAL));
    }

    #[test]
    fn test_clone_flag_all_ones_is_invalid() {
        assert_eq!(clone_flag_to_namespace_type(u64::MAX), Err(Errno::EINVAL));
    }

    #[test]
    fn test_clone_flag_combined_flags_invalid() {
        // OR-ing two flags together is not a single namespace type
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWPID | CLONE_NEWNS),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn test_clone_flag_with_non_namespace_bits() {
        // C deliberately ignores clone bits that do not select a namespace.
        assert_eq!(
            clone_flag_to_namespace_type(CLONE_NEWNET | 0x01),
            Ok(NamespaceType::Net)
        );
    }

    #[test]
    fn test_namespace_type_values() {
        assert_eq!(NamespaceType::Cgroup as i32, 0);
        assert_eq!(NamespaceType::Ipc as i32, 1);
        assert_eq!(NamespaceType::Net as i32, 2);
        assert_eq!(NamespaceType::Mount as i32, 3);
        assert_eq!(NamespaceType::Pid as i32, 4);
        assert_eq!(NamespaceType::User as i32, 5);
        assert_eq!(NamespaceType::Uts as i32, 6);
        assert_eq!(NamespaceType::Time as i32, 7);
    }

    // ── userns_shift_range_valid tests ───────────────────────────────────

    #[test]
    fn test_userns_range_valid_basic() {
        assert!(userns_shift_range_valid(0, 1));
    }

    #[test]
    fn test_userns_range_valid_large() {
        assert!(userns_shift_range_valid(0, 65536));
    }

    #[test]
    fn test_userns_range_valid_max_range() {
        assert!(userns_shift_range_valid(0, u32::MAX));
    }

    #[test]
    fn test_userns_range_zero_range_invalid() {
        assert!(!userns_shift_range_valid(0, 0));
    }

    #[test]
    fn test_userns_range_valid_zero_shift() {
        assert!(userns_shift_range_valid(0, 100));
    }

    #[test]
    fn test_userns_range_overflow() {
        assert!(!userns_shift_range_valid(u32::MAX, 1));
    }

    #[test]
    fn test_userns_range_near_overflow() {
        assert!(!userns_shift_range_valid(u32::MAX - 1, 2));
    }

    #[test]
    fn test_userns_range_valid_edge() {
        assert!(userns_shift_range_valid(u32::MAX - 1, 1));
    }

    #[test]
    fn test_userns_range_high_shift_small_range() {
        assert!(userns_shift_range_valid(1000000, 100));
    }

    #[test]
    fn test_userns_range_both_max() {
        assert!(!userns_shift_range_valid(u32::MAX, u32::MAX));
    }

    #[test]
    fn test_userns_range_one_one() {
        assert!(userns_shift_range_valid(1, 1));
    }

    #[test]
    fn test_userns_range_exact_boundary() {
        // shift + range = u32::MAX, should be valid
        assert!(userns_shift_range_valid(100, u32::MAX - 100));
    }
}
