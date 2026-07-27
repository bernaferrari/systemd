// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/process-util.c (string table subset)
//
// Process utility string tables (sigchld_code, sched_policy)
// and process parameter validators.

/* removed: use i32 */

use crate::ffi::Errno;

// ── sigchld_code table ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigchldCode {
    Exited = 1,
    Killed = 2,
    Dumped = 3,
    Trapped = 4,
    Stopped = 5,
    Continued = 6,
}

static SIGCHLD_CODE_TABLE: &[(i32, &[u8])] = &[
    (1, b"exited"),
    (2, b"killed"),
    (3, b"dumped"),
    (4, b"trapped"),
    (5, b"stopped"),
    (6, b"continued"),
];

pub fn sigchld_code_to_string(code: i32) -> Option<&'static str> {
    for &(idx, name) in SIGCHLD_CODE_TABLE {
        if idx == code {
            return Some(std::str::from_utf8(name).unwrap_or(""));
        }
    }
    None
}

pub fn sigchld_code_from_string(s: &str) -> Result<i32, i32> {
    for &(idx, name) in SIGCHLD_CODE_TABLE {
        if s.as_bytes() == name {
            return Ok(idx);
        }
    }
    Err(Errno::EINVAL.to_neg_errno())
}

// ── sched_policy table ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchedPolicy {
    Other = 0,
    Fifo = 1,
    Rr = 2,
    Batch = 3,
    Idle = 5,
    Ext = 7,
}

static SCHED_POLICY_TABLE: &[(i32, &[u8])] = &[
    (0, b"other"),
    (1, b"fifo"),
    (2, b"rr"),
    (3, b"batch"),
    (5, b"idle"),
    (7, b"ext"),
];

pub fn sched_policy_to_string(policy: i32) -> Option<&'static str> {
    for &(idx, name) in SCHED_POLICY_TABLE {
        if idx == policy {
            return Some(std::str::from_utf8(name).unwrap_or(""));
        }
    }
    None
}

pub fn sched_policy_from_string(s: &str) -> Result<i32, i32> {
    for &(idx, name) in SCHED_POLICY_TABLE {
        if s.as_bytes() == name {
            return Ok(idx);
        }
    }
    match s.parse::<i32>() {
        Ok(val) => Ok(val),
        Err(_) => Err(Errno::EINVAL.to_neg_errno()),
    }
}

// ── Validators ─────────────────────────────────────────────────────────────

const PRIO_MIN_VAL: i32 = -20;
const PRIO_MAX_VAL: i32 = 20;

pub fn nice_is_valid(n: i32) -> bool {
    n >= PRIO_MIN_VAL && n < PRIO_MAX_VAL
}

const SCHED_POLICY_VALUES: &[i32] = &[0, 1, 2, 3, 5, 7];

pub fn sched_policy_is_valid(policy: i32) -> bool {
    SCHED_POLICY_VALUES.contains(&policy)
}

const OOM_SCORE_ADJ_MIN: i32 = -1000;
const OOM_SCORE_ADJ_MAX: i32 = 1000;

pub fn oom_score_adjust_is_valid(oa: i32) -> bool {
    oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigchld_code_to_string_all() {
        assert_eq!(sigchld_code_to_string(1), Some("exited"));
        assert_eq!(sigchld_code_to_string(2), Some("killed"));
        assert_eq!(sigchld_code_to_string(3), Some("dumped"));
        assert_eq!(sigchld_code_to_string(4), Some("trapped"));
        assert_eq!(sigchld_code_to_string(5), Some("stopped"));
        assert_eq!(sigchld_code_to_string(6), Some("continued"));
    }

    #[test]
    fn test_sigchld_code_to_string_invalid() {
        assert!(sigchld_code_to_string(0).is_none());
        assert!(sigchld_code_to_string(7).is_none());
        assert!(sigchld_code_to_string(-1).is_none());
        assert!(sigchld_code_to_string(100).is_none());
    }

    #[test]
    fn test_sigchld_code_from_string_all() {
        assert_eq!(sigchld_code_from_string("exited"), Ok(1));
        assert_eq!(sigchld_code_from_string("killed"), Ok(2));
        assert_eq!(sigchld_code_from_string("dumped"), Ok(3));
        assert_eq!(sigchld_code_from_string("trapped"), Ok(4));
        assert_eq!(sigchld_code_from_string("stopped"), Ok(5));
        assert_eq!(sigchld_code_from_string("continued"), Ok(6));
    }

    #[test]
    fn test_sigchld_code_from_string_invalid() {
        assert_eq!(
            sigchld_code_from_string("unknown"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sigchld_code_from_string(""),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_sigchld_code_roundtrip() {
        for code in 1..=6 {
            let s = sigchld_code_to_string(code).unwrap();
            assert_eq!(sigchld_code_from_string(s), Ok(code));
        }
    }

    #[test]
    fn test_sched_policy_to_string_all() {
        assert_eq!(sched_policy_to_string(0), Some("other"));
        assert_eq!(sched_policy_to_string(1), Some("fifo"));
        assert_eq!(sched_policy_to_string(2), Some("rr"));
        assert_eq!(sched_policy_to_string(3), Some("batch"));
        assert_eq!(sched_policy_to_string(5), Some("idle"));
        assert_eq!(sched_policy_to_string(7), Some("ext"));
    }

    #[test]
    fn test_sched_policy_to_string_invalid() {
        assert!(sched_policy_to_string(4).is_none());
        assert!(sched_policy_to_string(6).is_none());
        assert!(sched_policy_to_string(-1).is_none());
    }

    #[test]
    fn test_sched_policy_from_string_all() {
        assert_eq!(sched_policy_from_string("other"), Ok(0));
        assert_eq!(sched_policy_from_string("fifo"), Ok(1));
        assert_eq!(sched_policy_from_string("rr"), Ok(2));
        assert_eq!(sched_policy_from_string("batch"), Ok(3));
        assert_eq!(sched_policy_from_string("idle"), Ok(5));
        assert_eq!(sched_policy_from_string("ext"), Ok(7));
    }

    #[test]
    fn test_sched_policy_from_string_numeric() {
        assert_eq!(sched_policy_from_string("4"), Ok(4));
        assert_eq!(sched_policy_from_string("6"), Ok(6));
        assert_eq!(sched_policy_from_string("0"), Ok(0));
        assert_eq!(sched_policy_from_string("-1"), Ok(-1));
    }

    #[test]
    fn test_sched_policy_from_string_invalid() {
        assert_eq!(
            sched_policy_from_string("unknown"),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sched_policy_from_string(""),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            sched_policy_from_string("abc"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn test_sched_policy_roundtrip() {
        for &policy in &[0, 1, 2, 3, 5, 7] {
            let s = sched_policy_to_string(policy).unwrap();
            assert_eq!(sched_policy_from_string(s), Ok(policy));
        }
    }

    #[test]
    fn test_nice_is_valid() {
        assert!(nice_is_valid(-20));
        assert!(nice_is_valid(0));
        assert!(nice_is_valid(19));
        assert!(!nice_is_valid(20));
        assert!(!nice_is_valid(-21));
        assert!(!nice_is_valid(100));
    }

    #[test]
    fn test_sched_policy_is_valid() {
        assert!(sched_policy_is_valid(0));
        assert!(sched_policy_is_valid(1));
        assert!(sched_policy_is_valid(2));
        assert!(sched_policy_is_valid(3));
        assert!(sched_policy_is_valid(5));
        assert!(sched_policy_is_valid(7));
        assert!(!sched_policy_is_valid(4));
        assert!(!sched_policy_is_valid(6));
        assert!(!sched_policy_is_valid(-1));
    }

    #[test]
    fn test_oom_score_adjust_is_valid() {
        assert!(oom_score_adjust_is_valid(-1000));
        assert!(oom_score_adjust_is_valid(0));
        assert!(oom_score_adjust_is_valid(1000));
        assert!(!oom_score_adjust_is_valid(-1001));
        assert!(!oom_score_adjust_is_valid(1001));
    }
}
