// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.ioprio-util; authority=src/shared/ioprio-util.h,src/include/uapi/linux/ioprio.h
//
// I/O priority bit manipulation helpers.
// Constants from <linux/ioprio.h>.

// ── Constants from linux/ioprio.h ─────────────────────────────────────────

const IOPRIO_CLASS_SHIFT: i32 = 13;
const IOPRIO_NR_CLASSES: i32 = 8;
const IOPRIO_CLASS_MASK: i32 = IOPRIO_NR_CLASSES - 1;
const IOPRIO_PRIO_MASK: i32 = (1 << IOPRIO_CLASS_SHIFT) - 1;

const IOPRIO_LEVEL_NR_BITS: i32 = 3;
const IOPRIO_NR_LEVELS: i32 = 1 << IOPRIO_LEVEL_NR_BITS;
const IOPRIO_LEVEL_MASK: i32 = IOPRIO_NR_LEVELS - 1;

const IOPRIO_HINT_SHIFT: i32 = IOPRIO_LEVEL_NR_BITS;
const IOPRIO_HINT_NR_BITS: i32 = 10;
const IOPRIO_NR_HINTS: i32 = 1 << IOPRIO_HINT_NR_BITS;
const IOPRIO_HINT_MASK: i32 = IOPRIO_NR_HINTS - 1;

const IOPRIO_CLASS_NONE: i32 = 0;
const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;
const IOPRIO_CLASS_INVALID: i32 = 7;

const IOPRIO_DEFAULT_CLASS_AND_PRIO: i32 = IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT | 4;

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful port of C ioprio_prio_class() / IOPRIO_PRIO_CLASS().
pub fn ioprio_prio_class(value: i32) -> i32 {
    (value >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK
}

/// Faithful port of C ioprio_prio_data() / IOPRIO_PRIO_DATA().
pub fn ioprio_prio_data(value: i32) -> i32 {
    value & IOPRIO_PRIO_MASK
}

/// Faithful port of C ioprio_prio_value() / IOPRIO_PRIO_VALUE_HINT().
/// The packed `data` input is first split through the kernel's masking macros;
/// only the class can therefore be out of range at this layer.
pub fn ioprio_prio_value(prioclass: i32, data: i32) -> i32 {
    let priolevel = data & IOPRIO_LEVEL_MASK;
    let priohint = (data >> IOPRIO_HINT_SHIFT) & IOPRIO_HINT_MASK;

    if prioclass < 0 || prioclass >= IOPRIO_NR_CLASSES {
        return IOPRIO_CLASS_INVALID << IOPRIO_CLASS_SHIFT;
    }
    (prioclass << IOPRIO_CLASS_SHIFT) | (priohint << IOPRIO_HINT_SHIFT) | priolevel
}

/// Faithful port of C ioprio_class_is_valid().
pub fn ioprio_class_is_valid(i: i32) -> bool {
    matches!(
        i,
        IOPRIO_CLASS_NONE | IOPRIO_CLASS_RT | IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE
    )
}

/// Faithful port of C ioprio_priority_is_valid().
pub fn ioprio_priority_is_valid(i: i32) -> bool {
    i >= 0 && i < IOPRIO_NR_LEVELS
}

/// Faithful port of C ioprio_normalize().
/// Converts IOPRIO_CLASS_NONE to what it actually means (BE with level 4).
pub fn ioprio_normalize(v: i32) -> i32 {
    if ioprio_prio_class(v) == IOPRIO_CLASS_NONE {
        IOPRIO_DEFAULT_CLASS_AND_PRIO
    } else {
        v
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_prio_class(value: libc::c_int) -> libc::c_int {
    ioprio_prio_class(value)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_prio_data(value: libc::c_int) -> libc::c_int {
    ioprio_prio_data(value)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_prio_value(prioclass: libc::c_int, data: libc::c_int) -> libc::c_int {
    ioprio_prio_value(prioclass, data)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_ioprio_normalize(value: libc::c_int) -> libc::c_int {
    ioprio_normalize(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioprio_prio_class_rt() {
        let val = IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT | 2;
        assert_eq!(ioprio_prio_class(val), IOPRIO_CLASS_RT);
    }

    #[test]
    fn test_ioprio_prio_class_idle() {
        let val = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
        assert_eq!(ioprio_prio_class(val), IOPRIO_CLASS_IDLE);
    }

    #[test]
    fn test_ioprio_prio_class_none() {
        assert_eq!(ioprio_prio_class(0), IOPRIO_CLASS_NONE);
    }

    #[test]
    fn test_ioprio_prio_class_negative() {
        assert_eq!(ioprio_prio_class(-1), 7);
    }

    #[test]
    fn test_ioprio_prio_data_basic() {
        let val = IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT | 4;
        assert_eq!(ioprio_prio_data(val), 4);
    }

    #[test]
    fn test_ioprio_prio_data_with_hint() {
        let val = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | (1 << IOPRIO_HINT_SHIFT) | 3;
        assert_eq!(ioprio_prio_data(val), (1 << IOPRIO_HINT_SHIFT) | 3);
    }

    #[test]
    fn test_ioprio_prio_data_zero() {
        assert_eq!(ioprio_prio_data(0), 0);
    }

    #[test]
    fn test_ioprio_prio_value_valid() {
        let val = ioprio_prio_value(IOPRIO_CLASS_BE, 4);
        assert_eq!(val, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT | 4);
    }

    #[test]
    fn test_ioprio_prio_value_with_hint() {
        let data = (1 << IOPRIO_HINT_SHIFT) | 2;
        let val = ioprio_prio_value(IOPRIO_CLASS_RT, data);
        assert_eq!(
            val,
            (IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT) | (1 << IOPRIO_HINT_SHIFT) | 2
        );
    }

    #[test]
    fn test_ioprio_prio_value_invalid_class() {
        let val = ioprio_prio_value(10, 0);
        assert_eq!(val, IOPRIO_CLASS_INVALID << IOPRIO_CLASS_SHIFT);
    }

    #[test]
    fn test_ioprio_prio_value_masks_high_data() {
        let val = ioprio_prio_value(IOPRIO_CLASS_BE, 10);
        assert_eq!(val, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT | 10);
    }

    #[test]
    fn test_ioprio_prio_value_negative_class() {
        let val = ioprio_prio_value(-1, 0);
        assert_eq!(val, IOPRIO_CLASS_INVALID << IOPRIO_CLASS_SHIFT);
    }

    #[test]
    fn test_ioprio_class_is_valid() {
        assert!(ioprio_class_is_valid(IOPRIO_CLASS_NONE));
        assert!(ioprio_class_is_valid(IOPRIO_CLASS_RT));
        assert!(ioprio_class_is_valid(IOPRIO_CLASS_BE));
        assert!(ioprio_class_is_valid(IOPRIO_CLASS_IDLE));
        assert!(!ioprio_class_is_valid(4));
        assert!(!ioprio_class_is_valid(-1));
        assert!(!ioprio_class_is_valid(IOPRIO_CLASS_INVALID));
    }

    #[test]
    fn test_ioprio_priority_is_valid() {
        assert!(ioprio_priority_is_valid(0));
        assert!(ioprio_priority_is_valid(4));
        assert!(ioprio_priority_is_valid(IOPRIO_NR_LEVELS - 1));
        assert!(!ioprio_priority_is_valid(-1));
        assert!(!ioprio_priority_is_valid(IOPRIO_NR_LEVELS));
    }

    #[test]
    fn test_ioprio_normalize_class_none() {
        assert_eq!(ioprio_normalize(0), IOPRIO_DEFAULT_CLASS_AND_PRIO);
    }

    #[test]
    fn test_ioprio_normalize_class_be() {
        let val = IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT | 4;
        assert_eq!(ioprio_normalize(val), val);
    }

    #[test]
    fn test_ioprio_normalize_class_rt() {
        let val = IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT | 1;
        assert_eq!(ioprio_normalize(val), val);
    }

    #[test]
    fn test_ioprio_normalize_class_idle() {
        let val = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
        assert_eq!(ioprio_normalize(val), val);
    }

    #[test]
    fn test_ioprio_prio_class_max_value() {
        assert_eq!(ioprio_prio_class(i32::MAX), IOPRIO_CLASS_MASK);
    }

    #[test]
    fn test_ioprio_prio_data_all_bits() {
        assert_eq!(ioprio_prio_data(i32::MAX), IOPRIO_PRIO_MASK);
    }

    #[test]
    fn test_ioprio_prio_value_max_hint() {
        let data = (1023 << IOPRIO_HINT_SHIFT) | 7;
        let val = ioprio_prio_value(IOPRIO_CLASS_BE, data);
        assert_eq!(
            val,
            (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | (1023 << IOPRIO_HINT_SHIFT) | 7
        );
    }

    #[test]
    fn test_ioprio_prio_value_invalid_hint() {
        let data = (2048 << IOPRIO_HINT_SHIFT) | 0;
        let val = ioprio_prio_value(IOPRIO_CLASS_BE, data);
        assert_eq!(val, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT);
    }

    #[test]
    fn test_ioprio_prio_value_masks_negative_data() {
        let val = ioprio_prio_value(IOPRIO_CLASS_BE, -1);
        assert_eq!(
            val,
            (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | IOPRIO_PRIO_MASK
        );
    }

    #[test]
    fn test_ioprio_normalize_default_matches_constant() {
        assert_eq!(
            ioprio_normalize(0),
            (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4
        );
    }
}
