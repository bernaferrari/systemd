// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.capability-util; authority=src/basic/capability-util.c,src/basic/capability-util.h
//
// Pure capability utility functions — no I/O, no syscalls.

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value for unset capability masks.
/// Mirrors C `CAP_MASK_UNSET` (UINT64_MAX).
pub const CAP_MASK_UNSET: u64 = u64::MAX;

/// All possible capability bits on (63 bits, since bit 63 is reserved for
/// the UNSET marker). Mirrors C `CAP_MASK_ALL`.
pub const CAP_MASK_ALL: u64 = 0x7fffffffffffffff;

/// The largest capability we can deal with (63 unavailable due to UNSET
/// marker). Mirrors C `CAP_LIMIT`.
pub const CAP_LIMIT: i32 = 62;

// ── Structs ───────────────────────────────────────────────────────────────

/// Capability quintet — stores all five types of capabilities in one go.
/// Mirrors C `CapabilityQuintet` from capability-util.h.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityQuintet {
    pub effective: u64,
    pub bounding: u64,
    pub inheritable: u64,
    pub permitted: u64,
    pub ambient: u64,
}

impl CapabilityQuintet {
    /// Returns the null/unset quintet where all fields are `CAP_MASK_UNSET`.
    /// Mirrors C `CAPABILITY_QUINTET_NULL`.
    pub const fn null() -> Self {
        Self {
            effective: CAP_MASK_UNSET,
            bounding: CAP_MASK_UNSET,
            inheritable: CAP_MASK_UNSET,
            permitted: CAP_MASK_UNSET,
            ambient: CAP_MASK_UNSET,
        }
    }

    /// Returns a quintet with all five fields set to zero (no capabilities).
    pub const fn empty() -> Self {
        Self {
            effective: 0,
            bounding: 0,
            inheritable: 0,
            permitted: 0,
            ambient: 0,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors for capability operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// A capability mask is not set (CAP_MASK_UNSET).
    Unset,
    /// A capability number is out of the valid range.
    OutOfRange,
    /// Invalid argument.
    InvalidArgument,
}

/// Result type for capability operations.
pub type CapabilityResult<T> = Result<T, CapabilityError>;

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a capability mask value is set (not `CAP_MASK_UNSET`).
/// Port of C `capability_is_set()`.
pub fn capability_is_set(v: u64) -> bool {
    v != CAP_MASK_UNSET
}

/// Check if any of the five capability fields is set.
/// Port of C `capability_quintet_is_set()`.
pub fn capability_quintet_is_set(q: &CapabilityQuintet) -> bool {
    capability_is_set(q.effective)
        || capability_is_set(q.bounding)
        || capability_is_set(q.inheritable)
        || capability_is_set(q.permitted)
        || capability_is_set(q.ambient)
}

/// Check if ALL five capability fields are set.
/// Port of C `capability_quintet_is_fully_set()`.
pub fn capability_quintet_is_fully_set(q: &CapabilityQuintet) -> bool {
    capability_is_set(q.effective)
        && capability_is_set(q.bounding)
        && capability_is_set(q.inheritable)
        && capability_is_set(q.permitted)
        && capability_is_set(q.ambient)
}

/// Check if two quintets have identical capability fields.
/// Port of C `capability_quintet_equal()`.
pub fn capability_quintet_equal(a: &CapabilityQuintet, b: &CapabilityQuintet) -> bool {
    a.effective == b.effective
        && a.bounding == b.bounding
        && a.inheritable == b.inheritable
        && a.permitted == b.permitted
        && a.ambient == b.ambient
}

// ── C ABI facades ─────────────────────────────────────────────────────────

/// C ABI mirror of the inline `capability_is_set()` helper.
#[unsafe(no_mangle)]
pub extern "C" fn rs_capability_is_set(v: u64) -> bool {
    capability_is_set(v)
}

/// C ABI mirror of `capability_quintet_is_set()`.
///
/// # Safety
///
/// If non-null, `q` must point to one readable, properly aligned C
/// `CapabilityQuintet`. `CapabilityQuintet` has `repr(C)` and is the exact
/// five-`uint64_t` layout declared by `src/basic/capability-util.h`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_capability_quintet_is_set(q: *const CapabilityQuintet) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe_ffi!(q.as_ref()).is_some_and(capability_quintet_is_set)
}

/// C ABI mirror of `capability_quintet_is_fully_set()`.
///
/// # Safety
///
/// If non-null, `q` must point to one readable, properly aligned C
/// `CapabilityQuintet`. `CapabilityQuintet` has `repr(C)` and is the exact
/// five-`uint64_t` layout declared by `src/basic/capability-util.h`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_capability_quintet_is_fully_set(q: *const CapabilityQuintet) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe_ffi!(q.as_ref()).is_some_and(capability_quintet_is_fully_set)
}

/// C ABI mirror of `capability_quintet_equal()`.
///
/// # Safety
///
/// Each non-null pointer must point to one readable, properly aligned C
/// `CapabilityQuintet`. `CapabilityQuintet` has `repr(C)` and is the exact
/// five-`uint64_t` layout declared by `src/basic/capability-util.h`. Two null
/// pointers compare equal; one null pointer compares unequal to a non-null
/// pointer, matching the explicit shadow-test boundary policy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_capability_quintet_equal(
    a: *const CapabilityQuintet,
    b: *const CapabilityQuintet,
) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    match (unsafe_ffi!(a.as_ref()), unsafe_ffi!(b.as_ref())) {
        (Some(a), Some(b)) => capability_quintet_equal(a, b),
        (None, None) => true,
        _ => false,
    }
}

/// Validate a capability number is within bounds [0, CAP_LIMIT].
/// Returns Ok(cap) if valid, Err otherwise.
pub fn capability_validate(cap: i32) -> CapabilityResult<u32> {
    if cap < 0 || cap > CAP_LIMIT {
        return Err(CapabilityError::OutOfRange);
    }
    Ok(cap as u32)
}

/// Build a capability mask from a single capability number.
/// Returns the mask with exactly that bit set.
pub fn capability_to_mask(cap: i32) -> CapabilityResult<u64> {
    let c = capability_validate(cap)?;
    Ok(1u64 << c)
}

/// Check if a specific capability bit is set in a mask.
pub fn capability_mask_has(mask: u64, cap: i32) -> CapabilityResult<bool> {
    let bit = capability_to_mask(cap)?;
    Ok(mask & bit != 0)
}

/// Mangle a capability quintet: for each field that is set (not CAP_MASK_UNSET),
/// mask off bits that don't fit in CAP_LIMIT bits (bit 63 is the UNSET sentinel).
///
/// This is a pure-data version of C `capability_quintet_mangle()` which additionally
/// takes the bounding set into account via syscalls. This Rust version only applies
/// the mask constraint.
///
/// Returns true if the quintet was modified.
pub fn capability_quintet_apply_limit(q: &mut CapabilityQuintet) -> bool {
    let mut changed = false;
    let fields = [
        &mut q.effective,
        &mut q.bounding,
        &mut q.inheritable,
        &mut q.permitted,
        &mut q.ambient,
    ];
    for field in fields {
        if capability_is_set(*field) && (*field & !CAP_MASK_ALL) != 0 {
            *field &= CAP_MASK_ALL;
            changed = true;
        }
    }
    changed
}

/// Merge two quintets: for each field, if `b`'s field is set, use it; otherwise
/// keep `a`'s field. This is useful for applying overrides.
pub fn capability_quintet_merge(a: &CapabilityQuintet, b: &CapabilityQuintet) -> CapabilityQuintet {
    CapabilityQuintet {
        effective: if capability_is_set(b.effective) {
            b.effective
        } else {
            a.effective
        },
        bounding: if capability_is_set(b.bounding) {
            b.bounding
        } else {
            a.bounding
        },
        inheritable: if capability_is_set(b.inheritable) {
            b.inheritable
        } else {
            a.inheritable
        },
        permitted: if capability_is_set(b.permitted) {
            b.permitted
        } else {
            a.permitted
        },
        ambient: if capability_is_set(b.ambient) {
            b.ambient
        } else {
            a.ambient
        },
    }
}

/// Compute the intersection of two quintets (bitwise AND of each set field).
/// Fields that are CAP_MASK_UNSET in either are CAP_MASK_UNSET in the result.
pub fn capability_quintet_intersect(
    a: &CapabilityQuintet,
    b: &CapabilityQuintet,
) -> CapabilityQuintet {
    CapabilityQuintet {
        effective: if capability_is_set(a.effective) && capability_is_set(b.effective) {
            a.effective & b.effective
        } else {
            CAP_MASK_UNSET
        },
        bounding: if capability_is_set(a.bounding) && capability_is_set(b.bounding) {
            a.bounding & b.bounding
        } else {
            CAP_MASK_UNSET
        },
        inheritable: if capability_is_set(a.inheritable) && capability_is_set(b.inheritable) {
            a.inheritable & b.inheritable
        } else {
            CAP_MASK_UNSET
        },
        permitted: if capability_is_set(a.permitted) && capability_is_set(b.permitted) {
            a.permitted & b.permitted
        } else {
            CAP_MASK_UNSET
        },
        ambient: if capability_is_set(a.ambient) && capability_is_set(b.ambient) {
            a.ambient & b.ambient
        } else {
            CAP_MASK_UNSET
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_is_set_unset() {
        assert!(!capability_is_set(CAP_MASK_UNSET));
    }

    #[test]
    fn test_capability_is_set_zero() {
        assert!(capability_is_set(0));
    }

    #[test]
    fn test_capability_is_set_one() {
        assert!(capability_is_set(1));
    }

    #[test]
    fn test_capability_is_set_all_bits_minus_one() {
        assert!(capability_is_set(u64::MAX - 1));
    }

    #[test]
    fn test_capability_is_set_various() {
        assert!(capability_is_set(0x1234));
        assert!(capability_is_set(0xABCD));
        assert!(!capability_is_set(CAP_MASK_UNSET));
    }

    #[test]
    fn test_quintet_null() {
        let q = CapabilityQuintet::null();
        assert_eq!(q.effective, CAP_MASK_UNSET);
        assert_eq!(q.bounding, CAP_MASK_UNSET);
        assert_eq!(q.inheritable, CAP_MASK_UNSET);
        assert_eq!(q.permitted, CAP_MASK_UNSET);
        assert_eq!(q.ambient, CAP_MASK_UNSET);
    }

    #[test]
    fn test_quintet_empty() {
        let q = CapabilityQuintet::empty();
        assert_eq!(q.effective, 0);
        assert_eq!(q.bounding, 0);
        assert_eq!(q.inheritable, 0);
        assert_eq!(q.permitted, 0);
        assert_eq!(q.ambient, 0);
    }

    #[test]
    fn test_quintet_is_set_all_unset() {
        let q = CapabilityQuintet::null();
        assert!(!capability_quintet_is_set(&q));
    }

    #[test]
    fn test_quintet_is_set_one_field_set() {
        let q = CapabilityQuintet {
            effective: 0,
            ..CapabilityQuintet::null()
        };
        assert!(capability_quintet_is_set(&q));
    }

    #[test]
    fn test_quintet_is_set_all_fields_set() {
        let q = CapabilityQuintet {
            effective: 0,
            bounding: 0,
            inheritable: 0,
            permitted: 0,
            ambient: 0,
        };
        assert!(capability_quintet_is_set(&q));
    }

    #[test]
    fn test_quintet_is_set_only_ambient() {
        let q = CapabilityQuintet {
            ambient: 42,
            ..CapabilityQuintet::null()
        };
        assert!(capability_quintet_is_set(&q));
    }

    #[test]
    fn test_quintet_is_fully_set_all_unset() {
        let q = CapabilityQuintet::null();
        assert!(!capability_quintet_is_fully_set(&q));
    }

    #[test]
    fn test_quintet_is_fully_set_one_unset() {
        let q = CapabilityQuintet {
            effective: 0,
            bounding: 0,
            inheritable: 0,
            permitted: 0,
            ambient: CAP_MASK_UNSET,
        };
        assert!(!capability_quintet_is_fully_set(&q));
    }

    #[test]
    fn test_quintet_is_fully_set_all_set() {
        let q = CapabilityQuintet {
            effective: 0,
            bounding: 0,
            inheritable: 0,
            permitted: 0,
            ambient: 0,
        };
        assert!(capability_quintet_is_fully_set(&q));
    }

    #[test]
    fn test_quintet_is_fully_set_various_masks() {
        let q = CapabilityQuintet {
            effective: 0xFF,
            bounding: 0x01,
            inheritable: 0x02,
            permitted: 0x04,
            ambient: 0x08,
        };
        assert!(capability_quintet_is_fully_set(&q));
    }

    #[test]
    fn test_quintet_equal_identical() {
        let q = CapabilityQuintet {
            effective: 0x1234,
            bounding: 0x5678,
            inheritable: 0xABCD,
            permitted: 0xEF01,
            ambient: 0x9999,
        };
        assert!(capability_quintet_equal(&q, &q));
    }

    #[test]
    fn test_quintet_equal_different() {
        let a = CapabilityQuintet {
            effective: 0x1234,
            bounding: 0x5678,
            inheritable: 0xABCD,
            permitted: 0xEF01,
            ambient: 0x9999,
        };
        let b = CapabilityQuintet {
            effective: 0x1234,
            bounding: 0x5678,
            inheritable: 0xABCD,
            permitted: 0xEF01,
            ambient: 0x8888,
        };
        assert!(!capability_quintet_equal(&a, &b));
    }

    #[test]
    fn test_quintet_equal_both_unset() {
        let a = CapabilityQuintet::null();
        let b = CapabilityQuintet::null();
        assert!(capability_quintet_equal(&a, &b));
    }

    #[test]
    fn test_capability_validate_valid() {
        assert_eq!(capability_validate(0), Ok(0));
        assert_eq!(capability_validate(1), Ok(1));
        assert_eq!(capability_validate(40), Ok(40));
        assert_eq!(capability_validate(62), Ok(62));
    }

    #[test]
    fn test_capability_validate_invalid() {
        assert_eq!(capability_validate(-1), Err(CapabilityError::OutOfRange));
        assert_eq!(capability_validate(63), Err(CapabilityError::OutOfRange));
        assert_eq!(capability_validate(100), Err(CapabilityError::OutOfRange));
    }

    #[test]
    fn test_capability_to_mask() {
        assert_eq!(capability_to_mask(0), Ok(1));
        assert_eq!(capability_to_mask(1), Ok(2));
        assert_eq!(capability_to_mask(62), Ok(1u64 << 62));
        assert_eq!(capability_to_mask(63), Err(CapabilityError::OutOfRange));
    }

    #[test]
    fn test_capability_mask_has() {
        let mask: u64 = 0b101; // caps 0 and 2
        assert_eq!(capability_mask_has(mask, 0), Ok(true));
        assert_eq!(capability_mask_has(mask, 1), Ok(false));
        assert_eq!(capability_mask_has(mask, 2), Ok(true));
        assert_eq!(
            capability_mask_has(mask, 63),
            Err(CapabilityError::OutOfRange)
        );
    }

    #[test]
    fn test_capability_quintet_apply_limit_no_change() {
        let mut q = CapabilityQuintet {
            effective: 0xFF,
            bounding: 0x01,
            inheritable: 0x02,
            permitted: 0x04,
            ambient: 0x08,
        };
        assert!(!capability_quintet_apply_limit(&mut q));
        assert_eq!(q.effective, 0xFF);
    }

    #[test]
    fn test_capability_quintet_apply_limit_with_bit63() {
        let mut q = CapabilityQuintet {
            effective: 1u64 << 63,
            ..CapabilityQuintet::empty()
        };
        assert!(capability_quintet_apply_limit(&mut q));
        assert_eq!(q.effective, 0); // bit 63 masked off
    }

    #[test]
    fn test_capability_quintet_apply_limit_unset_fields_unchanged() {
        let mut q = CapabilityQuintet::null();
        assert!(!capability_quintet_apply_limit(&mut q));
        assert_eq!(q.effective, CAP_MASK_UNSET);
    }

    #[test]
    fn test_capability_quintet_merge() {
        let a = CapabilityQuintet {
            effective: 0xFF,
            bounding: 0x01,
            inheritable: CAP_MASK_UNSET,
            permitted: 0x04,
            ambient: CAP_MASK_UNSET,
        };
        let b = CapabilityQuintet {
            effective: CAP_MASK_UNSET,
            bounding: CAP_MASK_UNSET,
            inheritable: 0x02,
            permitted: CAP_MASK_UNSET,
            ambient: 0x08,
        };
        let result = capability_quintet_merge(&a, &b);
        assert_eq!(result.effective, 0xFF); // kept from a (b unset)
        assert_eq!(result.bounding, 0x01); // kept from a (b unset)
        assert_eq!(result.inheritable, 0x02); // from b
        assert_eq!(result.permitted, 0x04); // kept from a (b unset)
        assert_eq!(result.ambient, 0x08); // from b
    }

    #[test]
    fn test_capability_quintet_intersect() {
        let a = CapabilityQuintet {
            effective: 0xFF,
            bounding: 0x0F,
            inheritable: CAP_MASK_UNSET,
            permitted: 0x04,
            ambient: 0x08,
        };
        let b = CapabilityQuintet {
            effective: 0x0F,
            bounding: 0x03,
            inheritable: 0x02,
            permitted: CAP_MASK_UNSET,
            ambient: 0xFF,
        };
        let result = capability_quintet_intersect(&a, &b);
        assert_eq!(result.effective, 0xFF & 0x0F); // 0x0F
        assert_eq!(result.bounding, 0x0F & 0x03); // 0x03
        assert_eq!(result.inheritable, CAP_MASK_UNSET); // a unset
        assert_eq!(result.permitted, CAP_MASK_UNSET); // b unset
        assert_eq!(result.ambient, 0x08 & 0xFF); // 0x08
    }

    #[test]
    fn test_constants() {
        assert_eq!(CAP_MASK_UNSET, u64::MAX);
        assert_eq!(CAP_MASK_ALL, 0x7fffffffffffffff);
        assert_eq!(CAP_LIMIT, 62);
    }
}
