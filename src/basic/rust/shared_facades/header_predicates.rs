// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/output-mode.h, src/shared/sleep-config.h, src/basic/user-util.h
//
// Inline validation predicates from shared/basic headers.
//
// Provides OUTPUT_MODE_IS_JSON, SLEEP_OPERATION_IS_HIBERNATION,
// and ERRNO_IS_NEG_BAD_ACCOUNT as safe Rust predicates plus C ABI facades.
//
// The C headers receive enum values as `int`, including values outside the
// declared enum domain. Keep the FFI entry points integer-based: constructing
// a Rust enum from such an input would be invalid, while the C inline helpers
// simply compare integer discriminants.

use libc::intmax_t;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Output mode for journal/process-tree display.
///
/// Faithful to `typedef enum OutputMode` in output-mode.h.
/// Discriminant values match the C enum ordering (0 through 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Short,
    ShortFull,
    ShortIso,
    ShortIsoPrecise,
    ShortPrecise,
    ShortMonotonic,
    ShortDelta,
    ShortUnix,
    Verbose,
    Export,
    Json,
    JsonPretty,
    JsonSse,
    JsonSeq,
    Cat,
    WithUnit,
}

/// Sleep operation types.
///
/// Faithful to `typedef enum SleepOperation` in sleep-config.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepOperation {
    Suspend,
    Hibernate,
    HybridSleep,
    SuspendThenHibernate,
}

// ── Validators ────────────────────────────────────────────────────────────

/// Check if output mode is a JSON variant.
///
/// Faithful to `static inline bool OUTPUT_MODE_IS_JSON(OutputMode m)` in output-mode.h:
/// `return IN_SET(m, OUTPUT_JSON, OUTPUT_JSON_PRETTY, OUTPUT_JSON_SSE, OUTPUT_JSON_SEQ);`
pub fn output_mode_is_json(m: OutputMode) -> bool {
    matches!(
        m,
        OutputMode::Json | OutputMode::JsonPretty | OutputMode::JsonSse | OutputMode::JsonSeq
    )
}

/// Check if a sleep operation is a hibernation variant.
///
/// Faithful to `static inline bool SLEEP_OPERATION_IS_HIBERNATION(SleepOperation operation)`
/// in sleep-config.h: `return IN_SET(operation, SLEEP_HIBERNATE, SLEEP_HYBRID_SLEEP);`
pub fn sleep_operation_is_hibernation(operation: SleepOperation) -> bool {
    matches!(
        operation,
        SleepOperation::Hibernate | SleepOperation::HybridSleep
    )
}

/// Check if a negative errno indicates a "bad account" error.
///
/// Faithful to `static inline bool ERRNO_IS_NEG_BAD_ACCOUNT(intmax_t r)` in user-util.h:
/// `return IN_SET(r, -ESRCH, -ENOEXEC);`
pub fn errno_is_neg_bad_account(r: intmax_t) -> bool {
    r == -(libc::ESRCH as intmax_t) || r == -(libc::ENOEXEC as intmax_t)
}

/// Exact raw-discriminant counterpart of `OUTPUT_MODE_IS_JSON`.
///
/// Unlike the typed helper, this accepts every value C may pass to the inline
/// macro, including `_OUTPUT_MODE_INVALID` and arbitrary out-of-range values.
pub const fn output_mode_is_json_raw(mode: i32) -> bool {
    matches!(mode, 10..=13)
}

/// Exact raw-discriminant counterpart of `SLEEP_OPERATION_IS_HIBERNATION`.
pub const fn sleep_operation_is_hibernation_raw(operation: i32) -> bool {
    matches!(operation, 1 | 2)
}

/// C ABI facade for `OUTPUT_MODE_IS_JSON(OutputMode)`.
///
/// The header type is deliberately `int`, matching the ABI of this C enum and
/// preventing invalid Rust enum construction at the FFI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_OUTPUT_MODE_IS_JSON(mode: i32) -> bool {
    output_mode_is_json_raw(mode)
}

/// C ABI facade for `SLEEP_OPERATION_IS_HIBERNATION(SleepOperation)`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_SLEEP_OPERATION_IS_HIBERNATION(operation: i32) -> bool {
    sleep_operation_is_hibernation_raw(operation)
}

/// C ABI facade for `ERRNO_IS_NEG_BAD_ACCOUNT(intmax_t)`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ERRNO_IS_NEG_BAD_ACCOUNT(r: intmax_t) -> bool {
    errno_is_neg_bad_account(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── output_mode_is_json tests ──────────────────────────────────────

    #[test]
    fn test_output_mode_is_json_all_json_variants() {
        assert!(output_mode_is_json(OutputMode::Json));
        assert!(output_mode_is_json(OutputMode::JsonPretty));
        assert!(output_mode_is_json(OutputMode::JsonSse));
        assert!(output_mode_is_json(OutputMode::JsonSeq));
    }

    #[test]
    fn test_output_mode_is_json_non_json() {
        assert!(!output_mode_is_json(OutputMode::Short));
        assert!(!output_mode_is_json(OutputMode::Verbose));
        assert!(!output_mode_is_json(OutputMode::Export));
        assert!(!output_mode_is_json(OutputMode::Cat));
        assert!(!output_mode_is_json(OutputMode::WithUnit));
    }

    #[test]
    fn test_output_mode_is_json_boundary_modes() {
        // Export (9) is right before Json (10)
        assert!(!output_mode_is_json(OutputMode::Export));
        // Cat (14) is right after JsonSeq (13)
        assert!(!output_mode_is_json(OutputMode::Cat));
    }

    #[test]
    fn test_output_mode_is_json_all_modes_covered() {
        let all_modes = [
            OutputMode::Short,
            OutputMode::ShortFull,
            OutputMode::ShortIso,
            OutputMode::ShortIsoPrecise,
            OutputMode::ShortPrecise,
            OutputMode::ShortMonotonic,
            OutputMode::ShortDelta,
            OutputMode::ShortUnix,
            OutputMode::Verbose,
            OutputMode::Export,
            OutputMode::Cat,
            OutputMode::WithUnit,
        ];
        for mode in &all_modes {
            assert!(!output_mode_is_json(*mode), "{:?} should not be JSON", mode);
        }
    }

    // ── sleep_operation_is_hibernation tests ───────────────────────────

    #[test]
    fn test_sleep_operation_is_hibernation_valid() {
        assert!(sleep_operation_is_hibernation(SleepOperation::Hibernate));
        assert!(sleep_operation_is_hibernation(SleepOperation::HybridSleep));
    }

    #[test]
    fn test_sleep_operation_is_hibernation_non_hibernation() {
        assert!(!sleep_operation_is_hibernation(SleepOperation::Suspend));
        assert!(!sleep_operation_is_hibernation(
            SleepOperation::SuspendThenHibernate
        ));
    }

    #[test]
    fn test_sleep_operation_is_hibernation_exhaustive() {
        let hibernation_ops = [SleepOperation::Hibernate, SleepOperation::HybridSleep];
        let non_hibernation_ops = [
            SleepOperation::Suspend,
            SleepOperation::SuspendThenHibernate,
        ];

        for op in &hibernation_ops {
            assert!(
                sleep_operation_is_hibernation(*op),
                "{:?} should be hibernation",
                op
            );
        }
        for op in &non_hibernation_ops {
            assert!(
                !sleep_operation_is_hibernation(*op),
                "{:?} should not be hibernation",
                op
            );
        }
    }

    // ── errno_is_neg_bad_account tests ─────────────────────────────────

    #[test]
    fn test_errno_is_neg_bad_account_valid() {
        assert!(errno_is_neg_bad_account(-(libc::ESRCH as intmax_t)));
        assert!(errno_is_neg_bad_account(-(libc::ENOEXEC as intmax_t)));
    }

    #[test]
    fn test_errno_is_neg_bad_account_invalid() {
        assert!(!errno_is_neg_bad_account(0));
        assert!(!errno_is_neg_bad_account(1));
        assert!(!errno_is_neg_bad_account(-1));
        assert!(!errno_is_neg_bad_account(-2));
        assert!(!errno_is_neg_bad_account(-4));
        assert!(!errno_is_neg_bad_account(-100));
    }

    #[test]
    fn test_errno_is_neg_bad_account_positive_values() {
        // Positive ESRCH/ENOEXEC values should not match
        assert!(!errno_is_neg_bad_account(libc::ESRCH as intmax_t));
        assert!(!errno_is_neg_bad_account(libc::ENOEXEC as intmax_t));
    }

    #[test]
    fn test_errno_is_neg_bad_account_edge_values() {
        assert!(!errno_is_neg_bad_account(i64::MIN));
        assert!(!errno_is_neg_bad_account(i64::MAX));
        assert!(!errno_is_neg_bad_account(-1000));
    }
}
