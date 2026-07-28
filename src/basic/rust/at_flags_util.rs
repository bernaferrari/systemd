// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.at-flags-util; authority=src/basic/fs-util.h
//
// openat() flag normalization utilities for consistent symlink-handling policy.
//
// Provides pure-Rust equivalents of the C inline functions
// `at_flags_normalize_nofollow()` and `at_flags_normalize_follow()` from
// fs-util.h. The C originals contain `assert()` guards against contradictory
// flags; the safe Rust API represents that invalid caller state explicitly.

// ── Constants ─────────────────────────────────────────────────────────────

/// Follow symbolic links when operating on a path.
///
/// Uses the target libc authority rather than duplicating a Linux header value.
pub const AT_SYMLINK_FOLLOW: i32 = libc::AT_SYMLINK_FOLLOW;

/// Do not follow symbolic links when operating on a path.
///
/// Uses the target libc authority rather than duplicating a Linux header value.
pub const AT_SYMLINK_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;

// ── Error type ────────────────────────────────────────────────────────────

/// Error returned when contradictory symlink flags are specified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictoryFlagsError {
    pub flags: i32,
}

impl std::fmt::Display for ContradictoryFlagsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "contradictory AT_SYMLINK_FOLLOW and AT_SYMLINK_NOFOLLOW flags: 0x{:x}",
            self.flags
        )
    }
}

impl std::error::Error for ContradictoryFlagsError {}

// ── Flag normalization ────────────────────────────────────────────────────

/// Ensure `AT_SYMLINK_NOFOLLOW` is set and `AT_SYMLINK_FOLLOW` is not.
///
/// If `AT_SYMLINK_FOLLOW` is set, clears it (the C version asserts that
/// `AT_SYMLINK_NOFOLLOW` is *not* also set). Otherwise, sets
/// `AT_SYMLINK_NOFOLLOW`.
///
/// Mirrors C `at_flags_normalize_nofollow()` from fs-util.h:
/// ```c
/// static inline int at_flags_normalize_nofollow(int flags) {
///         if (FLAGS_SET(flags, AT_SYMLINK_FOLLOW)) {
///                 assert(!FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW));
///                 flags &= ~AT_SYMLINK_FOLLOW;
///         } else
///                 flags |= AT_SYMLINK_NOFOLLOW;
///         return flags;
/// }
/// ```
///
/// # Errors
///
/// Returns `ContradictoryFlagsError` if both symlink-policy flags are set.
pub fn at_flags_normalize_nofollow(flags: i32) -> Result<i32, ContradictoryFlagsError> {
    if flags & AT_SYMLINK_FOLLOW != 0 {
        if flags & AT_SYMLINK_NOFOLLOW != 0 {
            return Err(ContradictoryFlagsError { flags });
        }
        Ok(flags & !AT_SYMLINK_FOLLOW)
    } else {
        Ok(flags | AT_SYMLINK_NOFOLLOW)
    }
}

/// Ensure `AT_SYMLINK_FOLLOW` is set and `AT_SYMLINK_NOFOLLOW` is not.
///
/// If `AT_SYMLINK_NOFOLLOW` is set, clears it (the C version asserts that
/// `AT_SYMLINK_FOLLOW` is *not* also set). Otherwise, sets
/// `AT_SYMLINK_FOLLOW`.
///
/// Mirrors C `at_flags_normalize_follow()` from fs-util.h:
/// ```c
/// static inline int at_flags_normalize_follow(int flags) {
///         if (FLAGS_SET(flags, AT_SYMLINK_NOFOLLOW)) {
///                 assert(!FLAGS_SET(flags, AT_SYMLINK_FOLLOW));
///                 flags &= ~AT_SYMLINK_NOFOLLOW;
///         } else
///                 flags |= AT_SYMLINK_FOLLOW;
///         return flags;
/// }
/// ```
///
/// # Errors
/// Returns `ContradictoryFlagsError` if both `AT_SYMLINK_FOLLOW` and
/// `AT_SYMLINK_NOFOLLOW` are set, matching the C `assert()`.
pub fn at_flags_normalize_follow(flags: i32) -> Result<i32, ContradictoryFlagsError> {
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        if flags & AT_SYMLINK_FOLLOW != 0 {
            return Err(ContradictoryFlagsError { flags });
        }
        Ok(flags & !AT_SYMLINK_NOFOLLOW)
    } else {
        Ok(flags | AT_SYMLINK_FOLLOW)
    }
}

/// Exact C ABI facade for `at_flags_normalize_nofollow()`.
///
/// The C inline function asserts on contradictory flags. Panicking or
/// unwinding through a C ABI would be unsound, so the Rust boundary returns
/// `-EINVAL` for that invalid caller state.
#[unsafe(no_mangle)]
pub extern "C" fn rs_at_flags_normalize_nofollow(flags: libc::c_int) -> libc::c_int {
    at_flags_normalize_nofollow(flags).unwrap_or(-libc::EINVAL)
}

/// Exact C ABI facade for `at_flags_normalize_follow()`.
///
/// Returns `-EINVAL` instead of attempting to unwind across C when both
/// mutually exclusive flags are present.
#[unsafe(no_mangle)]
pub extern "C" fn rs_at_flags_normalize_follow(flags: libc::c_int) -> libc::c_int {
    at_flags_normalize_follow(flags).unwrap_or(-libc::EINVAL)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- at_flags_normalize_nofollow -------------------------------------------

    #[test]
    fn test_nofollow_no_flags_set() {
        assert_eq!(at_flags_normalize_nofollow(0), Ok(AT_SYMLINK_NOFOLLOW));
    }

    #[test]
    fn test_nofollow_follow_set_clears_it() {
        let result = at_flags_normalize_nofollow(AT_SYMLINK_FOLLOW).unwrap();
        assert_eq!(result, 0);
        assert_eq!(result & AT_SYMLINK_FOLLOW, 0);
        assert_eq!(result & AT_SYMLINK_NOFOLLOW, 0);
    }

    #[test]
    fn test_nofollow_already_set_keeps_it() {
        assert_eq!(
            at_flags_normalize_nofollow(AT_SYMLINK_NOFOLLOW),
            Ok(AT_SYMLINK_NOFOLLOW)
        );
    }

    #[test]
    fn test_nofollow_preserves_other_flags() {
        let other = 0x10;
        let result = at_flags_normalize_nofollow(other).unwrap();
        assert_eq!(result, other | AT_SYMLINK_NOFOLLOW);
    }

    #[test]
    fn test_nofollow_follow_and_other_flags() {
        let flags = AT_SYMLINK_FOLLOW | 0x20;
        let result = at_flags_normalize_nofollow(flags).unwrap();
        assert_eq!(result, 0x20);
        assert_eq!(result & AT_SYMLINK_FOLLOW, 0);
    }

    #[test]
    fn test_nofollow_contradictory_flags_rejected() {
        let flags = AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW;
        assert!(at_flags_normalize_nofollow(flags).is_err());
    }

    // -- at_flags_normalize_follow ---------------------------------------------

    #[test]
    fn test_follow_no_flags_set() {
        assert_eq!(at_flags_normalize_follow(0), Ok(AT_SYMLINK_FOLLOW));
    }

    #[test]
    fn test_follow_nofollow_set_clears_it() {
        let result = at_flags_normalize_follow(AT_SYMLINK_NOFOLLOW).unwrap();
        assert_eq!(result, 0);
        assert_eq!(result & AT_SYMLINK_NOFOLLOW, 0);
        assert_eq!(result & AT_SYMLINK_FOLLOW, 0);
    }

    #[test]
    fn test_follow_already_set_keeps_it() {
        assert_eq!(
            at_flags_normalize_follow(AT_SYMLINK_FOLLOW),
            Ok(AT_SYMLINK_FOLLOW)
        );
    }

    #[test]
    fn test_follow_preserves_other_flags() {
        let other = 0x10;
        let result = at_flags_normalize_follow(other).unwrap();
        assert_eq!(result, other | AT_SYMLINK_FOLLOW);
    }

    #[test]
    fn test_follow_nofollow_and_other_flags() {
        let flags = AT_SYMLINK_NOFOLLOW | 0x20;
        let result = at_flags_normalize_follow(flags).unwrap();
        assert_eq!(result, 0x20);
        assert_eq!(result & AT_SYMLINK_NOFOLLOW, 0);
    }

    #[test]
    fn test_follow_contradictory_flags_rejected() {
        let flags = AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW;
        assert!(at_flags_normalize_follow(flags).is_err());
    }

    // -- constants -------------------------------------------------------------

    #[test]
    fn test_constants_match_linux_values() {
        assert_eq!(AT_SYMLINK_FOLLOW, libc::AT_SYMLINK_FOLLOW);
        assert_eq!(AT_SYMLINK_NOFOLLOW, libc::AT_SYMLINK_NOFOLLOW);
    }

    #[test]
    fn test_error_display() {
        let err = ContradictoryFlagsError {
            flags: AT_SYMLINK_FOLLOW | AT_SYMLINK_NOFOLLOW,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("contradictory"));
        assert!(msg.contains("0x500"));
    }
}
