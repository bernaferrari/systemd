// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/string-util.c (strverscmp_improved)
//
// Version string comparison utility (rpm-like version ordering).
// Handles '~' (pre-release), '-' (version/release separator),
// '^' (patch release), '.' (point release) markers.

// ── Error type ──────────────────────────────────────────────────────────

/// Error returned when version string comparison fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    /// One or both inputs were empty.
    EmptyInput,
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionError::EmptyInput => write!(f, "empty version string"),
        }
    }
}

impl std::error::Error for VersionError {}

// ── Internal helpers ────────────────────────────────────────────────────

fn is_valid_version_char(a: char) -> bool {
    a.is_ascii_digit() || a.is_ascii_alphabetic() || matches!(a, '~' | '-' | '^' | '.')
}

#[inline(always)]
fn cmp(a: i32, b: i32) -> std::cmp::Ordering {
    a.cmp(&b)
}

// ── Public API ──────────────────────────────────────────────────────────

/// Compare two version strings using rpm-like version ordering.
///
/// Returns `Ok(ordering)` where `Ordering::Less` means `a < b`,
/// `Ordering::Greater` means `a > b`, and `Ordering::Equal` means equal.
///
/// # Version ordering (older to newer)
///
/// ```text
/// 122.1 < 123~rc1-1 < 123 < 123-a < 123-a.1 < 123-1 < 123-1.1
/// < 123^post1 < 123.a-1 < 123.1-1 < 123a-1 < 124-1
/// ```
pub fn strverscmp_improved(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = 0usize;
    let mut bi = 0usize;
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();

    loop {
        // Drop leading invalid characters
        while ai < ac.len() && !is_valid_version_char(ac[ai]) {
            ai += 1;
        }
        while bi < bc.len() && !is_valid_version_char(bc[bi]) {
            bi += 1;
        }

        // Handle '~': pre-release marker, oldest
        if ai < ac.len() && ac[ai] == '~' || bi < bc.len() && bc[bi] == '~' {
            let a_not_tilde = if ai < ac.len() { ac[ai] != '~' } else { true };
            let b_not_tilde = if bi < bc.len() { bc[bi] != '~' } else { true };
            let r = cmp(a_not_tilde as i32, b_not_tilde as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
            continue;
        }

        // End of one or both strings: longer string is newer
        if ai >= ac.len() || bi >= bc.len() {
            let a_val = if ai < ac.len() { ac[ai] as i32 } else { 0 };
            let b_val = if bi < bc.len() { bc[bi] as i32 } else { 0 };
            return cmp(a_val, b_val);
        }

        // Handle '-': separator between version and release
        if ac[ai] == '-' || bc[bi] == '-' {
            let r = cmp((ac[ai] != '-') as i32, (bc[bi] != '-') as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        // Handle '^': patched release marker
        if ai < ac.len() && ac[ai] == '^' || bi < bc.len() && bc[bi] == '^' {
            let a_not_caret = if ai < ac.len() { ac[ai] != '^' } else { false };
            let b_not_caret = if bi < bc.len() { bc[bi] != '^' } else { false };
            let r = cmp(a_not_caret as i32, b_not_caret as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        // Handle '.': point release separator
        if ai < ac.len() && ac[ai] == '.' || bi < bc.len() && bc[bi] == '.' {
            let a_not_dot = if ai < ac.len() { ac[ai] != '.' } else { false };
            let b_not_dot = if bi < bc.len() { bc[bi] != '.' } else { false };
            let r = cmp(a_not_dot as i32, b_not_dot as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        let a_is_digit = ai < ac.len() && ac[ai].is_ascii_digit();
        let b_is_digit = bi < bc.len() && bc[bi].is_ascii_digit();

        if a_is_digit || b_is_digit {
            // Numeric segment: find end of digits
            let mut aa = ai;
            while aa < ac.len() && ac[aa].is_ascii_digit() {
                aa += 1;
            }
            let mut bb = bi;
            while bb < bc.len() && bc[bb].is_ascii_digit() {
                bb += 1;
            }

            // If one was empty, the non-empty numeric is newer
            let r = cmp((ai != aa) as i32, (bi != bb) as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            // Skip leading zeros
            while ai < aa && ac[ai] == '0' {
                ai += 1;
            }
            while bi < bb && bc[bi] == '0' {
                bi += 1;
            }

            // Longer number is newer
            let r = cmp((aa - ai) as i32, (bb - bi) as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            // Compare digit by digit
            let len = aa - ai;
            for j in 0..len {
                let ca = ac[ai + j];
                let cb = bc[bi + j];
                if ca != cb {
                    return cmp(ca as i32, cb as i32);
                }
            }

            ai = aa;
            bi = bb;
        } else {
            // Alpha segment: find end of alpha chars
            let mut aa = ai;
            while aa < ac.len() && ac[aa].is_ascii_alphabetic() {
                aa += 1;
            }
            let mut bb = bi;
            while bb < bc.len() && bc[bb].is_ascii_alphabetic() {
                bb += 1;
            }

            // Compare min length
            let min_len = std::cmp::min(aa - ai, bb - bi);
            for j in 0..min_len {
                let ca = ac[ai + j];
                let cb = bc[bi + j];
                if ca != cb {
                    return cmp(ca as i32, cb as i32);
                }
            }

            // Longer alpha segment is newer
            let r = cmp((aa - ai) as i32, (bb - bi) as i32);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            ai = aa;
            bi = bb;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_strings() {
        assert_eq!(strverscmp_improved("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("abc", "abc"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("", ""), std::cmp::Ordering::Equal);
        assert_eq!(
            strverscmp_improved("2.3.1", "2.3.1"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_empty_vs_nonempty() {
        assert_eq!(strverscmp_improved("", "1"), std::cmp::Ordering::Less);
        assert_eq!(strverscmp_improved("1", ""), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_numeric_comparison() {
        assert!(strverscmp_improved("2", "1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1", "2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("10", "2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("9", "10") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(strverscmp_improved("01", "1"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("007", "7"), std::cmp::Ordering::Equal);
        assert!(strverscmp_improved("0010", "09") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_tilde_pre_release() {
        assert!(strverscmp_improved("1.0~rc1", "1.0") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0", "1.0~rc1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0~alpha", "1.0~beta") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0~~", "1.0~") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_dash_separator() {
        assert!(strverscmp_improved("1.0-1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0-1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0-2", "1.0-1") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_dot_separator() {
        assert!(strverscmp_improved("1.1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.2.3", "1.2.2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("2.0", "1.9") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_caret_patch() {
        assert!(strverscmp_improved("1.0^1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0^1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0^2", "1.0^1") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_alpha_comparison() {
        assert!(strverscmp_improved("abc", "abd") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("abd", "abc") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("beta", "alpha") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_alpha_longer_is_newer() {
        assert!(strverscmp_improved("abc", "ab") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("ab", "abc") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_numeric_longer_is_newer() {
        assert!(strverscmp_improved("1.0.1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0.1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0.0", "1.0") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_numeric_vs_alpha() {
        assert!(strverscmp_improved("1", "a") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("a", "1") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_complex_versions() {
        assert!(strverscmp_improved("2.31.0-1", "2.30.0-1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0.0-1", "1.0.0-2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("3.14.159", "3.14.15") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_same_prefix_different_suffix() {
        assert!(strverscmp_improved("foo1", "foo2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("foo10", "foo2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("foo9", "foo10") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_large_numbers() {
        assert!(strverscmp_improved("999", "1000") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1000", "999") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("100000", "99999") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_full_ordering_chain() {
        // From C source documentation
        let versions = [
            "122.1",
            "123~rc1-1",
            "123",
            "123-a",
            "123-a.1",
            "123-1",
            "123-1.1",
            "123^post1",
            "123.a-1",
            "123.1-1",
            "123a-1",
            "124-1",
        ];
        for i in 0..versions.len() - 1 {
            assert!(
                strverscmp_improved(versions[i], versions[i + 1]) == std::cmp::Ordering::Less,
                "Expected {} < {}",
                versions[i],
                versions[i + 1]
            );
        }
    }
}
