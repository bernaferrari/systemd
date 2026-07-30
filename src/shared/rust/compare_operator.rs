// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/compare-operator.c, src/shared/compare-operator.h
//
// Comparison operator parsing and evaluation utilities.
//
// Supports various comparison operators for version strings, fnmatch
// patterns, and simple string comparisons. Operators can be symbolic
// (==, !=, <, >, <=, >=) or textual (eq, ne, lt, le, gt, ge).

// ── Constants ─────────────────────────────────────────────────────────────

pub const COMPARE_OPERATOR_CHARS: &[u8] = b"!<=>";
pub const COMPARE_OPERATOR_WITH_FNMATCH_CHARS: &[u8] = b"!<=>$";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Comparison operator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOperator {
    /// Simple string compare operators
    StringEqual,
    StringUnequal,

    /// fnmatch() compare operators
    FnmatchEqual,
    FnmatchUnequal,

    /// Order compare operators
    LowerOrEqual,
    GreaterOrEqual,
    Lower,
    Greater,
    Equal,
    Unequal,
}

impl CompareOperator {
    /// Sentinel for invalid values
    pub const INVALID: i32 = -22; // -EINVAL
}

bitflags::bitflags! {
    /// Parse flags for compare operators
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompareOperatorParseFlags: u32 {
        const ALLOW_FNMATCH = 1 << 0;
        const EQUAL_BY_STRING = 1 << 1;
        const ALLOW_TEXTUAL = 1 << 2;
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if operator is a string comparison
pub fn compare_operator_is_string(op: CompareOperator) -> bool {
    matches!(
        op,
        CompareOperator::StringEqual | CompareOperator::StringUnequal
    )
}

/// Check if operator is an fnmatch comparison
pub fn compare_operator_is_fnmatch(op: CompareOperator) -> bool {
    matches!(
        op,
        CompareOperator::FnmatchEqual | CompareOperator::FnmatchUnequal
    )
}

/// Check if operator is an order comparison
pub fn compare_operator_is_order(op: CompareOperator) -> bool {
    matches!(
        op,
        CompareOperator::Lower
            | CompareOperator::LowerOrEqual
            | CompareOperator::Equal
            | CompareOperator::Unequal
            | CompareOperator::GreaterOrEqual
            | CompareOperator::Greater
    )
}

// ── Parse operator ────────────────────────────────────────────────────────

struct OperatorEntry {
    op: CompareOperator,
    s: &'static str,
    valid_mask: u32,
    need_mask: u32,
}

static OPERATOR_TABLE: &[OperatorEntry] = &[
    // fnmatch operators
    OperatorEntry {
        op: CompareOperator::FnmatchEqual,
        s: "$=",
        valid_mask: 1,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::FnmatchUnequal,
        s: "!$=",
        valid_mask: 1,
        need_mask: 0,
    },
    // Standard comparison operators (longer strings first for correct matching)
    OperatorEntry {
        op: CompareOperator::Unequal,
        s: "<>",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::LowerOrEqual,
        s: "<=",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::GreaterOrEqual,
        s: ">=",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Lower,
        s: "<",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Greater,
        s: ">",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Equal,
        s: "==",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::StringEqual,
        s: "=",
        valid_mask: 0,
        need_mask: 2,
    },
    OperatorEntry {
        op: CompareOperator::Equal,
        s: "=",
        valid_mask: 0,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::StringUnequal,
        s: "!=",
        valid_mask: 0,
        need_mask: 2,
    },
    OperatorEntry {
        op: CompareOperator::Unequal,
        s: "!=",
        valid_mask: 0,
        need_mask: 0,
    },
    // Textual operators
    OperatorEntry {
        op: CompareOperator::Lower,
        s: "lt",
        valid_mask: 4,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::LowerOrEqual,
        s: "le",
        valid_mask: 4,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Equal,
        s: "eq",
        valid_mask: 4,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Unequal,
        s: "ne",
        valid_mask: 4,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::GreaterOrEqual,
        s: "ge",
        valid_mask: 4,
        need_mask: 0,
    },
    OperatorEntry {
        op: CompareOperator::Greater,
        s: "gt",
        valid_mask: 4,
        need_mask: 0,
    },
];

/// Parse a comparison operator from a string slice.
/// Returns (operator, remaining_string) on success, or None on failure.
pub fn parse_compare_operator<'a>(
    s: &'a str,
    flags: CompareOperatorParseFlags,
) -> Option<(CompareOperator, &'a str)> {
    for entry in OPERATOR_TABLE {
        // Check need_mask - skip if flag not set
        if entry.need_mask != 0
            && !flags.contains(CompareOperatorParseFlags::from_bits_retain(entry.need_mask))
        {
            continue;
        }

        if let Some(rest) = s.strip_prefix(entry.s) {
            // Check valid_mask - fail if flag not set
            if entry.valid_mask != 0
                && !flags.contains(CompareOperatorParseFlags::from_bits_retain(
                    entry.valid_mask,
                ))
            {
                return None;
            }
            return Some((entry.op, rest));
        }
    }

    None
}

// ── Test order ────────────────────────────────────────────────────────────

/// Test an order comparison with a given result value.
///
/// `k` is the comparison result (negative = a<b, 0 = a==b, positive = a>b)
/// Returns true if the comparison succeeds, false if it fails, or an error for non-order ops.
pub fn test_order(k: i32, op: CompareOperator) -> Result<bool, i32> {
    match op {
        CompareOperator::Lower => Ok(k < 0),
        CompareOperator::LowerOrEqual => Ok(k <= 0),
        CompareOperator::Equal => Ok(k == 0),
        CompareOperator::Unequal => Ok(k != 0),
        CompareOperator::GreaterOrEqual => Ok(k >= 0),
        CompareOperator::Greater => Ok(k > 0),
        _ => Err(CompareOperator::INVALID),
    }
}

// ── Version or fnmatch compare ────────────────────────────────────────────

/// Compare two strings using the specified operator (string equality/inequality only).
/// For fnmatch and order comparisons, use the appropriate dedicated functions.
pub fn string_compare(op: CompareOperator, a: Option<&str>, b: Option<&str>) -> Result<bool, i32> {
    match op {
        CompareOperator::StringEqual => match (a, b) {
            (None, None) => Ok(true),
            (Some(_), None) | (None, Some(_)) => Ok(false),
            (Some(a_val), Some(b_val)) => Ok(a_val == b_val),
        },
        CompareOperator::StringUnequal => match (a, b) {
            (None, None) => Ok(false),
            (Some(_), None) | (None, Some(_)) => Ok(true),
            (Some(a_val), Some(b_val)) => Ok(a_val != b_val),
        },
        _ => Err(CompareOperator::INVALID),
    }
}

/// Perform an fnmatch comparison
pub fn fnmatch_compare(op: CompareOperator, string: &str, pattern: &str) -> Result<bool, i32> {
    let matched = glob_match(pattern, string);
    match op {
        CompareOperator::FnmatchEqual => Ok(matched),
        CompareOperator::FnmatchUnequal => Ok(!matched),
        _ => Err(CompareOperator::INVALID),
    }
}

/// Simple glob matching (replaces fnmatch for basic patterns)
/// Supports *, ?, [abc], [!abc]
fn glob_match(pattern: &str, string: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let string: Vec<char> = string.chars().collect();
    glob_match_impl(&pattern, &string)
}

fn glob_match_impl(pattern: &[char], string: &[char]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < string.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '*' => {
                    star_pi = pi;
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                '[' => {
                    // Handle character class
                    if let Some(result) = match_char_class(&pattern[pi..], string[si]) {
                        pi = result.0;
                        if result.1 {
                            si += 1;
                            continue;
                        }
                    } else {
                        // Malformed pattern, treat [ as literal
                        if pattern[pi] == string[si] {
                            pi += 1;
                            si += 1;
                            continue;
                        }
                    }
                }
                c if c == string[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }

        // If we had a star, backtrack
        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
            continue;
        }

        return false;
    }

    // Consume trailing stars
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Match a character class [abc] or [!abc] or [a-z]
/// Returns Some((new_pattern_index, matched)) or None if malformed
fn match_char_class(pattern: &[char], c: char) -> Option<(usize, bool)> {
    if pattern.is_empty() || pattern[0] != '[' {
        return None;
    }

    let mut i = 1;
    let negate = if i < pattern.len() && pattern[i] == '!' {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    while i < pattern.len() && pattern[i] != ']' {
        if i + 2 < pattern.len() && pattern[i + 1] == '-' {
            // Range: a-z
            let start = pattern[i];
            let end = pattern[i + 2];
            if c >= start && c <= end {
                matched = true;
            }
            i += 3;
        } else {
            if pattern[i] == c {
                matched = true;
            }
            i += 1;
        }
    }

    if i < pattern.len() && pattern[i] == ']' {
        i += 1; // skip ]
        Some((i, matched != negate))
    } else {
        None // malformed
    }
}

/// Version string comparison (strverscmp equivalent)
/// Compares two version strings according to standard version ordering.
pub fn strverscmp(a: &str, b: &str) -> i32 {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut ai = 0usize;
    let mut bi = 0usize;

    loop {
        // Skip leading zeros
        while ai < a_chars.len() && a_chars[ai] == '0' {
            ai += 1;
        }
        while bi < b_chars.len() && b_chars[bi] == '0' {
            bi += 1;
        }

        // Count digits
        let mut a_digits = 0usize;
        while ai + a_digits < a_chars.len() && a_chars[ai + a_digits].is_ascii_digit() {
            a_digits += 1;
        }
        let mut b_digits = 0usize;
        while bi + b_digits < b_chars.len() && b_chars[bi + b_digits].is_ascii_digit() {
            b_digits += 1;
        }

        if a_digits != b_digits {
            return if a_digits > b_digits { 1 } else { -1 };
        }

        // Compare digit by digit
        for j in 0..a_digits {
            let a_d = if ai + j < a_chars.len() {
                a_chars[ai + j]
            } else {
                break;
            };
            let b_d = if bi + j < b_chars.len() {
                b_chars[bi + j]
            } else {
                break;
            };
            if a_d != b_d {
                return a_d as i32 - b_d as i32;
            }
        }

        ai += a_digits;
        bi += b_digits;

        // End of either string
        if ai >= a_chars.len() || bi >= b_chars.len() {
            // Check if one has more characters
            if ai < a_chars.len() {
                return 1;
            }
            if bi < b_chars.len() {
                return -1;
            }
            return 0;
        }

        // Compare non-digit characters
        if a_chars[ai] != b_chars[bi] {
            return a_chars[ai] as i32 - b_chars[bi] as i32;
        }

        ai += 1;
        bi += 1;
    }
}

/// Full version or fnmatch compare using the specified operator
pub fn version_or_fnmatch_compare(op: CompareOperator, a: &str, b: &str) -> Result<bool, i32> {
    match op {
        CompareOperator::StringEqual => Ok(a == b),
        CompareOperator::StringUnequal => Ok(a != b),
        CompareOperator::FnmatchEqual | CompareOperator::FnmatchUnequal => {
            fnmatch_compare(op, a, b)
        }
        _ if compare_operator_is_order(op) => {
            let k = strverscmp(a, b);
            test_order(k, op)
        }
        _ => Err(CompareOperator::INVALID),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_operator_is_string() {
        assert!(compare_operator_is_string(CompareOperator::StringEqual));
        assert!(compare_operator_is_string(CompareOperator::StringUnequal));
        assert!(!compare_operator_is_string(CompareOperator::Equal));
        assert!(!compare_operator_is_string(CompareOperator::FnmatchEqual));
    }

    #[test]
    fn test_compare_operator_is_fnmatch() {
        assert!(compare_operator_is_fnmatch(CompareOperator::FnmatchEqual));
        assert!(compare_operator_is_fnmatch(CompareOperator::FnmatchUnequal));
        assert!(!compare_operator_is_fnmatch(CompareOperator::Equal));
    }

    #[test]
    fn test_compare_operator_is_order() {
        assert!(compare_operator_is_order(CompareOperator::Equal));
        assert!(compare_operator_is_order(CompareOperator::Lower));
        assert!(compare_operator_is_order(CompareOperator::Greater));
        assert!(!compare_operator_is_order(CompareOperator::StringEqual));
        assert!(!compare_operator_is_order(CompareOperator::FnmatchEqual));
    }

    #[test]
    fn test_parse_compare_operator_basic() {
        let flags = CompareOperatorParseFlags::empty();
        let (op, rest) = parse_compare_operator("==test", flags).unwrap();
        assert_eq!(op, CompareOperator::Equal);
        assert_eq!(rest, "test");
    }

    #[test]
    fn test_parse_compare_operator_all() {
        let flags = CompareOperatorParseFlags::empty();
        assert_eq!(
            parse_compare_operator("<=", flags).unwrap().0,
            CompareOperator::LowerOrEqual
        );
        assert_eq!(
            parse_compare_operator(">=", flags).unwrap().0,
            CompareOperator::GreaterOrEqual
        );
        assert_eq!(
            parse_compare_operator("<>", flags).unwrap().0,
            CompareOperator::Unequal
        );
        assert_eq!(
            parse_compare_operator("<", flags).unwrap().0,
            CompareOperator::Lower
        );
        assert_eq!(
            parse_compare_operator(">", flags).unwrap().0,
            CompareOperator::Greater
        );
        assert_eq!(
            parse_compare_operator("==", flags).unwrap().0,
            CompareOperator::Equal
        );
    }

    #[test]
    fn test_parse_compare_operator_fnmatch() {
        let flags = CompareOperatorParseFlags::ALLOW_FNMATCH;
        let (op, rest) = parse_compare_operator("$=pattern", flags).unwrap();
        assert_eq!(op, CompareOperator::FnmatchEqual);
        assert_eq!(rest, "pattern");

        let (op, _) = parse_compare_operator("!$=x", flags).unwrap();
        assert_eq!(op, CompareOperator::FnmatchUnequal);

        // Without ALLOW_FNMATCH flag, $= should fail
        assert!(parse_compare_operator("$=x", CompareOperatorParseFlags::empty()).is_none());
    }

    #[test]
    fn test_parse_compare_operator_textual() {
        let flags = CompareOperatorParseFlags::ALLOW_TEXTUAL;
        assert_eq!(
            parse_compare_operator("lt", flags).unwrap().0,
            CompareOperator::Lower
        );
        assert_eq!(
            parse_compare_operator("le", flags).unwrap().0,
            CompareOperator::LowerOrEqual
        );
        assert_eq!(
            parse_compare_operator("eq", flags).unwrap().0,
            CompareOperator::Equal
        );
        assert_eq!(
            parse_compare_operator("ne", flags).unwrap().0,
            CompareOperator::Unequal
        );
        assert_eq!(
            parse_compare_operator("ge", flags).unwrap().0,
            CompareOperator::GreaterOrEqual
        );
        assert_eq!(
            parse_compare_operator("gt", flags).unwrap().0,
            CompareOperator::Greater
        );

        // Without ALLOW_TEXTUAL, textual operators should fail
        assert!(parse_compare_operator("lt", CompareOperatorParseFlags::empty()).is_none());
    }

    #[test]
    fn test_parse_compare_operator_equal_by_string() {
        let flags = CompareOperatorParseFlags::EQUAL_BY_STRING;
        let (op, _) = parse_compare_operator("=", flags).unwrap();
        assert_eq!(op, CompareOperator::StringEqual);

        let (op, _) = parse_compare_operator("!=", flags).unwrap();
        assert_eq!(op, CompareOperator::StringUnequal);

        // Without EQUAL_BY_STRING, = means Equal, not StringEqual
        let (op, _) = parse_compare_operator("=", CompareOperatorParseFlags::empty()).unwrap();
        assert_eq!(op, CompareOperator::Equal);
    }

    #[test]
    fn test_parse_compare_operator_invalid() {
        let flags = CompareOperatorParseFlags::empty();
        assert!(parse_compare_operator("xxx", flags).is_none());
        assert!(parse_compare_operator("", flags).is_none());
    }

    #[test]
    fn test_test_order() {
        assert_eq!(test_order(-1, CompareOperator::Lower), Ok(true));
        assert_eq!(test_order(-1, CompareOperator::Greater), Ok(false));
        assert_eq!(test_order(0, CompareOperator::Equal), Ok(true));
        assert_eq!(test_order(0, CompareOperator::Unequal), Ok(false));
        assert_eq!(test_order(1, CompareOperator::Greater), Ok(true));
        assert_eq!(test_order(1, CompareOperator::Lower), Ok(false));
        assert_eq!(test_order(-1, CompareOperator::LowerOrEqual), Ok(true));
        assert_eq!(test_order(0, CompareOperator::LowerOrEqual), Ok(true));
        assert_eq!(test_order(1, CompareOperator::LowerOrEqual), Ok(false));
        assert_eq!(test_order(1, CompareOperator::GreaterOrEqual), Ok(true));
        assert_eq!(test_order(0, CompareOperator::GreaterOrEqual), Ok(true));
        assert_eq!(test_order(-1, CompareOperator::GreaterOrEqual), Ok(false));
        // Non-order operator should return error
        assert!(test_order(0, CompareOperator::StringEqual).is_err());
    }

    #[test]
    fn test_string_compare_equal() {
        assert_eq!(
            string_compare(CompareOperator::StringEqual, Some("hello"), Some("hello")),
            Ok(true)
        );
        assert_eq!(
            string_compare(CompareOperator::StringEqual, Some("hello"), Some("world")),
            Ok(false)
        );
        assert_eq!(
            string_compare(CompareOperator::StringEqual, None, None),
            Ok(true)
        );
        assert_eq!(
            string_compare(CompareOperator::StringEqual, Some("test"), None),
            Ok(false)
        );
    }

    #[test]
    fn test_string_compare_unequal() {
        assert_eq!(
            string_compare(CompareOperator::StringUnequal, Some("hello"), Some("world")),
            Ok(true)
        );
        assert_eq!(
            string_compare(CompareOperator::StringUnequal, Some("hello"), Some("hello")),
            Ok(false)
        );
        assert_eq!(
            string_compare(CompareOperator::StringUnequal, None, None),
            Ok(false)
        );
        assert_eq!(
            string_compare(CompareOperator::StringUnequal, Some("test"), None),
            Ok(true)
        );
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*.txt", "file.txt"));
        assert!(glob_match("*.txt", ".txt"));
        assert!(!glob_match("*.txt", "file.rs"));
        assert!(glob_match("test", "test"));
        assert!(!glob_match("test", "other"));
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", "ab"));
        assert!(glob_match("[abc]", "a"));
        assert!(!glob_match("[abc]", "d"));
        assert!(glob_match("[!abc]", "d"));
        assert!(!glob_match("[!abc]", "a"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("file*", "file"));
        assert!(glob_match("file*", "filename"));
    }

    #[test]
    fn test_strverscmp() {
        assert_eq!(strverscmp("1", "2"), -1);
        assert_eq!(strverscmp("2", "1"), 1);
        assert_eq!(strverscmp("1", "1"), 0);
        assert_eq!(strverscmp("1.0", "1.1"), -1);
        assert_eq!(strverscmp("1.2", "1.10"), -1);
        assert_eq!(strverscmp("1.10", "1.2"), 1);
        assert_eq!(strverscmp("abc", "abd"), -1);
    }

    #[test]
    fn test_version_or_fnmatch_compare() {
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::StringEqual, "hello", "hello"),
            Ok(true)
        );
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::StringUnequal, "hello", "world"),
            Ok(true)
        );
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::Lower, "1.0", "2.0"),
            Ok(true)
        );
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::Greater, "2.0", "1.0"),
            Ok(true)
        );
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::FnmatchEqual, "file.txt", "*.txt"),
            Ok(true)
        );
        assert_eq!(
            version_or_fnmatch_compare(CompareOperator::FnmatchUnequal, "file.rs", "*.txt"),
            Ok(true)
        );
    }
}
