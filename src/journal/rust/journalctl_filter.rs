// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/journalctl-filter.c
//
// Native journalctl filter planning (matches, boots, units, and priorities).

use crate::journalctl::JournalctlArgs;
use std::collections::BTreeSet;

const LOG_EMERG: u8 = 0;
const LOG_DEBUG: u8 = 7;
const SYSLOG_FACILITY_MAX: u8 = 23;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterBuildError {
    InvalidFacility(u8),
    MisplacedPlusSeparator,
    AbsolutePathWithSourceConflict,
    InvalidAbsolutePath(&'static str),
}

// Mirrors field_list_has_scope_options() from src/journal/journalctl-filter.c.
//
// -F/--field and -N/--fields enumerate the whole journal, so accepting a
// filtering option here would silently ignore a user-supplied restriction.
pub fn field_list_has_scope_options(args: &JournalctlArgs) -> bool {
    args.boot_filter
        || args.invocation
        || args.dmesg
        || args.cursor.is_some()
        || args.after_cursor.is_some()
        || args.cursor_file.is_some()
        || !args.system_units.is_empty()
        || !args.user_units.is_empty()
        || !args.syslog_identifier.is_empty()
        || !args.exclude_identifier.is_empty()
        || args.priorities_mask != 0
        || !args.facilities.is_empty()
        || args.since.is_some()
        || args.until.is_some()
        || args.pattern.is_some()
}

// Mirrors add_priorities() from src/journal/journalctl-filter.c.
pub fn priority_match_terms(priorities_mask: u32) -> Vec<String> {
    let mut out = Vec::new();
    for level in LOG_EMERG..=LOG_DEBUG {
        if priorities_mask & (1u32 << level) != 0 {
            out.push(format!("PRIORITY={level}"));
        }
    }
    out
}

// Mirrors add_syslog_identifier() from src/journal/journalctl-filter.c.
pub fn syslog_identifier_terms(identifiers: &[String]) -> Vec<String> {
    identifiers
        .iter()
        .map(|identifier| format!("SYSLOG_IDENTIFIER={identifier}"))
        .collect()
}

// Mirrors add_exclude_identifier() from src/journal/journalctl-filter.c.
//
// The C code stores these identifiers in a Set, so duplicates are removed and
// ordering is not semantically significant.
pub fn excluded_syslog_identifier_set(identifiers: &[String]) -> BTreeSet<String> {
    identifiers.iter().cloned().collect()
}

// Mirrors add_facilities() from src/journal/journalctl-filter.c.
pub fn facility_match_terms(facilities: &BTreeSet<u8>) -> Result<Vec<String>, FilterBuildError> {
    let mut out = Vec::with_capacity(facilities.len());
    for facility in facilities {
        if *facility > SYSLOG_FACILITY_MAX {
            return Err(FilterBuildError::InvalidFacility(*facility));
        }
        out.push(format!("SYSLOG_FACILITY={facility}"));
    }
    Ok(out)
}

// Mirrors the `+` separator handling in add_matches() from
// src/journal/journalctl-filter.c.
//
// The C code treats `+` as a disjunction separator only when it appears
// between terms. A leading, trailing, or repeated `+` is rejected.
pub fn split_match_terms(args: &[String]) -> Result<Vec<Vec<String>>, FilterBuildError> {
    let mut groups: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut have_term = false;

    for arg in args {
        if arg == "+" {
            if !have_term {
                return Err(FilterBuildError::MisplacedPlusSeparator);
            }

            groups.push(current);
            current = Vec::new();
            have_term = false;
            continue;
        }

        current.push(arg.clone());
        have_term = true;
    }

    if !args.is_empty() {
        if !have_term {
            return Err(FilterBuildError::MisplacedPlusSeparator);
        }
        groups.push(current);
    }

    Ok(groups)
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn priority_match_terms_follow_syslog_order() {
        assert_eq!(
            priority_match_terms((1 << 0) | (1 << 3) | (1 << 7)),
            vec![
                "PRIORITY=0".to_string(),
                "PRIORITY=3".to_string(),
                "PRIORITY=7".to_string()
            ]
        );
    }

    #[test]
    fn priority_match_terms_ignore_bits_outside_syslog_range() {
        assert_eq!(priority_match_terms(1 << 12), Vec::<String>::new());
    }

    #[test]
    fn syslog_identifier_terms_preserve_order_and_duplicates() {
        let input = vec![
            "sshd".to_string(),
            "networkd".to_string(),
            "sshd".to_string(),
        ];
        assert_eq!(
            syslog_identifier_terms(&input),
            vec![
                "SYSLOG_IDENTIFIER=sshd".to_string(),
                "SYSLOG_IDENTIFIER=networkd".to_string(),
                "SYSLOG_IDENTIFIER=sshd".to_string()
            ]
        );
    }

    #[test]
    fn excluded_syslog_identifier_set_deduplicates_entries() {
        let input = vec![
            "sshd".to_string(),
            "networkd".to_string(),
            "sshd".to_string(),
        ];

        assert_eq!(
            excluded_syslog_identifier_set(&input),
            BTreeSet::from(["networkd".to_string(), "sshd".to_string()])
        );
    }

    #[test]
    fn facility_match_terms_builds_sorted_matches() {
        let facilities = BTreeSet::from([3u8, 1u8, 7u8]);
        assert_eq!(
            facility_match_terms(&facilities).unwrap(),
            vec![
                "SYSLOG_FACILITY=1".to_string(),
                "SYSLOG_FACILITY=3".to_string(),
                "SYSLOG_FACILITY=7".to_string()
            ]
        );
    }

    #[test]
    fn facility_match_terms_rejects_invalid_facility_number() {
        let facilities = BTreeSet::from([24u8]);
        assert_eq!(
            facility_match_terms(&facilities),
            Err(FilterBuildError::InvalidFacility(24))
        );
    }

    #[test]
    fn split_match_terms_keeps_terms_in_one_group_without_plus() {
        let input = vec!["MESSAGE=hello".to_string(), "_PID=42".to_string()];

        assert_eq!(
            split_match_terms(&input).unwrap(),
            vec![vec!["MESSAGE=hello".to_string(), "_PID=42".to_string()]]
        );
    }

    #[test]
    fn split_match_terms_splits_on_plus_only_between_terms() {
        let input = vec![
            "MESSAGE=hello".to_string(),
            "+".to_string(),
            "_PID=42".to_string(),
            "+".to_string(),
            "_COMM=journalctl".to_string(),
        ];

        assert_eq!(
            split_match_terms(&input).unwrap(),
            vec![
                vec!["MESSAGE=hello".to_string()],
                vec!["_PID=42".to_string()],
                vec!["_COMM=journalctl".to_string()],
            ]
        );
    }

    #[test]
    fn split_match_terms_rejects_misplaced_plus_separator() {
        assert_eq!(
            split_match_terms(&["+".to_string(), "MESSAGE=hello".to_string()]),
            Err(FilterBuildError::MisplacedPlusSeparator)
        );
        assert_eq!(
            split_match_terms(&["MESSAGE=hello".to_string(), "+".to_string()]),
            Err(FilterBuildError::MisplacedPlusSeparator)
        );
        assert_eq!(
            split_match_terms(&[
                "MESSAGE=hello".to_string(),
                "+".to_string(),
                "+".to_string(),
                "_PID=42".to_string(),
            ]),
            Err(FilterBuildError::MisplacedPlusSeparator)
        );
    }

    #[test]
    fn split_match_terms_treats_non_separator_plus_as_literal_input() {
        let input = vec!["priority+debug".to_string()];

        assert_eq!(
            split_match_terms(&input).unwrap(),
            vec![vec!["priority+debug".to_string()]]
        );
    }
}
