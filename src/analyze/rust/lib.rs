// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/analyze/analyze-compare-versions.c
#![deny(unsafe_op_in_unsafe_fn)]
//
//! Behavioral core for the deliberately narrow Rust `systemd-analyze` slice.
//!
//! Only `compare-versions` is implemented here. It is a pure operation and
//! does not need a manager connection. All manager, unit, TPM, and offline
//! analysis verbs remain owned by the installed C `systemd-analyze` binary.

use std::cmp::Ordering;

use systemd_basic_rs::shared_facades::validation::{
    COMPARE_ALLOW_TEXTUAL, CompareOperator, parse_compare_operator, test_order,
};
use systemd_basic_rs::strverscmp::strverscmp_improved;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_VERSION_GREATER: i32 = 11;
pub const EXIT_VERSION_LESS: i32 = 12;

/// Result materialized by the command-line frontend.
#[derive(Debug, PartialEq, Eq)]
pub struct CompareVersionsResult {
    pub stdout: Option<String>,
    pub warnings: Vec<String>,
    pub exit_status: i32,
}

/// User-visible failures whose text follows the corresponding C verb path.
#[derive(Debug, PartialEq, Eq)]
pub enum CompareVersionsError {
    TooFewArguments,
    TooManyArguments,
    UnknownOperator {
        operator: String,
        warnings: Vec<String>,
    },
}

impl CompareVersionsError {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::TooFewArguments => "Too few arguments.".to_string(),
            Self::TooManyArguments => "Too many arguments.".to_string(),
            Self::UnknownOperator { operator, .. } => format!("Unknown operator \"{operator}\"."),
        }
    }

    /// Warnings that C emits before the command reaches this error.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        match self {
            Self::UnknownOperator { warnings, .. } => warnings,
            Self::TooFewArguments | Self::TooManyArguments => &[],
        }
    }
}

fn version_is_valid_for_compare(value: &str) -> bool {
    // C version_is_valid() first applies filename_part_is_valid(), whose only
    // additional constraint for an argument without '/' is Linux NAME_MAX.
    // VERSION_ALLOW_EMPTY is set for this verb.
    value.len() <= 255
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'~' | b'^' | b'_' | b'+')
        })
}

fn warning(position: usize, value: &str) -> Option<String> {
    (!version_is_valid_for_compare(value)).then(|| {
        format!(
            "Version string {position} contains disallowed characters, they will be treated as separators: {value}"
        )
    })
}

fn ordering_value(ordering: Ordering) -> i32 {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn printable_version(value: &str) -> &str {
    if value.is_empty() { "''" } else { value }
}

fn comparison_operator(ordering: Ordering) -> &'static str {
    match ordering {
        Ordering::Less => "<",
        Ordering::Equal => "==",
        Ordering::Greater => ">",
    }
}

fn parse_operator(value: &str) -> Result<CompareOperator, String> {
    let Some((operator, remainder)) = parse_compare_operator(value, COMPARE_ALLOW_TEXTUAL) else {
        return Err(value.to_string());
    };

    if !remainder.is_empty() {
        return Err(remainder.to_string());
    }

    Ok(operator)
}

/// Implement C `verb_compare_versions()` for the post-verb arguments.
///
/// With two arguments it writes a human-readable comparison and uses the
/// rpmdev-vercmp-compatible 12/0/11 exit convention. With an operator it
/// emits no stdout and returns normal success/failure status.
pub fn compare_versions(
    arguments: &[String],
) -> Result<CompareVersionsResult, CompareVersionsError> {
    match arguments.len() {
        0 | 1 => return Err(CompareVersionsError::TooFewArguments),
        2 | 3 => {}
        _ => return Err(CompareVersionsError::TooManyArguments),
    }

    let first = &arguments[0];
    let last = &arguments[arguments.len() - 1];
    let ordering = strverscmp_improved(first, last);
    let warnings = [warning(1, first), warning(2, last)]
        .into_iter()
        .flatten()
        .collect();

    if arguments.len() == 2 {
        let exit_status = match ordering {
            Ordering::Less => EXIT_VERSION_LESS,
            Ordering::Equal => EXIT_SUCCESS,
            Ordering::Greater => EXIT_VERSION_GREATER,
        };
        return Ok(CompareVersionsResult {
            stdout: Some(format!(
                "{} {} {}",
                printable_version(first),
                comparison_operator(ordering),
                printable_version(last),
            )),
            warnings,
            exit_status,
        });
    }

    let operator = match parse_operator(&arguments[1]) {
        Ok(operator) => operator,
        Err(operator) => return Err(CompareVersionsError::UnknownOperator { operator, warnings }),
    };
    let matches = test_order(ordering_value(ordering), operator)
        .expect("compare-versions only accepts order comparison operators");
    Ok(CompareVersionsResult {
        stdout: None,
        warnings,
        exit_status: i32::from(!matches),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn bare_compare_matches_c_output_and_exit_statuses() {
        let result = compare_versions(&arguments(&["1", "2"])).unwrap();
        assert_eq!(result.stdout.as_deref(), Some("1 < 2"));
        assert_eq!(result.exit_status, EXIT_VERSION_LESS);

        let result = compare_versions(&arguments(&["2", "2"])).unwrap();
        assert_eq!(result.stdout.as_deref(), Some("2 == 2"));
        assert_eq!(result.exit_status, EXIT_SUCCESS);

        let result = compare_versions(&arguments(&["2", "1"])).unwrap();
        assert_eq!(result.stdout.as_deref(), Some("2 > 1"));
        assert_eq!(result.exit_status, EXIT_VERSION_GREATER);
    }

    #[test]
    fn operators_accept_c_textual_and_symbolic_spellings() {
        assert_eq!(
            compare_versions(&arguments(&["1", "lt", "2"]))
                .unwrap()
                .exit_status,
            EXIT_SUCCESS
        );
        assert_eq!(
            compare_versions(&arguments(&["1", "<=", "2"]))
                .unwrap()
                .exit_status,
            EXIT_SUCCESS
        );
        assert_eq!(
            compare_versions(&arguments(&["1", "ge", "2"]))
                .unwrap()
                .exit_status,
            EXIT_FAILURE
        );
    }

    #[test]
    fn reports_c_arity_and_operator_errors() {
        assert_eq!(
            compare_versions(&arguments(&["1"])),
            Err(CompareVersionsError::TooFewArguments)
        );
        assert_eq!(
            compare_versions(&arguments(&["1", "2", "3", "4"])),
            Err(CompareVersionsError::TooManyArguments)
        );
        assert_eq!(
            compare_versions(&arguments(&["1", "wat", "2"])),
            Err(CompareVersionsError::UnknownOperator {
                operator: "wat".to_string(),
                warnings: Vec::new(),
            })
        );
    }

    #[test]
    fn invalid_operator_retains_warnings_c_emits_first() {
        let error = compare_versions(&arguments(&["1/2", "<=suffix", "3 space"])).unwrap_err();
        assert_eq!(error.message(), "Unknown operator \"suffix\".");
        assert_eq!(
            error.warnings(),
            [
                "Version string 1 contains disallowed characters, they will be treated as separators: 1/2",
                "Version string 2 contains disallowed characters, they will be treated as separators: 3 space",
            ]
        );
    }

    #[test]
    fn version_warning_applies_c_name_max_and_character_rules() {
        let too_long = "1".repeat(256);
        let result = compare_versions(&[too_long, "1".to_string()]).unwrap();
        assert_eq!(result.warnings.len(), 1);

        let result = compare_versions(&arguments(&["1/2", "1"])).unwrap();
        assert_eq!(result.warnings.len(), 1);

        let result = compare_versions(&arguments(&["", ""])).unwrap();
        assert!(result.warnings.is_empty());
    }
}
