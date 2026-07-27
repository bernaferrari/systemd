// SPDX-License-Identifier: GPL-2.0-or-later
//
// PORT-SYNC: src/udev/udevadm-verify.c
//
// udevadm verify — validate udev rules files.
//
// Defines argument parsing, rules-file verification result tracking,
// and summary formatting for the verify subcommand.

// ── Resolve name timing ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveNameTiming {
    Early,
    Late,
    Never,
}

impl ResolveNameTiming {
    pub fn from_str(s: &str) -> Option<ResolveNameTiming> {
        match s {
            "early" => Some(ResolveNameTiming::Early),
            "late" => Some(ResolveNameTiming::Late),
            "never" => Some(ResolveNameTiming::Never),
            _ => None,
        }
    }
}

// ── Parsed arguments ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    pub resolve_name_timing: ResolveNameTiming,
    pub root: Option<String>,
    pub summary: bool,
    pub style: bool,
}

impl Default for VerifyArgs {
    fn default() -> Self {
        Self {
            resolve_name_timing: ResolveNameTiming::Early,
            root: None,
            summary: true,
            style: true,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    HelpRequested,
    VersionRequested,
    InvalidOption(String),
    InvalidResolveName(String),
    InvalidPath(String),
    RulesParseFailed(String),
    RulesCheckFailed(String),
    StyleIssues(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::HelpRequested => write!(f, "help requested"),
            VerifyError::VersionRequested => write!(f, "version requested"),
            VerifyError::InvalidOption(opt) => write!(f, "Invalid option: {opt}"),
            VerifyError::InvalidResolveName(s) => {
                write!(
                    f,
                    "--resolve-names= must be early, late, or never. Got: {s}"
                )
            }
            VerifyError::InvalidPath(s) => write!(f, "Invalid path: {s}"),
            VerifyError::RulesParseFailed(path) => {
                write!(f, "{path}: udev rules check failed.")
            }
            VerifyError::RulesCheckFailed(path) => {
                write!(f, "{path}: udev rules check failed.")
            }
            VerifyError::StyleIssues(path) => {
                write!(f, "{path}: udev rules have style issues.")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

// ── Issue tracking ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueMask(u32);

impl IssueMask {
    pub const ERROR: IssueMask = IssueMask(1 << 3);
    pub const WARNING: IssueMask = IssueMask(1 << 4);
    pub const NOTICE: IssueMask = IssueMask(1 << 5);
    pub const EMPTY: IssueMask = IssueMask(0);

    pub fn intersects(self, other: IssueMask) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn contains(self, other: IssueMask) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for IssueMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        IssueMask(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVerifyResult {
    pub path: String,
    pub issues: IssueMask,
    pub success: bool,
}

impl FileVerifyResult {
    pub fn new(path: &str, issues: IssueMask) -> Self {
        let has_errors = issues.intersects(IssueMask::ERROR | IssueMask::WARNING);
        let has_style = issues.intersects(IssueMask::NOTICE);
        Self {
            path: path.to_string(),
            issues,
            success: !has_errors && !has_style,
        }
    }

    pub fn has_errors(&self) -> bool {
        self.issues
            .intersects(IssueMask::ERROR | IssueMask::WARNING)
    }

    pub fn has_style_issues(&self) -> bool {
        self.issues.intersects(IssueMask::NOTICE)
    }

    pub fn check(&self, check_style: bool) -> Result<(), VerifyError> {
        if self.has_errors() {
            return Err(VerifyError::RulesCheckFailed(self.path.clone()));
        }
        if check_style && self.has_style_issues() {
            return Err(VerifyError::StyleIssues(self.path.clone()));
        }
        Ok(())
    }
}

// ── Summary formatting ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
}

impl VerifySummary {
    pub fn from_results(results: &[FileVerifyResult], check_style: bool) -> Self {
        let mut success = 0;
        let mut failed = 0;
        for r in results {
            if r.check(check_style).is_ok() {
                success += 1;
            } else {
                failed += 1;
            }
        }
        Self {
            total: results.len(),
            success,
            failed,
        }
    }

    pub fn format(&self) -> String {
        let fail_highlight = if self.failed > 0 { "\x1b[31;1m" } else { "" };
        let fail_reset = if self.failed > 0 { "\x1b[0m" } else { "" };
        format!(
            "\n\x1b[1m{} udev rules files have been checked.\x1b[0m\n\
             Success: {}\n\
             {fail_highlight}Fail:    {}{fail_reset}\n",
            self.total, self.success, self.failed
        )
    }
}

// ── Validation ────────────────────────────────────────────────────────────

pub fn validate_resolve_name(s: &str) -> Result<ResolveNameTiming, VerifyError> {
    ResolveNameTiming::from_str(s).ok_or_else(|| VerifyError::InvalidResolveName(s.to_string()))
}

pub fn validate_root_path(s: &str) -> Result<String, VerifyError> {
    if s.is_empty() || s.contains('\0') {
        Err(VerifyError::InvalidPath(s.to_string()))
    } else {
        Ok(s.to_string())
    }
}

// ── Help text ─────────────────────────────────────────────────────────────

pub fn help_text(program_name: &str) -> String {
    format!(
        "{program_name} verify [OPTIONS] [FILE...]\n\n\
         Verify udev rules files.\n\n\
         -h --help                            Show this help\n\
         -V --version                         Show package version\n\
         -N --resolve-names=early|late|never  When to resolve names\n\
            --root=PATH                       Operate on an alternate filesystem root\n\
            --no-summary                      Do not show summary\n\
            --no-style                        Ignore style issues\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_name_from_str() {
        assert_eq!(
            ResolveNameTiming::from_str("early"),
            Some(ResolveNameTiming::Early)
        );
        assert_eq!(
            ResolveNameTiming::from_str("late"),
            Some(ResolveNameTiming::Late)
        );
        assert_eq!(
            ResolveNameTiming::from_str("never"),
            Some(ResolveNameTiming::Never)
        );
        assert_eq!(ResolveNameTiming::from_str("bad"), None);
    }

    #[test]
    fn test_validate_resolve_name() {
        assert!(validate_resolve_name("early").is_ok());
        assert!(validate_resolve_name("bad").is_err());
    }

    #[test]
    fn test_validate_root_path() {
        assert!(validate_root_path("/").is_ok());
        assert!(validate_root_path("").is_err());
    }

    #[test]
    fn test_file_verify_result_no_issues() {
        let result = FileVerifyResult::new("test.rules", IssueMask::EMPTY);
        assert!(result.success);
        assert!(!result.has_errors());
        assert!(!result.has_style_issues());
        assert!(result.check(true).is_ok());
    }

    #[test]
    fn test_file_verify_result_errors() {
        let result = FileVerifyResult::new("bad.rules", IssueMask::ERROR);
        assert!(!result.success);
        assert!(result.has_errors());
        assert!(result.check(true).is_err());
    }

    #[test]
    fn test_file_verify_result_style_only() {
        let result = FileVerifyResult::new("style.rules", IssueMask::NOTICE);
        assert!(result.check(false).is_ok());
        assert!(result.check(true).is_err());
    }

    #[test]
    fn test_file_verify_result_warnings() {
        let result = FileVerifyResult::new("warn.rules", IssueMask::WARNING);
        assert!(result.has_errors());
        assert!(result.check(true).is_err());
    }

    #[test]
    fn test_verify_summary() {
        let results = vec![
            FileVerifyResult::new("ok.rules", IssueMask::EMPTY),
            FileVerifyResult::new("bad.rules", IssueMask::ERROR),
            FileVerifyResult::new("style.rules", IssueMask::NOTICE),
        ];
        let summary = VerifySummary::from_results(&results, true);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.success, 1);
        assert_eq!(summary.failed, 2);
    }

    #[test]
    fn test_verify_summary_no_style() {
        let results = vec![
            FileVerifyResult::new("ok.rules", IssueMask::EMPTY),
            FileVerifyResult::new("style.rules", IssueMask::NOTICE),
        ];
        let summary = VerifySummary::from_results(&results, false);
        assert_eq!(summary.success, 2);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_summary_format() {
        let summary = VerifySummary {
            total: 5,
            success: 3,
            failed: 2,
        };
        let text = summary.format();
        assert!(text.contains("5 udev rules files"));
        assert!(text.contains("3"));
        assert!(text.contains("2"));
    }

    #[test]
    fn test_summary_format_no_failures() {
        let summary = VerifySummary {
            total: 2,
            success: 2,
            failed: 0,
        };
        let text = summary.format();
        assert!(!text.contains("\x1b[31;1m"));
    }

    #[test]
    fn test_default_args() {
        let args = VerifyArgs::default();
        assert!(args.summary);
        assert!(args.style);
        assert!(args.root.is_none());
    }

    #[test]
    fn test_help_text() {
        let help = help_text("udevadm");
        assert!(help.contains("--resolve-names"));
        assert!(help.contains("--root"));
        assert!(help.contains("--no-style"));
    }
}
