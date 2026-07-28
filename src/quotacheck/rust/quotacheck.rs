// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-quotacheck-rs: conservative Rust shadow module for quotacheck.c
//
// Shadow port of src/quotacheck/quotacheck.c.
// Runs quotacheck on filesystems after fsck detected errors.

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCheckMode {
    Auto = 0,
    Force,
    Skip,
}

pub fn quota_check_mode_from_string(s: &str) -> Result<QuotaCheckMode> {
    match s {
        "auto" => Ok(QuotaCheckMode::Auto),
        "force" => Ok(QuotaCheckMode::Force),
        "skip" => Ok(QuotaCheckMode::Skip),
        _ => Err(Errno(-libc::EINVAL)),
    }
}

pub fn quota_check_mode_to_string(mode: QuotaCheckMode) -> &'static str {
    match mode {
        QuotaCheckMode::Auto => "auto",
        QuotaCheckMode::Force => "force",
        QuotaCheckMode::Skip => "skip",
    }
}

pub fn parse_proc_cmdline_item(key: &str, value: Option<&str>) -> Option<QuotaCheckMode> {
    if key == "quotacheck.mode" {
        if let Some(v) = value {
            return quota_check_mode_from_string(v).ok();
        }
    } else if key == "forcequotacheck" && value.is_none() {
        return Some(QuotaCheckMode::Force);
    }
    None
}

pub fn should_run_quotacheck(mode: QuotaCheckMode, trigger_file_exists: bool) -> bool {
    match mode {
        QuotaCheckMode::Skip => false,
        QuotaCheckMode::Force => true,
        QuotaCheckMode::Auto => trigger_file_exists,
    }
}

pub fn build_quotacheck_args(path: Option<&str>) -> Vec<&'static str> {
    if path.is_some() {
        vec!["quotacheck", "-nug"]
    } else {
        vec!["quotacheck", "-anug"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_from_string() {
        assert_eq!(
            quota_check_mode_from_string("auto").unwrap(),
            QuotaCheckMode::Auto
        );
        assert_eq!(
            quota_check_mode_from_string("force").unwrap(),
            QuotaCheckMode::Force
        );
        assert_eq!(
            quota_check_mode_from_string("skip").unwrap(),
            QuotaCheckMode::Skip
        );
        assert!(quota_check_mode_from_string("bad").is_err());
    }

    #[test]
    fn mode_roundtrip() {
        for m in [
            QuotaCheckMode::Auto,
            QuotaCheckMode::Force,
            QuotaCheckMode::Skip,
        ] {
            assert_eq!(
                quota_check_mode_from_string(quota_check_mode_to_string(m)).unwrap(),
                m
            );
        }
    }

    #[test]
    fn parse_cmdline() {
        assert_eq!(
            parse_proc_cmdline_item("quotacheck.mode", Some("force")),
            Some(QuotaCheckMode::Force)
        );
        assert_eq!(
            parse_proc_cmdline_item("forcequotacheck", None),
            Some(QuotaCheckMode::Force)
        );
        assert_eq!(parse_proc_cmdline_item("other", None), None);
    }

    #[test]
    fn should_run() {
        assert!(!should_run_quotacheck(QuotaCheckMode::Skip, true));
        assert!(should_run_quotacheck(QuotaCheckMode::Force, false));
        assert!(should_run_quotacheck(QuotaCheckMode::Auto, true));
        assert!(!should_run_quotacheck(QuotaCheckMode::Auto, false));
    }

    #[test]
    fn build_args() {
        let args = build_quotacheck_args(None);
        assert!(args.contains(&"-anug"));
        let args = build_quotacheck_args(Some("/mnt"));
        assert!(args.contains(&"-nug"));
    }
}
