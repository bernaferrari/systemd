// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/delta/delta.c
//
// Safe Rust model of override classification used by systemd-delta.

pub const SHOW_MASKED: u32 = 1 << 0;
pub const SHOW_EQUIVALENT: u32 = 1 << 1;
pub const SHOW_REDIRECTED: u32 = 1 << 2;
pub const SHOW_OVERRIDDEN: u32 = 1 << 3;
pub const SHOW_UNCHANGED: u32 = 1 << 4;
pub const SHOW_EXTENDED: u32 = 1 << 5;
pub const SHOW_DEFAULTS: u32 =
    SHOW_MASKED | SHOW_EQUIVALENT | SHOW_REDIRECTED | SHOW_OVERRIDDEN | SHOW_EXTENDED;

pub const PREFIXES: &[&str] = &[
    "/etc",
    "/run",
    "/usr/local/lib",
    "/usr/local/share",
    "/usr/lib",
    "/usr/share",
];
pub const SUFFIXES: &[&str] = &[
    "sysctl.d",
    "tmpfiles.d",
    "modules-load.d",
    "binfmt.d",
    "systemd/system",
    "systemd/user",
    "systemd/system-preset",
    "systemd/user-preset",
    "udev/rules.d",
    "modprobe.d",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideType {
    Masked,
    Equivalent,
    Redirected,
    Overridden,
    Unchanged,
    Extended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub diff: bool,
    pub flags: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            diff: false,
            flags: SHOW_DEFAULTS,
        }
    }
}

pub fn build_scan_paths() -> Vec<String> {
    PREFIXES
        .iter()
        .flat_map(|p| SUFFIXES.iter().map(move |s| format!("{p}/{s}")))
        .collect()
}

pub fn classify(
    top: &str,
    bottom: &str,
    top_is_empty: bool,
    top_is_symlink: bool,
    symlink_target_matches: Option<bool>,
) -> OverrideType {
    if top_is_empty {
        OverrideType::Masked
    } else if top_is_symlink && symlink_target_matches == Some(true) {
        OverrideType::Equivalent
    } else if top_is_symlink {
        OverrideType::Redirected
    } else if top == bottom {
        OverrideType::Unchanged
    } else if top.starts_with(bottom) || bottom.starts_with(top) {
        OverrideType::Extended
    } else {
        OverrideType::Overridden
    }
}

pub fn label(kind: OverrideType) -> &'static str {
    match kind {
        OverrideType::Masked => "[MASKED]",
        OverrideType::Equivalent => "[EQUIVALENT]",
        OverrideType::Redirected => "[REDIRECTED]",
        OverrideType::Overridden => "[OVERRIDDEN]",
        OverrideType::Unchanged => "[UNCHANGED]",
        OverrideType::Extended => "[EXTENDED]",
    }
}

pub fn enabled(flags: u32, kind: OverrideType) -> bool {
    let bit = match kind {
        OverrideType::Masked => SHOW_MASKED,
        OverrideType::Equivalent => SHOW_EQUIVALENT,
        OverrideType::Redirected => SHOW_REDIRECTED,
        OverrideType::Overridden => SHOW_OVERRIDDEN,
        OverrideType::Unchanged => SHOW_UNCHANGED,
        OverrideType::Extended => SHOW_EXTENDED,
    };
    flags & bit != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_follow_c() {
        assert_eq!(Config::default().flags, SHOW_DEFAULTS);
    }
    #[test]
    fn path_matrix_size() {
        assert_eq!(build_scan_paths().len(), PREFIXES.len() * SUFFIXES.len());
    }
    #[test]
    fn masked_classification() {
        assert_eq!(
            classify("", "/usr/lib/x", true, false, None),
            OverrideType::Masked
        );
    }
    #[test]
    fn equivalent_classification() {
        assert_eq!(
            classify("a", "b", false, true, Some(true)),
            OverrideType::Equivalent
        );
    }
    #[test]
    fn redirected_classification() {
        assert_eq!(
            classify("a", "b", false, true, Some(false)),
            OverrideType::Redirected
        );
    }
    #[test]
    fn unchanged_classification() {
        assert_eq!(
            classify("a", "a", false, false, None),
            OverrideType::Unchanged
        );
    }
    #[test]
    fn extended_classification() {
        assert_eq!(
            classify("a/b", "a", false, false, None),
            OverrideType::Extended
        );
    }
    #[test]
    fn overridden_classification() {
        assert_eq!(
            classify("a", "z", false, false, None),
            OverrideType::Overridden
        );
    }
    #[test]
    fn labels_match_output() {
        assert_eq!(label(OverrideType::Masked), "[MASKED]");
    }
    #[test]
    fn enabled_checks_bits() {
        assert!(enabled(SHOW_MASKED, OverrideType::Masked));
    }
}
