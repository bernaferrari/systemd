// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/taint.c
//
use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTargetState<'a> {
    Canonical(&'a str),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintEnvironment<'a> {
    pub bin_target: LinkTargetState<'a>,
    pub usr_sbin_target: LinkTargetState<'a>,
    pub var_run_target: LinkTargetState<'a>,
    pub local_hwclock: bool,
    pub support_ended: bool,
    pub kernel_release: &'a str,
    pub baseline_kernel_release: &'a str,
    pub overflow_uid: Option<&'a str>,
    pub overflow_gid: Option<&'a str>,
    pub short_uid_range: bool,
    pub short_gid_range: bool,
}

impl<'a> Default for TaintEnvironment<'a> {
    fn default() -> Self {
        Self {
            bin_target: LinkTargetState::Canonical("/usr/bin"),
            usr_sbin_target: LinkTargetState::Canonical("/usr/bin"),
            var_run_target: LinkTargetState::Canonical("/run"),
            local_hwclock: false,
            support_ended: false,
            kernel_release: "6.8.0",
            baseline_kernel_release: "5.4.0",
            overflow_uid: Some("65534"),
            overflow_gid: Some("65534"),
            short_uid_range: false,
            short_gid_range: false,
        }
    }
}

const TAINT_UNMERGED_USR: &str = "unmerged-usr";
const TAINT_UNMERGED_BIN: &str = "unmerged-bin";
const TAINT_VAR_RUN_BAD: &str = "var-run-bad";
const TAINT_LOCAL_HWCLOCK: &str = "local-hwclock";
const TAINT_SUPPORT_ENDED: &str = "support-ended";
const TAINT_OLD_KERNEL: &str = "old-kernel";
const TAINT_OVERFLOW_UID: &str = "overflowuid-not-65534";
const TAINT_OVERFLOW_GID: &str = "overflowgid-not-65534";
const TAINT_SHORT_UID_RANGE: &str = "short-uid-range";
const TAINT_SHORT_GID_RANGE: &str = "short-gid-range";

fn path_in_set(candidate: LinkTargetState<'_>, allowed: &[&str]) -> bool {
    match candidate {
        LinkTargetState::Canonical(path) => allowed.contains(&path),
        LinkTargetState::Missing => false,
    }
}

fn kernel_release_older_than(release: &str, baseline: &str) -> bool {
    systemd_basic_rs::strverscmp::strverscmp_improved(release, baseline).is_lt()
}

pub fn taint_strv(env: &TaintEnvironment<'_>) -> Result<Vec<&'static str>, Errno> {
    if env.kernel_release.is_empty() || env.baseline_kernel_release.is_empty() {
        return Err(Errno::EINVAL);
    }

    let mut taints = Vec::new();

    if !path_in_set(env.bin_target, &["usr/bin", "/usr/bin"]) {
        taints.push(TAINT_UNMERGED_USR);
    }
    if !path_in_set(env.usr_sbin_target, &["bin", "/usr/bin"]) {
        taints.push(TAINT_UNMERGED_BIN);
    }
    if !path_in_set(env.var_run_target, &["../run", "/run"]) {
        taints.push(TAINT_VAR_RUN_BAD);
    }
    if env.local_hwclock {
        taints.push(TAINT_LOCAL_HWCLOCK);
    }
    if env.support_ended {
        taints.push(TAINT_SUPPORT_ENDED);
    }
    if kernel_release_older_than(env.kernel_release, env.baseline_kernel_release) {
        taints.push(TAINT_OLD_KERNEL);
    }
    if matches!(env.overflow_uid, Some(value) if value != "65534") {
        taints.push(TAINT_OVERFLOW_UID);
    }
    if matches!(env.overflow_gid, Some(value) if value != "65534") {
        taints.push(TAINT_OVERFLOW_GID);
    }
    if env.short_uid_range {
        taints.push(TAINT_SHORT_UID_RANGE);
    }
    if env.short_gid_range {
        taints.push(TAINT_SHORT_GID_RANGE);
    }

    Ok(taints)
}

pub fn taint_string(env: &TaintEnvironment<'_>) -> Result<String, Errno> {
    Ok(taint_strv(env)?.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_environment_is_untainted() {
        let env = TaintEnvironment::default();
        assert_eq!(taint_strv(&env).unwrap(), Vec::<&str>::new());
    }

    #[test]
    fn detects_unmerged_usr() {
        let env = TaintEnvironment {
            bin_target: LinkTargetState::Canonical("/bin"),
            ..TaintEnvironment::default()
        };
        assert!(taint_strv(&env).unwrap().contains(&TAINT_UNMERGED_USR));
    }

    #[test]
    fn detects_unmerged_bin() {
        let env = TaintEnvironment {
            usr_sbin_target: LinkTargetState::Canonical("/usr/sbin"),
            ..TaintEnvironment::default()
        };
        assert!(taint_strv(&env).unwrap().contains(&TAINT_UNMERGED_BIN));
    }

    #[test]
    fn detects_var_run_misconfiguration() {
        let env = TaintEnvironment {
            var_run_target: LinkTargetState::Missing,
            ..TaintEnvironment::default()
        };
        assert!(taint_strv(&env).unwrap().contains(&TAINT_VAR_RUN_BAD));
    }

    #[test]
    fn detects_runtime_flags() {
        let env = TaintEnvironment {
            local_hwclock: true,
            support_ended: true,
            ..TaintEnvironment::default()
        };
        let taints = taint_strv(&env).unwrap();
        assert!(taints.contains(&TAINT_LOCAL_HWCLOCK));
        assert!(taints.contains(&TAINT_SUPPORT_ENDED));
    }

    #[test]
    fn detects_old_kernel() {
        let env = TaintEnvironment {
            kernel_release: "4.9.12",
            baseline_kernel_release: "5.4.0",
            ..TaintEnvironment::default()
        };
        assert!(taint_strv(&env).unwrap().contains(&TAINT_OLD_KERNEL));
    }

    #[test]
    fn kernel_release_comparison_matches_c_release_ordering() {
        assert!(kernel_release_older_than("6.8~rc1", "6.8"));
        // In systemd's version ordering, '-' introduces a release segment;
        // unlike '~', it is newer than the bare version.
        assert!(!kernel_release_older_than("6.8-rc1", "6.8"));
    }

    #[test]
    fn kernel_release_comparison_does_not_truncate_large_components() {
        assert!(kernel_release_older_than("6.42949672960", "6.42949672961"));
    }

    #[test]
    fn detects_non_standard_overflow_ids() {
        let env = TaintEnvironment {
            overflow_uid: Some("123"),
            overflow_gid: Some("456"),
            ..TaintEnvironment::default()
        };
        let taints = taint_strv(&env).unwrap();
        assert!(taints.contains(&TAINT_OVERFLOW_UID));
        assert!(taints.contains(&TAINT_OVERFLOW_GID));
    }

    #[test]
    fn detects_short_ranges() {
        let env = TaintEnvironment {
            short_uid_range: true,
            short_gid_range: true,
            ..TaintEnvironment::default()
        };
        let taints = taint_strv(&env).unwrap();
        assert!(taints.contains(&TAINT_SHORT_UID_RANGE));
        assert!(taints.contains(&TAINT_SHORT_GID_RANGE));
    }

    #[test]
    fn taint_string_preserves_order() {
        let env = TaintEnvironment {
            local_hwclock: true,
            short_gid_range: true,
            ..TaintEnvironment::default()
        };
        assert_eq!(taint_string(&env).unwrap(), "local-hwclock:short-gid-range");
    }

    #[test]
    fn empty_kernel_release_is_rejected() {
        let env = TaintEnvironment {
            kernel_release: "",
            ..TaintEnvironment::default()
        };
        assert_eq!(taint_strv(&env).unwrap_err(), Errno::EINVAL);
    }
}
