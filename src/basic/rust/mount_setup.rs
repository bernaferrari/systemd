// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mount-setup.c (mount_point_is_api, mount_point_ignore)
//
// Mount point classification — pure string comparison against static tables.

// ── API mount point table ──────────────────────────────────────────────────
// These are the .where fields from the mount_table in mount-setup.c.

const API_MOUNT_POINTS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/sys/kernel/security",
    "/sys/fs/smackfs",
    "/dev/shm",
    "/dev/pts",
    "/run",
    "/sys/fs/cgroup",
    "/sys/fs/pstore",
    "/sys/firmware/efi/efivars",
    "/sys/fs/bpf",
];

const CGROUP_PREFIX: &str = "/sys/fs/cgroup/";

// ── Ignore mount point table ───────────────────────────────────────────────

const IGNORE_MOUNT_POINTS: &[&str] = &[
    "/sys/fs/selinux",
    "/dev/console",
    "/proc/kmsg",
    "/proc/sys",
    "/proc/sys/kernel/random/boot_id",
];

const RUN_HOST_PREFIX: &str = "/run/host";

// ── Internal helpers ───────────────────────────────────────────────────────

/// Pure Rust path equality: exact string match for normalized paths.
fn path_equal(path: &str, candidate: &str) -> bool {
    path == candidate
}

/// Pure Rust path_startswith: returns Some(remaining) if path starts with prefix.
fn path_startswith<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if path.starts_with(prefix) {
        Some(&path[prefix.len()..])
    } else {
        None
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Check if the path is an API mount point (managed by systemd).
///
/// Port of `mount_point_is_api()` from mount-setup.c.
/// Matches any path in the API table or anything under `/sys/fs/cgroup/`.
pub fn mount_point_is_api(path: &str) -> bool {
    for entry in API_MOUNT_POINTS {
        if path_equal(path, entry) {
            return true;
        }
    }
    path_startswith(path, CGROUP_PREFIX).is_some()
}

/// Check if the mount point should be ignored by systemd.
///
/// Port of `mount_point_ignore()` from mount-setup.c.
/// Matches paths in the ignore table or anything under `/run/host`.
pub fn mount_point_ignore(path: &str) -> bool {
    for entry in IGNORE_MOUNT_POINTS {
        if path_equal(path, entry) {
            return true;
        }
    }
    path_startswith(path, RUN_HOST_PREFIX).is_some()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── mount_point_is_api tests ─────────────────────────────────────────

    #[test]
    fn test_is_api_proc() {
        assert!(mount_point_is_api("/proc"));
    }

    #[test]
    fn test_is_api_sys() {
        assert!(mount_point_is_api("/sys"));
    }

    #[test]
    fn test_is_api_dev() {
        assert!(mount_point_is_api("/dev"));
    }

    #[test]
    fn test_is_api_run() {
        assert!(mount_point_is_api("/run"));
    }

    #[test]
    fn test_is_api_cgroup() {
        assert!(mount_point_is_api("/sys/fs/cgroup"));
    }

    #[test]
    fn test_is_api_cgroup_subdir() {
        assert!(mount_point_is_api("/sys/fs/cgroup/systemd"));
    }

    #[test]
    fn test_is_api_cgroup_deep() {
        assert!(mount_point_is_api("/sys/fs/cgroup/cpu/user.slice"));
    }

    #[test]
    fn test_is_api_dev_shm() {
        assert!(mount_point_is_api("/dev/shm"));
    }

    #[test]
    fn test_is_api_dev_pts() {
        assert!(mount_point_is_api("/dev/pts"));
    }

    #[test]
    fn test_is_api_security() {
        assert!(mount_point_is_api("/sys/kernel/security"));
    }

    #[test]
    fn test_is_api_efivars() {
        assert!(mount_point_is_api("/sys/firmware/efi/efivars"));
    }

    #[test]
    fn test_is_api_bpf() {
        assert!(mount_point_is_api("/sys/fs/bpf"));
    }

    #[test]
    fn test_is_api_pstore() {
        assert!(mount_point_is_api("/sys/fs/pstore"));
    }

    #[test]
    fn test_is_api_smackfs() {
        assert!(mount_point_is_api("/sys/fs/smackfs"));
    }

    #[test]
    fn test_is_api_not_api() {
        assert!(!mount_point_is_api("/home"));
        assert!(!mount_point_is_api("/tmp"));
        assert!(!mount_point_is_api("/var"));
        assert!(!mount_point_is_api("/etc"));
    }

    #[test]
    fn test_is_api_empty() {
        assert!(!mount_point_is_api(""));
    }

    #[test]
    fn test_is_api_partial_match() {
        assert!(!mount_point_is_api("/procfs"));
        assert!(!mount_point_is_api("/sysfs"));
    }

    #[test]
    fn test_is_api_cgroup_prefix_only() {
        // "/sys/fs/cgroup/" itself should match as a cgroup path
        assert!(mount_point_is_api("/sys/fs/cgroup/"));
    }

    // ── mount_point_ignore tests ─────────────────────────────────────────

    #[test]
    fn test_ignore_selinux() {
        assert!(mount_point_ignore("/sys/fs/selinux"));
    }

    #[test]
    fn test_ignore_console() {
        assert!(mount_point_ignore("/dev/console"));
    }

    #[test]
    fn test_ignore_kmsg() {
        assert!(mount_point_ignore("/proc/kmsg"));
    }

    #[test]
    fn test_ignore_proc_sys() {
        assert!(mount_point_ignore("/proc/sys"));
    }

    #[test]
    fn test_ignore_boot_id() {
        assert!(mount_point_ignore("/proc/sys/kernel/random/boot_id"));
    }

    #[test]
    fn test_ignore_run_host() {
        assert!(mount_point_ignore("/run/host"));
        assert!(mount_point_ignore("/run/host/usr"));
        assert!(mount_point_ignore("/run/host/os-release"));
    }

    #[test]
    fn test_ignore_not_ignored() {
        assert!(!mount_point_ignore("/home"));
        assert!(!mount_point_ignore("/var/log"));
    }

    #[test]
    fn test_ignore_empty() {
        assert!(!mount_point_ignore(""));
    }

    #[test]
    fn test_ignore_run_host_trailing_slash() {
        assert!(mount_point_ignore("/run/host/"));
    }
}
