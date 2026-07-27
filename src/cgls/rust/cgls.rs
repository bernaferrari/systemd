// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/cgls/cgls.c

pub const OUTPUT_SHOW_ALL: u32 = 1 << 0;
pub const OUTPUT_KERNEL_THREADS: u32 = 1 << 1;
pub const OUTPUT_FULL_WIDTH: u32 = 1 << 2;
pub const OUTPUT_CGROUP_XATTRS: u32 = 1 << 3;
pub const OUTPUT_CGROUP_ID: u32 = 1 << 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowUnit {
    None,
    System,
    User,
}
pub fn parse_show_unit(system: bool, user: bool) -> Result<ShowUnit, i32> {
    match (system, user) {
        (true, true) => Err(-22),
        (true, false) => Ok(ShowUnit::System),
        (false, true) => Ok(ShowUnit::User),
        _ => Ok(ShowUnit::None),
    }
}
pub fn info(path: &str) -> String {
    format!("CGroup {}:", if path.is_empty() { "/" } else { path })
}
pub fn recalc_flags(base: u32, full: Option<bool>, pager: bool) -> u32 {
    if full.unwrap_or(pager) {
        base | OUTPUT_FULL_WIDTH
    } else {
        base
    }
}
pub fn is_sysfs_path(p: &str) -> bool {
    p.starts_with("/sys/fs/cgroup")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_none() {
        assert_eq!(parse_show_unit(false, false).unwrap(), ShowUnit::None);
    }
    #[test]
    fn parse_system() {
        assert_eq!(parse_show_unit(true, false).unwrap(), ShowUnit::System);
    }
    #[test]
    fn parse_user() {
        assert_eq!(parse_show_unit(false, true).unwrap(), ShowUnit::User);
    }
    #[test]
    fn mixed_mode_fails() {
        assert!(parse_show_unit(true, true).is_err());
    }
    #[test]
    fn info_root() {
        assert_eq!(info(""), "CGroup /:");
    }
    #[test]
    fn info_path() {
        assert_eq!(info("/x"), "CGroup /x:");
    }
    #[test]
    fn pager_enables_full() {
        assert!(recalc_flags(0, None, true) & OUTPUT_FULL_WIDTH != 0);
    }
    #[test]
    fn explicit_false_disables_full() {
        assert_eq!(recalc_flags(0, Some(false), true), 0);
    }
    #[test]
    fn sysfs_path_detection() {
        assert!(is_sysfs_path("/sys/fs/cgroup/a"));
    }
    #[test]
    fn non_sysfs_path_detection() {
        assert!(!is_sysfs_path("/tmp"));
    }
}
