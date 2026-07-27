// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fstab-generator/fstab-generator.c

pub const MOUNT_NOAUTO: u32 = 1 << 0;
pub const MOUNT_NOFAIL: u32 = 1 << 1;
pub const MOUNT_AUTOMOUNT: u32 = 1 << 2;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub what: String,
    pub where_: String,
    pub fstype: String,
    pub options: String,
    pub passno: u32,
}
pub fn parse_line(line: &str) -> Option<Entry> {
    if line.trim().is_empty() || line.trim_start().starts_with('#') {
        return None;
    }
    let f: Vec<_> = line.split_whitespace().collect();
    if f.len() < 2 {
        return None;
    }
    Some(Entry {
        what: f[0].into(),
        where_: f[1].into(),
        fstype: f.get(2).copied().unwrap_or("auto").into(),
        options: f.get(3).copied().unwrap_or("").into(),
        passno: f.get(5).and_then(|x| x.parse().ok()).unwrap_or(0),
    })
}
pub fn mount_unit(path: &str) -> String {
    let e = path.trim_matches('/').replace('/', "-");
    if e.is_empty() {
        "-.mount".into()
    } else {
        format!("{e}.mount")
    }
}
pub fn is_network_fs(t: &str) -> bool {
    matches!(
        t,
        "nfs" | "nfs4" | "cifs" | "9p" | "glusterfs" | "fuse.sshfs"
    )
}
pub fn mount_flags(options: &str) -> u32 {
    let mut f = 0;
    for o in options.split(',') {
        match o {
            "noauto" => f |= MOUNT_NOAUTO,
            "nofail" => f |= MOUNT_NOFAIL,
            "x-systemd.automount" => f |= MOUNT_AUTOMOUNT,
            _ => {}
        }
    }
    f
}
pub fn root_rw(options: &str) -> Option<bool> {
    if options.split(',').any(|o| o == "rw") {
        Some(true)
    } else if options.split(',').any(|o| o == "ro") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_basic_line() {
        assert_eq!(
            parse_line("/dev/sda1 / ext4 defaults 0 1").unwrap().passno,
            1
        );
    }
    #[test]
    fn ignore_comment() {
        assert!(parse_line("# x").is_none());
    }
    #[test]
    fn ignore_empty() {
        assert!(parse_line("").is_none());
    }
    #[test]
    fn root_unit_name() {
        assert_eq!(mount_unit("/"), "-.mount");
    }
    #[test]
    fn nested_unit_name() {
        assert_eq!(mount_unit("/var/lib"), "var-lib.mount");
    }
    #[test]
    fn network_fs_detected() {
        assert!(is_network_fs("nfs"));
    }
    #[test]
    fn local_fs_not_network() {
        assert!(!is_network_fs("ext4"));
    }
    #[test]
    fn flags_parse_noauto() {
        assert!(mount_flags("noauto") & MOUNT_NOAUTO != 0);
    }
    #[test]
    fn flags_parse_automount() {
        assert!(mount_flags("x-systemd.automount") & MOUNT_AUTOMOUNT != 0);
    }
    #[test]
    fn root_rw_finds_ro() {
        assert_eq!(root_rw("ro,noatime"), Some(false));
    }
}
