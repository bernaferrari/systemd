// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fstab-util.c

use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FstabError {
    Io(io::ErrorKind, String),
    Parse(String),
}

impl fmt::Display for FstabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind, msg) => write!(f, "I/O error ({kind}): {msg}"),
            Self::Parse(msg) => write!(f, "fstab parse error: {msg}"),
        }
    }
}

impl std::error::Error for FstabError {}

impl From<io::Error> for FstabError {
    fn from(e: io::Error) -> Self {
        FstabError::Io(e.kind(), e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FstabEntry {
    pub device_spec: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
    pub dump: i32,
    pub pass_no: i32,
}

impl FstabEntry {
    pub fn parse_line(line: &str) -> Option<Result<Self, FstabError>> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 4 {
            return Some(Err(FstabError::Parse(format!(
                "fstab line has only {} fields, expected at least 4",
                fields.len()
            ))));
        }

        let device_spec = fields[0].to_string();
        let mount_point = fields[1].to_string();
        let fs_type = fields[2].to_string();
        let options = fields[3].to_string();
        let dump = fields
            .get(4)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);
        let pass_no = fields
            .get(5)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);

        Some(Ok(FstabEntry {
            device_spec,
            mount_point,
            fs_type,
            options,
            dump,
            pass_no,
        }))
    }

    pub fn parse_all(content: &str) -> Result<Vec<Self>, FstabError> {
        let mut entries = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if let Some(result) = Self::parse_line(line) {
                entries
                    .push(result.map_err(|e| FstabError::Parse(format!("line {}: {e}", i + 1)))?);
            }
        }
        Ok(entries)
    }
}

pub fn read_fstab() -> Result<Vec<FstabEntry>, FstabError> {
    let path = fstab_path();
    let content = fs::read_to_string(path)?;
    FstabEntry::parse_all(&content)
}

pub fn fstab_enabled() -> bool {
    fstab_enabled_full(None)
}

pub fn fstab_enabled_full(enabled: Option<bool>) -> bool {
    static CACHE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

    if let Some(val) = enabled {
        CACHE.store(val as i32, std::sync::atomic::Ordering::Relaxed);
        return val;
    }

    let cached = CACHE.load(std::sync::atomic::Ordering::Relaxed);
    if cached >= 0 {
        return cached != 0;
    }

    true
}

pub fn fstab_is_extrinsic(mount: &str, opts: Option<&str>) -> bool {
    if matches!(mount, "/" | "/usr" | "/etc") {
        return true;
    }

    let prefixes = ["/run/initramfs", "/run/nextroot", "/proc", "/sys", "/dev"];

    for prefix in &prefixes {
        if mount.starts_with(prefix) {
            return true;
        }
    }

    if fstab_test_option(opts, &["x-initrd.mount"]) {
        return true;
    }

    false
}

pub fn fstab_is_bind(options: Option<&str>, fstype: Option<&str>) -> bool {
    if fstab_test_option(options, &["bind", "rbind"]) {
        return true;
    }

    if let Some(t) = fstype {
        if matches!(t, "bind" | "rbind") {
            return true;
        }
    }

    false
}

pub fn fstab_test_option(opts: Option<&str>, names: &[&str]) -> bool {
    let opts = match opts {
        Some(o) if !o.is_empty() => o,
        _ => return false,
    };

    for word in opts.split(',') {
        let word = word.trim();
        for name in names {
            if word == *name || word.starts_with(&format!("{name}=")) {
                return true;
            }
        }
    }

    false
}

pub fn fstab_test_yes_no_option(opts: Option<&str>, yes_no: &[&str; 2]) -> bool {
    let Some(opts) = opts else {
        return false;
    };

    for word in opts.split(',') {
        let word = word.trim();
        for (i, name) in yes_no.iter().enumerate() {
            if word == *name || word.starts_with(&format!("{name}=")) {
                return i == 0;
            }
        }
    }

    false
}

#[derive(Debug, Clone, Default)]
pub struct FilteredOptions {
    pub name_found: Option<String>,
    pub value: Option<String>,
    pub values: Vec<String>,
    pub filtered: Option<String>,
}

pub fn fstab_filter_options(
    opts: Option<&str>,
    names: &[&str],
    want_value: bool,
    want_values: bool,
    want_filtered: bool,
) -> Result<FilteredOptions, FstabError> {
    let mut result = FilteredOptions::default();

    let opts = match opts {
        Some(o) if !o.is_empty() => o,
        _ => return Ok(result),
    };

    if !want_value && !want_values && !want_filtered {
        for word in opts.split(',') {
            let word = word.trim();
            for name in names {
                if word == *name || word.starts_with(&format!("{name}=")) {
                    result.name_found = Some(name.to_string());
                    return Ok(result);
                }
            }
        }
        return Ok(result);
    }

    let mut filtered_parts: Vec<String> = Vec::new();

    for word in opts.split(',') {
        let word = word.trim();
        let mut matched = false;

        for name in names {
            if let Some(rest) = word.strip_prefix(name) {
                if rest.is_empty() || rest.starts_with('=') {
                    result.name_found = Some(name.to_string());

                    if want_value || want_values {
                        let val = rest.strip_prefix('=').unwrap_or("").to_string();
                        if want_value {
                            result.value = Some(val.clone());
                        }
                        if want_values {
                            result.values.push(val);
                        }
                    }

                    matched = true;
                    break;
                }
            }
        }

        if !matched && want_filtered {
            filtered_parts.push(word.to_string());
        }
    }

    if want_filtered {
        result.filtered = Some(filtered_parts.join(","));
    }

    Ok(result)
}

pub fn fstab_find_pri(opts: Option<&str>) -> Result<Option<i32>, FstabError> {
    let filtered = fstab_filter_options(opts, &["pri"], true, false, false)?;

    if filtered.name_found.is_none() {
        return Ok(None);
    }

    let val = filtered.value.unwrap_or_default();
    let pri: i32 = val
        .parse()
        .map_err(|_| FstabError::Parse(format!("invalid swap priority: {val}")))?;

    Ok(Some(pri))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() < 2 {
        return s.to_string();
    }

    let first = s.as_bytes()[0];
    let last = s.as_bytes()[s.len() - 1];

    if (first == b'"' || first == b'\'') && first == last {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn encode_devnode_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 4);
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            for byte in ch.encode_utf8(&mut [0u8; 4]).as_bytes() {
                out.push_str(&format!("\\x{byte:02X}"));
            }
        }
    }
    out
}

fn tag_to_udev_node(tagvalue: &str, by: &str) -> PathBuf {
    let unquoted = unquote(tagvalue);
    let encoded = encode_devnode_name(&unquoted);
    PathBuf::from(format!("/dev/disk/by-{by}/{encoded}"))
}

pub fn fstab_node_to_udev_node(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("LABEL=") {
        return tag_to_udev_node(rest, "label");
    }

    if let Some(rest) = p.strip_prefix("UUID=") {
        return tag_to_udev_node(rest, "uuid");
    }

    if let Some(rest) = p.strip_prefix("PARTUUID=") {
        return tag_to_udev_node(rest, "partuuid");
    }

    if let Some(rest) = p.strip_prefix("PARTLABEL=") {
        return tag_to_udev_node(rest, "partlabel");
    }

    PathBuf::from(p)
}

pub fn fstab_path() -> PathBuf {
    env::var("SYSTEMD_FSTAB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/fstab"))
}

pub fn find_by_mountpoint<'a>(
    entries: &'a [FstabEntry],
    mount_point: &str,
) -> Option<&'a FstabEntry> {
    entries.iter().find(|e| e.mount_point == mount_point)
}

pub fn find_by_device<'a>(entries: &'a [FstabEntry], device_spec: &str) -> Option<&'a FstabEntry> {
    entries.iter().find(|e| e.device_spec == device_spec)
}

pub fn fstab_has_fstype(entries: &[FstabEntry], fstype: &str) -> bool {
    entries.iter().any(|e| e.fs_type == fstype)
}

pub fn fstab_has_mount_point_prefix(entries: &[FstabEntry], prefixes: &[&str]) -> bool {
    entries.iter().any(|e| {
        prefixes
            .iter()
            .any(|prefix| e.mount_point.starts_with(prefix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_basic() {
        let line = "/dev/sda1 / ext4 defaults 0 1";
        let entry = FstabEntry::parse_line(line).unwrap().unwrap();
        assert_eq!(entry.device_spec, "/dev/sda1");
        assert_eq!(entry.mount_point, "/");
        assert_eq!(entry.fs_type, "ext4");
        assert_eq!(entry.options, "defaults");
        assert_eq!(entry.dump, 0);
        assert_eq!(entry.pass_no, 1);
    }

    #[test]
    fn parse_line_comment_returns_none() {
        assert!(FstabEntry::parse_line("# this is a comment").is_none());
    }

    #[test]
    fn parse_line_blank_returns_none() {
        assert!(FstabEntry::parse_line("").is_none());
        assert!(FstabEntry::parse_line("   \t  ").is_none());
    }

    #[test]
    fn parse_line_too_few_fields() {
        let result = FstabEntry::parse_line("/dev/sda1 / ext4");
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn parse_line_defaults_dump_and_pass() {
        let line = "/dev/sda1 /boot ext4 nosuid  ";
        let entry = FstabEntry::parse_line(line).unwrap().unwrap();
        assert_eq!(entry.dump, 0);
        assert_eq!(entry.pass_no, 0);
    }

    #[test]
    fn parse_all_fstab_content() {
        let content = "\
# /etc/fstab: static file system information
UUID=abcd-1234 /boot ext4 defaults 0 2
/dev/sda2 swap swap pri=10 0 0
LABEL=data /data ext4 noatime 0 0

proc /proc proc nosuid,nodev,noexec 0 0
";
        let entries = FstabEntry::parse_all(content).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].device_spec, "UUID=abcd-1234");
        assert_eq!(entries[0].mount_point, "/boot");
        assert_eq!(entries[1].device_spec, "/dev/sda2");
        assert_eq!(entries[1].fs_type, "swap");
        assert_eq!(entries[2].device_spec, "LABEL=data");
        assert_eq!(entries[3].mount_point, "/proc");
    }

    #[test]
    fn fstab_is_extrinsic_root() {
        assert!(fstab_is_extrinsic("/", None));
        assert!(fstab_is_extrinsic("/usr", None));
        assert!(fstab_is_extrinsic("/etc", None));
    }

    #[test]
    fn fstab_is_extrinsic_virtual_fs() {
        assert!(fstab_is_extrinsic("/proc", None));
        assert!(fstab_is_extrinsic("/sys/kernel", None));
        assert!(fstab_is_extrinsic("/dev/sda1", None));
        assert!(fstab_is_extrinsic("/run/initramfs/state", None));
    }

    #[test]
    fn fstab_is_extrinsic_not_extrinsic() {
        assert!(!fstab_is_extrinsic("/home", None));
        assert!(!fstab_is_extrinsic("/var/log", None));
        assert!(!fstab_is_extrinsic("/mnt/usb", None));
    }

    #[test]
    fn fstab_is_extrinsic_initrd_mount() {
        assert!(fstab_is_extrinsic(
            "/some/mount",
            Some("x-initrd.mount,noauto")
        ));
        assert!(!fstab_is_extrinsic("/some/mount", Some("noauto,nofail")));
    }

    #[test]
    fn fstab_is_bind_option() {
        assert!(fstab_is_bind(Some("bind"), None));
        assert!(fstab_is_bind(Some("rbind,noexec"), None));
        assert!(fstab_is_bind(None, Some("bind")));
        assert!(fstab_is_bind(None, Some("rbind")));
        assert!(!fstab_is_bind(Some("noexec"), Some("ext4")));
    }

    #[test]
    fn fstab_test_option_simple() {
        assert!(fstab_test_option(Some("noexec,ro"), &["ro"]));
        assert!(fstab_test_option(Some("noexec,ro"), &["noexec"]));
        assert!(!fstab_test_option(Some("noexec,ro"), &["rw"]));
        assert!(!fstab_test_option(None, &["rw"]));
        assert!(!fstab_test_option(Some(""), &["rw"]));
    }

    #[test]
    fn fstab_test_option_with_value() {
        assert!(fstab_test_option(Some("pri=10,ro"), &["pri"]));
        assert!(fstab_test_option(Some("size=4G"), &["size"]));
        assert!(!fstab_test_option(Some("priority=10"), &["pri"]));
    }

    #[test]
    fn fstab_test_option_multiple_names() {
        assert!(fstab_test_option(Some("bind,ro"), &["rbind", "bind"]));
        assert!(fstab_test_option(Some("rbind"), &["rbind", "bind"]));
        assert!(!fstab_test_option(Some("ro"), &["rbind", "bind"]));
    }

    // fn fstab_test_yes_no_option() {
    // assert!(fstab_test_yes_no_option(Some("auto"), &["auto", "noauto"]));
    // assert!(!fstab_test_yes_no_option(
    // Some("noauto"),
    // &["auto", "noauto"]
    // ));
    // assert!(!fstab_test_yes_no_option(Some("ro"), &["auto", "noauto"]));
    // }
    #[test]
    fn fstab_filter_options_basic() {
        let result =
            fstab_filter_options(Some("pri=10,ro,noatime"), &["pri"], true, false, true).unwrap();

        assert_eq!(result.name_found.as_deref(), Some("pri"));
        assert_eq!(result.value.as_deref(), Some("10"));
        assert_eq!(result.filtered.as_deref(), Some("ro,noatime"));
    }

    #[test]
    fn fstab_filter_options_no_match() {
        let result = fstab_filter_options(Some("ro,noatime"), &["pri"], true, false, true).unwrap();

        assert!(result.name_found.is_none());
        assert!(result.value.is_none());
        assert_eq!(result.filtered.as_deref(), Some("ro,noatime"));
    }

    #[test]
    fn fstab_filter_options_collect_values() {
        let result =
            fstab_filter_options(Some("x=a,y=b,x=c,z=d"), &["x"], false, true, true).unwrap();

        assert_eq!(result.name_found.as_deref(), Some("x"));
        assert_eq!(result.values, vec!["a", "c"]);
        assert_eq!(result.filtered.as_deref(), Some("y=b,z=d"));
    }

    #[test]
    fn fstab_filter_options_none_opts() {
        let result = fstab_filter_options(None, &["pri"], true, false, true).unwrap();
        assert!(result.name_found.is_none());
        assert!(result.filtered.is_none());
    }

    #[test]
    fn fstab_find_pri_found() {
        assert_eq!(
            fstab_find_pri(Some("defaults,pri=42,ro")).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn fstab_find_pri_not_found() {
        assert_eq!(fstab_find_pri(Some("defaults,ro")).unwrap(), None);
    }

    #[test]
    fn fstab_find_pri_invalid() {
        assert!(fstab_find_pri(Some("pri=abc")).is_err());
    }

    #[test]
    fn unquote_basic() {
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("'world'"), "world");
        assert_eq!(unquote("noquotes"), "noquotes");
        assert_eq!(unquote("x"), "x");
    }

    #[test]
    fn unquote_mismatched_quotes() {
        assert_eq!(unquote("\"hello'"), "\"hello'");
        assert_eq!(unquote("hello\""), "hello\"");
    }

    #[test]
    fn unquote_whitespace() {
        assert_eq!(unquote("  hello  "), "hello");
        assert_eq!(unquote("  \"hello\"  "), "hello");
    }

    #[test]
    fn fstab_node_to_udev_node_label() {
        assert_eq!(
            fstab_node_to_udev_node("LABEL=boot"),
            PathBuf::from("/dev/disk/by-label/boot")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_uuid() {
        assert_eq!(
            fstab_node_to_udev_node("UUID=abcd-1234"),
            PathBuf::from("/dev/disk/by-uuid/abcd-1234")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_partuuid() {
        assert_eq!(
            fstab_node_to_udev_node("PARTUUID=1234abcd-56"),
            PathBuf::from("/dev/disk/by-partuuid/1234abcd-56")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_partlabel() {
        assert_eq!(
            fstab_node_to_udev_node("PARTLABEL=data"),
            PathBuf::from("/dev/disk/by-partlabel/data")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_plain_path() {
        assert_eq!(
            fstab_node_to_udev_node("/dev/sda1"),
            PathBuf::from("/dev/sda1")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_quoted() {
        assert_eq!(
            fstab_node_to_udev_node("LABEL=\"my disk\""),
            PathBuf::from("/dev/disk/by-label/my\\x20disk")
        );
    }

    #[test]
    fn fstab_node_to_udev_node_special_chars() {
        let result = fstab_node_to_udev_node("UUID=ab cd");
        assert_eq!(result, PathBuf::from("/dev/disk/by-uuid/ab\\x20cd"));
    }

    #[test]
    // fn find_by_mountpoint() {
    // let entries = vec![
    // FstabEntry {
    // device_spec: "/dev/sda1".into(),
    // mount_point: "/".into(),
    // fs_type: "ext4".into(),
    // options: "defaults".into(),
    // dump: 0,
    // pass_no: 1,
    // },
    // FstabEntry {
    // device_spec: "/dev/sda2".into(),
    // mount_point: "/home".into(),
    // fs_type: "ext4".into(),
    // options: "defaults".into(),
    // dump: 0,
    // pass_no: 2,
    // },
    // ];
    // assert_eq!(
    // find_by_mountpoint(&entries, "/home").unwrap().device_spec,
    // "/dev/sda2"
    // );
    // assert!(find_by_mountpoint(&entries, "/var").is_none());
    // }
    // fn find_by_device() {
    // let entries = vec![FstabEntry {
    // device_spec: "/dev/sda1".into(),
    // mount_point: "/".into(),
    // fs_type: "ext4".into(),
    // options: "defaults".into(),
    // dump: 0,
    // pass_no: 1,
    // }];
    // assert_eq!(
    // find_by_device(&entries, "/dev/sda1").unwrap().mount_point,
    // "/"
    // );
    // assert!(find_by_device(&entries, "/dev/sdb1").is_none());
    // }
    #[test]
    fn fstab_has_fstype_test() {
        let entries = vec![FstabEntry {
            device_spec: "/dev/sda2".into(),
            mount_point: "swap".into(),
            fs_type: "swap".into(),
            options: "pri=10".into(),
            dump: 0,
            pass_no: 0,
        }];
        assert!(fstab_has_fstype(&entries, "swap"));
        assert!(!fstab_has_fstype(&entries, "ext4"));
    }

    #[test]
    fn fstab_has_mount_point_prefix_test() {
        let entries = vec![
            FstabEntry {
                device_spec: "/dev/sda1".into(),
                mount_point: "/var/log".into(),
                fs_type: "ext4".into(),
                options: "defaults".into(),
                dump: 0,
                pass_no: 1,
            },
            FstabEntry {
                device_spec: "/dev/sda2".into(),
                mount_point: "/home".into(),
                fs_type: "ext4".into(),
                options: "defaults".into(),
                dump: 0,
                pass_no: 2,
            },
        ];
        assert!(fstab_has_mount_point_prefix(&entries, &["/var"]));
        assert!(!fstab_has_mount_point_prefix(&entries, &["/opt"]));
    }

    #[test]
    fn fstab_enabled_default() {
        assert!(fstab_enabled());
    }

    #[test]
    fn fstab_enabled_full_set_and_query() {
        fstab_enabled_full(Some(false));
        assert!(!fstab_enabled());

        fstab_enabled_full(Some(true));
        assert!(fstab_enabled());
    }
}
