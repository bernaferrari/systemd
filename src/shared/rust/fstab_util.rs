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

    // Match `proc_cmdline_get_bool("fstab", STRIP_RD_PREFIX |
    // TRUE_WHEN_MISSING, …)`. Errors are deliberately ignored by the C
    // caller, which retains the default of `true`.
    let value = fstab_enabled_from_current_cmdline().unwrap_or(true);
    CACHE.store(value as i32, std::sync::atomic::Ordering::Relaxed);
    value
}

fn fstab_enabled_from_current_cmdline() -> Result<bool, FstabError> {
    let cmdline = match env::var("SYSTEMD_PROC_CMDLINE") {
        Ok(cmdline) => cmdline,
        Err(_) => fs::read_to_string("/proc/cmdline")?,
    };

    fstab_enabled_from_cmdline(&cmdline, in_initrd())
}

/// Evaluate the `fstab=` command-line switch with the same relevant policy as
/// `proc_cmdline_get_bool()` in `fstab_enabled_full()`. The public wrapper
/// intentionally falls back to `true` when this returns an error, as C does.
fn fstab_enabled_from_cmdline(cmdline: &str, in_initrd: bool) -> Result<bool, FstabError> {
    let mut found = false;
    let mut value = None;

    for word in cmdline.split(|ch: char| ch.is_whitespace() || ch == '\0') {
        if word.is_empty() {
            continue;
        }

        let word = if in_initrd {
            word.strip_prefix("rd.").unwrap_or(word)
        } else if word.starts_with("rd.") {
            continue;
        } else {
            word
        };

        let Some(suffix) = word.strip_prefix("fstab") else {
            continue;
        };
        if suffix.is_empty() {
            found = true;
        } else if let Some(parsed) = suffix.strip_prefix('=') {
            found = true;
            value = Some(parsed);
        }
    }

    if !found {
        return Ok(true);
    }
    let Some(value) = value else {
        return Ok(true);
    };

    parse_boolean(value).ok_or_else(|| {
        FstabError::Parse(format!("invalid fstab= kernel command-line value: {value}"))
    })
}

pub fn fstab_is_extrinsic(mount: &str, opts: Option<&str>) -> bool {
    fstab_is_extrinsic_with_initrd(mount, opts, in_initrd())
}

/// Pure form of [`fstab_is_extrinsic`] used where the initrd state is already
/// known. This mirrors the `!in_initrd()` condition in `fstab-util.c`.
pub fn fstab_is_extrinsic_with_initrd(mount: &str, opts: Option<&str>, in_initrd: bool) -> bool {
    if matches!(mount, "/" | "/usr" | "/etc") {
        return true;
    }

    let prefixes = ["/run/initramfs", "/run/nextroot", "/proc", "/sys", "/dev"];

    for prefix in &prefixes {
        if path_startswith(mount, prefix) {
            return true;
        }
    }

    if !in_initrd && fstab_test_option(opts, &["x-initrd.mount"]) {
        return true;
    }

    false
}

/// Equivalent to systemd's `path_startswith()`: a string prefix only matches
/// when it also ends at a path-component boundary.
fn path_startswith(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

/// `in_initrd()`'s observable policy from `src/basic/initrd-util.c`.
///
/// The C implementation uses `secure_getenv()` because it may run in a
/// privileged process. This pure-Rust library has no equivalent process-level
/// secure-environment primitive, so callers that need a fixed answer should
/// use `fstab_is_extrinsic_with_initrd()` instead.
fn in_initrd() -> bool {
    if let Ok(value) = env::var("SYSTEMD_IN_INITRD") {
        if let Some(value) = parse_boolean(&value) {
            return value;
        }
    }

    Path::new("/etc/initrd-release").exists()
}

fn parse_boolean(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("y")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("t")
        || value.eq_ignore_ascii_case("on")
    {
        Some(true)
    } else if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("n")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("f")
        || value.eq_ignore_ascii_case("off")
    {
        Some(false)
    } else {
        None
    }
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
    fstab_filter_options(opts, names, false, false, false)
        .map(|result| result.name_found.is_some())
        .unwrap_or(false)
}

pub fn fstab_test_yes_no_option(opts: Option<&str>, yes_no: &[&str; 2]) -> bool {
    fstab_filter_options(opts, yes_no, false, false, false)
        .ok()
        .and_then(|result| result.name_found)
        .is_some_and(|name| name == yes_no[0])
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

    if names.is_empty() || names.iter().any(|name| name.is_empty()) {
        return Err(FstabError::Parse(
            "option names must contain at least one non-empty name".to_string(),
        ));
    }
    if want_value && want_values {
        return Err(FstabError::Parse(
            "last value and all values are mutually exclusive".to_string(),
        ));
    }

    let Some(opts) = opts else {
        return Ok(result);
    };

    let mut filtered_parts: Vec<String> = Vec::new();

    for word in split_mount_options(opts) {
        let matching = matching_option(&word, names, want_values);
        if let Some((name, suffix)) = matching {
            result.name_found = Some(name.to_string());

            if want_value {
                result.value = suffix.strip_prefix('=').map(str::to_owned);
            } else if want_values {
                // `matching_option()` only returns a bare option when all
                // values are not requested, so this byte index is safe.
                result.values.push(suffix[1..].to_string());
            }
        } else if want_filtered {
            filtered_parts.push(word);
        }
    }

    if want_filtered {
        result.filtered = Some(join_mount_options(&filtered_parts));
    }

    Ok(result)
}

pub fn fstab_find_pri(opts: Option<&str>) -> Result<Option<i32>, FstabError> {
    let filtered = fstab_filter_options(opts, &["pri"], true, false, false)?;

    if filtered.name_found.is_none() {
        return Ok(None);
    }

    let Some(val) = filtered.value else {
        return Ok(None);
    };
    let pri: i32 = val
        .parse()
        .map_err(|_| FstabError::Parse(format!("invalid swap priority: {val}")))?;

    Ok(Some(pri))
}

fn unquote(s: &str) -> String {
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
        if !ch.is_ascii() {
            // `encode_devnode_name()` copies valid multi-byte UTF-8 sequences
            // as-is, instead of escaping their individual UTF-8 bytes.
            out.push(ch);
        } else if ch.is_ascii_alphanumeric() || "#+-.:=@_".contains(ch) {
            out.push(ch);
        } else {
            out.push_str(&format!("\\x{:02x}", ch as u8));
        }
    }
    out
}

/// Split fstab mount options exactly like the allocation-taking branch of
/// `fstab_filter_options()`: commas and backslashes may be escaped, all other
/// escapes are retained, and empty fields are ignored.
fn split_mount_options(opts: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut chars = opts.chars();

    while let Some(ch) = chars.next() {
        match ch {
            ',' => {
                if !part.is_empty() {
                    parts.push(std::mem::take(&mut part));
                }
            }
            '\\' => match chars.next() {
                Some(escaped @ (',' | '\\')) => part.push(escaped),
                Some(other) => {
                    part.push('\\');
                    part.push(other);
                }
                None => part.push('\\'),
            },
            other => part.push(other),
        }
    }

    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

fn matching_option<'a, 'b>(
    word: &'b str,
    names: &'a [&str],
    values_only: bool,
) -> Option<(&'a str, &'b str)> {
    names.iter().find_map(|name| {
        let suffix = word.strip_prefix(name)?;
        if suffix.starts_with('=') || (!values_only && suffix.is_empty()) {
            Some((*name, suffix))
        } else {
            None
        }
    })
}

fn join_mount_options(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| part.replace(',', "\\,"))
        .collect::<Vec<_>>()
        .join(",")
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
        assert!(fstab_is_extrinsic_with_initrd("/proc", None, false));
        assert!(fstab_is_extrinsic_with_initrd("/sys/kernel", None, false));
        assert!(fstab_is_extrinsic_with_initrd("/dev/sda1", None, false));
        assert!(fstab_is_extrinsic_with_initrd(
            "/run/initramfs/state",
            None,
            false
        ));
    }

    #[test]
    fn fstab_is_extrinsic_uses_path_component_boundaries() {
        for path in ["/procfs", "/sysroot", "/device", "/run/initramfs-old"] {
            assert!(!fstab_is_extrinsic_with_initrd(path, None, false), "{path}");
        }
    }

    #[test]
    fn fstab_is_extrinsic_not_extrinsic() {
        assert!(!fstab_is_extrinsic("/home", None));
        assert!(!fstab_is_extrinsic("/var/log", None));
        assert!(!fstab_is_extrinsic("/mnt/usb", None));
    }

    #[test]
    fn fstab_is_extrinsic_initrd_mount() {
        assert!(fstab_is_extrinsic_with_initrd(
            "/some/mount",
            Some("x-initrd.mount,noauto"),
            false,
        ));
        assert!(!fstab_is_extrinsic_with_initrd(
            "/some/mount",
            Some("x-initrd.mount,noauto"),
            true,
        ));
        assert!(!fstab_is_extrinsic_with_initrd(
            "/some/mount",
            Some("noauto,nofail"),
            false,
        ));
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
        // A comma escaped with a single backslash stays in the word. Two
        // backslashes escape each other, leaving the comma as a separator.
        assert!(!fstab_test_option(Some("foo\\,opt"), &["opt"]));
        assert!(fstab_test_option(Some("foo\\\\,opt"), &["opt"]));
    }

    #[test]
    fn fstab_test_yes_no_option_uses_the_last_match() {
        assert!(fstab_test_yes_no_option(
            Some("nofail,fail,nofail"),
            &["nofail", "fail"]
        ));
        assert!(!fstab_test_yes_no_option(
            Some("nofail,nofail,fail"),
            &["nofail", "fail"]
        ));
        assert!(fstab_test_yes_no_option(
            Some("nofail,fail=0,nofail=0"),
            &["nofail", "fail"]
        ));
    }
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
    fn fstab_filter_options_matches_c_escaping_and_last_value_rules() {
        let result = fstab_filter_options(
            Some("first,opt=0\\,1,last,opt=2"),
            &["opt"],
            true,
            false,
            true,
        )
        .unwrap();

        assert_eq!(result.name_found.as_deref(), Some("opt"));
        assert_eq!(result.value.as_deref(), Some("2"));
        assert_eq!(result.filtered.as_deref(), Some("first,last"));

        let values =
            fstab_filter_options(Some("opt=0\\,1,opt=2"), &["opt"], false, true, true).unwrap();
        assert_eq!(values.values, vec!["0,1", "2"]);
        assert_eq!(values.filtered.as_deref(), Some(""));
    }

    #[test]
    fn fstab_filter_options_keeps_bare_options_when_collecting_values() {
        let result =
            fstab_filter_options(Some("opt,other,opt=1"), &["opt"], false, true, true).unwrap();
        assert_eq!(result.name_found.as_deref(), Some("opt"));
        assert_eq!(result.values, vec!["1"]);
        assert_eq!(result.filtered.as_deref(), Some("opt,other"));
    }

    #[test]
    fn fstab_filter_options_does_not_trim_or_preserve_empty_fields() {
        let result =
            fstab_filter_options(Some(",,,opt=0 ,,,"), &["opt"], true, false, true).unwrap();
        assert_eq!(result.value.as_deref(), Some("0 "));
        assert_eq!(result.filtered.as_deref(), Some(""));

        assert!(!fstab_test_option(Some(" opt "), &["opt"]));
        assert!(!fstab_test_option(Some("opt;"), &["opt"]));
    }

    #[test]
    fn fstab_filter_options_rejects_invalid_output_combinations() {
        assert!(fstab_filter_options(Some("opt=1"), &["opt"], true, true, false).is_err());
        assert!(fstab_filter_options(Some("opt=1"), &[], false, false, false).is_err());
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
        assert_eq!(fstab_find_pri(Some("pri")).unwrap(), None);
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
        assert_eq!(unquote("  hello  "), "  hello  ");
        assert_eq!(unquote("  \"hello\"  "), "  \"hello\"  ");
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
    fn fstab_node_to_udev_node_keeps_valid_utf8_and_c_allowed_ascii() {
        assert_eq!(
            fstab_node_to_udev_node("LABEL=applé/jack"),
            PathBuf::from("/dev/disk/by-label/applé\\x2fjack")
        );
        assert_eq!(
            fstab_node_to_udev_node("LABEL=a#b+c:d=e@f_g"),
            PathBuf::from("/dev/disk/by-label/a#b+c:d=e@f_g")
        );
    }

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
    fn fstab_enabled_cmdline_defaults_and_parses_boolean_values() {
        assert!(fstab_enabled_from_cmdline("quiet", false).unwrap());
        assert!(!fstab_enabled_from_cmdline("quiet fstab=0", false).unwrap());
        assert!(fstab_enabled_from_cmdline("fstab", false).unwrap());
        assert!(fstab_enabled_from_cmdline("fstab=on", false).unwrap());
        // `proc_cmdline_get_key()` keeps the latest explicit value; a later
        // value-less occurrence only marks the key as present.
        assert!(!fstab_enabled_from_cmdline("fstab=off fstab", false).unwrap());
        assert!(fstab_enabled_from_cmdline("fstab=bogus", false).is_err());
    }

    #[test]
    fn fstab_enabled_cmdline_honors_rd_prefix_only_in_initrd() {
        assert!(fstab_enabled_from_cmdline("rd.fstab=0", false).unwrap());
        assert!(!fstab_enabled_from_cmdline("rd.fstab=0", true).unwrap());
        assert!(fstab_enabled_from_cmdline("fstab=0 rd.fstab=1", true).unwrap());
    }

    #[test]
    fn fstab_enabled_full_set_and_query() {
        fstab_enabled_full(Some(false));
        assert!(!fstab_enabled());

        fstab_enabled_full(Some(true));
        assert!(fstab_enabled());
    }
}
