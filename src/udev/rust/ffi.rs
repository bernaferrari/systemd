// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: N/A (FFI conventions)
//
// udev FFI-safe type definitions and safe Rust wrappers.
// Provides struct layouts matching the C ABI without requiring
// extern "C" function declarations.

use std::fmt;
use std::marker::PhantomData;
use std::marker::PhantomPinned;

// ── Constants ──────────────────────────────────────────────────────────────

pub const EVENT_UDEV_WORKER: i32 = 0;
pub const EVENT_UDEVADM_TEST_BUILTIN: i32 = 2;

pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const ENOENT: i32 = 2;
pub const ENOSYS: i32 = 38;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    Einval = EINVAL,
    Enosys = ENOSYS,
    Efault = EFAULT,
    Enoent = ENOENT,
}

impl Errno {
    pub const EINVAL: Errno = Errno::Einval;
    pub const ENOSYS: Errno = Errno::Enosys;
    pub const EFAULT: Errno = Errno::Efault;
    pub const ENOENT: Errno = Errno::Enoent;

    pub const fn to_neg_errno(self) -> i32 {
        -(self as i32)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Einval => write!(f, "EINVAL"),
            Self::Enosys => write!(f, "ENOSYS"),
            Self::Efault => write!(f, "EFAULT"),
            Self::Enoent => write!(f, "ENOENT"),
        }
    }
}

impl std::error::Error for Errno {}

// ── Opaque device type ─────────────────────────────────────────────────────

#[repr(C)]
pub struct SdDevice {
    _opaque: [u8; 0],
    _pinned: PhantomData<PhantomPinned>,
}

impl SdDevice {
    pub fn null() -> *mut Self {
        std::ptr::null_mut()
    }
}

// ── Udev event ─────────────────────────────────────────────────────────────

#[repr(C)]
pub struct UdevEvent {
    pub n_ref: u32,
    _pad0: u32,
    pub worker: *mut std::ffi::c_void,
    pub rtnl: *mut std::ffi::c_void,
    pub dev: *mut SdDevice,
    pub dev_parent: *mut SdDevice,
    pub name: *mut std::ffi::c_char,
    pub altnames: *mut *mut std::ffi::c_char,
    pub program_result: *mut std::ffi::c_char,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    _pad1: u32,
    pub seclabel_list: *mut std::ffi::c_void,
    pub run_list: *mut std::ffi::c_void,
    pub written_sysattrs: *mut std::ffi::c_void,
    pub written_sysctls: *mut std::ffi::c_void,
    pub birth_usec: i64,
    pub builtin_run: u32,
    pub builtin_ret: u32,
    pub esc: i32,
    pub inotify_watch: bool,
    pub inotify_watch_final: bool,
    pub group_final: bool,
    pub owner_final: bool,
    pub mode_final: bool,
    pub name_final: bool,
    pub devlink_final: bool,
    pub run_final: bool,
    pub trace: bool,
    pub log_level_was_debug: bool,
    pub default_log_level: i32,
    pub event_mode: i32,
}

impl UdevEvent {
    pub fn null_event() -> Self {
        Self {
            n_ref: 0,
            _pad0: 0,
            worker: std::ptr::null_mut(),
            rtnl: std::ptr::null_mut(),
            dev: std::ptr::null_mut(),
            dev_parent: std::ptr::null_mut(),
            name: std::ptr::null_mut(),
            altnames: std::ptr::null_mut(),
            program_result: std::ptr::null_mut(),
            mode: 0,
            uid: 0,
            gid: 0,
            _pad1: 0,
            seclabel_list: std::ptr::null_mut(),
            run_list: std::ptr::null_mut(),
            written_sysattrs: std::ptr::null_mut(),
            written_sysctls: std::ptr::null_mut(),
            birth_usec: 0,
            builtin_run: 0,
            builtin_ret: 0,
            esc: 0,
            inotify_watch: false,
            inotify_watch_final: false,
            group_final: false,
            owner_final: false,
            mode_final: false,
            name_final: false,
            devlink_final: false,
            run_final: false,
            trace: false,
            log_level_was_debug: false,
            default_log_level: 0,
            event_mode: 0,
        }
    }
}

// ── Device property access (safe wrappers) ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeviceProperties {
    props: Vec<(String, String)>,
}

impl DeviceProperties {
    pub fn new() -> Self {
        Self { props: Vec::new() }
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(entry) = self.props.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.to_string();
        } else {
            self.props.push((key.to_string(), value.to_string()));
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.props
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn remove(&mut self, key: &str) -> bool {
        let len_before = self.props.len();
        self.props.retain(|(k, _)| k != key);
        self.props.len() != len_before
    }

    pub fn len(&self) -> usize {
        self.props.len()
    }

    pub fn is_empty(&self) -> bool {
        self.props.is_empty()
    }
}

impl Default for DeviceProperties {
    fn default() -> Self {
        Self::new()
    }
}

// ── Udev event property management (safe wrappers) ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EventPropertyList {
    properties: DeviceProperties,
}

impl EventPropertyList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_property(&mut self, key: &str, val: &str) -> std::result::Result<(), Errno> {
        if key.is_empty() {
            return Err(Errno::Einval);
        }
        self.properties.set(key, val);
        Ok(())
    }

    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key)
    }

    pub fn remove_property(&mut self, key: &str) -> bool {
        self.properties.remove(key)
    }

    pub fn property_count(&self) -> usize {
        self.properties.len()
    }
}

// ── Device path escaping ───────────────────────────────────────────────────

pub fn udev_node_escape_path(src: &str) -> String {
    src.replace('/', "\\x2f")
        .replace(' ', "\\x20")
        .replace('\t', "\\x09")
}

pub fn udev_node_unescape_path(src: &str) -> String {
    src.replace("\\x2f", "/")
        .replace("\\x20", " ")
        .replace("\\x09", "\t")
}

// ── Devpath conflict detection ─────────────────────────────────────────────

pub fn devpath_conflict(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Strip trailing digits from each path component, then compare.
    // /dev/sda1 and /dev/sda2 conflict because the base path /dev/sda matches.
    // /dev/sda1 and /dev/sdb1 do NOT conflict because /dev/sda != /dev/sdb.
    let strip_trailing_digits = |s: &str| -> String {
        let end = s.char_indices().rev().take_while(|(_, c)| c.is_ascii_digit()).last();
        match end {
            Some((i, _)) => s[..i].to_string(),
            None => s.to_string(),
        }
    };
    strip_trailing_digits(a) == strip_trailing_digits(b)
}

// ── Format checking ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    InvalidFormat,
    UnknownSpecifier(char),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid format string"),
            Self::UnknownSpecifier(c) => write!(f, "unknown format specifier: {}", c),
        }
    }
}

impl std::error::Error for FormatError {}

pub fn udev_check_format(value: &str) -> std::result::Result<(), FormatError> {
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            if i + 1 >= chars.len() {
                return Err(FormatError::InvalidFormat);
            }
            match chars[i + 1] {
                'k' | 'n' | 'p' | 's' | 'S' | 'M' | 'b' | 'c' | 'd' | 'r' | 't' | 'P' | 'Q'
                | 'N' | 'E' | 'a' | 'A' | 'D' | 'L' | 'm' | '%' => {}
                _ => return Err(FormatError::UnknownSpecifier(chars[i + 1])),
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_constants() {
        assert_eq!(EVENT_UDEV_WORKER, 0);
        assert_eq!(EVENT_UDEVADM_TEST_BUILTIN, 2);
    }

    #[test]
    fn errno_to_neg() {
        assert_eq!(Errno::Einval.to_neg_errno(), -EINVAL);
        assert_eq!(Errno::Enosys.to_neg_errno(), -ENOSYS);
        assert_eq!(Errno::Efault.to_neg_errno(), -EFAULT);
    }

    #[test]
    fn errno_display() {
        assert_eq!(format!("{}", Errno::Einval), "EINVAL");
        assert_eq!(format!("{}", Errno::Enosys), "ENOSYS");
    }

    #[test]
    fn device_properties_set_get() {
        let mut props = DeviceProperties::new();
        assert!(props.is_empty());

        props.set("ID_VENDOR", "acme");
        props.set("ID_MODEL", "widget");

        assert_eq!(props.get("ID_VENDOR"), Some("acme"));
        assert_eq!(props.get("ID_MODEL"), Some("widget"));
        assert_eq!(props.get("MISSING"), None);
        assert_eq!(props.len(), 2);
    }

    #[test]
    fn device_properties_overwrite() {
        let mut props = DeviceProperties::new();
        props.set("key", "old");
        props.set("key", "new");
        assert_eq!(props.get("key"), Some("new"));
        assert_eq!(props.len(), 1);
    }

    #[test]
    fn device_properties_remove() {
        let mut props = DeviceProperties::new();
        props.set("a", "1");
        props.set("b", "2");
        assert!(props.remove("a"));
        assert!(!props.remove("a"));
        assert_eq!(props.len(), 1);
        assert_eq!(props.get("b"), Some("2"));
    }

    #[test]
    fn event_property_list_add() {
        let mut list = EventPropertyList::new();
        assert!(list.add_property("KEY", "value").is_ok());
        assert_eq!(list.get_property("KEY"), Some("value"));
        assert_eq!(list.property_count(), 1);
    }

    #[test]
    fn event_property_list_empty_key_rejected() {
        let mut list = EventPropertyList::new();
        assert!(list.add_property("", "value").is_err());
        assert_eq!(list.property_count(), 0);
    }

    #[test]
    fn escape_path_special_chars() {
        assert_eq!(udev_node_escape_path("foo/bar baz"), "foo\\x2fbar\\x20baz");
        assert_eq!(udev_node_escape_path("simple"), "simple");
        assert_eq!(udev_node_escape_path(""), "");
    }

    #[test]
    fn escape_unescape_roundtrip() {
        let original = "dev/node name";
        let escaped = udev_node_escape_path(original);
        let unescaped = udev_node_unescape_path(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn devpath_conflict_same() {
        assert!(devpath_conflict("/dev/sda1", "/dev/sda1"));
    }

    #[test]
    fn devpath_conflict_different() {
        assert!(!devpath_conflict("/dev/sda1", "/dev/sdb1"));
    }

    #[test]
    fn udev_check_format_valid() {
        assert!(udev_check_format("syspath/%k").is_ok());
        assert!(udev_check_format("name %n").is_ok());
        assert!(udev_check_format("100%%").is_ok());
        assert!(udev_check_format("plain text").is_ok());
    }

    #[test]
    fn udev_check_format_invalid_trailing_percent() {
        assert!(udev_check_format("bad %").is_err());
    }

    #[test]
    fn udev_check_format_unknown_specifier() {
        let result = udev_check_format("bad %z");
        assert!(matches!(result, Err(FormatError::UnknownSpecifier('z'))));
    }

    #[test]
    fn udev_event_null_event() {
        let event = UdevEvent::null_event();
        assert_eq!(event.n_ref, 0);
        assert!(event.dev.is_null());
        assert!(event.worker.is_null());
        assert!(!event.inotify_watch);
        assert!(!event.trace);
    }
}
