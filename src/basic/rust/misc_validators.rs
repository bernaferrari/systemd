// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/mountpoint-util.c (mount_propagation_flag_is_valid),
//           src/basic/parse-util.c (nft_identifier_valid),
//           src/basic/os-util.c (image_name_is_valid),
//           src/shared/hostname-setup.c (shorten_overlong),
//           src/shared/bus-print-properties.c (bus_property_is_timestamp),
//           src/basic/user-util.c (valid_gecos, valid_home, valid_shell),
//           src/shared/reboot-util.c (reboot_parameter_is_valid),
//           src/basic/syslog-util.c (log_namespace_name_valid),
//           src/basic/socket-util.c (address_label_valid)

use libc::c_char;
use std::ffi::CStr;

use crate::process_util_str_tables::{
    nice_is_valid as process_nice_is_valid,
    oom_score_adjust_is_valid as process_oom_score_adjust_is_valid,
    sched_policy_is_valid as process_sched_policy_is_valid,
};

// ── Constants ─────────────────────────────────────────────────────────────

const MS_SHARED: u64 = 1 << 20;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const NFT_NAME_MAXLEN: usize = 256;
const IFNAMSIZ: usize = 16;
const NAME_MAX: usize = 255;
const LOG_NAMESPACE_MAX: usize = 222;
const LINUX_HOST_NAME_MAX: usize = 64;

// ── mount_propagation_flag_is_valid ───────────────────────────────────────

pub fn mount_propagation_flag_is_valid(flag: u64) -> bool {
    matches!(flag, 0 | MS_SHARED | MS_PRIVATE | MS_SLAVE)
}

// ── nft_identifier_valid ──────────────────────────────────────────────────

pub fn nft_identifier_valid(id: &str) -> bool {
    if id.is_empty() || id.len() >= NFT_NAME_MAXLEN {
        return false;
    }
    let mut chars = id.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '/' || c == '\\' || c == '_' || c == '.') {
            return false;
        }
    }
    true
}

// ── image_name_is_valid ───────────────────────────────────────────────────

pub fn image_name_is_valid(s: &str) -> bool {
    image_name_is_valid_bytes(s.as_bytes())
}

/// Byte-oriented counterpart of C's `image_name_is_valid()`.
///
/// The public C function validates the filename shape first, then rejects
/// ASCII control bytes and malformed UTF-8. Keeping this core byte-oriented
/// means the FFI facade can reject non-UTF-8 input rather than silently
/// imposing Rust's `str` precondition before it reaches the policy.
fn image_name_is_valid_bytes(s: &[u8]) -> bool {
    if s.is_empty()
        || s.len() > NAME_MAX
        || matches!(s, b"." | b"..")
        || s.contains(&b'/')
        || has_control_char(s)
        || std::str::from_utf8(s).is_err()
    {
        return false;
    }

    !s.starts_with(b".#")
}

/// # Safety
///
/// `s`, when non-NULL, must point to a live NUL-terminated C string for the
/// duration of this call. The input remains owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_name_is_valid(s: *const c_char) -> bool {
    if s.is_null() {
        return false;
    }

    // SAFETY: guaranteed by the entry point contract after the NULL check.
    image_name_is_valid_bytes(unsafe { CStr::from_ptr(s) }.to_bytes())
}

// ── log_namespace_name_valid ──────────────────────────────────────────────

pub fn log_namespace_name_valid(s: &str) -> bool {
    if !filename_is_valid(s) || s.len() > LOG_NAMESPACE_MAX {
        return false;
    }
    if !unit_instance_is_valid(s) || !string_is_safe(s) || string_is_glob(s) {
        return false;
    }
    true
}

// ── address_label_valid ───────────────────────────────────────────────────

pub fn address_label_valid(p: &str) -> bool {
    if p.is_empty() || p.len() >= IFNAMSIZ {
        return false;
    }
    p.bytes().all(|b| (32..=126).contains(&b))
}

/// # Safety
///
/// `p`, when non-NULL, must point to a live NUL-terminated C string for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_address_label_valid(p: *const c_char) -> bool {
    if p.is_null() {
        return false;
    }

    // SAFETY: required by the entry point's contract and checked for NULL.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    !bytes.is_empty()
        && bytes.len() < IFNAMSIZ
        && bytes.iter().all(|byte| (32..=126).contains(byte))
}

// ── valid_gecos ───────────────────────────────────────────────────────────

pub fn valid_gecos(d: &str) -> bool {
    if has_control_char(d.as_bytes()) || d.contains(':') {
        return false;
    }
    true
}

// ── valid_home ────────────────────────────────────────────────────────────

pub fn valid_home(p: &str) -> bool {
    if p.is_empty() || has_control_char(p.as_bytes()) {
        return false;
    }
    if !path_is_absolute(p) || !path_is_normalized(p) || p.contains(':') {
        return false;
    }
    true
}

// ── valid_shell ───────────────────────────────────────────────────────────

pub fn valid_shell(p: &str) -> bool {
    if !valid_home(p) {
        return false;
    }
    if p.ends_with('/') {
        return false;
    }
    true
}

// ── reboot_parameter_is_valid ─────────────────────────────────────────────

pub fn reboot_parameter_is_valid(parameter: &str) -> bool {
    parameter.is_ascii() && parameter.len() <= NAME_MAX
}

// ── bus_property_is_timestamp ─────────────────────────────────────────────

pub fn bus_property_is_timestamp(name: &str) -> bool {
    if name.ends_with("Timestamp") {
        return true;
    }
    matches!(
        name,
        "NextElapseUSecRealtime" | "LastTriggerUSec" | "TimeUSec" | "RTCTimeUSec"
    )
}

fn nft_identifier_valid_bytes(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() < NFT_NAME_MAXLEN
        && id[0].is_ascii_alphabetic()
        && id[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'\\' | b'_' | b'.'))
}

fn valid_gecos_bytes(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok() && !has_control_char(value) && !value.contains(&b':')
}

fn path_is_normalized_bytes(path: &[u8]) -> bool {
    path.starts_with(b"/")
        && !path.windows(2).any(|window| window == b"//")
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !matches!(component, b"." | b".."))
}

fn valid_home_bytes(path: &[u8]) -> bool {
    !path.is_empty()
        && std::str::from_utf8(path).is_ok()
        && !has_control_char(path)
        && !path.contains(&b':')
        && path_is_normalized_bytes(path)
}

fn valid_shell_bytes(path: &[u8]) -> bool {
    valid_home_bytes(path) && !path.ends_with(b"/")
}

fn log_namespace_name_valid_bytes(name: &[u8]) -> bool {
    if name.is_empty()
        || name.len() > LOG_NAMESPACE_MAX
        || std::str::from_utf8(name).is_err()
        || has_control_char(name)
        || name.contains(&b'/')
        || matches!(name, b"." | b"..")
        || name
            .iter()
            .any(|byte| matches!(*byte, b'\\' | b'\'' | b'\"' | b'*' | b'?' | b'['))
    {
        return false;
    }

    name.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(*byte, b'@' | b':' | b'-' | b'_' | b'.')
    })
}

fn bus_property_is_timestamp_bytes(name: &[u8]) -> bool {
    name.ends_with(b"Timestamp")
        || matches!(
            name,
            b"NextElapseUSecRealtime" | b"LastTriggerUSec" | b"TimeUSec" | b"RTCTimeUSec"
        )
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_nice_is_valid(n: i32) -> bool {
    process_nice_is_valid(n)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_sched_policy_is_valid(policy: i32) -> bool {
    process_sched_policy_is_valid(policy)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_oom_score_adjust_is_valid(oa: i32) -> bool {
    process_oom_score_adjust_is_valid(oa)
}

/// # Safety
/// `id`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_nft_identifier_valid(id: *const c_char) -> bool {
    if id.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    nft_identifier_valid_bytes(unsafe { CStr::from_ptr(id) }.to_bytes())
}

/// # Safety
/// `value`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_valid_gecos(value: *const c_char) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    valid_gecos_bytes(unsafe { CStr::from_ptr(value) }.to_bytes())
}

/// # Safety
/// `name`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_log_namespace_name_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    log_namespace_name_valid_bytes(unsafe { CStr::from_ptr(name) }.to_bytes())
}

/// # Safety
/// `path`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_valid_home(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    valid_home_bytes(unsafe { CStr::from_ptr(path) }.to_bytes())
}

/// # Safety
/// `path`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_valid_shell(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    valid_shell_bytes(unsafe { CStr::from_ptr(path) }.to_bytes())
}

/// # Safety
/// `name`, when non-null, must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bus_property_is_timestamp(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    // SAFETY: required by this C ABI entry point's contract.
    bus_property_is_timestamp_bytes(unsafe { CStr::from_ptr(name) }.to_bytes())
}

// ── shorten_overlong ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortenOverlongResult {
    Unchanged(String),
    Shortened(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortenOverlongError {
    InvalidHostname,
}

pub fn shorten_overlong(s: &str) -> Result<ShortenOverlongResult, ShortenOverlongError> {
    if hostname_is_valid(s) {
        return Ok(ShortenOverlongResult::Unchanged(s.to_owned()));
    }

    let head = s.split('.').next().unwrap_or_default();
    let candidate = if head.len() > LINUX_HOST_NAME_MAX {
        &head[..LINUX_HOST_NAME_MAX]
    } else {
        head
    };

    if !hostname_is_valid(candidate) {
        return Err(ShortenOverlongError::InvalidHostname);
    }

    Ok(ShortenOverlongResult::Shortened(candidate.to_owned()))
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn filename_is_valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= NAME_MAX && !s.contains('/') && s != "." && s != ".."
}

fn path_is_absolute(p: &str) -> bool {
    p.starts_with('/')
}

fn path_is_normalized(p: &str) -> bool {
    if !path_is_absolute(p) || p.contains("//") {
        return false;
    }
    for component in p.split('/') {
        if component == "." || component == ".." {
            return false;
        }
    }
    true
}

fn has_control_char(data: &[u8]) -> bool {
    data.iter().any(|&b| b < 0x20 || b == 0x7F)
}

fn string_is_safe(s: &str) -> bool {
    !has_control_char(s.as_bytes())
}

fn unit_instance_is_valid(s: &str) -> bool {
    !s.is_empty() && string_is_safe(s) && !s.contains('/')
}

fn string_is_glob(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

fn hostname_is_valid(s: &str) -> bool {
    if s.is_empty() || s == ".host" || s.len() > LINUX_HOST_NAME_MAX {
        return false;
    }

    let mut dot = true;
    let mut hyphen = true;

    for byte in s.bytes() {
        match byte {
            b'.' => {
                if dot || hyphen {
                    return false;
                }
                dot = true;
                hyphen = false;
            }
            b'-' => {
                if dot {
                    return false;
                }
                dot = false;
                hyphen = true;
            }
            b if b.is_ascii_alphanumeric() => {
                dot = false;
                hyphen = false;
            }
            _ => return false,
        }
    }

    !dot && !hyphen
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_propagation_valid() {
        assert!(mount_propagation_flag_is_valid(0));
        assert!(mount_propagation_flag_is_valid(MS_SHARED));
        assert!(mount_propagation_flag_is_valid(MS_PRIVATE));
        assert!(mount_propagation_flag_is_valid(MS_SLAVE));
    }

    #[test]
    fn test_mount_propagation_invalid() {
        assert!(!mount_propagation_flag_is_valid(1));
        assert!(!mount_propagation_flag_is_valid(2));
        assert!(!mount_propagation_flag_is_valid(999));
        assert!(!mount_propagation_flag_is_valid(u64::MAX));
    }

    #[test]
    fn test_nft_identifier_valid_normal() {
        assert!(nft_identifier_valid("mychain"));
        assert!(nft_identifier_valid("a"));
        assert!(nft_identifier_valid("my_table"));
        assert!(nft_identifier_valid("my.table"));
        assert!(nft_identifier_valid("my/path"));
        assert!(nft_identifier_valid("Ab12"));
        assert!(nft_identifier_valid(r"my\chain"));
    }

    #[test]
    fn test_nft_identifier_invalid() {
        assert!(!nft_identifier_valid(""));
        assert!(!nft_identifier_valid("1abc"));
        assert!(!nft_identifier_valid("_abc"));
        assert!(!nft_identifier_valid(".abc"));
        assert!(!nft_identifier_valid("abc def"));
        assert!(!nft_identifier_valid("abc!"));
    }

    #[test]
    fn test_nft_identifier_max_length() {
        let ok: String = "a".repeat(255);
        assert!(nft_identifier_valid(&ok));
        let too_long: String = "a".repeat(256);
        assert!(!nft_identifier_valid(&too_long));
    }

    #[test]
    fn test_image_name_valid() {
        assert!(image_name_is_valid("myimage.raw"));
        assert!(image_name_is_valid("a.b"));
    }

    #[test]
    fn test_image_name_invalid() {
        assert!(!image_name_is_valid(""));
        assert!(!image_name_is_valid(".#tempfile"));
        assert!(!image_name_is_valid("has/slash"));
        assert!(!image_name_is_valid(".."));
    }

    #[test]
    fn test_address_label_valid_normal() {
        assert!(address_label_valid("eth0"));
        assert!(address_label_valid("lo"));
        assert!(address_label_valid("a"));
        assert!(address_label_valid("my label"));
    }

    #[test]
    fn test_address_label_invalid() {
        assert!(!address_label_valid(""));
        assert!(!address_label_valid("\u{1}"));
        assert!(!address_label_valid("\u{7f}"));
    }

    #[test]
    fn test_address_label_max_length() {
        let ok: String = "a".repeat(15);
        assert!(address_label_valid(&ok));
        let too_long: String = "a".repeat(16);
        assert!(!address_label_valid(&too_long));
    }

    #[test]
    fn test_valid_gecos_valid() {
        assert!(valid_gecos("John Doe"));
        assert!(valid_gecos(""));
        assert!(valid_gecos("Room 101"));
    }

    #[test]
    fn test_valid_gecos_invalid() {
        assert!(!valid_gecos("has:colon"));
        assert!(!valid_gecos("has\u{1}ctrl"));
    }

    #[test]
    fn test_valid_home_valid() {
        assert!(valid_home("/home/user"));
        assert!(valid_home("/"));
    }

    #[test]
    fn test_valid_home_invalid() {
        assert!(!valid_home(""));
        assert!(!valid_home("relative"));
        assert!(!valid_home("/home/../user"));
        assert!(!valid_home("/home/has:colon"));
    }

    #[test]
    fn test_valid_shell_valid() {
        assert!(valid_shell("/bin/bash"));
        assert!(valid_shell("/usr/bin/zsh"));
    }

    #[test]
    fn test_valid_shell_invalid() {
        assert!(!valid_shell(""));
        assert!(!valid_shell("relative"));
        assert!(!valid_shell("/bin/bash/"));
        assert!(!valid_shell("/"));
    }

    #[test]
    fn test_reboot_parameter_valid() {
        assert!(reboot_parameter_is_valid("reboot"));
        assert!(reboot_parameter_is_valid("kexec"));
        assert!(reboot_parameter_is_valid(""));
    }

    #[test]
    fn test_reboot_parameter_invalid() {
        assert!(!reboot_parameter_is_valid(&"a".repeat(256)));
        assert!(!reboot_parameter_is_valid("not\u{ff}ascii"));
    }

    #[test]
    fn test_bus_property_timestamp_suffix() {
        assert!(bus_property_is_timestamp("SomeTimestamp"));
        assert!(bus_property_is_timestamp("Timestamp"));
    }

    #[test]
    fn test_bus_property_timestamp_special() {
        assert!(bus_property_is_timestamp("NextElapseUSecRealtime"));
        assert!(bus_property_is_timestamp("LastTriggerUSec"));
        assert!(bus_property_is_timestamp("TimeUSec"));
        assert!(bus_property_is_timestamp("RTCTimeUSec"));
    }

    #[test]
    fn test_bus_property_timestamp_negative() {
        assert!(!bus_property_is_timestamp("Name"));
        assert!(!bus_property_is_timestamp("Timestamps"));
        assert!(!bus_property_is_timestamp(""));
    }

    #[test]
    fn test_log_namespace_valid() {
        assert!(log_namespace_name_valid("myservice"));
        assert!(log_namespace_name_valid("my.service"));
    }

    #[test]
    fn test_log_namespace_invalid() {
        assert!(!log_namespace_name_valid(""));
        assert!(!log_namespace_name_valid("*glob*"));
        assert!(!log_namespace_name_valid(&"a".repeat(223)));
    }

    #[test]
    fn test_shorten_overlong_preserves_valid() {
        assert_eq!(
            shorten_overlong("name1.example.com"),
            Ok(ShortenOverlongResult::Unchanged(
                "name1.example.com".to_owned()
            ))
        );
    }

    #[test]
    fn test_shorten_overlong_truncates() {
        assert_eq!(
            shorten_overlong(
                "name1.test-dhcp-this-one-here-is-a-very-very-long-domain.example.com"
            ),
            Ok(ShortenOverlongResult::Shortened("name1".to_owned()))
        );

        let long = "test-dhcp-this-one-here-is-a-very-very-long-hostname-without-domainname";
        assert_eq!(
            shorten_overlong(long),
            Ok(ShortenOverlongResult::Shortened(
                "test-dhcp-this-one-here-is-a-very-very-long-hostname-without-dom".to_owned(),
            ))
        );
    }

    #[test]
    fn test_shorten_overlong_rejects_unfixable() {
        assert_eq!(
            shorten_overlong(".test-dhcp-this-one-here-is-a-very-very-long-hostname.example.com"),
            Err(ShortenOverlongError::InvalidHostname)
        );
    }
}
