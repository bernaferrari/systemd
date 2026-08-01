// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Own unit-name decomposition and specifier expansion, including the host identity lookups used
 * by specifiers. This module depends on neither parsed unit configuration nor RuntimeManager.
 */
use std::env;
use std::fs;
use std::path::Path;

use nix::unistd::{Gid, Uid};
#[cfg(target_os = "linux")]
use std::ffi::CStr;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;

pub(super) fn is_template_unit_name(unit_name: &str) -> bool {
    let stem = unit_name.split('.').next().unwrap_or(unit_name);
    stem.ends_with('@')
}

pub(super) fn is_instance_unit_name(unit_name: &str) -> bool {
    let stem = unit_name.split('.').next().unwrap_or(unit_name);
    stem.split_once('@')
        .is_some_and(|(_, instance)| !instance.is_empty())
}

pub(super) fn default_instance_is_valid(instance: &str) -> bool {
    !instance.is_empty()
        && !instance.contains('/')
        && !instance.contains('\\')
        && !instance.contains(char::is_whitespace)
}

pub(super) fn template_unit_name(unit_name: &str) -> Option<String> {
    let (stem, suffix) = unit_name.rsplit_once('.')?;
    let (prefix, instance) = stem.split_once('@')?;
    if instance.is_empty() {
        return None;
    }

    Some(format!("{prefix}@.{suffix}"))
}

pub(super) fn unit_instance_name(unit_name: &str) -> Option<&str> {
    let stem = unit_name.split('.').next().unwrap_or(unit_name);
    let (_, instance) = stem.split_once('@')?;
    if instance.is_empty() {
        return None;
    }
    Some(instance)
}

pub(super) fn unit_name_without_suffix(unit_name: &str) -> &str {
    unit_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(unit_name)
}

pub(super) fn unit_name_prefix(unit_name: &str) -> &str {
    let stem = unit_name_without_suffix(unit_name);
    stem.split_once('@')
        .map(|(prefix, _)| prefix)
        .unwrap_or(stem)
}

pub(super) fn unit_name_last_component(unit_name: &str) -> &str {
    unit_name_prefix(unit_name)
        .rsplit('-')
        .next()
        .unwrap_or(unit_name_prefix(unit_name))
}

pub(super) fn unit_name_unescape(value: &str) -> String {
    value.replace('-', "/")
}

pub(super) fn unit_name_path_unescape(value: &str) -> String {
    format!("/{}", unit_name_unescape(value).trim_start_matches('/'))
}

pub(super) fn read_trimmed_file(path: impl AsRef<Path>) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn normalize_hex_id(value: &str) -> String {
    value.chars().filter(|ch| *ch != '-').collect()
}

pub(super) fn resolve_runtime_dir_root() -> String {
    env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| v.starts_with('/'))
        .unwrap_or_else(|| "/run".to_string())
}

pub(super) fn resolve_env_tmp_dir() -> Option<String> {
    ["TMPDIR", "TEMP", "TMP"].iter().find_map(|key| {
        env::var(key).ok().and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.starts_with('/') {
                Some(trimmed)
            } else {
                None
            }
        })
    })
}

pub(super) fn resolve_tmp_dir() -> String {
    resolve_env_tmp_dir().unwrap_or_else(|| "/tmp".to_string())
}

pub(super) fn resolve_var_tmp_dir() -> String {
    resolve_env_tmp_dir().unwrap_or_else(|| "/var/tmp".to_string())
}

pub(super) fn resolve_machine_id_from_paths(paths: &[&str]) -> String {
    for path in paths {
        if let Some(value) = read_trimmed_file(path) {
            let value = normalize_hex_id(&value);
            if !value.is_empty() {
                return value;
            }
        }
    }

    String::new()
}

pub(super) fn resolve_machine_id() -> String {
    resolve_machine_id_from_paths(&["/etc/machine-id", "/var/lib/dbus/machine-id"])
}

pub(super) fn resolve_boot_id_from_path(path: &str) -> String {
    read_trimmed_file(path)
        .map(|value| normalize_hex_id(&value))
        .unwrap_or_default()
}

pub(super) fn resolve_boot_id() -> String {
    resolve_boot_id_from_path("/proc/sys/kernel/random/boot_id")
}

pub(super) fn resolve_hostname_from_path(path: &str) -> String {
    read_trimmed_file(path).unwrap_or_default()
}

pub(super) fn resolve_hostname() -> String {
    let hostname = resolve_hostname_from_path("/proc/sys/kernel/hostname");
    if !hostname.is_empty() {
        return hostname;
    }

    env::var("HOSTNAME").unwrap_or_default()
}

pub(super) fn parse_env_assignment_style_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let quoted = (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'');
        if quoted {
            let inner = &trimmed[1..trimmed.len() - 1];
            if bytes[0] == b'"' {
                let mut out = String::new();
                let mut escaped = false;
                for ch in inner.chars() {
                    if escaped {
                        out.push(ch);
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else {
                        out.push(ch);
                    }
                }
                if escaped {
                    out.push('\\');
                }
                return out;
            }
            return inner.to_string();
        }
    }

    trimmed.to_string()
}

pub(super) fn resolve_key_from_assignment_file(path: &str, key: &str) -> String {
    let Ok(contents) = fs::read_to_string(path) else {
        return String::new();
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        if lhs.trim() == key {
            return parse_env_assignment_style_value(rhs);
        }
    }

    String::new()
}

pub(super) fn resolve_os_release_field_from_paths(paths: &[&str], key: &str) -> String {
    for path in paths {
        let value = resolve_key_from_assignment_file(path, key);
        if !value.is_empty() {
            return value;
        }
    }

    String::new()
}

pub(super) fn resolve_os_release_field(key: &str) -> String {
    resolve_os_release_field_from_paths(&["/etc/os-release", "/usr/lib/os-release"], key)
}

pub(super) fn resolve_short_hostname() -> String {
    let hostname = resolve_hostname();
    hostname.split('.').next().unwrap_or("").to_string()
}

pub(super) fn resolve_pretty_hostname_from_path(path: &str) -> String {
    resolve_key_from_assignment_file(path, "PRETTY_HOSTNAME")
}

pub(super) fn resolve_pretty_hostname() -> String {
    let pretty = resolve_pretty_hostname_from_path("/etc/machine-info");
    if !pretty.is_empty() {
        return pretty;
    }
    resolve_short_hostname()
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_passwd_record(uid: libc::uid_t) -> Option<(String, String, String)> {
    // SAFETY: `sysconf` has no additional safety preconditions.
    let size = unsafe_ffi!(libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX));
    let capacity = if size <= 0 { 16_384 } else { size as usize };
    let mut buf = vec![0u8; capacity];
    let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
    let mut result = std::ptr::null_mut();

    // SAFETY: all pointers are valid for writes/reads for the duration of this call.
    let rc = unsafe_ffi!({
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    });
    if rc != 0 || result.is_null() {
        return None;
    }

    // SAFETY: `result` points at `pwd` initialized by `getpwuid_r` above.
    let pwd = unsafe_ffi!(pwd.assume_init());
    // SAFETY: pointers in `passwd` refer into `buf`, which is still alive here.
    let name = unsafe_ffi!(CStr::from_ptr(pwd.pw_name))
        .to_string_lossy()
        .into_owned();
    // SAFETY: pointers in `passwd` refer into `buf`, which is still alive here.
    let home = unsafe_ffi!(CStr::from_ptr(pwd.pw_dir))
        .to_string_lossy()
        .into_owned();
    // SAFETY: pointers in `passwd` refer into `buf`, which is still alive here.
    let shell = unsafe_ffi!(CStr::from_ptr(pwd.pw_shell))
        .to_string_lossy()
        .into_owned();

    Some((name, home, shell))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn resolve_passwd_record(_uid: libc::uid_t) -> Option<(String, String, String)> {
    None
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_group_name_from_gid(gid: libc::gid_t) -> Option<String> {
    // SAFETY: `sysconf` has no additional safety preconditions.
    let size = unsafe_ffi!(libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX));
    let capacity = if size <= 0 { 16_384 } else { size as usize };
    let mut buf = vec![0u8; capacity];
    let mut grp = MaybeUninit::<libc::group>::zeroed();
    let mut result = std::ptr::null_mut();

    // SAFETY: all pointers are valid for writes/reads for the duration of this call.
    let rc = unsafe_ffi!({
        libc::getgrgid_r(
            gid,
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    });
    if rc != 0 || result.is_null() {
        return None;
    }

    // SAFETY: `result` points at `grp` initialized by `getgrgid_r` above.
    let grp = unsafe_ffi!(grp.assume_init());
    // SAFETY: pointer in `group` refers into `buf`, which is still alive here.
    Some(
        unsafe_ffi!(CStr::from_ptr(grp.gr_name))
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn resolve_group_name_from_gid(_gid: libc::gid_t) -> Option<String> {
    None
}

pub(super) fn resolve_user_name() -> String {
    let uid = Uid::effective().as_raw();
    resolve_passwd_record(uid)
        .map(|(name, _, _)| name)
        .or_else(|| env::var("USER").ok())
        .unwrap_or_default()
}

pub(super) fn resolve_user_id() -> String {
    Uid::effective().as_raw().to_string()
}

pub(super) fn resolve_group_name() -> String {
    let gid = Gid::effective().as_raw();
    resolve_group_name_from_gid(gid).unwrap_or_default()
}

pub(super) fn resolve_group_id() -> String {
    Gid::effective().as_raw().to_string()
}

pub(super) fn resolve_user_home() -> String {
    let uid = Uid::effective().as_raw();
    resolve_passwd_record(uid)
        .map(|(_, home, _)| home)
        .or_else(|| env::var("HOME").ok())
        .unwrap_or_default()
}

pub(super) fn resolve_user_shell() -> String {
    let uid = Uid::effective().as_raw();
    resolve_passwd_record(uid)
        .map(|(_, _, shell)| shell)
        .or_else(|| env::var("SHELL").ok())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_kernel_release() -> String {
    nix::sys::utsname::uname()
        .ok()
        .map(|uts| uts.release().to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn resolve_kernel_release() -> String {
    String::new()
}

pub(super) fn resolve_fragment_real_path(fragment_path: Option<&Path>) -> String {
    let Some(path) = fragment_path else {
        return String::new();
    };

    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

pub(super) fn resolve_fragment_real_directory(fragment_path: Option<&Path>) -> String {
    let real_path = resolve_fragment_real_path(fragment_path);
    if real_path.is_empty() {
        return String::new();
    }
    Path::new(&real_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub(super) fn expand_instance_specifiers(
    value: &str,
    unit_name: &str,
    fragment_path: Option<&Path>,
) -> Option<String> {
    let instance = unit_instance_name(unit_name).unwrap_or("");
    let mut expanded = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            expanded.push(ch);
            continue;
        }

        let Some(specifier) = chars.next() else {
            expanded.push('%');
            break;
        };

        match specifier {
            '%' => expanded.push('%'),
            'i' => expanded.push_str(instance),
            'I' => expanded.push_str(&unit_name_unescape(instance)),
            'n' => expanded.push_str(unit_name),
            'N' => expanded.push_str(unit_name_without_suffix(unit_name)),
            'p' => expanded.push_str(unit_name_prefix(unit_name)),
            'P' => expanded.push_str(&unit_name_unescape(unit_name_prefix(unit_name))),
            'j' => expanded.push_str(unit_name_last_component(unit_name)),
            'J' => expanded.push_str(&unit_name_unescape(unit_name_last_component(unit_name))),
            'f' => expanded.push_str(&unit_name_path_unescape(if instance.is_empty() {
                unit_name_prefix(unit_name)
            } else {
                instance
            })),
            'a' => expanded.push_str(std::env::consts::ARCH),
            'A' => expanded.push_str(&resolve_os_release_field("IMAGE_VERSION")),
            't' => expanded.push_str(&resolve_runtime_dir_root()),
            'm' => expanded.push_str(&resolve_machine_id()),
            'b' => expanded.push_str(&resolve_boot_id()),
            'B' => expanded.push_str(&resolve_os_release_field("BUILD_ID")),
            'H' => expanded.push_str(&resolve_hostname()),
            'l' => expanded.push_str(&resolve_short_hostname()),
            'q' => expanded.push_str(&resolve_pretty_hostname()),
            'M' => expanded.push_str(&resolve_os_release_field("IMAGE_ID")),
            'o' => expanded.push_str(&resolve_os_release_field("ID")),
            'v' => expanded.push_str(&resolve_kernel_release()),
            'w' => expanded.push_str(&resolve_os_release_field("VERSION_ID")),
            'W' => expanded.push_str(&resolve_os_release_field("VARIANT_ID")),
            'g' => expanded.push_str(&resolve_group_name()),
            'G' => expanded.push_str(&resolve_group_id()),
            'u' => expanded.push_str(&resolve_user_name()),
            'U' => expanded.push_str(&resolve_user_id()),
            'h' => expanded.push_str(&resolve_user_home()),
            's' => expanded.push_str(&resolve_user_shell()),
            'y' => expanded.push_str(&resolve_fragment_real_path(fragment_path)),
            'Y' => expanded.push_str(&resolve_fragment_real_directory(fragment_path)),
            'T' => expanded.push_str(&resolve_tmp_dir()),
            'V' => expanded.push_str(&resolve_var_tmp_dir()),
            other => {
                if other.is_ascii_alphanumeric() {
                    return None;
                }
                expanded.push('%');
                expanded.push(other);
            }
        }
    }

    Some(expanded)
}

pub(super) fn expand_instance_specifiers_token_wise(
    value: &str,
    unit_name: &str,
    fragment_path: Option<&Path>,
) -> Option<String> {
    if value.trim().is_empty() {
        return Some(String::new());
    }

    let mut expanded_tokens = Vec::new();
    for token in value.split_whitespace() {
        if let Some(expanded) = expand_instance_specifiers(token, unit_name, fragment_path) {
            expanded_tokens.push(expanded);
        }
    }

    if expanded_tokens.is_empty() {
        None
    } else {
        Some(expanded_tokens.join(" "))
    }
}
