// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::{HashMap, HashSet};

use crate::Errno;

use super::architecture::seccomp_arch_from_string;
use super::filter_set::{expand_filter_set, syscall_filter_set_find};
use super::model::{
    ParsedSyscallEntry, Result, SCMP_ACT_ALLOW, SCMP_ACT_LOG, SECCOMP_ERROR_NUMBER_KILL,
    SeccompError, SeccompParseFlags, scmp_act_errno,
};

// ── Errno / Action Helpers ───────────────────────────────────────────────

/// Check whether a value is a valid errno number or the special
/// `SECCOMP_ERROR_NUMBER_KILL` sentinel.
///
/// A valid errno on Linux is in the range `1..=4095`.
///
/// Corresponds to `seccomp_errno_or_action_is_valid()` in the C source.
pub fn seccomp_errno_or_action_is_valid(n: i32) -> bool {
    n == SECCOMP_ERROR_NUMBER_KILL || (n > 0 && n <= 4095)
}

/// Parse an errno number or the string `"kill"` from `p`.
///
/// Returns the parsed value on success or `Err(Errno::EINVAL)` on failure.
///
/// Corresponds to `seccomp_parse_errno_or_action()` in the C source.
pub fn seccomp_parse_errno_or_action(p: &str) -> std::result::Result<i32, Errno> {
    if p == "kill" {
        return Ok(SECCOMP_ERROR_NUMBER_KILL);
    }
    if let Ok(n) = systemd_basic_rs::errno_util::errno_from_name(p) {
        return Ok(n);
    }
    match p.parse::<i32>() {
        Ok(n) if seccomp_errno_or_action_is_valid(n) => Ok(n),
        _ => Err(Errno::EINVAL),
    }
}

/// Convert an errno-or-action value back to a display string.
///
/// Corresponds to `seccomp_errno_or_action_to_string()` in the C source.
pub fn seccomp_errno_or_action_to_string(n: i32) -> &'static str {
    if n == SECCOMP_ERROR_NUMBER_KILL {
        return "kill";
    }
    systemd_basic_rs::errno_util::errno_name_no_fallback(n).unwrap_or("errno")
}

// ── Default-Action Override ──────────────────────────────────────────────

/// When the requested filter is a deny-list and the default action is
/// something critical, install `ENOSYS` as the default — it will only
/// apply to syscalls not in the `@known` set.
///
/// `SCMP_ACT_ALLOW` and `SCMP_ACT_LOG` pass through unchanged.
///
/// Corresponds to `override_default_action()` in the C source.
pub fn override_default_action(default_action: u32) -> u32 {
    if default_action == SCMP_ACT_ALLOW || default_action == SCMP_ACT_LOG {
        return default_action;
    }
    scmp_act_errno(libc::ENOSYS as u32)
}

// ── Fatal Error Detection ────────────────────────────────────────────────

/// Returns `true` if the given (negative) libseccomp return code represents
/// a fatal error that should not be silently ignored.
///
/// Fatal errors: `EPERM`, `EACCES`, `ENOMEM`, `EFAULT`.
///
/// Corresponds to `ERRNO_IS_NEG_SECCOMP_FATAL()` in the C source.
pub fn errno_is_seccomp_fatal(r: i32) -> bool {
    matches!(-r, libc::EPERM | libc::EACCES | libc::ENOMEM | libc::EFAULT)
}

// ── Parsing Utilities ────────────────────────────────────────────────────

/// Parse a `"syscall:errno"` style string (e.g. `"uname:EILSEQ"`,
/// `"@sync:255"`).
///
/// Returns `Ok((name, errno))` where `errno` is `-1` when omitted.
/// Empty syscall names are rejected.
///
/// Corresponds to `parse_syscall_and_errno()` in the C source.
pub fn parse_syscall_and_errno(input: &str) -> Result<(&str, i32)> {
    if input.is_empty() {
        return Err(SeccompError::InvalidArgument("empty syscall name".into()));
    }

    if let Some(colon_pos) = input.find(':') {
        let name = &input[..colon_pos];
        let errno_str = &input[colon_pos + 1..];
        if name.is_empty() {
            return Err(SeccompError::InvalidArgument("empty syscall name".into()));
        }
        let errno_val = seccomp_parse_errno_or_action(errno_str).map_err(|_| {
            SeccompError::InvalidArgument(format!("invalid errno/action: {}", errno_str))
        })?;
        Ok((name, errno_val))
    } else {
        Ok((input, -1))
    }
}

/// Parse a list of architecture name strings into a set of seccomp
/// architecture constants.
///
/// Returns an error if any name is unrecognised.
///
/// Corresponds to `parse_syscall_archs()` in the C source.
pub fn parse_syscall_archs(names: &[&str]) -> Result<HashSet<u32>> {
    let mut archs = HashSet::new();
    for &name in names {
        let arch = seccomp_arch_from_string(name).map_err(|_| {
            SeccompError::InvalidArgument(format!("unknown architecture: {}", name))
        })?;
        archs.insert(arch);
    }
    Ok(archs)
}

/// Parse a `"syscall:errno"` string and return owned components.
///
/// Like [`parse_syscall_and_errno`] but returns owned `String` for the name.
pub fn parse_syscall_and_errno_owned(input: &str) -> Result<(String, i32)> {
    let (name, errno) = parse_syscall_and_errno(input)?;
    Ok((name.to_owned(), errno))
}

// ── Seccomp Filter Parsing ──────────────────────────────────────────────

/// Parse a full syscall filter specification into a list of entries.
///
/// Handles individual syscall names, `@set` references, and `name:errno`
/// syntax.  Unknown set names are rejected unless `flags` includes
/// `PERMISSIVE`.
///
/// Corresponds to `seccomp_parse_syscall_filter()` in the C source.
pub fn seccomp_parse_syscall_filter_spec(
    items: &[&str],
    flags: SeccompParseFlags,
) -> Result<Vec<ParsedSyscallEntry>> {
    let mut entries = Vec::new();

    for &item in items {
        let (name, errno) = parse_syscall_and_errno(item)?;

        if name.starts_with('@') {
            let set = match syscall_filter_set_find(name) {
                Some(s) => s,
                None => {
                    if flags.contains(SeccompParseFlags::PERMISSIVE) {
                        continue;
                    }
                    return Err(SeccompError::InvalidArgument(format!(
                        "unknown system call group: {}",
                        name
                    )));
                }
            };
            for sys in expand_filter_set(set) {
                entries.push(ParsedSyscallEntry {
                    name: sys.to_owned(),
                    errno,
                });
            }
        } else {
            entries.push(ParsedSyscallEntry {
                name: name.to_owned(),
                errno,
            });
        }
    }

    Ok(entries)
}

// ── Seccomp Parse Syscall Filter (Logic) ────────────────────────────────

/// Build a syscall filter map from parsed entries.
///
/// Returns unresolved syscall names mapped to their configured errno.
///
/// Numeric syscall resolution is architecture- and libseccomp-dependent and
/// must happen at the OS boundary. Keeping names here prevents hash collisions
/// from silently merging distinct policy entries.
pub fn build_syscall_filter_map(
    entries: &[ParsedSyscallEntry],
    flags: SeccompParseFlags,
) -> Result<HashMap<String, i32>> {
    let mut filter = HashMap::new();
    let invert = flags.contains(SeccompParseFlags::INVERT);
    let allow_list = flags.contains(SeccompParseFlags::ALLOW_LIST);

    for entry in entries {
        let effective_errno = entry.errno;

        // Determine whether to insert or remove
        // The four C parser modes reduce to one rule: ordinary parsing and
        // deny-lists retain every entry; an inverted allow-list omits only
        // entries without an explicit errno override.
        let should_insert = !invert || !allow_list || effective_errno >= 0;

        if should_insert {
            filter.insert(entry.name.clone(), effective_errno);
        }
    }

    Ok(filter)
}
