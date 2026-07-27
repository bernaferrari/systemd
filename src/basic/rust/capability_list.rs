// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/capability-list.c (name/value lookup subset)
//
// Linux capability name/value lookups — pure data, no syscalls.

use crate::capability_util::CAP_LIMIT;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLookupError {
    InvalidArgument,
    NotFound,
}

pub type CapabilityLookupResult<T> = Result<T, CapabilityLookupError>;

// ── capability_names array (indexed by capability number) ───────────────

static CAPABILITY_NAMES: &[&str] = &[
    "cap_chown",              // 0
    "cap_dac_override",       // 1
    "cap_dac_read_search",    // 2
    "cap_fowner",             // 3
    "cap_fsetid",             // 4
    "cap_kill",               // 5
    "cap_setgid",             // 6
    "cap_setuid",             // 7
    "cap_setpcap",            // 8
    "cap_linux_immutable",    // 9
    "cap_net_bind_service",   // 10
    "cap_net_broadcast",      // 11
    "cap_net_admin",          // 12
    "cap_net_raw",            // 13
    "cap_ipc_lock",           // 14
    "cap_ipc_owner",          // 15
    "cap_sys_module",         // 16
    "cap_sys_rawio",          // 17
    "cap_sys_chroot",         // 18
    "cap_sys_ptrace",         // 19
    "cap_sys_pacct",          // 20
    "cap_sys_admin",          // 21
    "cap_sys_boot",           // 22
    "cap_sys_nice",           // 23
    "cap_sys_resource",       // 24
    "cap_sys_time",           // 25
    "cap_sys_tty_config",     // 26
    "cap_mknod",              // 27
    "cap_lease",              // 28
    "cap_audit_write",        // 29
    "cap_audit_control",      // 30
    "cap_setfcap",            // 31
    "cap_mac_override",       // 32
    "cap_mac_admin",          // 33
    "cap_syslog",             // 34
    "cap_wake_alarm",         // 35
    "cap_block_suspend",      // 36
    "cap_audit_read",         // 37
    "cap_perfmon",            // 38
    "cap_bpf",                // 39
    "cap_checkpoint_restore", // 40
];

// ── capability_from_name lookup table (sorted by name) ─────────────────

static CAPABILITY_FROM_NAME_TABLE: &[(&str, i32)] = &[
    ("cap_audit_control", 30),
    ("cap_audit_read", 37),
    ("cap_audit_write", 29),
    ("cap_block_suspend", 36),
    ("cap_bpf", 39),
    ("cap_checkpoint_restore", 40),
    ("cap_chown", 0),
    ("cap_dac_override", 1),
    ("cap_dac_read_search", 2),
    ("cap_fowner", 3),
    ("cap_fsetid", 4),
    ("cap_ipc_lock", 14),
    ("cap_ipc_owner", 15),
    ("cap_kill", 5),
    ("cap_lease", 28),
    ("cap_linux_immutable", 9),
    ("cap_mac_admin", 33),
    ("cap_mac_override", 32),
    ("cap_mknod", 27),
    ("cap_net_admin", 12),
    ("cap_net_bind_service", 10),
    ("cap_net_broadcast", 11),
    ("cap_net_raw", 13),
    ("cap_perfmon", 38),
    ("cap_setfcap", 31),
    ("cap_setgid", 6),
    ("cap_setpcap", 8),
    ("cap_setuid", 7),
    ("cap_sys_admin", 21),
    ("cap_sys_boot", 22),
    ("cap_sys_chroot", 18),
    ("cap_sys_module", 16),
    ("cap_sys_nice", 23),
    ("cap_sys_pacct", 20),
    ("cap_sys_ptrace", 19),
    ("cap_sys_rawio", 17),
    ("cap_sys_resource", 24),
    ("cap_sys_time", 25),
    ("cap_sys_tty_config", 26),
    ("cap_syslog", 34),
    ("cap_wake_alarm", 35),
];

// ── Public API ────────────────────────────────────────────────────────────

/// Look up a capability name by its numeric ID.
/// Returns `Some(name)` if the ID is known, `None` otherwise.
/// Port of C `capability_to_name()`.
pub fn capability_to_name(id: i32) -> Option<&'static str> {
    if id < 0 {
        return None;
    }
    CAPABILITY_NAMES.get(id as usize).copied()
}

/// Format a capability as a string: returns the name if known,
/// or formats as "0x{hex}" for unknown capabilities within the valid range.
/// Port of C `capability_to_string()`.
pub fn capability_to_string(id: i32) -> Option<String> {
    if id < 0 || id > CAP_LIMIT {
        return None;
    }
    match capability_to_name(id) {
        Some(name) => Some(name.to_string()),
        None => Some(format!("0x{:x}", id as u32)),
    }
}

/// Parse a capability name or numeric string to its integer ID.
/// Accepts names like "cap_chown" and numeric strings like "0".
/// Port of C `capability_from_name()`.
pub fn capability_from_name(name: &str) -> CapabilityLookupResult<i32> {
    if name.is_empty() {
        return Err(CapabilityLookupError::NotFound);
    }

    if name.bytes().all(|b| b.is_ascii_digit()) {
        let val: i32 = name
            .parse()
            .map_err(|_| CapabilityLookupError::InvalidArgument)?;
        if val < 0 || val > CAP_LIMIT {
            return Err(CapabilityLookupError::InvalidArgument);
        }
        return Ok(val);
    }

    match CAPABILITY_FROM_NAME_TABLE.binary_search_by(|(entry_name, _)| (*entry_name).cmp(name)) {
        Ok(idx) => Ok(CAPABILITY_FROM_NAME_TABLE[idx].1),
        Err(_) => Err(CapabilityLookupError::NotFound),
    }
}

/// Return the number of compiled-in capability names, capped at CAP_LIMIT+1.
/// Port of C `capability_list_length()`.
pub fn capability_list_length() -> u32 {
    let from_table = CAPABILITY_NAMES.len() as u32;
    let limit = (CAP_LIMIT + 1) as u32;
    if from_table < limit {
        from_table
    } else {
        limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_to_name_valid() {
        assert_eq!(capability_to_name(0), Some("cap_chown"));
        assert_eq!(capability_to_name(21), Some("cap_sys_admin"));
        assert_eq!(capability_to_name(40), Some("cap_checkpoint_restore"));
    }

    #[test]
    fn test_capability_to_name_invalid() {
        assert_eq!(capability_to_name(-1), None);
        assert_eq!(capability_to_name(41), None);
        assert_eq!(capability_to_name(100), None);
    }

    #[test]
    fn test_capability_to_name_boundaries() {
        assert_eq!(capability_to_name(0), Some("cap_chown"));
        assert_eq!(capability_to_name(40), Some("cap_checkpoint_restore"));
    }

    #[test]
    fn test_capability_to_string_known() {
        assert_eq!(capability_to_string(0), Some("cap_chown".to_string()));
        assert_eq!(capability_to_string(13), Some("cap_net_raw".to_string()));
        assert_eq!(
            capability_to_string(40),
            Some("cap_checkpoint_restore".to_string())
        );
    }

    #[test]
    fn test_capability_to_string_hex_fallback() {
        assert_eq!(capability_to_string(41), Some("0x29".to_string()));
        assert_eq!(capability_to_string(62), Some("0x3e".to_string()));
    }

    #[test]
    fn test_capability_to_string_invalid() {
        assert!(capability_to_string(-1).is_none());
        assert!(capability_to_string(63).is_none());
    }

    #[test]
    fn test_capability_from_name_valid() {
        assert_eq!(capability_from_name("cap_chown"), Ok(0));
        assert_eq!(capability_from_name("cap_sys_admin"), Ok(21));
        assert_eq!(capability_from_name("cap_net_raw"), Ok(13));
        assert_eq!(capability_from_name("cap_checkpoint_restore"), Ok(40));
    }

    #[test]
    fn test_capability_from_name_numeric() {
        assert_eq!(capability_from_name("0"), Ok(0));
        assert_eq!(capability_from_name("21"), Ok(21));
        assert_eq!(capability_from_name("40"), Ok(40));
        assert_eq!(capability_from_name("62"), Ok(62));
    }

    #[test]
    fn test_capability_from_name_invalid() {
        assert!(capability_from_name("nonexistent").is_err());
        assert!(capability_from_name("").is_err());
        assert!(capability_from_name("63").is_err());
        assert!(capability_from_name("-1").is_err());
    }

    #[test]
    fn test_capability_from_name_case_sensitive() {
        assert!(capability_from_name("CAP_CHOWN").is_err());
        assert!(capability_from_name("Cap_Chown").is_err());
    }

    #[test]
    fn test_capability_list_length() {
        let len = capability_list_length();
        assert!(len > 0);
        assert_eq!(len, 41);
    }

    #[test]
    fn test_capability_roundtrip() {
        for i in 0..41 {
            let name = capability_to_name(i);
            assert!(
                name.is_some(),
                "capability_to_name({}) should return a name",
                i
            );
            let back = capability_from_name(name.unwrap());
            assert_eq!(back, Ok(i), "roundtrip for cap {} failed", i);
        }
    }

    #[test]
    fn test_capability_from_name_all_table_entries() {
        for (name, val) in CAPABILITY_FROM_NAME_TABLE {
            let result = capability_from_name(name);
            assert_eq!(result, Ok(*val), "lookup failed for {}", name);
        }
    }
}
