// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/nsflags.c (namespace_single_flag_to_string,
//            namespace_flags_to_string, namespace_flags_to_strv,
//            namespace_flags_from_string)
//
// Namespace flag classification utilities — pure computation, no I/O.

// ── CLONE_* flag values from linux/sched.h ────────────────────────────────

pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWTIME: u64 = 0x00000080;

const EINVAL: i32 = 22;

// ── Namespace info table ──────────────────────────────────────────────────
// Mirrors namespace_info[] from namespace-util.c. Only proc_name and
// clone_flag fields are needed for pure flag operations.

struct NamespaceInfo {
    proc_name: &'static str,
    clone_flag: u64,
}

static NAMESPACE_INFO: &[NamespaceInfo] = &[
    NamespaceInfo {
        proc_name: "cgroup",
        clone_flag: CLONE_NEWCGROUP,
    },
    NamespaceInfo {
        proc_name: "ipc",
        clone_flag: CLONE_NEWIPC,
    },
    NamespaceInfo {
        proc_name: "net",
        clone_flag: CLONE_NEWNET,
    },
    NamespaceInfo {
        proc_name: "mnt",
        clone_flag: CLONE_NEWNS,
    },
    NamespaceInfo {
        proc_name: "pid",
        clone_flag: CLONE_NEWPID,
    },
    NamespaceInfo {
        proc_name: "user",
        clone_flag: CLONE_NEWUSER,
    },
    NamespaceInfo {
        proc_name: "uts",
        clone_flag: CLONE_NEWUTS,
    },
    NamespaceInfo {
        proc_name: "time",
        clone_flag: CLONE_NEWTIME,
    },
];

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful port of C namespace_single_flag_to_string().
/// Returns the proc_name for a single namespace flag, or None if not found.
pub fn namespace_single_flag_to_string(flag: u64) -> Option<&'static str> {
    NAMESPACE_INFO
        .iter()
        .find(|info| info.clone_flag == flag)
        .map(|info| info.proc_name)
}

/// Faithful port of C namespace_flags_to_strv().
/// Converts a flags bitmask to a Vec of proc_name strings.
pub fn namespace_flags_to_strv(flags: u64) -> Vec<String> {
    NAMESPACE_INFO
        .iter()
        .filter(|info| (flags & info.clone_flag) == info.clone_flag)
        .map(|info| info.proc_name.to_string())
        .collect()
}

/// Faithful port of C namespace_flags_to_string().
/// Converts a flags bitmask to a space-separated string.
/// Returns an empty string for flags == 0.
pub fn namespace_flags_to_string(flags: u64) -> String {
    let names = namespace_flags_to_strv(flags);
    names.join(" ")
}

/// Faithful port of C namespace_flags_from_string().
/// Parses a space-separated string of namespace proc_names into a flags bitmask.
/// Returns Err(-EINVAL) if any word is not a recognized namespace name.
pub fn namespace_flags_from_string(name: &str) -> Result<u64, i32> {
    let mut flags: u64 = 0;

    for word in name.split_whitespace() {
        let found = NAMESPACE_INFO.iter().find(|info| info.proc_name == word);
        match found {
            Some(info) => flags |= info.clone_flag,
            None => return Err(-EINVAL),
        }
    }

    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── namespace_single_flag_to_string tests ──────────────────────────

    #[test]
    fn test_single_flag_to_string_known() {
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWNS), Some("mnt"));
        assert_eq!(
            namespace_single_flag_to_string(CLONE_NEWCGROUP),
            Some("cgroup")
        );
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWUTS), Some("uts"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWIPC), Some("ipc"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWUSER), Some("user"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWPID), Some("pid"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWNET), Some("net"));
        assert_eq!(namespace_single_flag_to_string(CLONE_NEWTIME), Some("time"));
    }

    #[test]
    fn test_single_flag_to_string_unknown() {
        assert_eq!(namespace_single_flag_to_string(0), None);
        assert_eq!(namespace_single_flag_to_string(0xFFFFFFFF), None);
        assert_eq!(namespace_single_flag_to_string(1), None);
    }

    #[test]
    fn test_single_flag_to_string_combined_flags() {
        let combined = CLONE_NEWNS | CLONE_NEWNET;
        assert_eq!(namespace_single_flag_to_string(combined), None);
    }

    // ── namespace_flags_to_strv tests ──────────────────────────────────

    #[test]
    fn test_flags_to_strv_empty() {
        let result = namespace_flags_to_strv(0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_flags_to_strv_single() {
        let result = namespace_flags_to_strv(CLONE_NEWNS);
        assert_eq!(result, vec!["mnt"]);
    }

    #[test]
    fn test_flags_to_strv_multiple() {
        let flags = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID;
        let result = namespace_flags_to_strv(flags);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"mnt".to_string()));
        assert!(result.contains(&"net".to_string()));
        assert!(result.contains(&"pid".to_string()));
    }

    #[test]
    fn test_flags_to_strv_all_flags() {
        let flags = CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET
            | CLONE_NEWTIME;
        let result = namespace_flags_to_strv(flags);
        assert_eq!(result.len(), 8);
    }

    // ── namespace_flags_to_string tests ────────────────────────────────

    #[test]
    fn test_flags_to_string_empty() {
        let result = namespace_flags_to_string(0);
        assert_eq!(result, "");
    }

    #[test]
    fn test_flags_to_string_single() {
        let result = namespace_flags_to_string(CLONE_NEWNS);
        assert_eq!(result, "mnt");
    }

    #[test]
    fn test_flags_to_string_multiple() {
        let flags = CLONE_NEWNS | CLONE_NEWNET;
        let result = namespace_flags_to_string(flags);
        let parts: Vec<&str> = result.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts.contains(&"mnt"));
        assert!(parts.contains(&"net"));
    }

    #[test]
    fn test_flags_to_string_all() {
        let flags = CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET
            | CLONE_NEWTIME;
        let result = namespace_flags_to_string(flags);
        let parts: Vec<&str> = result.split(' ').collect();
        assert_eq!(parts.len(), 8);
    }

    // ── namespace_flags_from_string tests ──────────────────────────────

    #[test]
    fn test_flags_from_string_single() {
        assert_eq!(namespace_flags_from_string("mnt"), Ok(CLONE_NEWNS));
    }

    #[test]
    fn test_flags_from_string_all_names() {
        let tests = [
            ("cgroup", CLONE_NEWCGROUP),
            ("ipc", CLONE_NEWIPC),
            ("net", CLONE_NEWNET),
            ("mnt", CLONE_NEWNS),
            ("pid", CLONE_NEWPID),
            ("user", CLONE_NEWUSER),
            ("uts", CLONE_NEWUTS),
            ("time", CLONE_NEWTIME),
        ];
        for (name, expected) in tests {
            assert_eq!(
                namespace_flags_from_string(name),
                Ok(expected),
                "Failed for {name}"
            );
        }
    }

    #[test]
    fn test_flags_from_string_multiple() {
        assert_eq!(
            namespace_flags_from_string("mnt net pid"),
            Ok(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID)
        );
    }

    #[test]
    fn test_flags_from_string_with_extra_spaces() {
        assert_eq!(
            namespace_flags_from_string("  mnt   net  "),
            Ok(CLONE_NEWNS | CLONE_NEWNET)
        );
    }

    #[test]
    fn test_flags_from_string_empty() {
        assert_eq!(namespace_flags_from_string(""), Ok(0));
    }

    #[test]
    fn test_flags_from_string_invalid() {
        assert!(namespace_flags_from_string("unknown").is_err());
    }

    #[test]
    fn test_flags_from_string_partial_invalid() {
        assert!(namespace_flags_from_string("mnt bogus").is_err());
    }

    // ── roundtrip test ─────────────────────────────────────────────────

    #[test]
    fn test_flags_roundtrip() {
        let original = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID;
        let s = namespace_flags_to_string(original);
        let parsed = namespace_flags_from_string(&s).unwrap();
        assert_eq!(parsed, original);
    }
}
