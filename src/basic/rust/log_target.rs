// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/log.c (log_target string table subset)
//
// Log target string table lookups.

use crate::ffi::Errno;

// ── Constants ──────────────────────────────────────────────────────────────

/// Log target indices matching the C LogTarget enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogTarget {
    Console = 0,
    Kmsg = 1,
    Journal = 2,
    Syslog = 3,
    ConsolePrefixed = 4,
    JournalOrKmsg = 5,
    SyslogOrKmsg = 6,
    Auto = 7,
    Null = 8,
}

// ── Internal table ─────────────────────────────────────────────────────────

struct LogTargetEntry {
    target: LogTarget,
    name: &'static str,
}

static LOG_TARGET_TABLE: &[LogTargetEntry] = &[
    LogTargetEntry {
        target: LogTarget::Console,
        name: "console",
    },
    LogTargetEntry {
        target: LogTarget::Kmsg,
        name: "kmsg",
    },
    LogTargetEntry {
        target: LogTarget::Journal,
        name: "journal",
    },
    LogTargetEntry {
        target: LogTarget::Syslog,
        name: "syslog",
    },
    LogTargetEntry {
        target: LogTarget::ConsolePrefixed,
        name: "console-prefixed",
    },
    LogTargetEntry {
        target: LogTarget::JournalOrKmsg,
        name: "journal-or-kmsg",
    },
    LogTargetEntry {
        target: LogTarget::SyslogOrKmsg,
        name: "syslog-or-kmsg",
    },
    LogTargetEntry {
        target: LogTarget::Auto,
        name: "auto",
    },
    LogTargetEntry {
        target: LogTarget::Null,
        name: "null",
    },
];

// ── Public API ─────────────────────────────────────────────────────────────

/// Convert a LogTarget to its string representation.
///
/// Port of `log_target_to_string()` from log.c.
/// Returns `Some(name)` on valid target, `None` on invalid index.
pub fn log_target_to_string(target: LogTarget) -> Option<&'static str> {
    for entry in LOG_TARGET_TABLE {
        if entry.target == target {
            return Some(entry.name);
        }
    }
    None
}

/// Parse a log target string into a LogTarget enum value.
///
/// Port of `log_target_from_string()` from log.c.
/// Case-sensitive. Returns `Ok(LogTarget)` on match, `Err(EINVAL)` on failure.
pub fn log_target_from_string(s: &str) -> Result<LogTarget, Errno> {
    for entry in LOG_TARGET_TABLE {
        if s == entry.name {
            return Ok(entry.target);
        }
    }
    Err(Errno::EINVAL)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_string_console() {
        assert_eq!(log_target_to_string(LogTarget::Console), Some("console"));
    }

    #[test]
    fn test_to_string_kmsg() {
        assert_eq!(log_target_to_string(LogTarget::Kmsg), Some("kmsg"));
    }

    #[test]
    fn test_to_string_journal() {
        assert_eq!(log_target_to_string(LogTarget::Journal), Some("journal"));
    }

    #[test]
    fn test_to_string_syslog() {
        assert_eq!(log_target_to_string(LogTarget::Syslog), Some("syslog"));
    }

    #[test]
    fn test_to_string_console_prefixed() {
        assert_eq!(
            log_target_to_string(LogTarget::ConsolePrefixed),
            Some("console-prefixed")
        );
    }

    #[test]
    fn test_to_string_journal_or_kmsg() {
        assert_eq!(
            log_target_to_string(LogTarget::JournalOrKmsg),
            Some("journal-or-kmsg")
        );
    }

    #[test]
    fn test_to_string_syslog_or_kmsg() {
        assert_eq!(
            log_target_to_string(LogTarget::SyslogOrKmsg),
            Some("syslog-or-kmsg")
        );
    }

    #[test]
    fn test_to_string_auto() {
        assert_eq!(log_target_to_string(LogTarget::Auto), Some("auto"));
    }

    #[test]
    fn test_to_string_null() {
        assert_eq!(log_target_to_string(LogTarget::Null), Some("null"));
    }

    #[test]
    fn test_from_string_roundtrip() {
        for entry in LOG_TARGET_TABLE {
            let back = log_target_from_string(entry.name).unwrap();
            assert_eq!(back, entry.target);
        }
    }

    #[test]
    fn test_from_string_case_sensitive() {
        assert_eq!(log_target_from_string("SYSLOG"), Err(Errno::EINVAL));
        assert_eq!(log_target_from_string("Journal"), Err(Errno::EINVAL));
        assert_eq!(log_target_from_string("AUTO"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_from_string_invalid() {
        assert_eq!(log_target_from_string("invalid"), Err(Errno::EINVAL));
        assert_eq!(log_target_from_string(""), Err(Errno::EINVAL));
    }

    #[test]
    fn test_from_string_partial_match() {
        assert_eq!(log_target_from_string("consol"), Err(Errno::EINVAL));
        assert_eq!(log_target_from_string("journal-or"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_enum_values() {
        assert_eq!(LogTarget::Console as i32, 0);
        assert_eq!(LogTarget::Kmsg as i32, 1);
        assert_eq!(LogTarget::Journal as i32, 2);
        assert_eq!(LogTarget::Syslog as i32, 3);
        assert_eq!(LogTarget::ConsolePrefixed as i32, 4);
        assert_eq!(LogTarget::JournalOrKmsg as i32, 5);
        assert_eq!(LogTarget::SyslogOrKmsg as i32, 6);
        assert_eq!(LogTarget::Auto as i32, 7);
        assert_eq!(LogTarget::Null as i32, 8);
    }

    #[test]
    fn test_to_string_from_string_symmetry() {
        let targets = [
            LogTarget::Console,
            LogTarget::Kmsg,
            LogTarget::Journal,
            LogTarget::Syslog,
            LogTarget::ConsolePrefixed,
            LogTarget::JournalOrKmsg,
            LogTarget::SyslogOrKmsg,
            LogTarget::Auto,
            LogTarget::Null,
        ];
        for t in targets {
            let name = log_target_to_string(t).unwrap();
            let back = log_target_from_string(name).unwrap();
            assert_eq!(back, t);
        }
    }
}
