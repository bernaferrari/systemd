// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/exec-util.c (exec_command_flags_to_string, exec_command_flags_from_string,
//            exec_command_flags_from_strv, exec_command_flags_to_strv)
//            src/shared/bootspec.c (indent_embedded_newlines)
//
// Exec command flags string table and embedded newline indentation.

// ── Error types ──────────────────────────────────────────────────────────

/// Error constants matching the C return conventions.
const EINVAL: i32 = -22;
const ENOMEM: i32 = -12;

// ── Exec command flags enum ──────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExecCommandFlags: u32 {
        const IGNORE_FAILURE = 1 << 0;
        const FULLY_PRIVILEGED = 1 << 1;
        const NO_SETUID = 1 << 2;
        const NO_ENV_EXPAND = 1 << 3;
        const VIA_SHELL = 1 << 4;
    }
}

static EXEC_COMMAND_STRINGS: [&str; 5] = [
    "ignore-failure",
    "privileged",
    "no-setuid",
    "no-env-expand",
    "via-shell",
];

// ── exec_command_flags_to_string ─────────────────────────────────────────

/// Convert a single exec command flag bit to its string name.
/// Mirrors `exec_command_flags_to_string()` from exec-util.c.
pub fn exec_command_flags_to_string(flag: ExecCommandFlags) -> Option<&'static str> {
    let bits = flag.bits();
    for (idx, &s) in EXEC_COMMAND_STRINGS.iter().enumerate() {
        if bits == (1 << idx) {
            return Some(s);
        }
    }
    None
}

// ── exec_command_flags_from_string ───────────────────────────────────────

/// Parse a string into an exec command flag bit.
/// Mirrors `exec_command_flags_from_string()` from exec-util.c.
/// "ambient" maps to no bits set (0) for backward compatibility.
pub fn exec_command_flags_from_string(s: &str) -> Result<ExecCommandFlags, i32> {
    if s == "ambient" {
        return Ok(ExecCommandFlags::empty());
    }
    for (idx, &table_s) in EXEC_COMMAND_STRINGS.iter().enumerate() {
        if s == table_s {
            return Ok(ExecCommandFlags::from_bits_retain(1 << idx));
        }
    }
    Err(EINVAL)
}

// ── exec_command_flags_from_strv ─────────────────────────────────────────

/// Parse a list of flag name strings into a combined bitmask.
/// Mirrors `exec_command_flags_from_strv()` from exec-util.c.
pub fn exec_command_flags_from_strv(opts: &[&str]) -> Result<ExecCommandFlags, i32> {
    let mut flags = ExecCommandFlags::empty();
    for opt in opts {
        let fl = exec_command_flags_from_string(opt)?;
        flags |= fl;
    }
    Ok(flags)
}

// ── exec_command_flags_to_strv ───────────────────────────────────────────

/// Convert a bitmask into a list of flag name strings.
/// Mirrors `exec_command_flags_to_strv()` from exec-util.c.
/// Returns an empty Vec for zero flags.
pub fn exec_command_flags_to_strv(flags: ExecCommandFlags) -> Result<Vec<String>, i32> {
    if flags.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    for idx in 0..EXEC_COMMAND_STRINGS.len() {
        let bit = ExecCommandFlags::from_bits_retain(1 << idx);
        if flags.contains(bit) {
            let s = exec_command_flags_to_string(bit).ok_or(EINVAL)?;
            result.push(s.to_string());
        }
    }
    Ok(result)
}

// ── indent_embedded_newlines ─────────────────────────────────────────────

/// Indent embedded newlines with 14 spaces.
/// Mirrors `indent_embedded_newlines()` from bootspec.c:
/// splits on newlines and rejoins with "\n              " (newline + 14 spaces).
pub fn indent_embedded_newlines(cmdline: &str) -> String {
    if cmdline.is_empty() {
        return String::new();
    }
    let indent = "\n              ";
    cmdline.split('\n').collect::<Vec<&str>>().join(indent)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_to_string_valid() {
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::IGNORE_FAILURE),
            Some("ignore-failure")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::FULLY_PRIVILEGED),
            Some("privileged")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::NO_SETUID),
            Some("no-setuid")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::NO_ENV_EXPAND),
            Some("no-env-expand")
        );
        assert_eq!(
            exec_command_flags_to_string(ExecCommandFlags::VIA_SHELL),
            Some("via-shell")
        );
    }

    #[test]
    fn test_flags_to_string_invalid() {
        assert!(exec_command_flags_to_string(ExecCommandFlags::empty()).is_none());
        let combined = ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED;
        assert!(exec_command_flags_to_string(combined).is_none());
        let out_of_range = ExecCommandFlags::from_bits_retain(1 << 5);
        assert!(exec_command_flags_to_string(out_of_range).is_none());
    }

    #[test]
    fn test_flags_from_string_valid() {
        assert_eq!(
            exec_command_flags_from_string("ignore-failure"),
            Ok(ExecCommandFlags::IGNORE_FAILURE)
        );
        assert_eq!(
            exec_command_flags_from_string("privileged"),
            Ok(ExecCommandFlags::FULLY_PRIVILEGED)
        );
        assert_eq!(
            exec_command_flags_from_string("no-setuid"),
            Ok(ExecCommandFlags::NO_SETUID)
        );
        assert_eq!(
            exec_command_flags_from_string("no-env-expand"),
            Ok(ExecCommandFlags::NO_ENV_EXPAND)
        );
        assert_eq!(
            exec_command_flags_from_string("via-shell"),
            Ok(ExecCommandFlags::VIA_SHELL)
        );
    }

    #[test]
    fn test_flags_from_string_ambient() {
        assert_eq!(
            exec_command_flags_from_string("ambient"),
            Ok(ExecCommandFlags::empty())
        );
    }

    #[test]
    fn test_flags_from_string_invalid() {
        assert!(exec_command_flags_from_string("foobar").is_err());
        assert!(exec_command_flags_from_string("").is_err());
    }

    #[test]
    fn test_flags_roundtrip() {
        for idx in 0..EXEC_COMMAND_STRINGS.len() {
            let flag = ExecCommandFlags::from_bits_retain(1 << idx);
            let name = exec_command_flags_to_string(flag).unwrap();
            assert_eq!(exec_command_flags_from_string(name), Ok(flag));
        }
    }

    #[test]
    fn test_flags_from_strv_valid() {
        let result = exec_command_flags_from_strv(&["ignore-failure", "privileged"]).unwrap();
        assert_eq!(
            result,
            ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED
        );
    }

    #[test]
    fn test_flags_from_strv_empty() {
        let result = exec_command_flags_from_strv(&[]).unwrap();
        assert_eq!(result, ExecCommandFlags::empty());
    }

    #[test]
    fn test_flags_from_strv_invalid_entry() {
        assert!(exec_command_flags_from_strv(&["ignore-failure", "foobar"]).is_err());
    }

    #[test]
    fn test_flags_to_strv_valid() {
        let flags = ExecCommandFlags::IGNORE_FAILURE | ExecCommandFlags::FULLY_PRIVILEGED;
        let result = exec_command_flags_to_strv(flags).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"ignore-failure".to_string()));
        assert!(result.contains(&"privileged".to_string()));
    }

    #[test]
    fn test_flags_to_strv_zero() {
        let result = exec_command_flags_to_strv(ExecCommandFlags::empty()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_flags_to_strv_all_flags() {
        let all = ExecCommandFlags::IGNORE_FAILURE
            | ExecCommandFlags::FULLY_PRIVILEGED
            | ExecCommandFlags::NO_SETUID
            | ExecCommandFlags::NO_ENV_EXPAND
            | ExecCommandFlags::VIA_SHELL;
        let result = exec_command_flags_to_strv(all).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_indent_no_newlines() {
        assert_eq!(indent_embedded_newlines("hello world"), "hello world");
    }

    #[test]
    fn test_indent_with_newlines() {
        assert_eq!(
            indent_embedded_newlines("line1\nline2"),
            "line1\n              line2"
        );
    }

    #[test]
    fn test_indent_multiple_newlines() {
        assert_eq!(
            indent_embedded_newlines("a\nb\nc"),
            "a\n              b\n              c"
        );
    }

    #[test]
    fn test_indent_empty() {
        assert_eq!(indent_embedded_newlines(""), "");
    }

    #[test]
    fn test_flags_from_strv_ambient() {
        let result = exec_command_flags_from_strv(&["ambient"]).unwrap();
        assert_eq!(result, ExecCommandFlags::empty());
    }

    #[test]
    fn test_flags_from_strv_mixed() {
        let result = exec_command_flags_from_strv(&["ambient", "privileged"]).unwrap();
        assert_eq!(result, ExecCommandFlags::FULLY_PRIVILEGED);
    }
}
