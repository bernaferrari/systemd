// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/update-done/update-done.c
//
// System update completion marker tool.
//
// Implements the systemd-update-done tool which marks /etc/ and /var/
// as fully updated by creating .updated files containing the mtime of /usr/.
// This allows systemd to detect when /etc/ or /var/ need migration after
// a system update. The timestamp is stored both as the file's mtime and
// in the file content for nanosecond precision support.

// ── Constants ─────────────────────────────────────────────────────────────

/// Directories to mark as updated.
pub const UPDATE_DIRS: &[&str; 2] = &["/etc/", "/var/"];

/// The /usr path to stat for the timestamp.
pub const USR_PATH: &str = "/usr";

/// Filename for the timestamp marker file.
pub const UPDATED_FILENAME: &str = ".updated";

/// Default umask for the tool.
pub const DEFAULT_UMASK: u32 = 0o022;

// ── Types ─────────────────────────────────────────────────────────────────

/// A timestamp with nanosecond precision, matching `struct timespec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds since epoch
    pub sec: i64,
    /// Nanoseconds within the second
    pub nsec: i64,
}

impl Timespec {
    /// Create a zero timestamp.
    pub fn zero() -> Self {
        Self { sec: 0, nsec: 0 }
    }

    /// Convert to total nanoseconds.
    pub fn to_nsec(&self) -> i64 {
        self.sec * 1_000_000_000 + self.nsec
    }

    /// Create from total nanoseconds.
    pub fn from_nsec(nsec: i64) -> Self {
        Self {
            sec: nsec / 1_000_000_000,
            nsec: nsec % 1_000_000_000,
        }
    }

    /// Create from a seconds and nanoseconds pair.
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }
}

impl Default for Timespec {
    fn default() -> Self {
        Self::zero()
    }
}

// ── Timestamp file content ────────────────────────────────────────────────

/// File header comment for the .updated file.
pub const TIMESTAMP_HEADER: &[&str] = &[
    "# This file was created by systemd-update-done. The timestamp below is the",
    "# modification time of /usr/ for which the most recent updates of",
];

/// Generate the content for a .updated file.
///
/// The file contains a header comment explaining its purpose, followed by
/// a TIMESTAMP_NSEC= line with the nanosecond-precision timestamp.
pub fn generate_updated_content(dir: &str, ts: &Timespec) -> String {
    format!(
        "# This file was created by systemd-update-done. The timestamp below is the\n\
         # modification time of /usr/ for which the most recent updates of {} have\n\
         # been applied. See man:systemd-update-done.service(8) for details.\n\
         TIMESTAMP_NSEC={}\n",
        dir,
        ts.to_nsec()
    )
}

/// Parse the TIMESTAMP_NSEC value from .updated file content.
pub fn parse_timestamp_nsec(content: &str) -> Option<Timespec> {
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("TIMESTAMP_NSEC=") {
            let nsec: i64 = value.trim().parse().ok()?;
            return Some(Timespec::from_nsec(nsec));
        }
    }
    None
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the update-done tool.
#[derive(Debug, Clone, Default)]
pub struct UpdateDoneArgs {
    /// Root directory for path resolution (None = current root)
    pub root: Option<String>,
}

impl UpdateDoneArgs {
    /// Parse command-line arguments.
    /// The tool takes no positional arguments, only --root= option.
    pub fn parse(args: &[&str]) -> Result<Self, i32> {
        // The C tool uses FOREACH_OPTION for proper option parsing.
        // Here we just handle the simplified case.
        if args.len() > 1 {
            return Err(-libc::EINVAL);
        }
        Ok(Self::default())
    }

    /// Get the effective /usr path considering the root prefix.
    pub fn usr_path(&self) -> String {
        match self.root {
            Some(ref r) => format!("{}{}", r, USR_PATH),
            None => USR_PATH.to_string(),
        }
    }

    /// Get the path for a .updated file in a given directory.
    pub fn updated_path(&self, dir: &str) -> String {
        match self.root {
            Some(ref r) => {
                let trimmed = dir.trim_end_matches('/');
                format!("{}{}/{}", r, trimmed, UPDATED_FILENAME)
            }
            None => format!("{}{}", dir, UPDATED_FILENAME),
        }
    }
}

// ── Chase flags ───────────────────────────────────────────────────────────

/// Chase flags used by update-done for path resolution.
pub const CHASE_FLAGS: u64 = (1 << 0)  // CHASE_PREFIX_ROOT
    | (1 << 8); // CHASE_WARN

/// Additional chase flag requiring the target to be a directory.
pub const CHASE_MUST_BE_DIRECTORY: u64 = 1 << 14;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timespec_zero() {
        let ts = Timespec::zero();
        assert_eq!(ts.sec, 0);
        assert_eq!(ts.nsec, 0);
        assert_eq!(ts.to_nsec(), 0);
    }

    #[test]
    fn test_timespec_from_nsec() {
        let ts = Timespec::from_nsec(1_234_567_890_123_456_789);
        assert_eq!(ts.sec, 1_234_567_890);
        assert_eq!(ts.nsec, 123_456_789);
    }

    #[test]
    fn test_timespec_roundtrip() {
        let ts = Timespec::new(1700000000, 500_000_000);
        let nsec = ts.to_nsec();
        let ts2 = Timespec::from_nsec(nsec);
        assert_eq!(ts, ts2);
    }

    #[test]
    fn test_generate_updated_content() {
        let ts = Timespec::new(1700000000, 123_456_789);
        let content = generate_updated_content("/etc/", &ts);
        assert!(content.contains("TIMESTAMP_NSEC="));
        assert!(content.contains("1700000000123456789"));
        assert!(content.contains("/etc/"));
        assert!(content.contains("systemd-update-done"));
    }

    #[test]
    fn test_parse_timestamp_nsec() {
        let content = "# Comment\nTIMESTAMP_NSEC=1700000000123456789\n";
        let ts = parse_timestamp_nsec(content).unwrap();
        assert_eq!(ts.sec, 1700000000);
        assert_eq!(ts.nsec, 123456789);
    }

    #[test]
    fn test_parse_timestamp_nsec_missing() {
        let content = "# No timestamp here\n";
        assert!(parse_timestamp_nsec(content).is_none());
    }

    #[test]
    fn test_parse_timestamp_nsec_invalid() {
        let content = "TIMESTAMP_NSEC=notanumber\n";
        assert!(parse_timestamp_nsec(content).is_none());
    }

    #[test]
    fn test_update_done_args_default() {
        let args = UpdateDoneArgs::default();
        assert!(args.root.is_none());
        assert_eq!(args.usr_path(), "/usr");
    }

    #[test]
    fn test_update_done_args_usr_path_with_root() {
        let args = UpdateDoneArgs {
            root: Some("/mnt".to_string()),
        };
        assert_eq!(args.usr_path(), "/mnt/usr");
    }

    #[test]
    fn test_update_done_args_updated_path() {
        let args = UpdateDoneArgs::default();
        assert_eq!(args.updated_path("/etc/"), "/etc/.updated");
        assert_eq!(args.updated_path("/var/"), "/var/.updated");
    }

    #[test]
    fn test_update_done_args_updated_path_with_root() {
        let args = UpdateDoneArgs {
            root: Some("/sysroot".to_string()),
        };
        assert_eq!(args.updated_path("/etc/"), "/sysroot/etc/.updated");
    }

    #[test]
    fn test_constants() {
        assert_eq!(UPDATE_DIRS.len(), 2);
        assert_eq!(UPDATED_FILENAME, ".updated");
        assert_eq!(USR_PATH, "/usr");
    }
}
