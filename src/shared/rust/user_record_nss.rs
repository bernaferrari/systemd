// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/user-record-nss.c
//
// Pure-Rust data conversion logic for synthesizing UserRecord and GroupRecord
// objects from NSS data. All validation, transformation, and helper functions
// are safe Rust with no FFI.

use std::time::Duration;

// ── Constants ─────────────────────────────────────────────────────────────

/// Microseconds per day — used for shadow password time field conversions.
pub const USEC_PER_DAY: u64 = 86_400_000_000;

/// Maximum username / groupname length.
pub const NAME_MAX_LEN: usize = 255;

/// Sentinel value indicating a field is unset / infinite.
pub const UINT64_MAX: u64 = u64::MAX;

/// Sentinel value indicating a signed field is unset.
pub const SENTINEL_UNSET_I64: i64 = -1;

/// Default initial buffer size for NSS reentrant lookups (bytes).
pub const NSS_INITIAL_BUFFER_SIZE: usize = 4096;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by NSS record conversion functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssRecordError {
    /// Invalid argument (null pointer, empty name, name mismatch).
    InvalidArgument,
    /// Out of memory.
    OutOfMemory,
    /// No such entry found.
    NotFound,
    /// I/O error during NSS lookup.
    IOError,
    /// Supplied buffer too small, retry with larger buffer.
    Range,
    /// Not a privilege error (EPERM/EACCES).
    NotPrivilege,
}

impl NssRecordError {
    /// Convert to the negative errno convention used by systemd C code.
    pub fn to_neg_errno(self) -> i32 {
        match self {
            Self::InvalidArgument => -22, // -EINVAL
            Self::OutOfMemory => -12,     // -ENOMEM
            Self::NotFound => -3,         // -ESRCH
            Self::IOError => -5,          // -EIO
            Self::Range => -34,           // -ERANGE
            Self::NotPrivilege => -1,     // sentinel
        }
    }
}

// ── NSS record mask flags ────────────────────────────────────────────────

bitflags::bitflags! {
    /// Bitmask describing which fields of a user/group record are populated.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NssRecordMask: u32 {
        /// Regular (non-privileged) fields are present.
        const REGULAR = 1 << 0;
        /// Privileged fields (hashed passwords) are present.
        const PRIVILEGED = 1 << 1;
    }
}

// ── Passwd data ──────────────────────────────────────────────────────────

/// Rust-side mirror of a POSIX `struct passwd`, used for safe data conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssPasswdEntry {
    pub pw_name: String,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: Option<String>,
    pub pw_dir: Option<String>,
    pub pw_shell: Option<String>,
}

// ── Shadow password data ─────────────────────────────────────────────────

/// Rust-side mirror of a POSIX `struct spwd`, used for safe data conversion.
///
/// Day-count fields (`sp_lstchg`, `sp_min`, `sp_max`, `sp_warn`, `sp_inact`,
/// `sp_expire`) use `Option<i64>` where `None` means "not set" (-1 in C)
/// and `Some(n)` holds the day count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssSpwdEntry {
    pub sp_namp: String,
    pub sp_pwdp: Option<String>,
    pub sp_lstchg: Option<i64>,
    pub sp_min: Option<i64>,
    pub sp_max: Option<i64>,
    pub sp_warn: Option<i64>,
    pub sp_inact: Option<i64>,
    pub sp_expire: Option<i64>,
}

// ── Group data ───────────────────────────────────────────────────────────

/// Rust-side mirror of a POSIX `struct group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssGroupEntry {
    pub gr_name: String,
    pub gr_gid: u32,
    pub gr_mem: Vec<String>,
}

// ── Shadow group data ────────────────────────────────────────────────────

/// Rust-side mirror of a POSIX `struct sgrp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssSgrpEntry {
    pub sg_namp: String,
    pub sg_passwd: Option<String>,
    pub sg_mem: Vec<String>,
    pub sg_adm: Vec<String>,
}

// ── Synthesized user record ──────────────────────────────────────────────

/// A user record synthesized from NSS passwd + optional shadow data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssUserRecord {
    pub user_name: String,
    pub real_name: Option<String>,
    pub home_directory: Option<String>,
    pub shell: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub hashed_password: Vec<String>,
    pub locked: Option<bool>,
    pub not_after_usec: u64,
    pub password_change_now: Option<bool>,
    pub last_password_change_usec: u64,
    pub password_change_min_usec: u64,
    pub password_change_max_usec: u64,
    pub password_change_warn_usec: u64,
    pub password_change_inactive_usec: u64,
    pub incomplete: bool,
    pub mask: NssRecordMask,
}

// ── Synthesized group record ─────────────────────────────────────────────

/// A group record synthesized from NSS group + optional shadow data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssGroupRecord {
    pub group_name: String,
    pub gid: u32,
    pub members: Vec<String>,
    pub hashed_password: Vec<String>,
    pub administrators: Vec<String>,
    pub incomplete: bool,
    pub mask: NssRecordMask,
}

// ── Validation helpers ───────────────────────────────────────────────────

/// Check whether a username or groupname is syntactically valid.
///
/// Rules derived from systemd's `valid_user_group_name()` / `valid_gecos()`:
/// - non-empty, ≤ 255 bytes
/// - no NUL, colon, newline
/// - must not start with `-` or `.`
/// - only alphanumeric, `_`, `-`, `.`, `$`
pub fn validate_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX_LEN
        && !name.contains('\0')
        && !name.contains(':')
        && !name.contains('\n')
        && !name.starts_with('-')
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'$')
}

/// Group names follow the same validation rules as usernames.
pub fn validate_groupname(name: &str) -> bool {
    validate_username(name)
}

/// Validate a GECOS (real name) field.
///
/// GECOS fields must not contain `:` or `\n` since those are record
/// separators in `/etc/passwd`.
pub fn valid_gecos(gecos: &str) -> bool {
    !gecos.is_empty() && !gecos.contains(':') && !gecos.contains('\n')
}

/// Mangle a GECOS field by replacing `:` with `;` and `\n` with `,`.
///
/// This mirrors the C `mangle_gecos()` helper — some NSS modules produce
/// GECOS fields with embedded separators that are incompatible with the
/// `/etc/passwd` format.
pub fn mangle_gecos(gecos: &str) -> String {
    let mut out = String::with_capacity(gecos.len());
    for ch in gecos.chars() {
        match ch {
            ':' => out.push(';'),
            '\n' => out.push(','),
            _ => out.push(ch),
        }
    }
    out
}

/// Filter a list of strings, keeping only those that are valid UTF-8.
///
/// In practice Rust `String` values are always valid UTF-8, but this mirrors
/// the C `strv_extend_strv_utf8_only()` helper which filters out mojibake.
pub fn filter_utf8_only(strings: &[String]) -> Vec<String> {
    strings
        .iter()
        .filter(|s| std::str::from_utf8(s.as_bytes()).is_ok())
        .cloned()
        .collect()
}

/// Extend a vector with items from another, optionally deduplicating.
pub fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
    for s in src {
        if !dst.contains(s) {
            dst.push(s.clone());
        }
    }
}

/// Check whether a string looks like a hashed password.
///
/// A valid hashed password starts with `$` followed by an algorithm prefix,
/// or is the special `"!"` / `"*"` lock markers. Mirrors the C
/// `looks_like_hashed_password()`.
pub fn looks_like_hashed_password(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Locked / disabled markers
    if s == "!" || s == "*" || s == "!!" {
        return false;
    }
    // Must start with '$' (e.g. $6$, $y$, $1$)
    if s.starts_with('$') {
        // Reject pure lock prefixes like "!$"
        return true;
    }
    false
}

/// Convert an empty string to `None`, pass non-empty through.
pub fn empty_to_none(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

// ── Shadow time conversion ───────────────────────────────────────────────

/// Convert a shadow day-count field to microseconds.
///
/// Returns `UINT64_MAX` if the value is unset or would overflow.
pub fn days_to_usec(days: i64) -> u64 {
    if days <= 0 {
        return UINT64_MAX;
    }
    let limit = (UINT64_MAX - 1) / USEC_PER_DAY;
    if (days as u64) > limit {
        return UINT64_MAX;
    }
    (days as u64) * USEC_PER_DAY
}

/// Convert a microseconds value to a `Duration`, or `None` if sentinel.
pub fn usec_to_duration(usec: u64) -> Option<Duration> {
    if usec == UINT64_MAX {
        None
    } else {
        Some(Duration::from_micros(usec))
    }
}

// ── NSS passwd → user record conversion ──────────────────────────────────

/// Convert a passwd entry (and optional shadow entry) into a synthesized
/// user record. This is the pure-Rust equivalent of
/// `nss_passwd_to_user_record()`.
pub fn nss_passwd_to_user_record(
    pwd: &NssPasswdEntry,
    spwd: Option<&NssSpwdEntry>,
) -> Result<NssUserRecord, NssRecordError> {
    if pwd.pw_name.is_empty() {
        return Err(NssRecordError::InvalidArgument);
    }

    if let Some(sp) = spwd {
        if sp.sp_namp != pwd.pw_name {
            return Err(NssRecordError::InvalidArgument);
        }
    }

    // Real name / GECOS handling
    let real_name =
        if pwd.pw_gecos.is_none() || pwd.pw_gecos.as_deref() == Some(pwd.pw_name.as_str()) {
            None
        } else if let Some(ref gecos) = pwd.pw_gecos {
            if valid_gecos(gecos) {
                Some(empty_to_none(gecos).unwrap_or(gecos).to_owned())
            } else {
                Some(mangle_gecos(gecos))
            }
        } else {
            None
        };

    // Home directory and shell — must be valid UTF-8
    let home_directory = pwd
        .pw_dir
        .as_deref()
        .and_then(empty_to_none)
        .map(str::to_owned);
    let shell = pwd
        .pw_shell
        .as_deref()
        .and_then(empty_to_none)
        .map(str::to_owned);

    // Hashed password from shadow
    let hashed_password = match spwd {
        Some(sp)
            if sp
                .sp_pwdp
                .as_deref()
                .is_some_and(looks_like_hashed_password) =>
        {
            sp.sp_pwdp.iter().cloned().collect()
        }
        _ => Vec::new(),
    };

    let locked = spwd.and_then(|sp| sp.sp_expire).map(|expires| expires <= 1);

    // notAfterUSec
    let not_after_usec = spwd
        .and_then(|sp| sp.sp_expire)
        .filter(|expires| *expires > 1)
        .map_or(UINT64_MAX, days_to_usec);

    // passwordChangeNow: sp_lstchg == 0
    let password_change_now = spwd
        .and_then(|sp| sp.sp_lstchg)
        .map(|last_change| last_change == 0);

    // lastPasswordChangeUSec
    let last_password_change_usec = spwd
        .and_then(|sp| sp.sp_lstchg)
        .filter(|last_change| *last_change > 0)
        .map_or(UINT64_MAX, days_to_usec);

    // passwordChangeMinUSec
    let password_change_min_usec = spwd
        .and_then(|sp| sp.sp_min)
        .filter(|minimum| *minimum > 0)
        .map_or(UINT64_MAX, days_to_usec);

    // passwordChangeMaxUSec
    let password_change_max_usec = spwd
        .and_then(|sp| sp.sp_max)
        .filter(|maximum| *maximum > 0)
        .map_or(UINT64_MAX, days_to_usec);

    // passwordChangeWarnUSec
    let password_change_warn_usec = spwd
        .and_then(|sp| sp.sp_warn)
        .filter(|warning| *warning > 0)
        .map_or(UINT64_MAX, days_to_usec);

    // passwordChangeInactiveUSec
    let password_change_inactive_usec = spwd
        .and_then(|sp| sp.sp_inact)
        .filter(|inactive| *inactive > 0)
        .map_or(UINT64_MAX, days_to_usec);

    // Record mask
    let mut mask = NssRecordMask::REGULAR;
    if !hashed_password.is_empty() {
        mask |= NssRecordMask::PRIVILEGED;
    }

    Ok(NssUserRecord {
        user_name: pwd.pw_name.clone(),
        real_name,
        home_directory,
        shell,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        hashed_password,
        locked,
        not_after_usec,
        password_change_now,
        last_password_change_usec,
        password_change_min_usec,
        password_change_max_usec,
        password_change_warn_usec,
        password_change_inactive_usec,
        incomplete: false,
        mask,
    })
}

// ── NSS group → group record conversion ─────────────────────────────────

/// Convert a group entry (and optional shadow group entry) into a synthesized
/// group record. This is the pure-Rust equivalent of
/// `nss_group_to_group_record()`.
pub fn nss_group_to_group_record(
    grp: &NssGroupEntry,
    sgrp: Option<&NssSgrpEntry>,
) -> Result<NssGroupRecord, NssRecordError> {
    if grp.gr_name.is_empty() {
        return Err(NssRecordError::InvalidArgument);
    }

    if let Some(sg) = sgrp {
        if sg.sg_namp != grp.gr_name {
            return Err(NssRecordError::InvalidArgument);
        }
    }

    // Start with group members, filtering for valid UTF-8
    let mut members = filter_utf8_only(&grp.gr_mem);

    // Process shadow group data
    let hashed_password;
    if let Some(sg) = sgrp {
        hashed_password = if sg
            .sg_passwd
            .as_deref()
            .is_some_and(looks_like_hashed_password)
        {
            sg.sg_passwd.iter().cloned().collect()
        } else {
            Vec::new()
        };

        // Add shadow members (deduplicating)
        extend_unique(&mut members, &filter_utf8_only(&sg.sg_mem));
    } else {
        hashed_password = Vec::new();
    }

    // Administrators from shadow group
    let administrators = sgrp
        .map(|sg| filter_utf8_only(&sg.sg_adm))
        .unwrap_or_default();

    // Record mask
    let mut mask = NssRecordMask::REGULAR;
    if !hashed_password.is_empty() {
        mask |= NssRecordMask::PRIVILEGED;
    }

    Ok(NssGroupRecord {
        group_name: grp.gr_name.clone(),
        gid: grp.gr_gid,
        members,
        hashed_password,
        administrators,
        incomplete: false,
        mask,
    })
}

// ── Buffer size calculation ──────────────────────────────────────────────

/// Compute the next buffer size for a retrying NSS lookup.
///
/// Doubles the current size, capping at `usize::MAX / 2` to avoid overflow.
/// Returns `None` if the buffer cannot grow further.
pub fn next_nss_buffer_size(current: usize) -> Option<usize> {
    if current > usize::MAX / 2 {
        None
    } else {
        Some(current * 2)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_username ─────────────────────────────────────────────

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("root"));
        assert!(validate_username("user-name"));
        assert!(validate_username("user.name"));
        assert!(validate_username("user_name"));
        assert!(validate_username("user$"));
        assert!(validate_username("a"));
        assert!(validate_username(&"a".repeat(255)));
    }

    #[test]
    fn test_validate_username_invalid() {
        assert!(!validate_username(""));
        assert!(!validate_username("-invalid"));
        assert!(!validate_username(".hidden"));
        assert!(!validate_username("user:name"));
        assert!(!validate_username("user\nname"));
        assert!(!validate_username("user\x00name"));
        assert!(!validate_username("user name"));
        assert!(!validate_username(&"a".repeat(256)));
    }

    // ── validate_groupname ────────────────────────────────────────────

    #[test]
    fn test_validate_groupname_valid() {
        assert!(validate_groupname("root"));
        assert!(validate_groupname("docker"));
        assert!(validate_groupname("wheel"));
    }

    #[test]
    fn test_validate_groupname_invalid() {
        assert!(!validate_groupname(""));
        assert!(!validate_groupname("-bad"));
        assert!(!validate_groupname(".hidden"));
        assert!(!validate_groupname("has:colon"));
    }

    // ── valid_gecos / mangle_gecos ────────────────────────────────────

    #[test]
    fn test_valid_gecos() {
        assert!(valid_gecos("John Doe"));
        assert!(valid_gecos("Room 101"));
        assert!(!valid_gecos(""));
        assert!(!valid_gecos("John:Doe"));
        assert!(!valid_gecos("John\nDoe"));
    }

    #[test]
    fn test_mangle_gecos() {
        assert_eq!(mangle_gecos("John:Doe"), "John;Doe");
        assert_eq!(mangle_gecos("Line1\nLine2"), "Line1,Line2");
        assert_eq!(mangle_gecos("Normal Name"), "Normal Name");
        assert_eq!(mangle_gecos(""), "");
        assert_eq!(mangle_gecos("A:B\nC"), "A;B,C");
    }

    // ── looks_like_hashed_password ────────────────────────────────────

    #[test]
    fn test_looks_like_hashed_password() {
        assert!(looks_like_hashed_password("$6$salt$hash"));
        assert!(looks_like_hashed_password("$y$j9T$blah"));
        assert!(looks_like_hashed_password("$1$abc$def"));
        assert!(!looks_like_hashed_password(""));
        assert!(!looks_like_hashed_password("!"));
        assert!(!looks_like_hashed_password("*"));
        assert!(!looks_like_hashed_password("!!"));
        assert!(!looks_like_hashed_password("plaintext"));
        assert!(!looks_like_hashed_password("x")); // traditionally means "use shadow"
    }

    // ── filter_utf8_only ──────────────────────────────────────────────

    #[test]
    fn test_filter_utf8_only_all_valid() {
        let input = vec!["hello".to_owned(), "world".to_owned()];
        assert_eq!(filter_utf8_only(&input), input);
    }

    #[test]
    fn test_filter_utf8_only_empty() {
        assert!(filter_utf8_only(&[]).is_empty());
    }

    #[test]
    fn test_filter_utf8_only_preserves_valid_utf8() {
        let input = vec!["café".to_owned(), "naïve".to_owned()];
        assert_eq!(filter_utf8_only(&input).len(), 2);
    }

    // ── extend_unique ─────────────────────────────────────────────────

    #[test]
    fn test_extend_unique_no_duplicates() {
        let mut dst = vec!["a".to_owned()];
        let src = vec!["b".to_owned(), "c".to_owned()];
        extend_unique(&mut dst, &src);
        assert_eq!(dst, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_extend_unique_with_duplicates() {
        let mut dst = vec!["a".to_owned(), "b".to_owned()];
        let src = vec!["b".to_owned(), "c".to_owned()];
        extend_unique(&mut dst, &src);
        assert_eq!(dst, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_extend_unique_empty_dst() {
        let mut dst: Vec<String> = Vec::new();
        let src = vec!["x".to_owned()];
        extend_unique(&mut dst, &src);
        assert_eq!(dst, vec!["x"]);
    }

    // ── empty_to_none ─────────────────────────────────────────────────

    #[test]
    fn test_empty_to_none() {
        assert_eq!(empty_to_none(""), None);
        assert_eq!(empty_to_none("hello"), Some("hello"));
        assert_eq!(empty_to_none("  "), Some("  "));
    }

    // ── days_to_usec ──────────────────────────────────────────────────

    #[test]
    fn test_days_to_usec() {
        assert_eq!(days_to_usec(1), USEC_PER_DAY);
        assert_eq!(days_to_usec(0), UINT64_MAX);
        assert_eq!(days_to_usec(-1), UINT64_MAX);
        assert_eq!(days_to_usec(365), 365 * USEC_PER_DAY);
    }

    #[test]
    fn test_days_to_usec_overflow() {
        // Overflow case: days * USEC_PER_DAY > UINT64_MAX
        let huge = (UINT64_MAX / USEC_PER_DAY) + 1;
        assert_eq!(days_to_usec(huge as i64), UINT64_MAX);
    }

    // ── usec_to_duration ──────────────────────────────────────────────

    #[test]
    fn test_usec_to_duration() {
        assert_eq!(usec_to_duration(UINT64_MAX), None);
        assert_eq!(usec_to_duration(0), Some(Duration::from_micros(0)));
        assert_eq!(
            usec_to_duration(USEC_PER_DAY),
            Some(Duration::from_secs(86400))
        );
    }

    // ── next_nss_buffer_size ──────────────────────────────────────────

    #[test]
    fn test_next_nss_buffer_size() {
        assert_eq!(next_nss_buffer_size(4096), Some(8192));
        assert_eq!(next_nss_buffer_size(8192), Some(16384));
        assert_eq!(next_nss_buffer_size(0), Some(0));
    }

    #[test]
    fn test_next_nss_buffer_size_overflow() {
        assert_eq!(next_nss_buffer_size(usize::MAX), None);
        assert_eq!(next_nss_buffer_size(usize::MAX / 2 + 1), None);
    }

    // ── NssRecordError ────────────────────────────────────────────────

    #[test]
    fn test_nss_record_error_to_neg_errno() {
        assert_eq!(NssRecordError::InvalidArgument.to_neg_errno(), -22);
        assert_eq!(NssRecordError::OutOfMemory.to_neg_errno(), -12);
        assert_eq!(NssRecordError::NotFound.to_neg_errno(), -3);
        assert_eq!(NssRecordError::IOError.to_neg_errno(), -5);
        assert_eq!(NssRecordError::Range.to_neg_errno(), -34);
    }

    // ── NssRecordMask ─────────────────────────────────────────────────

    #[test]
    fn test_nss_record_mask() {
        let m = NssRecordMask::REGULAR;
        assert!(m.contains(NssRecordMask::REGULAR));
        assert!(!m.contains(NssRecordMask::PRIVILEGED));

        let m = NssRecordMask::REGULAR | NssRecordMask::PRIVILEGED;
        assert!(m.contains(NssRecordMask::REGULAR));
        assert!(m.contains(NssRecordMask::PRIVILEGED));
    }

    // ── nss_passwd_to_user_record ─────────────────────────────────────

    #[test]
    fn test_passwd_to_user_record_basic() {
        let pwd = NssPasswdEntry {
            pw_name: "root".into(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: Some("root".into()),
            pw_dir: Some("/root".into()),
            pw_shell: Some("/bin/bash".into()),
        };

        let rec = nss_passwd_to_user_record(&pwd, None).unwrap();
        assert_eq!(rec.user_name, "root");
        assert_eq!(rec.uid, 0);
        assert_eq!(rec.gid, 0);
        assert_eq!(rec.real_name, None); // GECOS == username → None
        assert_eq!(rec.home_directory.as_deref(), Some("/root"));
        assert_eq!(rec.shell.as_deref(), Some("/bin/bash"));
        assert!(rec.hashed_password.is_empty());
        assert!(rec.mask.contains(NssRecordMask::REGULAR));
        assert!(!rec.mask.contains(NssRecordMask::PRIVILEGED));
    }

    #[test]
    fn test_passwd_to_user_record_with_gecos() {
        let pwd = NssPasswdEntry {
            pw_name: "alice".into(),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: Some("Alice Smith".into()),
            pw_dir: Some("/home/alice".into()),
            pw_shell: Some("/bin/zsh".into()),
        };

        let rec = nss_passwd_to_user_record(&pwd, None).unwrap();
        assert_eq!(rec.real_name.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn test_passwd_to_user_record_mangled_gecos() {
        let pwd = NssPasswdEntry {
            pw_name: "bob".into(),
            pw_uid: 1001,
            pw_gid: 1001,
            pw_gecos: Some("Bob:Builder\nInc".into()),
            pw_dir: None,
            pw_shell: None,
        };

        let rec = nss_passwd_to_user_record(&pwd, None).unwrap();
        assert_eq!(rec.real_name.as_deref(), Some("Bob;Builder,Inc"));
    }

    #[test]
    fn test_passwd_to_user_record_empty_name() {
        let pwd = NssPasswdEntry {
            pw_name: String::new(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: None,
            pw_dir: None,
            pw_shell: None,
        };

        assert_eq!(
            nss_passwd_to_user_record(&pwd, None),
            Err(NssRecordError::InvalidArgument)
        );
    }

    #[test]
    fn test_passwd_to_user_record_shadow_name_mismatch() {
        let pwd = NssPasswdEntry {
            pw_name: "alice".into(),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: None,
            pw_dir: None,
            pw_shell: None,
        };
        let spwd = NssSpwdEntry {
            sp_namp: "bob".into(), // mismatch!
            sp_pwdp: None,
            sp_lstchg: None,
            sp_min: None,
            sp_max: None,
            sp_warn: None,
            sp_inact: None,
            sp_expire: None,
        };

        assert_eq!(
            nss_passwd_to_user_record(&pwd, Some(&spwd)),
            Err(NssRecordError::InvalidArgument)
        );
    }

    #[test]
    fn test_passwd_to_user_record_with_shadow() {
        let pwd = NssPasswdEntry {
            pw_name: "alice".into(),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: Some("Alice".into()),
            pw_dir: Some("/home/alice".into()),
            pw_shell: Some("/bin/bash".into()),
        };
        let spwd = NssSpwdEntry {
            sp_namp: "alice".into(),
            sp_pwdp: Some("$6$salt$hash".into()),
            sp_lstchg: Some(19500),
            sp_min: Some(0),
            sp_max: Some(99999),
            sp_warn: Some(7),
            sp_inact: None,
            sp_expire: None,
        };

        let rec = nss_passwd_to_user_record(&pwd, Some(&spwd)).unwrap();
        assert_eq!(rec.hashed_password, vec!["$6$salt$hash".to_owned()]);
        assert!(rec.mask.contains(NssRecordMask::PRIVILEGED));
        assert_eq!(rec.last_password_change_usec, days_to_usec(19500));
        assert_eq!(rec.password_change_warn_usec, days_to_usec(7));
        assert_eq!(rec.password_change_max_usec, days_to_usec(99999));
        // sp_min == 0 → unset
        assert_eq!(rec.password_change_min_usec, UINT64_MAX);
    }

    #[test]
    fn test_passwd_to_user_record_locked_account() {
        let pwd = NssPasswdEntry {
            pw_name: "locked".into(),
            pw_uid: 1002,
            pw_gid: 1002,
            pw_gecos: None,
            pw_dir: None,
            pw_shell: None,
        };
        let spwd = NssSpwdEntry {
            sp_namp: "locked".into(),
            sp_pwdp: None,
            sp_lstchg: None,
            sp_min: None,
            sp_max: None,
            sp_warn: None,
            sp_inact: None,
            sp_expire: Some(0), // locked
        };

        let rec = nss_passwd_to_user_record(&pwd, Some(&spwd)).unwrap();
        assert_eq!(rec.locked, Some(true));
        assert_eq!(rec.not_after_usec, UINT64_MAX); // expire 0 → not > 1
    }

    #[test]
    fn test_passwd_to_user_record_not_after() {
        let pwd = NssPasswdEntry {
            pw_name: "expiring".into(),
            pw_uid: 1003,
            pw_gid: 1003,
            pw_gecos: None,
            pw_dir: None,
            pw_shell: None,
        };
        let spwd = NssSpwdEntry {
            sp_namp: "expiring".into(),
            sp_pwdp: None,
            sp_lstchg: None,
            sp_min: None,
            sp_max: None,
            sp_warn: None,
            sp_inact: None,
            sp_expire: Some(30),
        };

        let rec = nss_passwd_to_user_record(&pwd, Some(&spwd)).unwrap();
        assert_eq!(rec.locked, Some(false)); // expire 30 > 1 → not locked
        assert_eq!(rec.not_after_usec, days_to_usec(30));
    }

    #[test]
    fn test_passwd_to_user_record_empty_home_shell() {
        let pwd = NssPasswdEntry {
            pw_name: "svc".into(),
            pw_uid: 50,
            pw_gid: 50,
            pw_gecos: None,
            pw_dir: Some("".into()),
            pw_shell: Some("".into()),
        };

        let rec = nss_passwd_to_user_record(&pwd, None).unwrap();
        assert!(rec.home_directory.is_none()); // empty → None
        assert!(rec.shell.is_none());
    }

    // ── nss_group_to_group_record ─────────────────────────────────────

    #[test]
    fn test_group_to_group_record_basic() {
        let grp = NssGroupEntry {
            gr_name: "wheel".into(),
            gr_gid: 10,
            gr_mem: vec!["alice".into(), "bob".into()],
        };

        let rec = nss_group_to_group_record(&grp, None).unwrap();
        assert_eq!(rec.group_name, "wheel");
        assert_eq!(rec.gid, 10);
        assert_eq!(rec.members, vec!["alice", "bob"]);
        assert!(rec.hashed_password.is_empty());
        assert!(rec.administrators.is_empty());
        assert!(rec.mask.contains(NssRecordMask::REGULAR));
    }

    #[test]
    fn test_group_to_group_record_empty_name() {
        let grp = NssGroupEntry {
            gr_name: String::new(),
            gr_gid: 0,
            gr_mem: vec![],
        };

        assert_eq!(
            nss_group_to_group_record(&grp, None),
            Err(NssRecordError::InvalidArgument)
        );
    }

    #[test]
    fn test_group_to_group_record_shadow_mismatch() {
        let grp = NssGroupEntry {
            gr_name: "docker".into(),
            gr_gid: 999,
            gr_mem: vec![],
        };
        let sgrp = NssSgrpEntry {
            sg_namp: "podman".into(), // mismatch
            sg_passwd: None,
            sg_mem: vec![],
            sg_adm: vec![],
        };

        assert_eq!(
            nss_group_to_group_record(&grp, Some(&sgrp)),
            Err(NssRecordError::InvalidArgument)
        );
    }

    #[test]
    fn test_group_to_group_record_with_shadow() {
        let grp = NssGroupEntry {
            gr_name: "admins".into(),
            gr_gid: 100,
            gr_mem: vec!["alice".into()],
        };
        let sgrp = NssSgrpEntry {
            sg_namp: "admins".into(),
            sg_passwd: Some("$6$salt$hash".into()),
            sg_mem: vec!["bob".into(), "alice".into()], // alice is duplicate
            sg_adm: vec!["charlie".into()],
        };

        let rec = nss_group_to_group_record(&grp, Some(&sgrp)).unwrap();
        assert_eq!(rec.hashed_password, vec!["$6$salt$hash".to_owned()]);
        assert!(rec.mask.contains(NssRecordMask::PRIVILEGED));
        // alice appears once (deduped), bob added from shadow
        assert_eq!(rec.members.len(), 2);
        assert!(rec.members.contains(&"alice".to_owned()));
        assert!(rec.members.contains(&"bob".to_owned()));
        assert_eq!(rec.administrators, vec!["charlie".to_owned()]);
    }

    #[test]
    fn test_group_to_group_record_shadow_no_hash() {
        let grp = NssGroupEntry {
            gr_name: "users".into(),
            gr_gid: 1000,
            gr_mem: vec![],
        };
        let sgrp = NssSgrpEntry {
            sg_namp: "users".into(),
            sg_passwd: Some("*".into()), // not a real hash
            sg_mem: vec![],
            sg_adm: vec![],
        };

        let rec = nss_group_to_group_record(&grp, Some(&sgrp)).unwrap();
        assert!(rec.hashed_password.is_empty());
        assert!(!rec.mask.contains(NssRecordMask::PRIVILEGED));
    }
}
