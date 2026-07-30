// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/user-record.c / src/shared/user-record.h
//
// User record handling — JSON-based user identity records with NSS integration.
//
// This module provides pure-Rust data types and logic for user record management:
// enums, bitmasks, validation helpers, and matching — all without FFI.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum blob directory size: 64 MiB
pub const BLOB_DIR_MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Default rate-limit burst
pub const DEFAULT_RATELIMIT_BURST: u64 = 30;

/// Default rate-limit interval in microseconds (1 minute)
pub const DEFAULT_RATELIMIT_INTERVAL_USEC: u64 = 60_000_000;

// ── Enums ─────────────────────────────────────────────────────────────────

/// User disposition classification.
///
/// Maps to `UserDisposition` in `src/shared/user-record.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum UserDisposition {
    Intrinsic = 0, // root and nobody
    System = 1,    // statically allocated users for system services
    Dynamic = 2,   // dynamically allocated users for system services
    #[default]
    Regular = 3, // regular (typically human users)
    Container = 4, // UID ranges allocated for container uses
    Foreign = 5,   // UID range allocated for foreign OS images
    Reserved = 6,  // Range above 2^31
}

impl UserDisposition {
    pub const MAX: i32 = 7;
    pub const INVALID: i32 = -22; // -EINVAL

    /// All variant discriminants, for iteration.
    pub const ALL: [Self; 7] = [
        Self::Intrinsic,
        Self::System,
        Self::Dynamic,
        Self::Regular,
        Self::Container,
        Self::Foreign,
        Self::Reserved,
    ];

    /// Convert a raw `i32` discriminant to a `UserDisposition`.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Intrinsic),
            1 => Some(Self::System),
            2 => Some(Self::Dynamic),
            3 => Some(Self::Regular),
            4 => Some(Self::Container),
            5 => Some(Self::Foreign),
            6 => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Convert a string name to a `UserDisposition`.
    /// Case-insensitive, matches the C `user_disposition_from_string()` table.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "intrinsic" => Some(Self::Intrinsic),
            "system" => Some(Self::System),
            "dynamic" => Some(Self::Dynamic),
            "regular" => Some(Self::Regular),
            "container" => Some(Self::Container),
            "foreign" => Some(Self::Foreign),
            "reserved" => Some(Self::Reserved),
            _ => None,
        }
    }

    /// The canonical string name for this disposition.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intrinsic => "intrinsic",
            Self::System => "system",
            Self::Dynamic => "dynamic",
            Self::Regular => "regular",
            Self::Container => "container",
            Self::Foreign => "foreign",
            Self::Reserved => "reserved",
        }
    }

    /// Convert to the old `to_cstr` name (alias kept for compatibility).
    pub fn to_cstr(self) -> &'static str {
        self.as_str()
    }
}

/// User storage type.
///
/// Maps to `UserStorage` in `src/shared/user-record.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum UserStorage {
    Classic = 0,
    LUKS = 1,
    Directory = 2,
    Subvolume = 3,
    FSCrypt = 4,
    CIFS = 5,
}

impl UserStorage {
    pub const MAX: i32 = 6;
    pub const INVALID: i32 = -22;

    /// All variant discriminants, for iteration.
    pub const ALL: [Self; 6] = [
        Self::Classic,
        Self::LUKS,
        Self::Directory,
        Self::Subvolume,
        Self::FSCrypt,
        Self::CIFS,
    ];

    /// Convert a raw `i32` discriminant to a `UserStorage`.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Classic),
            1 => Some(Self::LUKS),
            2 => Some(Self::Directory),
            3 => Some(Self::Subvolume),
            4 => Some(Self::FSCrypt),
            5 => Some(Self::CIFS),
            _ => None,
        }
    }

    /// Convert a string name to a `UserStorage`.
    /// Matches the C `user_storage_from_string()` table.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "classic" => Some(Self::Classic),
            "luks" => Some(Self::LUKS),
            "directory" => Some(Self::Directory),
            "subvolume" => Some(Self::Subvolume),
            "fscrypt" => Some(Self::FSCrypt),
            "cifs" => Some(Self::CIFS),
            _ => None,
        }
    }

    /// The canonical string name for this storage type.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::LUKS => "luks",
            Self::Directory => "directory",
            Self::Subvolume => "subvolume",
            Self::FSCrypt => "fscrypt",
            Self::CIFS => "cifs",
        }
    }

    /// Convert to the old `to_cstr` name (alias kept for compatibility).
    pub fn to_cstr(self) -> &'static str {
        self.as_str()
    }
}

/// Auto-resize mode for user home directories.
///
/// Maps to `AutoResizeMode` in `src/shared/user-record.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum AutoResizeMode {
    Off = 0,
    Grow = 1,
    ShrinkAndGrow = 2,
}

impl AutoResizeMode {
    pub const MAX: i32 = 3;
    pub const INVALID: i32 = -22;

    /// All variant discriminants, for iteration.
    pub const ALL: [Self; 3] = [Self::Off, Self::Grow, Self::ShrinkAndGrow];

    /// Convert a raw `i32` discriminant to an `AutoResizeMode`.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Off),
            1 => Some(Self::Grow),
            2 => Some(Self::ShrinkAndGrow),
            _ => None,
        }
    }

    /// Convert a string name to an `AutoResizeMode`.
    /// Matches the C `auto_resize_mode_from_string()` table.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "grow" => Some(Self::Grow),
            "shrink-and-grow" => Some(Self::ShrinkAndGrow),
            _ => None,
        }
    }

    /// The canonical string name for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Grow => "grow",
            Self::ShrinkAndGrow => "shrink-and-grow",
        }
    }
}

// ── Bitmasks ──────────────────────────────────────────────────────────────

/// User record section bitmask.
///
/// Maps to `UserRecordMask` in `src/shared/user-record.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserRecordMask(pub u32);

impl UserRecordMask {
    pub const REGULAR: u32 = 1 << 0;
    pub const SECRET: u32 = 1 << 1;
    pub const PRIVILEGED: u32 = 1 << 2;
    pub const PER_MACHINE: u32 = 1 << 3;
    pub const BINDING: u32 = 1 << 4;
    pub const STATUS: u32 = 1 << 5;
    pub const SIGNATURE: u32 = 1 << 6;
    pub const MAX: u32 = (1 << 7) - 1;

    /// All individual section bits, for iteration.
    pub const ALL_SECTIONS: [u32; 7] = [
        Self::REGULAR,
        Self::SECRET,
        Self::PRIVILEGED,
        Self::PER_MACHINE,
        Self::BINDING,
        Self::STATUS,
        Self::SIGNATURE,
    ];

    /// Check whether a given section bit is set in this mask.
    pub fn contains(&self, section: u32) -> bool {
        (self.0 & section) != 0
    }

    /// Convert a raw `u32` to a mask, clamping to valid bits.
    pub fn from_u32_truncated(v: u32) -> Self {
        Self(v & Self::MAX)
    }
}

impl std::fmt::Display for UserRecordMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for &bit in &Self::ALL_SECTIONS {
            if self.contains(bit) {
                if !first {
                    write!(f, "|")?;
                }
                first = false;
                match bit {
                    Self::REGULAR => write!(f, "REGULAR")?,
                    Self::SECRET => write!(f, "SECRET")?,
                    Self::PRIVILEGED => write!(f, "PRIVILEGED")?,
                    Self::PER_MACHINE => write!(f, "PER_MACHINE")?,
                    Self::BINDING => write!(f, "BINDING")?,
                    Self::STATUS => write!(f, "STATUS")?,
                    Self::SIGNATURE => write!(f, "SIGNATURE")?,
                    _ => unreachable!(),
                }
            }
        }
        if first {
            write!(f, "NONE")?;
        }
        Ok(())
    }
}

/// Flags controlling user record loading.
///
/// Maps to `UserRecordLoadFlags` in `src/shared/user-record.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserRecordLoadFlags(pub u32);

impl UserRecordLoadFlags {
    // What to require (bits 7-13)
    pub const REQUIRE_REGULAR: u32 = UserRecordMask::REGULAR << 7;
    pub const REQUIRE_SECRET: u32 = UserRecordMask::SECRET << 7;
    pub const REQUIRE_PRIVILEGED: u32 = UserRecordMask::PRIVILEGED << 7;
    pub const REQUIRE_PER_MACHINE: u32 = UserRecordMask::PER_MACHINE << 7;
    pub const REQUIRE_BINDING: u32 = UserRecordMask::BINDING << 7;
    pub const REQUIRE_STATUS: u32 = UserRecordMask::STATUS << 7;
    pub const REQUIRE_SIGNATURE: u32 = UserRecordMask::SIGNATURE << 7;

    // What to allow (bits 14-20)
    pub const ALLOW_REGULAR: u32 = UserRecordMask::REGULAR << 14;
    pub const ALLOW_SECRET: u32 = UserRecordMask::SECRET << 14;
    pub const ALLOW_PRIVILEGED: u32 = UserRecordMask::PRIVILEGED << 14;
    pub const ALLOW_PER_MACHINE: u32 = UserRecordMask::PER_MACHINE << 14;
    pub const ALLOW_BINDING: u32 = UserRecordMask::BINDING << 14;
    pub const ALLOW_STATUS: u32 = UserRecordMask::STATUS << 14;
    pub const ALLOW_SIGNATURE: u32 = UserRecordMask::SIGNATURE << 14;

    // What to strip (bits 21-27)
    pub const STRIP_REGULAR: u32 = UserRecordMask::REGULAR << 21;
    pub const STRIP_SECRET: u32 = UserRecordMask::SECRET << 21;
    pub const STRIP_PRIVILEGED: u32 = UserRecordMask::PRIVILEGED << 21;
    pub const STRIP_PER_MACHINE: u32 = UserRecordMask::PER_MACHINE << 21;
    pub const STRIP_BINDING: u32 = UserRecordMask::BINDING << 21;
    pub const STRIP_STATUS: u32 = UserRecordMask::STATUS << 21;
    pub const STRIP_SIGNATURE: u32 = UserRecordMask::SIGNATURE << 21;

    // Predefined combinations
    pub const LOAD_FULL: u32 = Self::REQUIRE_REGULAR
        | Self::ALLOW_SECRET
        | Self::ALLOW_PRIVILEGED
        | Self::ALLOW_PER_MACHINE
        | Self::ALLOW_BINDING
        | Self::ALLOW_STATUS
        | Self::ALLOW_SIGNATURE;

    pub const LOAD_REFUSE_SECRET: u32 = Self::REQUIRE_REGULAR
        | Self::ALLOW_PRIVILEGED
        | Self::ALLOW_PER_MACHINE
        | Self::ALLOW_BINDING
        | Self::ALLOW_STATUS
        | Self::ALLOW_SIGNATURE;

    pub const LOAD_MASK_SECRET: u32 = Self::REQUIRE_REGULAR
        | Self::ALLOW_PRIVILEGED
        | Self::ALLOW_PER_MACHINE
        | Self::ALLOW_BINDING
        | Self::ALLOW_STATUS
        | Self::ALLOW_SIGNATURE
        | Self::STRIP_SECRET;

    pub const EXTRACT_SECRET: u32 = Self::REQUIRE_SECRET
        | Self::STRIP_REGULAR
        | Self::STRIP_PRIVILEGED
        | Self::STRIP_PER_MACHINE
        | Self::STRIP_BINDING
        | Self::STRIP_STATUS
        | Self::STRIP_SIGNATURE;

    pub const LOAD_SIGNABLE: u32 =
        Self::REQUIRE_REGULAR | Self::ALLOW_PRIVILEGED | Self::ALLOW_PER_MACHINE;

    pub const EXTRACT_SIGNABLE: u32 = Self::LOAD_SIGNABLE
        | Self::STRIP_SECRET
        | Self::STRIP_BINDING
        | Self::STRIP_STATUS
        | Self::STRIP_SIGNATURE;

    pub const LOAD_EMBEDDED: u32 = Self::REQUIRE_REGULAR
        | Self::ALLOW_PRIVILEGED
        | Self::ALLOW_PER_MACHINE
        | Self::ALLOW_SIGNATURE;

    pub const EXTRACT_EMBEDDED: u32 =
        Self::LOAD_EMBEDDED | Self::STRIP_SECRET | Self::STRIP_BINDING | Self::STRIP_STATUS;

    pub const LOAD_MASK_PRIVILEGED: u32 = Self::REQUIRE_REGULAR
        | Self::STRIP_PRIVILEGED
        | Self::ALLOW_PER_MACHINE
        | Self::ALLOW_BINDING
        | Self::ALLOW_STATUS
        | Self::ALLOW_SIGNATURE;

    pub const EXTRACT_PRIVILEGED: u32 = Self::STRIP_REGULAR
        | Self::ALLOW_PRIVILEGED
        | Self::STRIP_PER_MACHINE
        | Self::STRIP_BINDING
        | Self::STRIP_STATUS
        | Self::STRIP_SIGNATURE;

    // Control flags (bits 28-30)
    pub const LOG: u32 = 1 << 28;
    pub const PERMISSIVE: u32 = 1 << 29;
    pub const EMPTY_OK: u32 = 1 << 30;

    /// Extract the "require" section mask from these flags.
    /// Corresponds to C `USER_RECORD_REQUIRE_MASK()`.
    pub fn require_mask(self) -> UserRecordMask {
        UserRecordMask((self.0 >> 7) & UserRecordMask::MAX)
    }

    /// Extract the "allow" section mask from these flags (includes requires).
    /// Corresponds to C `USER_RECORD_ALLOW_MASK()`.
    pub fn allow_mask(self) -> UserRecordMask {
        UserRecordMask(((self.0 >> 14) & UserRecordMask::MAX) | self.require_mask().0)
    }

    /// Extract the "strip" section mask from these flags.
    /// Corresponds to C `USER_RECORD_STRIP_MASK()`.
    pub fn strip_mask(self) -> UserRecordMask {
        UserRecordMask((self.0 >> 21) & UserRecordMask::MAX)
    }

    pub fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

// ── Rebalance weight constants ────────────────────────────────────────────

/// Rebalance weight off — automatic rebalancing disabled.
pub const REBALANCE_WEIGHT_OFF: u64 = 0;
/// Rebalance weight default — 100%.
pub const REBALANCE_WEIGHT_DEFAULT: u64 = 100;
/// Rebalance weight backing — used for backing filesystems.
pub const REBALANCE_WEIGHT_BACKING: u64 = 20;
/// Rebalance weight minimum valid value.
pub const REBALANCE_WEIGHT_MIN: u64 = 2;
/// Rebalance weight maximum valid value.
pub const REBALANCE_WEIGHT_MAX: u64 = 10000;
/// Rebalance weight sentinel for "unset".
pub const REBALANCE_WEIGHT_UNSET: u64 = u64::MAX;

// ── Tmpfs limit descriptor ────────────────────────────────────────────────

/// Tmpfs limit descriptor.
///
/// Describes absolute and relative tmpfs size limits for `/tmp` and `/dev/shm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpfsLimit {
    /// Absolute limit in bytes.
    pub limit: u64,
    /// Relative limit (normalized: `u32::MAX` = 100% of free space).
    pub limit_scale: u32,
    /// Whether the limit has been explicitly set.
    pub is_set: bool,
}

impl Default for TmpfsLimit {
    fn default() -> Self {
        Self {
            limit: u64::MAX,
            limit_scale: u32::MAX,
            is_set: false,
        }
    }
}

impl TmpfsLimit {
    /// Sentinel for an unset tmpfs limit (matches C `TMPFS_LIMIT_NULL`).
    pub const NULL: Self = Self {
        limit: u64::MAX,
        limit_scale: u32::MAX,
        is_set: false,
    };

    /// Create a new tmpfs limit from absolute and relative values.
    pub fn new(limit: u64, limit_scale: u32) -> Self {
        Self {
            limit,
            limit_scale,
            is_set: true,
        }
    }

    /// Check whether this limit is the null/unset sentinel.
    pub fn is_null(&self) -> bool {
        self.limit == u64::MAX && self.limit_scale == u32::MAX && !self.is_set
    }
}

// ── UserDB match ──────────────────────────────────────────────────────────

/// All dispositions mask — matches every disposition.
pub const USER_DISPOSITION_MASK_ALL: u64 = (1u64 << UserDisposition::MAX as u64) - 1;

/// A match filter for user/group database lookups.
///
/// Maps to `UserDBMatch` in `src/shared/user-record.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDBMatch {
    /// Fuzzy name match strings (substring or Levenshtein distance).
    pub fuzzy_names: Vec<String>,
    /// Bitmask of allowed dispositions.
    pub disposition_mask: u64,
    /// Minimum UID/GID (inclusive).
    pub id_min: u32,
    /// Maximum UID/GID (inclusive).
    pub id_max: u32,
}

impl Default for UserDBMatch {
    fn default() -> Self {
        Self {
            fuzzy_names: Vec::new(),
            disposition_mask: USER_DISPOSITION_MASK_ALL,
            id_min: 0,
            id_max: u32::MAX - 1,
        }
    }
}

impl UserDBMatch {
    /// Create a null/default match that accepts everything.
    pub fn null() -> Self {
        Self::default()
    }

    /// Check whether this match filter is non-trivial (has any constraints set).
    ///
    /// Corresponds to C `userdb_match_is_set()`.
    pub fn is_set(&self) -> bool {
        !self.fuzzy_names.is_empty()
            || self.disposition_mask != USER_DISPOSITION_MASK_ALL
            || self.id_min > 0
            || self.id_max != u32::MAX - 1
    }

    /// Check whether a given disposition is allowed by this match.
    pub fn disposition_allowed(&self, d: UserDisposition) -> bool {
        (self.disposition_mask & (1u64 << d as u64)) != 0
    }

    /// Check whether a UID falls within the allowed range.
    pub fn uid_in_range(&self, uid: u32) -> bool {
        uid >= self.id_min && uid <= self.id_max
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate whether a blob filename is suitable.
///
/// Enforces filename requirements as described in `docs/USER_RECORD_BULK_DIRS.md`:
/// - Must be a valid filename (no `/`, no NUL, not empty, ≤255 bytes)
/// - Must contain only URI-unreserved characters (`A-Za-z0-9-._~`)
/// - Must not start with `.`
///
/// Corresponds to C `suitable_blob_filename()`.
pub fn suitable_blob_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 || name.starts_with('.') {
        return false;
    }

    name.bytes().all(|b| {
        // URI-unreserved characters per RFC 3986: ALPHA / DIGIT / "-" / "." / "_" / "~"
        b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
    })
}

/// Check if a user record matches a user name.
///
/// Performs exact matching against the primary user name, the `user_name_and_realm`
/// composite, and any aliases. Also checks realm-qualified alias matching.
///
/// Corresponds to C `user_record_matches_user_name()`.
pub fn user_record_matches_user_name(
    user_name: Option<&str>,
    user_name_and_realm: Option<&str>,
    aliases: &[&str],
    realm: Option<&str>,
    match_name: &str,
) -> bool {
    // Exact match on primary name
    if user_name == Some(match_name) {
        return true;
    }

    // Exact match on composite name
    if user_name_and_realm == Some(match_name) {
        return true;
    }

    // Exact match on any alias
    if aliases.contains(&match_name) {
        return true;
    }

    // Realm-qualified alias matching: if match_name contains '@realm',
    // check if any alias appears before the '@'
    if let Some(at_pos) = match_name.rfind('@') {
        if let Some(r) = realm {
            if match_name[at_pos + 1..] == *r {
                let prefix = &match_name[..at_pos];
                if aliases.contains(&prefix) {
                    return true;
                }
            }
        }
    }

    false
}

pub fn user_name_matches(user_name: &str, match_name: &str) -> bool {
    user_name == match_name
}

/// Check whether a user is "root" by UID or name.
///
/// Corresponds to C `user_record_is_root()`.
pub fn user_record_is_root(uid: u32, user_name: Option<&str>) -> bool {
    uid == 0 || user_name == Some("root")
}

/// Check whether a user is "nobody" by UID or name.
///
/// Corresponds to C `user_record_is_nobody()`.
pub fn user_record_is_nobody(uid: u32, user_name: Option<&str>) -> bool {
    // UID_NOBODY is typically 65534
    uid == 65534
        || user_name == Some("nobody")
        || user_name == Some("Nobody")
        || user_name == Some("NOBODY")
}

/// Validate that a nice level is in the acceptable range.
///
/// The nice level must be in `[PRIO_MIN (-20), PRIO_MAX (20))`.
pub fn valid_nice_level(nice: i32) -> bool {
    (-20..20).contains(&nice)
}

/// Validate that a nice level is valid or the sentinel `INT_MAX` (unset).
pub fn valid_nice_level_or_max(nice: i32) -> bool {
    nice == i32::MAX || valid_nice_level(nice)
}

/// Validate that a rebalance weight is in the acceptable range.
///
/// Valid range is `[REBALANCE_WEIGHT_MIN, REBALANCE_WEIGHT_MAX]`, or
/// `REBALANCE_WEIGHT_OFF` (0), or `REBALANCE_WEIGHT_UNSET` (u64::MAX).
pub fn valid_rebalance_weight(w: u64) -> bool {
    w == REBALANCE_WEIGHT_UNSET
        || w == REBALANCE_WEIGHT_OFF
        || (REBALANCE_WEIGHT_MIN..=REBALANCE_WEIGHT_MAX).contains(&w)
}

/// Build the default image path for a given storage type and user name.
///
/// Corresponds to C `user_record_build_image_path()`.
pub fn build_image_path(storage: UserStorage, user_name_and_realm: &str) -> Option<String> {
    match storage {
        UserStorage::Classic
        | UserStorage::Directory
        | UserStorage::Subvolume
        | UserStorage::FSCrypt => None,
        UserStorage::LUKS => {
            let home = format!("/home/{}", user_name_and_realm);
            let image = format!("{}.home", home);
            Some(image)
        }
        UserStorage::CIFS => {
            let home = format!("/home/{}", user_name_and_realm);
            Some(home)
        }
    }
}

/// Simple Levenshtein distance for fuzzy matching.
///
/// Used by `user_name_fuzzy_match()` — only called when needle length ≥ 5,
/// threshold < 3. This implementation is O(n*m) which is fine for short strings.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_len = a.chars().count();
    let b_len = b.chars().count();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev = vec![0usize; b_len + 1];
    let mut curr = vec![0usize; b_len + 1];

    for (j, slot) in prev.iter_mut().enumerate() {
        *slot = j;
    }

    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    for (i, ac) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, bc) in b_chars.iter().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1) // deletion
                .min(curr[j] + 1) // insertion
                .min(prev[j] + cost); // substitution
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Fuzzy match a set of record name strings against a set of search strings.
///
/// For each record name, checks if any search string is a substring or has
/// Levenshtein distance < 3 (only when the search string is ≥ 5 chars).
/// All comparisons are case-insensitive.
///
/// Corresponds to C `user_name_fuzzy_match()`.
pub fn user_name_fuzzy_match(record_names: &[&str], search_strings: &[&str]) -> bool {
    for record_name in record_names {
        if record_name.is_empty() {
            continue;
        }
        let record_lower = record_name.to_ascii_lowercase();

        for search in search_strings {
            if search.is_empty() {
                continue;
            }
            let search_lower = search.to_ascii_lowercase();

            // Substring check
            if record_lower.contains(&search_lower) {
                return true;
            }

            // Levenshtein fuzzy check (only for non-trivial search strings)
            if search_lower.len() >= 5 && levenshtein_distance(&record_lower, &search_lower) < 3 {
                return true;
            }
        }
    }

    false
}

/// Check if a user record matches a `UserDBMatch` filter.
///
/// Corresponds to C `user_record_match()`.
pub fn user_record_match(
    uid: u32,
    disposition: UserDisposition,
    record_names: &[&str],
    aliases: &[&str],
    match_filter: &UserDBMatch,
) -> bool {
    if !match_filter.uid_in_range(uid) {
        return false;
    }

    if !match_filter.disposition_allowed(disposition) {
        return false;
    }

    if !match_filter.fuzzy_names.is_empty() {
        let mut all_names: Vec<&str> = record_names.to_vec();
        all_names.extend_from_slice(aliases);

        if !user_name_fuzzy_match(
            &all_names,
            &match_filter
                .fuzzy_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ) {
            return false;
        }
    }

    true
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_disposition_roundtrip_i32() {
        for d in UserDisposition::ALL {
            assert_eq!(UserDisposition::from_i32(d as i32), Some(d));
            assert!(!d.to_cstr().is_empty());
            assert!(!d.as_str().is_empty());
        }
    }

    #[test]
    fn test_user_disposition_from_str() {
        assert_eq!(
            UserDisposition::from_str_lossy("regular"),
            Some(UserDisposition::Regular)
        );
        assert_eq!(
            UserDisposition::from_str_lossy("REGULAR"),
            Some(UserDisposition::Regular)
        );
        assert_eq!(
            UserDisposition::from_str_lossy("System"),
            Some(UserDisposition::System)
        );
        assert_eq!(UserDisposition::from_str_lossy("bogus"), None);
        assert_eq!(UserDisposition::from_str_lossy(""), None);
    }

    #[test]
    fn test_user_disposition_invalid_i32() {
        assert_eq!(UserDisposition::from_i32(-1), None);
        assert_eq!(UserDisposition::from_i32(99), None);
        assert_eq!(UserDisposition::from_i32(7), None); // MAX is exclusive
    }

    #[test]
    fn test_user_storage_roundtrip_i32() {
        for s in UserStorage::ALL {
            assert_eq!(UserStorage::from_i32(s as i32), Some(s));
            assert!(!s.to_cstr().is_empty());
            assert!(!s.as_str().is_empty());
        }
    }

    #[test]
    fn test_user_storage_from_str() {
        assert_eq!(
            UserStorage::from_str_lossy("classic"),
            Some(UserStorage::Classic)
        );
        assert_eq!(UserStorage::from_str_lossy("LUKS"), Some(UserStorage::LUKS));
        assert_eq!(UserStorage::from_str_lossy("bogus"), None);
    }

    #[test]
    fn test_auto_resize_mode_roundtrip() {
        for m in AutoResizeMode::ALL {
            assert_eq!(AutoResizeMode::from_i32(m as i32), Some(m));
            assert!(!m.as_str().is_empty());
        }
        assert_eq!(
            AutoResizeMode::from_str_lossy("shrink-and-grow"),
            Some(AutoResizeMode::ShrinkAndGrow)
        );
        assert_eq!(AutoResizeMode::from_str_lossy("invalid"), None);
    }

    #[test]
    fn test_record_mask_flags() {
        assert_eq!(UserRecordMask::REGULAR, 1);
        assert_eq!(UserRecordMask::SECRET, 2);
        assert_eq!(UserRecordMask::PRIVILEGED, 4);
        assert_eq!(UserRecordMask::SIGNATURE, 64);
    }

    #[test]
    fn test_record_mask_contains() {
        let mask = UserRecordMask(UserRecordMask::REGULAR | UserRecordMask::SECRET);
        assert!(mask.contains(UserRecordMask::REGULAR));
        assert!(mask.contains(UserRecordMask::SECRET));
        assert!(!mask.contains(UserRecordMask::PRIVILEGED));
    }

    #[test]
    fn test_record_mask_display() {
        let mask = UserRecordMask(UserRecordMask::REGULAR | UserRecordMask::SECRET);
        let s = format!("{}", mask);
        assert!(s.contains("REGULAR"));
        assert!(s.contains("SECRET"));
        assert!(!s.contains("PRIVILEGED"));
    }

    #[test]
    fn test_record_mask_from_u32_truncated() {
        let mask = UserRecordMask::from_u32_truncated(0xFFFFFFFF);
        assert_eq!(mask.0, UserRecordMask::MAX);
    }

    #[test]
    fn test_load_flags_composition() {
        let full = UserRecordLoadFlags::LOAD_FULL;
        let flags = UserRecordLoadFlags(full);
        assert!(flags.contains(UserRecordLoadFlags::REQUIRE_REGULAR));
        assert!(flags.contains(UserRecordLoadFlags::ALLOW_SECRET));
        assert!(flags.contains(UserRecordLoadFlags::ALLOW_PRIVILEGED));
        assert!(!flags.contains(UserRecordLoadFlags::REQUIRE_SECRET));
    }

    #[test]
    fn test_load_flags_predefined() {
        // LOAD_REFUSE_SECRET must require regular but not allow secret
        let refuse = UserRecordLoadFlags::LOAD_REFUSE_SECRET;
        assert!(UserRecordLoadFlags(refuse).contains(UserRecordLoadFlags::REQUIRE_REGULAR));
        assert!(!UserRecordLoadFlags(refuse).contains(UserRecordLoadFlags::ALLOW_SECRET));

        // EXTRACT_SECRET must require secret and strip regular
        let extract = UserRecordLoadFlags::EXTRACT_SECRET;
        assert!(UserRecordLoadFlags(extract).contains(UserRecordLoadFlags::REQUIRE_SECRET));
        assert!(UserRecordLoadFlags(extract).contains(UserRecordLoadFlags::STRIP_REGULAR));
    }

    #[test]
    fn test_load_flags_mask_extraction() {
        let flags = UserRecordLoadFlags(
            UserRecordLoadFlags::REQUIRE_REGULAR
                | UserRecordLoadFlags::ALLOW_SECRET
                | UserRecordLoadFlags::STRIP_PRIVILEGED,
        );

        let require = flags.require_mask();
        assert!(require.contains(UserRecordMask::REGULAR));
        assert!(!require.contains(UserRecordMask::SECRET));

        let allow = flags.allow_mask();
        assert!(allow.contains(UserRecordMask::REGULAR)); // requires imply allows
        assert!(allow.contains(UserRecordMask::SECRET));

        let strip = flags.strip_mask();
        assert!(strip.contains(UserRecordMask::PRIVILEGED));
        assert!(!strip.contains(UserRecordMask::SECRET));
    }

    #[test]
    fn test_blob_filename_validation() {
        assert!(suitable_blob_filename("valid_name"));
        assert!(suitable_blob_filename("foo-bar.baz"));
        assert!(suitable_blob_filename("UPPER123"));
        assert!(suitable_blob_filename("a"));
        assert!(!suitable_blob_filename(""));
        assert!(!suitable_blob_filename("/etc/passwd"));
        assert!(!suitable_blob_filename(".hidden"));
        assert!(!suitable_blob_filename("has space"));
        assert!(!suitable_blob_filename("has\nnewline"));
        assert!(!suitable_blob_filename("has/slash"));
        assert!(!suitable_blob_filename("has!bang"));
    }

    #[test]
    fn test_blob_filename_max_length() {
        let long_name = "a".repeat(255);
        assert!(suitable_blob_filename(&long_name));
        let too_long = "a".repeat(256);
        assert!(!suitable_blob_filename(&too_long));
    }

    #[test]
    fn test_user_record_matches_user_name() {
        // Exact match on primary name
        assert!(user_record_matches_user_name(
            Some("alice"),
            Some("alice@example.com"),
            &[],
            Some("example.com"),
            "alice"
        ));

        // Exact match on composite name
        assert!(user_record_matches_user_name(
            Some("alice"),
            Some("alice@example.com"),
            &[],
            Some("example.com"),
            "alice@example.com"
        ));

        // Match on alias
        assert!(user_record_matches_user_name(
            Some("alice"),
            Some("alice@example.com"),
            &["a"],
            Some("example.com"),
            "a"
        ));

        // Realm-qualified alias match
        assert!(user_record_matches_user_name(
            Some("alice"),
            Some("alice@example.com"),
            &["a"],
            Some("example.com"),
            "a@example.com"
        ));

        // No match
        assert!(!user_record_matches_user_name(
            Some("alice"),
            Some("alice@example.com"),
            &[],
            Some("example.com"),
            "bob"
        ));
    }

    #[test]
    fn test_user_record_is_root() {
        assert!(user_record_is_root(0, None));
        assert!(user_record_is_root(1000, Some("root")));
        assert!(!user_record_is_root(1000, Some("alice")));
        assert!(!user_record_is_root(1000, None));
    }

    #[test]
    fn test_user_record_is_nobody() {
        assert!(user_record_is_nobody(65534, None));
        assert!(user_record_is_nobody(1000, Some("nobody")));
        assert!(user_record_is_nobody(1000, Some("Nobody")));
        assert!(user_record_is_nobody(1000, Some("NOBODY")));
        assert!(!user_record_is_nobody(1000, Some("alice")));
        assert!(!user_record_is_nobody(0, None));
    }

    #[test]
    fn test_valid_nice_level() {
        assert!(valid_nice_level(-20));
        assert!(valid_nice_level(0));
        assert!(valid_nice_level(19));
        assert!(!valid_nice_level(20));
        assert!(!valid_nice_level(-21));
        assert!(valid_nice_level_or_max(i32::MAX));
        assert!(valid_nice_level_or_max(0));
        assert!(!valid_nice_level_or_max(20));
    }

    #[test]
    fn test_valid_rebalance_weight() {
        assert!(valid_rebalance_weight(REBALANCE_WEIGHT_OFF));
        assert!(valid_rebalance_weight(REBALANCE_WEIGHT_MIN));
        assert!(valid_rebalance_weight(REBALANCE_WEIGHT_DEFAULT));
        assert!(valid_rebalance_weight(REBALANCE_WEIGHT_MAX));
        assert!(valid_rebalance_weight(REBALANCE_WEIGHT_UNSET));
        assert!(!valid_rebalance_weight(REBALANCE_WEIGHT_MIN - 1));
        assert!(!valid_rebalance_weight(REBALANCE_WEIGHT_MAX + 1));
    }

    #[test]
    fn test_tmpfs_limit_default() {
        let limit = TmpfsLimit::default();
        assert_eq!(limit.limit, u64::MAX);
        assert_eq!(limit.limit_scale, u32::MAX);
        assert!(!limit.is_set);
        assert!(limit.is_null());
    }

    #[test]
    fn test_tmpfs_limit_new() {
        let limit = TmpfsLimit::new(1024, 50);
        assert_eq!(limit.limit, 1024);
        assert_eq!(limit.limit_scale, 50);
        assert!(limit.is_set);
        assert!(!limit.is_null());
    }

    #[test]
    fn test_tmpfs_limit_null_const() {
        let limit = TmpfsLimit::NULL;
        assert!(limit.is_null());
        assert!(!limit.is_set);
    }

    #[test]
    fn test_rebalance_weight_constants() {
        assert_eq!(REBALANCE_WEIGHT_OFF, 0);
        assert_eq!(REBALANCE_WEIGHT_MIN, 2);
        assert_eq!(REBALANCE_WEIGHT_DEFAULT, 100);
        assert_eq!(REBALANCE_WEIGHT_MAX, 10_000);
        assert_eq!(REBALANCE_WEIGHT_UNSET, u64::MAX);
        assert_eq!(REBALANCE_WEIGHT_BACKING, 20);
    }

    #[test]
    fn test_build_image_path() {
        // LUKS storage should produce a .home path
        let path = build_image_path(UserStorage::LUKS, "alice@example.com");
        assert_eq!(path, Some("/home/alice@example.com.home".to_string()));

        // CIFS storage should produce a home path
        let path = build_image_path(UserStorage::CIFS, "alice@example.com");
        assert_eq!(path, Some("/home/alice@example.com".to_string()));

        // Classic and other storage types return None
        assert_eq!(build_image_path(UserStorage::Classic, "alice"), None);
        assert_eq!(build_image_path(UserStorage::Directory, "alice"), None);
        assert_eq!(build_image_path(UserStorage::Subvolume, "alice"), None);
        assert_eq!(build_image_path(UserStorage::FSCrypt, "alice"), None);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
        assert_eq!(levenshtein_distance("abc", "axc"), 1);
        assert_eq!(levenshtein_distance("abc", "abc123"), 3);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
    }

    #[test]
    fn test_user_name_fuzzy_match() {
        // Substring match
        assert!(user_name_fuzzy_match(&["alice", "Alice Smith"], &["alice"]));

        // Case-insensitive substring
        assert!(user_name_fuzzy_match(&["Alice Johnson"], &["alice"]));

        // Levenshtein fuzzy match (search string ≥ 5 chars, distance < 3)
        assert!(user_name_fuzzy_match(
            &["bernard"],
            &["bernard"] // exact substring
        ));

        // No match
        assert!(!user_name_fuzzy_match(&["alice"], &["bob"]));

        // Empty record names are skipped
        assert!(!user_name_fuzzy_match(&[], &["alice"]));

        // Empty search strings are skipped
        assert!(!user_name_fuzzy_match(&["alice"], &[]));
    }

    #[test]
    fn test_userdb_match_default() {
        let m = UserDBMatch::default();
        assert!(!m.is_set());
        assert!(m.disposition_allowed(UserDisposition::Regular));
        assert!(m.uid_in_range(0));
        assert!(m.uid_in_range(65534));
    }

    #[test]
    fn test_userdb_match_is_set() {
        let m = UserDBMatch {
            fuzzy_names: vec!["alice".to_string()],
            ..Default::default()
        };
        assert!(m.is_set());

        let m2 = UserDBMatch {
            id_min: 1000,
            ..Default::default()
        };
        assert!(m2.is_set());

        let m3 = UserDBMatch {
            disposition_mask: 0,
            ..Default::default()
        };
        assert!(m3.is_set());
    }

    #[test]
    fn test_user_record_match() {
        let filter = UserDBMatch::default();
        assert!(user_record_match(
            1000,
            UserDisposition::Regular,
            &["alice"],
            &[],
            &filter
        ));

        // UID out of range
        let filter_range = UserDBMatch {
            id_min: 100,
            id_max: 200,
            ..Default::default()
        };
        assert!(!user_record_match(
            1000,
            UserDisposition::Regular,
            &["alice"],
            &[],
            &filter_range
        ));

        // Disposition not allowed
        let filter_disp = UserDBMatch {
            disposition_mask: 1 << UserDisposition::System as u64,
            ..Default::default()
        };
        assert!(!user_record_match(
            0,
            UserDisposition::Regular,
            &["alice"],
            &[],
            &filter_disp
        ));

        // Fuzzy name match
        let filter_fuzzy = UserDBMatch {
            fuzzy_names: vec!["ali".to_string()],
            ..Default::default()
        };
        assert!(user_record_match(
            1000,
            UserDisposition::Regular,
            &["alice"],
            &[],
            &filter_fuzzy
        ));
    }

    #[test]
    fn test_disposition_mask_all() {
        // USER_DISPOSITION_MASK_ALL should have bits 0..MAX-1 set
        assert_eq!(
            USER_DISPOSITION_MASK_ALL,
            (1u64 << UserDisposition::MAX as u64) - 1
        );
        for d in UserDisposition::ALL {
            assert!(
                (USER_DISPOSITION_MASK_ALL & (1u64 << d as u64)) != 0,
                "disposition {:?} should be in mask all",
                d
            );
        }
    }

    #[test]
    fn test_constants_values() {
        assert_eq!(DEFAULT_RATELIMIT_BURST, 30);
        assert_eq!(DEFAULT_RATELIMIT_INTERVAL_USEC, 60_000_000);
        assert_eq!(BLOB_DIR_MAX_SIZE, 64 * 1024 * 1024);
    }
}
