// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/image-policy.c, src/shared/image-policy.h
//
// Image policy parsing and evaluation.
//
// An image policy controls which disk partitions are trusted, verified, or
// required. Policies are expressed as strings like "root=verity+signed:usr=absent:=-"
// where each `designator=flags` pair is separated by `:`.
//
// Three symbolic shortcuts exist:
//   "-"  → ignore policy (everything may exist, nothing used)
//   "*"  → allow policy (everything is allowed)
//   "~"  → deny policy (nothing may exist)

// ── Partition Designator ────────────────────────────────────────────────────

/// Identifies a specific GPT partition by role.
use crate::ffi::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum PartitionDesignator {
    Root = 0,
    Usr = 1,
    Home = 2,
    Srv = 3,
    Esp = 4,
    XBootLoader = 5,
    Swap = 6,
    RootVerity = 7,
    UsrVerity = 8,
    RootVeritySig = 9,
    UsrVeritySig = 10,
    Tmp = 11,
    Var = 12,
}

impl PartitionDesignator {
    /// Total number of partition designators.
    pub const MAX: usize = 13;

    /// Parse a partition designator from its string name.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "root" => Some(Self::Root),
            "usr" => Some(Self::Usr),
            "home" => Some(Self::Home),
            "srv" => Some(Self::Srv),
            "esp" => Some(Self::Esp),
            "xbootldr" => Some(Self::XBootLoader),
            "swap" => Some(Self::Swap),
            "root-verity" => Some(Self::RootVerity),
            "usr-verity" => Some(Self::UsrVerity),
            "root-verity-sig" => Some(Self::RootVeritySig),
            "usr-verity-sig" => Some(Self::UsrVeritySig),
            "tmp" => Some(Self::Tmp),
            "var" => Some(Self::Var),
            _ => None,
        }
    }

    /// Return the string name for this designator.
    pub fn to_name(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Usr => "usr",
            Self::Home => "home",
            Self::Srv => "srv",
            Self::Esp => "esp",
            Self::XBootLoader => "xbootldr",
            Self::Swap => "swap",
            Self::RootVerity => "root-verity",
            Self::UsrVerity => "usr-verity",
            Self::RootVeritySig => "root-verity-sig",
            Self::UsrVeritySig => "usr-verity-sig",
            Self::Tmp => "tmp",
            Self::Var => "var",
        }
    }

    /// All designator values in order.
    pub const ALL: [PartitionDesignator; Self::MAX] = [
        Self::Root,
        Self::Usr,
        Self::Home,
        Self::Srv,
        Self::Esp,
        Self::XBootLoader,
        Self::Swap,
        Self::RootVerity,
        Self::UsrVerity,
        Self::RootVeritySig,
        Self::UsrVeritySig,
        Self::Tmp,
        Self::Var,
    ];

    /// If this is a verity hash partition, return the corresponding data partition.
    pub fn verity_hash_to_data(self) -> Option<Self> {
        match self {
            Self::RootVerity => Some(Self::Root),
            Self::UsrVerity => Some(Self::Usr),
            _ => None,
        }
    }

    /// If this is a verity signature partition, return the corresponding data partition.
    pub fn verity_sig_to_data(self) -> Option<Self> {
        match self {
            Self::RootVeritySig => Some(Self::Root),
            Self::UsrVeritySig => Some(Self::Usr),
            _ => None,
        }
    }

    /// If this data partition has a verity hash partition, return it.
    pub fn verity_hash_of(self) -> Option<Self> {
        match self {
            Self::Root => Some(Self::RootVerity),
            Self::Usr => Some(Self::UsrVerity),
            _ => None,
        }
    }
}

// ── Partition Policy Flags ──────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags describing what protection/state is required for a partition.
    ///
    /// Negative values are used as error codes; the valid flag range is
    /// non-negative and uses bits 0–17.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PartitionPolicyFlags: i64 {
        // ── Use mask (bits 0–6) ──
        const VERITY                  = 1 << 0;
        const SIGNED                  = 1 << 1;
        const ENCRYPTED               = 1 << 2;
        const ENCRYPTED_WITH_INTEGRITY= 1 << 3;
        const UNPROTECTED             = 1 << 4;
        const UNUSED                  = 1 << 5;
        const ABSENT                  = 1 << 6;
        /// Shorthand: all use flags set.
        const OPEN  = Self::VERITY.bits() | Self::SIGNED.bits()
                    | Self::ENCRYPTED.bits() | Self::ENCRYPTED_WITH_INTEGRITY.bits()
                    | Self::UNPROTECTED.bits() | Self::UNUSED.bits() | Self::ABSENT.bits();
        /// Shorthand: unused + absent.
        const IGNORE = Self::UNUSED.bits() | Self::ABSENT.bits();

        const _USE_MASK = Self::OPEN.bits();

        // ── GPT partition flags (bits 7–10) ──
        const READ_ONLY_OFF           = 1 << 7;
        const READ_ONLY_ON            = 1 << 8;
        const _READ_ONLY_MASK         = Self::READ_ONLY_OFF.bits() | Self::READ_ONLY_ON.bits();

        const GROWFS_OFF              = 1 << 9;
        const GROWFS_ON               = 1 << 10;
        const _GROWFS_MASK            = Self::GROWFS_OFF.bits() | Self::GROWFS_ON.bits();

        const _PFLAGS_MASK            = Self::_READ_ONLY_MASK.bits() | Self::_GROWFS_MASK.bits();

        const _MASK                   = Self::_USE_MASK.bits() | Self::_PFLAGS_MASK.bits();

        // ── Filesystem type flags (bits 11–17) ──
        const BTRFS                   = 1 << 11;
        const EROFS                   = 1 << 12;
        const EXT4                    = 1 << 13;
        const F2FS                    = 1 << 14;
        const SQUASHFS                = 1 << 15;
        const VFAT                    = 1 << 16;
        const XFS                     = 1 << 17;
        const _FSTYPE_MASK            = Self::BTRFS.bits() | Self::EROFS.bits() | Self::EXT4.bits()
                                      | Self::F2FS.bits() | Self::SQUASHFS.bits()
                                      | Self::VFAT.bits() | Self::XFS.bits();
    }
}

/// Error codes for policy operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// Duplicate rule for the same partition.
    Duplicate = 39,
    /// Unknown partition designator.
    UnknownDesignator = 28,
    /// Unknown policy flag string.
    UnknownFlag = 56,
    /// Invalid argument.
    Invalid = 22,
    /// Out of memory.
    NoMemory = 12,
    /// Intersection is empty / impossible policy.
    Unavailable = 119,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate => write!(f, "duplicate rule in image policy"),
            Self::UnknownDesignator => write!(f, "unknown partition designator"),
            Self::UnknownFlag => write!(f, "unknown partition policy flag"),
            Self::Invalid => write!(f, "invalid argument"),
            Self::NoMemory => write!(f, "out of memory"),
            Self::Unavailable => write!(f, "impossible policy (intersection empty)"),
        }
    }
}

impl std::error::Error for PolicyError {}

// ── Data structures ─────────────────────────────────────────────────────────

/// Policy for a single partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionPolicy {
    pub designator: PartitionDesignator,
    pub flags: PartitionPolicyFlags,
}

/// Complete image policy: a sorted list of per-partition rules plus a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePolicy {
    pub default_flags: PartitionPolicyFlags,
    pub policies: Vec<PartitionPolicy>,
}

impl ImagePolicy {
    /// Create a new empty policy with the given default flags.
    pub fn new(default_flags: PartitionPolicyFlags) -> Self {
        Self {
            default_flags,
            policies: Vec::new(),
        }
    }

    /// Create the symbolic "ignore" policy (`"-"`).
    pub fn ignore() -> Self {
        Self::new(PartitionPolicyFlags::IGNORE)
    }

    /// Create the symbolic "allow" policy (`"*"`).
    pub fn allow() -> Self {
        Self::new(PartitionPolicyFlags::OPEN)
    }

    /// Create the symbolic "deny" policy (`"~"`).
    pub fn deny() -> Self {
        Self::new(PartitionPolicyFlags::ABSENT)
    }

    /// Binary search for a partition policy by designator.
    pub fn find(&self, designator: PartitionDesignator) -> Option<&PartitionPolicy> {
        self.policies
            .binary_search_by_key(&designator, |p| p.designator)
            .ok()
            .map(|i| &self.policies[i])
    }

    /// Number of explicit policy entries.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether there are no explicit policy entries.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

impl Default for ImagePolicy {
    fn default() -> Self {
        Self::ignore()
    }
}

// ── Flag parsing ────────────────────────────────────────────────────────────

/// Parse a single policy flag keyword (e.g. `"verity"`, `"encrypted"`, `"btrfs"`).
fn policy_flag_from_string_one(s: &str) -> Option<PartitionPolicyFlags> {
    match s {
        "verity" => Some(PartitionPolicyFlags::VERITY),
        "signed" => Some(PartitionPolicyFlags::SIGNED),
        "encrypted" => Some(PartitionPolicyFlags::ENCRYPTED),
        "encryptedwithintegrity" => Some(PartitionPolicyFlags::ENCRYPTED_WITH_INTEGRITY),
        "unprotected" => Some(PartitionPolicyFlags::UNPROTECTED),
        "unused" => Some(PartitionPolicyFlags::UNUSED),
        "absent" => Some(PartitionPolicyFlags::ABSENT),
        "open" => Some(PartitionPolicyFlags::OPEN),
        "ignore" => Some(PartitionPolicyFlags::IGNORE),
        "read-only-on" => Some(PartitionPolicyFlags::READ_ONLY_ON),
        "read-only-off" => Some(PartitionPolicyFlags::READ_ONLY_OFF),
        "growfs-on" => Some(PartitionPolicyFlags::GROWFS_ON),
        "growfs-off" => Some(PartitionPolicyFlags::GROWFS_OFF),
        _ => policy_flag_from_fstype(s),
    }
}

/// Parse a filesystem type name into its policy flag.
fn policy_flag_from_fstype(s: &str) -> Option<PartitionPolicyFlags> {
    match s {
        "btrfs" => Some(PartitionPolicyFlags::BTRFS),
        "erofs" => Some(PartitionPolicyFlags::EROFS),
        "ext4" => Some(PartitionPolicyFlags::EXT4),
        "f2fs" => Some(PartitionPolicyFlags::F2FS),
        "squashfs" => Some(PartitionPolicyFlags::SQUASHFS),
        "vfat" => Some(PartitionPolicyFlags::VFAT),
        "xfs" => Some(PartitionPolicyFlags::XFS),
        _ => None,
    }
}

/// Parse a `+`-separated list of policy flag keywords into a bitflag set.
///
/// An empty or `"-"` string yields zero flags. Unknown keywords produce
/// `Err(PolicyError::UnknownFlag)` when `graceful` is `false`, or are skipped
/// when `graceful` is `true`.
pub fn partition_policy_flags_from_string(
    s: &str,
    graceful: bool,
) -> Result<PartitionPolicyFlags, PolicyError> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return Ok(PartitionPolicyFlags::empty());
    }

    let mut flags = PartitionPolicyFlags::empty();
    for word in s.split('+') {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }
        match policy_flag_from_string_one(word) {
            Some(f) => flags |= f,
            None if graceful => continue,
            None => return Err(PolicyError::UnknownFlag),
        }
    }
    Ok(flags)
}

// ── Flag manipulation ───────────────────────────────────────────────────────

/// Extend flags: fill in unspecified fields with "all options allowed".
pub fn partition_policy_flags_extend(flags: PartitionPolicyFlags) -> PartitionPolicyFlags {
    let mut f = flags;
    if f.intersects(PartitionPolicyFlags::_USE_MASK) == false {
        f |= PartitionPolicyFlags::OPEN;
    }
    if f.intersects(PartitionPolicyFlags::_READ_ONLY_MASK) == false {
        f |= PartitionPolicyFlags::READ_ONLY_ON | PartitionPolicyFlags::READ_ONLY_OFF;
    }
    if f.intersects(PartitionPolicyFlags::_GROWFS_MASK) == false {
        f |= PartitionPolicyFlags::GROWFS_ON | PartitionPolicyFlags::GROWFS_OFF;
    }
    f
}

/// Reduce flags: if all options are set for a field, clear them to shorten.
pub fn partition_policy_flags_reduce(flags: PartitionPolicyFlags) -> PartitionPolicyFlags {
    let mut f = flags;
    if f.intersects(PartitionPolicyFlags::_USE_MASK) == true
        && f.contains(PartitionPolicyFlags::_USE_MASK)
    {
        f.remove(PartitionPolicyFlags::_USE_MASK);
    }
    if f.contains(PartitionPolicyFlags::_READ_ONLY_MASK) {
        f.remove(PartitionPolicyFlags::_READ_ONLY_MASK);
    }
    if f.contains(PartitionPolicyFlags::_GROWFS_MASK) {
        f.remove(PartitionPolicyFlags::_GROWFS_MASK);
    }
    f
}

/// Check if any flag field is left unspecified.
pub fn partition_policy_flags_has_unspecified(flags: PartitionPolicyFlags) -> bool {
    !flags.intersects(PartitionPolicyFlags::_USE_MASK)
}

/// Normalize flags for a specific partition designator.
///
/// Extends unspecified fields and masks off flags that don't apply
/// (e.g. verity flags on verity partitions themselves).
pub fn partition_policy_normalized_flags(
    designator: PartitionDesignator,
    flags: PartitionPolicyFlags,
) -> PartitionPolicyFlags {
    let mut f = partition_policy_flags_extend(flags);

    // Verity/signature partitions don't need protection themselves
    if designator.verity_hash_to_data().is_some() || designator.verity_sig_to_data().is_some() {
        f.remove(
            PartitionPolicyFlags::VERITY
                | PartitionPolicyFlags::SIGNED
                | PartitionPolicyFlags::ENCRYPTED
                | PartitionPolicyFlags::ENCRYPTED_WITH_INTEGRITY
                | PartitionPolicyFlags::UNPROTECTED,
        );
    }

    // Partitions without a verity concept: strip verity flags
    if designator.verity_hash_of().is_none() {
        f.remove(PartitionPolicyFlags::VERITY | PartitionPolicyFlags::SIGNED);
    }

    // If the partition must be absent, GPT flags don't matter
    let use_bits = f & PartitionPolicyFlags::_USE_MASK;
    if use_bits == PartitionPolicyFlags::ABSENT {
        f.remove(PartitionPolicyFlags::_READ_ONLY_MASK | PartitionPolicyFlags::_GROWFS_MASK);
    }

    f
}

/// Check if two flags are equivalent after extension.
pub fn partition_policy_flags_extended_equal(
    a: PartitionPolicyFlags,
    b: PartitionPolicyFlags,
) -> bool {
    partition_policy_flags_extend(a) == partition_policy_flags_extend(b)
}

// ── Policy lookup ───────────────────────────────────────────────────────────

/// Look up the effective policy flags for a designator.
///
/// Returns `None` if no policy covers this designator (and no default can be
/// derived). `None` policy means "everything allowed".
pub fn image_policy_get(
    policy: &Option<ImagePolicy>,
    designator: PartitionDesignator,
) -> Option<PartitionPolicyFlags> {
    // No policy → everything allowed
    let pol = match policy {
        None => {
            return Some(partition_policy_normalized_flags(
                designator,
                PartitionPolicyFlags::OPEN,
            ))
        }
        Some(p) => p,
    };

    // Direct lookup
    if let Some(pp) = pol.find(designator) {
        return Some(partition_policy_normalized_flags(designator, pp.flags));
    }

    // Derive from data partition for verity hash
    if let Some(data) = designator.verity_hash_to_data() {
        let data_flags = image_policy_get(policy, data)?;
        // Verity or signed must be requested on the data partition
        if !data_flags.intersects(PartitionPolicyFlags::SIGNED | PartitionPolicyFlags::VERITY) {
            return None;
        }
        let inherited = PartitionPolicyFlags::UNPROTECTED
            | (data_flags & (PartitionPolicyFlags::UNUSED | PartitionPolicyFlags::ABSENT))
            | (data_flags & PartitionPolicyFlags::_PFLAGS_MASK);
        return Some(partition_policy_normalized_flags(designator, inherited));
    }

    // Derive from data partition for verity signature
    if let Some(data) = designator.verity_sig_to_data() {
        let data_flags = image_policy_get(policy, data)?;
        if !data_flags.intersects(PartitionPolicyFlags::SIGNED) {
            return None;
        }
        let inherited = PartitionPolicyFlags::UNPROTECTED
            | (data_flags & (PartitionPolicyFlags::UNUSED | PartitionPolicyFlags::ABSENT))
            | (data_flags & PartitionPolicyFlags::_PFLAGS_MASK);
        return Some(partition_policy_normalized_flags(designator, inherited));
    }

    Some(partition_policy_normalized_flags(
        designator,
        pol.default_flags,
    ))
}

/// Like [`image_policy_get`] but falls back to the policy's default flags.
pub fn image_policy_get_exhaustively(
    policy: &Option<ImagePolicy>,
    designator: PartitionDesignator,
) -> PartitionPolicyFlags {
    match image_policy_get(policy, designator) {
        Some(f) => f,
        None => {
            let default = match policy {
                None => PartitionPolicyFlags::OPEN,
                Some(p) => p.default_flags,
            };
            partition_policy_normalized_flags(designator, default)
        }
    }
}

// ── Policy parsing ──────────────────────────────────────────────────────────

/// Parse an image policy string.
///
/// Accepts the symbolic forms `"-"`, `"*"`, `"~"` or explicit
/// `designator=flags` colon-separated entries.
pub fn image_policy_from_string(s: &str, graceful: bool) -> Result<ImagePolicy, PolicyError> {
    let s = s.trim();

    // Symbolic shortcuts
    let sym = match s {
        "" | "-" => Some(PartitionPolicyFlags::IGNORE),
        "*" => Some(PartitionPolicyFlags::OPEN),
        "~" => Some(PartitionPolicyFlags::ABSENT),
        _ => None,
    };
    if let Some(default) = sym {
        return Ok(ImagePolicy::new(default));
    }

    let mut policy = ImagePolicy::new(PartitionPolicyFlags::IGNORE);
    let mut seen = [false; PartitionDesignator::MAX];
    let mut default_specified = false;

    for entry in s.split(':') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let (designator_name, flags_str) = match entry.split_once('=') {
            Some((d, f)) => (d.trim(), f.trim()),
            None => return Err(PolicyError::Invalid),
        };

        if designator_name.is_empty() {
            // Default policy
            if default_specified {
                return Err(PolicyError::Duplicate);
            }
            default_specified = true;
            let default_flags = partition_policy_flags_from_string(flags_str, graceful)?;
            policy.default_flags = if default_flags.is_empty() {
                PartitionPolicyFlags::IGNORE
            } else {
                default_flags
            };
        } else {
            let designator = match PartitionDesignator::from_name(designator_name) {
                Some(d) => d,
                None => {
                    if graceful {
                        continue;
                    }
                    return Err(PolicyError::UnknownDesignator);
                }
            };
            let idx = designator as usize;
            if seen[idx] {
                return Err(PolicyError::Duplicate);
            }
            seen[idx] = true;
            let flags = partition_policy_flags_from_string(flags_str, graceful)?;
            policy.policies.push(PartitionPolicy { designator, flags });
        }
    }

    // Sort by designator for binary search
    policy.policies.sort_by_key(|p| p.designator);
    Ok(policy)
}

// ── Policy serialization ────────────────────────────────────────────────────

/// Serialize partition policy flags to a `+`-separated string.
///
/// When `simplify` is true, `"open"` and `"ignore"` shortcuts are used and
/// don't-care GPT flags are suppressed.
pub fn partition_policy_flags_to_string(flags: PartitionPolicyFlags, simplify: bool) -> String {
    let mut parts: Vec<&'static str> = Vec::new();

    let use_bits = flags & PartitionPolicyFlags::_USE_MASK;

    if simplify && use_bits == PartitionPolicyFlags::OPEN {
        parts.push("open");
    } else if simplify && use_bits == PartitionPolicyFlags::IGNORE {
        parts.push("ignore");
    } else {
        if flags.contains(PartitionPolicyFlags::VERITY) {
            parts.push("verity");
        }
        if flags.contains(PartitionPolicyFlags::SIGNED) {
            parts.push("signed");
        }
        if flags.contains(PartitionPolicyFlags::ENCRYPTED) {
            parts.push("encrypted");
        }
        if flags.contains(PartitionPolicyFlags::ENCRYPTED_WITH_INTEGRITY) {
            parts.push("encryptedwithintegrity");
        }
        if flags.contains(PartitionPolicyFlags::UNPROTECTED) {
            parts.push("unprotected");
        }
        if flags.contains(PartitionPolicyFlags::UNUSED) {
            parts.push("unused");
        }
        if flags.contains(PartitionPolicyFlags::ABSENT) {
            parts.push("absent");
        }
    }

    // Read-only: show when not both set (or not simplifying)
    let ro_on = flags.contains(PartitionPolicyFlags::READ_ONLY_ON);
    let ro_off = flags.contains(PartitionPolicyFlags::READ_ONLY_OFF);
    if !simplify || ro_on != ro_off {
        if ro_on {
            parts.push("read-only-on");
        }
        if ro_off {
            parts.push("read-only-off");
        }
    }

    // Growfs: show when not both set (or not simplifying)
    let grow_on = flags.contains(PartitionPolicyFlags::GROWFS_ON);
    let grow_off = flags.contains(PartitionPolicyFlags::GROWFS_OFF);
    if !simplify || grow_on != grow_off {
        if grow_off {
            parts.push("growfs-off");
        }
        if grow_on {
            parts.push("growfs-on");
        }
    }

    // Filesystem type flags
    if flags.contains(PartitionPolicyFlags::BTRFS) {
        parts.push("btrfs");
    }
    if flags.contains(PartitionPolicyFlags::EROFS) {
        parts.push("erofs");
    }
    if flags.contains(PartitionPolicyFlags::EXT4) {
        parts.push("ext4");
    }
    if flags.contains(PartitionPolicyFlags::F2FS) {
        parts.push("f2fs");
    }
    if flags.contains(PartitionPolicyFlags::SQUASHFS) {
        parts.push("squashfs");
    }
    if flags.contains(PartitionPolicyFlags::VFAT) {
        parts.push("vfat");
    }
    if flags.contains(PartitionPolicyFlags::XFS) {
        parts.push("xfs");
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("+")
    }
}

/// Serialize an image policy to a string.
///
/// When `simplify` is true, the symbolic forms `"*"`, `"-"`, `"~"` are used
/// when the policy is equivalent to one of them, and entries matching the
/// default are omitted.
pub fn image_policy_to_string(policy: &ImagePolicy, simplify: bool) -> String {
    if simplify {
        if image_policy_equiv_allow(policy) {
            return "*".to_string();
        }
        if image_policy_equiv_ignore(policy) {
            return "-".to_string();
        }
        if image_policy_equiv_deny(policy) {
            return "~".to_string();
        }
    }

    let mut entries: Vec<String> = Vec::new();

    for pp in &policy.policies {
        if simplify {
            let default_normalized =
                partition_policy_normalized_flags(pp.designator, policy.default_flags);
            if default_normalized == pp.flags {
                continue;
            }
        }
        let flags_str = partition_policy_flags_to_string(pp.flags, simplify);
        entries.push(format!("{}={}", pp.designator.to_name(), flags_str));
    }

    // Append default unless it equals ignore (and we're simplifying)
    if !simplify
        || !partition_policy_flags_extended_equal(
            policy.default_flags,
            PartitionPolicyFlags::IGNORE,
        )
    {
        let default_str = partition_policy_flags_to_string(policy.default_flags, simplify);
        entries.push(format!("={default_str}"));
    }

    if entries.is_empty() {
        "-".to_string()
    } else {
        entries.join(":")
    }
}

// ── Policy equivalence ──────────────────────────────────────────────────────

fn image_policy_flags_all_match(policy: &ImagePolicy, expected: PartitionPolicyFlags) -> bool {
    if !partition_policy_flags_extended_equal(policy.default_flags, expected) {
        return false;
    }
    for d in PartitionDesignator::ALL {
        let f = image_policy_get_exhaustively(&Some(policy.clone()), d);
        let w = partition_policy_normalized_flags(d, expected);
        if f != w {
            return false;
        }
    }
    true
}

/// Check if this policy is equivalent to the ignore policy (`"-"`).
pub fn image_policy_equiv_ignore(policy: &ImagePolicy) -> bool {
    image_policy_flags_all_match(policy, PartitionPolicyFlags::IGNORE)
}

/// Check if this policy is equivalent to the allow policy (`"*"`).
pub fn image_policy_equiv_allow(policy: &ImagePolicy) -> bool {
    image_policy_flags_all_match(policy, PartitionPolicyFlags::OPEN)
}

/// Check if this policy is equivalent to the deny policy (`"~"`).
pub fn image_policy_equiv_deny(policy: &ImagePolicy) -> bool {
    image_policy_flags_all_match(policy, PartitionPolicyFlags::ABSENT)
}

/// Check if two policies are defined identically (byte-for-byte same rules).
pub fn image_policy_equal(a: &ImagePolicy, b: &ImagePolicy) -> bool {
    a == b
}

/// Check if two policies produce the same outcome for every designator.
pub fn image_policy_equivalent(a: &ImagePolicy, b: &ImagePolicy) -> bool {
    if !partition_policy_flags_extended_equal(a.default_flags, b.default_flags) {
        return false;
    }
    for d in PartitionDesignator::ALL {
        let fa = image_policy_get_exhaustively(&Some(a.clone()), d);
        let fb = image_policy_get_exhaustively(&Some(b.clone()), d);
        if fa != fb {
            return false;
        }
    }
    true
}

// ── Policy intersection / union ─────────────────────────────────────────────

fn policy_flags_or(a: PartitionPolicyFlags, b: PartitionPolicyFlags) -> PartitionPolicyFlags {
    a | b
}

fn policy_flags_and(a: PartitionPolicyFlags, b: PartitionPolicyFlags) -> PartitionPolicyFlags {
    a & b
}

fn policy_intersect_or_union(
    a: &ImagePolicy,
    b: &ImagePolicy,
    op: fn(PartitionPolicyFlags, PartitionPolicyFlags) -> PartitionPolicyFlags,
) -> Result<ImagePolicy, PolicyError> {
    let mut result = ImagePolicy::new(PartitionPolicyFlags::empty());

    let default = op(
        partition_policy_flags_extend(a.default_flags),
        partition_policy_flags_extend(b.default_flags),
    );

    if partition_policy_flags_has_unspecified(default) {
        return Err(PolicyError::Unavailable);
    }
    result.default_flags = partition_policy_flags_reduce(default);

    for d in PartitionDesignator::ALL {
        let a_has = a.find(d).is_some();
        let b_has = b.find(d).is_some();
        if !a_has && !b_has {
            continue;
        }

        let x = image_policy_get_exhaustively(&Some(a.clone()), d);
        let y = image_policy_get_exhaustively(&Some(b.clone()), d);
        let z = op(x, y);

        if z != PartitionPolicyFlags::ABSENT && partition_policy_flags_has_unspecified(z) {
            return Err(PolicyError::Unavailable);
        }

        let df = partition_policy_normalized_flags(d, result.default_flags);
        if df == z {
            continue;
        }

        let z_reduced = partition_policy_flags_reduce(z);
        result.policies.push(PartitionPolicy {
            designator: d,
            flags: z_reduced,
        });
    }

    result.policies.sort_by_key(|p| p.designator);
    Ok(result)
}

/// Compute the intersection of two policies (what both permit).
pub fn image_policy_intersect(
    a: &ImagePolicy,
    b: &ImagePolicy,
) -> Result<ImagePolicy, PolicyError> {
    policy_intersect_or_union(a, b, policy_flags_and)
}

/// Compute the union of two policies (what either permits).
pub fn image_policy_union(a: &ImagePolicy, b: &ImagePolicy) -> Result<ImagePolicy, PolicyError> {
    policy_intersect_or_union(a, b, policy_flags_or)
}

// ── Ignore designators ──────────────────────────────────────────────────────

/// Return a copy of the policy with the specified designators replaced by ignore.
pub fn image_policy_ignore_designators(
    policy: &ImagePolicy,
    designators: &[PartitionDesignator],
) -> ImagePolicy {
    let mut result = ImagePolicy::new(policy.default_flags);

    // Insert ignore entries for the specified designators
    for &d in designators {
        if result.find(d).is_none() {
            result.policies.push(PartitionPolicy {
                designator: d,
                flags: PartitionPolicyFlags::IGNORE,
            });
            result.policies.sort_by_key(|p| p.designator);
        }
    }

    // Copy non-ignored entries from the original policy
    for pp in &policy.policies {
        if result.find(pp.designator).is_none() {
            result.policies.push(pp.clone());
            result.policies.sort_by_key(|p| p.designator);
        }
    }

    result
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_designator_from_name_roundtrip() {
        for d in PartitionDesignator::ALL {
            assert_eq!(PartitionDesignator::from_name(d.to_name()), Some(d));
        }
    }

    #[test]
    fn test_designator_from_name_unknown() {
        assert_eq!(PartitionDesignator::from_name("bogus"), None);
        assert_eq!(PartitionDesignator::from_name(""), None);
    }

    #[test]
    fn test_policy_flag_from_string_one() {
        assert_eq!(
            policy_flag_from_string_one("verity"),
            Some(PartitionPolicyFlags::VERITY)
        );
        assert_eq!(
            policy_flag_from_string_one("signed"),
            Some(PartitionPolicyFlags::SIGNED)
        );
        assert_eq!(
            policy_flag_from_string_one("encrypted"),
            Some(PartitionPolicyFlags::ENCRYPTED)
        );
        assert_eq!(
            policy_flag_from_string_one("encryptedwithintegrity"),
            Some(PartitionPolicyFlags::ENCRYPTED_WITH_INTEGRITY)
        );
        assert_eq!(
            policy_flag_from_string_one("unprotected"),
            Some(PartitionPolicyFlags::UNPROTECTED)
        );
        assert_eq!(
            policy_flag_from_string_one("unused"),
            Some(PartitionPolicyFlags::UNUSED)
        );
        assert_eq!(
            policy_flag_from_string_one("absent"),
            Some(PartitionPolicyFlags::ABSENT)
        );
        assert_eq!(
            policy_flag_from_string_one("open"),
            Some(PartitionPolicyFlags::OPEN)
        );
        assert_eq!(
            policy_flag_from_string_one("ignore"),
            Some(PartitionPolicyFlags::IGNORE)
        );
        assert_eq!(policy_flag_from_string_one("bogus"), None);
    }

    #[test]
    fn test_policy_flag_from_fstype() {
        assert_eq!(
            policy_flag_from_fstype("btrfs"),
            Some(PartitionPolicyFlags::BTRFS)
        );
        assert_eq!(
            policy_flag_from_fstype("ext4"),
            Some(PartitionPolicyFlags::EXT4)
        );
        assert_eq!(
            policy_flag_from_fstype("xfs"),
            Some(PartitionPolicyFlags::XFS)
        );
        assert_eq!(policy_flag_from_fstype("zfs"), None);
    }

    #[test]
    fn test_partition_policy_flags_from_string_basic() {
        let f = partition_policy_flags_from_string("verity+signed", false).unwrap();
        assert!(f.contains(PartitionPolicyFlags::VERITY));
        assert!(f.contains(PartitionPolicyFlags::SIGNED));
        assert!(!f.contains(PartitionPolicyFlags::ENCRYPTED));
    }

    #[test]
    fn test_partition_policy_flags_from_string_empty() {
        assert_eq!(
            partition_policy_flags_from_string("", false).unwrap(),
            PartitionPolicyFlags::empty()
        );
        assert_eq!(
            partition_policy_flags_from_string("-", false).unwrap(),
            PartitionPolicyFlags::empty()
        );
    }

    #[test]
    fn test_partition_policy_flags_from_string_graceful() {
        let f = partition_policy_flags_from_string("verity+bogus", true).unwrap();
        assert!(f.contains(PartitionPolicyFlags::VERITY));
        // "bogus" silently ignored in graceful mode
    }

    #[test]
    fn test_partition_policy_flags_from_string_strict_unknown() {
        let result = partition_policy_flags_from_string("verity+bogus", false);
        assert_eq!(result.unwrap_err(), PolicyError::UnknownFlag);
    }

    #[test]
    fn test_partition_policy_flags_extend_reduce() {
        let empty = PartitionPolicyFlags::empty();
        let extended = partition_policy_flags_extend(empty);
        assert!(extended.contains(PartitionPolicyFlags::_USE_MASK));
        assert!(extended.contains(PartitionPolicyFlags::_READ_ONLY_MASK));
        assert!(extended.contains(PartitionPolicyFlags::_GROWFS_MASK));

        // Reduce should bring it back to empty
        let reduced = partition_policy_flags_reduce(extended);
        assert!(!reduced.intersects(PartitionPolicyFlags::_USE_MASK));
        assert!(!reduced.intersects(PartitionPolicyFlags::_READ_ONLY_MASK));
        assert!(!reduced.intersects(PartitionPolicyFlags::_GROWFS_MASK));
    }

    #[test]
    fn test_partition_policy_flags_has_unspecified() {
        assert!(partition_policy_flags_has_unspecified(
            PartitionPolicyFlags::empty()
        ));
        assert!(!partition_policy_flags_has_unspecified(
            partition_policy_flags_extend(PartitionPolicyFlags::empty())
        ));
        assert!(!partition_policy_flags_has_unspecified(
            PartitionPolicyFlags::OPEN
        ));
    }

    #[test]
    fn test_image_policy_from_string_symbolic() {
        let p = image_policy_from_string("-", false).unwrap();
        assert_eq!(p.default_flags, PartitionPolicyFlags::IGNORE);
        assert!(p.policies.is_empty());

        let p = image_policy_from_string("*", false).unwrap();
        assert_eq!(p.default_flags, PartitionPolicyFlags::OPEN);

        let p = image_policy_from_string("~", false).unwrap();
        assert_eq!(p.default_flags, PartitionPolicyFlags::ABSENT);
    }

    #[test]
    fn test_image_policy_from_string_explicit() {
        let p = image_policy_from_string("root=verity+signed:usr=absent:=-", false).unwrap();
        assert_eq!(p.default_flags, PartitionPolicyFlags::IGNORE);
        assert_eq!(p.policies.len(), 2);
        assert_eq!(p.policies[0].designator, PartitionDesignator::Root);
        assert!(p.policies[0].flags.contains(PartitionPolicyFlags::VERITY));
        assert!(p.policies[0].flags.contains(PartitionPolicyFlags::SIGNED));
        assert_eq!(p.policies[1].designator, PartitionDesignator::Usr);
        assert!(p.policies[1].flags.contains(PartitionPolicyFlags::ABSENT));
    }

    #[test]
    fn test_image_policy_from_string_duplicate() {
        let result = image_policy_from_string("root=verity:root=absent", false);
        assert_eq!(result.unwrap_err(), PolicyError::Duplicate);
    }

    #[test]
    fn test_image_policy_from_string_duplicate_default() {
        let result = image_policy_from_string("=absent:=verity", false);
        assert_eq!(result.unwrap_err(), PolicyError::Duplicate);
    }

    #[test]
    fn test_image_policy_from_string_unknown_designator() {
        let result = image_policy_from_string("bogus=verity", false);
        assert_eq!(result.unwrap_err(), PolicyError::UnknownDesignator);
    }

    #[test]
    fn test_image_policy_from_string_unknown_designator_graceful() {
        let p = image_policy_from_string("bogus=verity:root=absent", true).unwrap();
        assert_eq!(p.policies.len(), 1);
        assert_eq!(p.policies[0].designator, PartitionDesignator::Root);
    }

    #[test]
    fn test_image_policy_from_string_empty_string_is_ignore() {
        let p = image_policy_from_string("", false).unwrap();
        assert_eq!(p.default_flags, PartitionPolicyFlags::IGNORE);
    }

    #[test]
    fn test_partition_policy_flags_to_string_basic() {
        let flags = PartitionPolicyFlags::VERITY | PartitionPolicyFlags::SIGNED;
        let s = partition_policy_flags_to_string(flags, false);
        assert_eq!(s, "verity+signed");
    }

    #[test]
    fn test_partition_policy_flags_to_string_empty() {
        let s = partition_policy_flags_to_string(PartitionPolicyFlags::empty(), false);
        assert_eq!(s, "-");
    }

    #[test]
    fn test_partition_policy_flags_to_string_simplify_open() {
        let all = partition_policy_flags_extend(PartitionPolicyFlags::empty());
        let s = partition_policy_flags_to_string(all, true);
        assert_eq!(s, "open");
    }

    #[test]
    fn test_partition_policy_flags_to_string_simplify_ignore() {
        let s = partition_policy_flags_to_string(PartitionPolicyFlags::IGNORE, true);
        assert_eq!(s, "ignore");
    }

    #[test]
    fn test_partition_policy_flags_to_string_fstype() {
        let flags = PartitionPolicyFlags::BTRFS | PartitionPolicyFlags::EXT4;
        let s = partition_policy_flags_to_string(flags, false);
        assert_eq!(s, "btrfs+ext4");
    }

    #[test]
    fn test_partition_policy_flags_to_string_gpt_flags() {
        let flags = PartitionPolicyFlags::OPEN
            | PartitionPolicyFlags::READ_ONLY_ON
            | PartitionPolicyFlags::GROWFS_OFF;
        let s = partition_policy_flags_to_string(flags, false);
        assert!(s.contains("read-only-on"));
        assert!(s.contains("growfs-off"));
    }

    #[test]
    fn test_partition_policy_flags_to_string_simplify_suppresses_both_gpt() {
        // When both read-only flags are set, simplify suppresses them
        let flags = PartitionPolicyFlags::OPEN
            | PartitionPolicyFlags::READ_ONLY_ON
            | PartitionPolicyFlags::READ_ONLY_OFF;
        let s = partition_policy_flags_to_string(flags, true);
        assert_eq!(s, "open");
        assert!(!s.contains("read-only"));
    }

    #[test]
    fn test_image_policy_to_string_symbolic() {
        assert_eq!(image_policy_to_string(&ImagePolicy::allow(), true), "*");
        assert_eq!(image_policy_to_string(&ImagePolicy::ignore(), true), "-");
        assert_eq!(image_policy_to_string(&ImagePolicy::deny(), true), "~");
    }

    #[test]
    fn test_image_policy_to_string_explicit_roundtrip() {
        let original = "root=verity+signed:usr=absent:=-";
        let p = image_policy_from_string(original, false).unwrap();
        let s = image_policy_to_string(&p, false);
        let p2 = image_policy_from_string(&s, false).unwrap();
        assert!(image_policy_equal(&p, &p2));
    }

    #[test]
    fn test_image_policy_equiv_ignore() {
        assert!(image_policy_equiv_ignore(&ImagePolicy::ignore()));
        assert!(image_policy_equiv_ignore(
            &image_policy_from_string("-", false).unwrap()
        ));
        assert!(!image_policy_equiv_ignore(&ImagePolicy::allow()));
    }

    #[test]
    fn test_image_policy_equiv_allow() {
        assert!(image_policy_equiv_allow(&ImagePolicy::allow()));
        assert!(image_policy_equiv_allow(
            &image_policy_from_string("*", false).unwrap()
        ));
        assert!(!image_policy_equiv_allow(&ImagePolicy::deny()));
    }

    #[test]
    fn test_image_policy_equiv_deny() {
        assert!(image_policy_equiv_deny(&ImagePolicy::deny()));
        assert!(image_policy_equiv_deny(
            &image_policy_from_string("~", false).unwrap()
        ));
        assert!(!image_policy_equiv_deny(&ImagePolicy::allow()));
    }

    #[test]
    fn test_image_policy_equal() {
        let a = image_policy_from_string("root=verity+signed", false).unwrap();
        let b = image_policy_from_string("root=verity+signed", false).unwrap();
        assert!(image_policy_equal(&a, &b));

        let c = image_policy_from_string("root=verity", false).unwrap();
        assert!(!image_policy_equal(&a, &c));
    }

    #[test]
    fn test_image_policy_equivalent() {
        // A policy with root=ignore and default=ignore should be equivalent to just ignore
        let a = image_policy_from_string("root=ignore:=-", false).unwrap();
        let b = ImagePolicy::ignore();
        assert!(image_policy_equivalent(&a, &b));
    }

    #[test]
    fn test_image_policy_intersect() {
        let a = image_policy_from_string("root=verity+signed+absent", false).unwrap();
        let b = image_policy_from_string("root=verity+unprotected+absent", false).unwrap();
        let i = image_policy_intersect(&a, &b).unwrap();
        // Intersection should allow verity + absent for root
        let root_flags = i.find(PartitionDesignator::Root).unwrap();
        assert!(root_flags.flags.contains(PartitionPolicyFlags::VERITY));
        assert!(root_flags.flags.contains(PartitionPolicyFlags::ABSENT));
        assert!(!root_flags.flags.contains(PartitionPolicyFlags::SIGNED));
        assert!(!root_flags.flags.contains(PartitionPolicyFlags::UNPROTECTED));
    }

    #[test]
    fn test_image_policy_union() {
        let a = image_policy_from_string("root=verity", false).unwrap();
        let b = image_policy_from_string("root=signed", false).unwrap();
        let u = image_policy_union(&a, &b).unwrap();
        let root_flags = u.find(PartitionDesignator::Root).unwrap();
        assert!(root_flags.flags.contains(PartitionPolicyFlags::VERITY));
        assert!(root_flags.flags.contains(PartitionPolicyFlags::SIGNED));
    }

    #[test]
    fn test_image_policy_get_none_policy_allows_everything() {
        let flags = image_policy_get(&None, PartitionDesignator::Root).unwrap();
        // No policy means open
        assert!(flags.contains(PartitionPolicyFlags::VERITY));
        assert!(flags.contains(PartitionPolicyFlags::SIGNED));
        assert!(flags.contains(PartitionPolicyFlags::UNPROTECTED));
    }

    #[test]
    fn test_image_policy_get_deny_all() {
        let policy = ImagePolicy::deny();
        let flags = image_policy_get(&Some(policy), PartitionDesignator::Root).unwrap();
        assert!(flags.contains(PartitionPolicyFlags::ABSENT));
        assert!(!flags.contains(PartitionPolicyFlags::UNPROTECTED));
    }

    #[test]
    fn test_image_policy_ignore_designators() {
        let policy = image_policy_from_string("root=verity:usr=absent", false).unwrap();
        let patched = image_policy_ignore_designators(&policy, &[PartitionDesignator::Root]);
        // Root should now be ignore
        let root = patched.find(PartitionDesignator::Root).unwrap();
        assert!(root.flags.contains(PartitionPolicyFlags::IGNORE));
        // Usr should still be absent
        let usr = patched.find(PartitionDesignator::Usr).unwrap();
        assert!(usr.flags.contains(PartitionPolicyFlags::ABSENT));
    }

    #[test]
    fn test_partition_policy_normalized_flags_verity_partition() {
        // Verity partitions should not have protection flags
        let flags = PartitionPolicyFlags::VERITY
            | PartitionPolicyFlags::ENCRYPTED
            | PartitionPolicyFlags::UNPROTECTED;
        let normalized = partition_policy_normalized_flags(PartitionDesignator::RootVerity, flags);
        assert!(!normalized.contains(PartitionPolicyFlags::VERITY));
        assert!(!normalized.contains(PartitionPolicyFlags::ENCRYPTED));
        assert!(!normalized.contains(PartitionPolicyFlags::UNPROTECTED));
    }

    #[test]
    fn test_partition_policy_normalized_flags_no_verity_concept() {
        // Home has no verity concept, so verity flags should be stripped
        let flags = PartitionPolicyFlags::VERITY | PartitionPolicyFlags::UNPROTECTED;
        let normalized = partition_policy_normalized_flags(PartitionDesignator::Home, flags);
        assert!(!normalized.contains(PartitionPolicyFlags::VERITY));
        assert!(normalized.contains(PartitionPolicyFlags::UNPROTECTED));
    }

    #[test]
    fn test_partition_policy_normalized_flags_absent_strips_gpt() {
        let flags = PartitionPolicyFlags::ABSENT
            | PartitionPolicyFlags::READ_ONLY_ON
            | PartitionPolicyFlags::GROWFS_ON;
        let normalized = partition_policy_normalized_flags(PartitionDesignator::Root, flags);
        assert!(normalized.contains(PartitionPolicyFlags::ABSENT));
        assert!(!normalized.contains(PartitionPolicyFlags::READ_ONLY_ON));
        assert!(!normalized.contains(PartitionPolicyFlags::GROWFS_ON));
    }

    #[test]
    fn test_designator_verity_helpers() {
        assert_eq!(
            PartitionDesignator::RootVerity.verity_hash_to_data(),
            Some(PartitionDesignator::Root)
        );
        assert_eq!(
            PartitionDesignator::UsrVerity.verity_hash_to_data(),
            Some(PartitionDesignator::Usr)
        );
        assert_eq!(PartitionDesignator::Home.verity_hash_to_data(), None);

        assert_eq!(
            PartitionDesignator::RootVeritySig.verity_sig_to_data(),
            Some(PartitionDesignator::Root)
        );
        assert_eq!(PartitionDesignator::Home.verity_sig_to_data(), None);

        assert_eq!(
            PartitionDesignator::Root.verity_hash_of(),
            Some(PartitionDesignator::RootVerity)
        );
        assert_eq!(PartitionDesignator::Home.verity_hash_of(), None);
    }

    #[test]
    fn test_image_policy_new_default() {
        let p = ImagePolicy::default();
        assert_eq!(p.default_flags, PartitionPolicyFlags::IGNORE);
        assert!(p.is_empty());
    }

    #[test]
    fn test_image_policy_find() {
        let p = image_policy_from_string("root=verity:usr=absent:var=encrypted", false).unwrap();
        assert!(p.find(PartitionDesignator::Root).is_some());
        assert!(p.find(PartitionDesignator::Usr).is_some());
        assert!(p.find(PartitionDesignator::Var).is_some());
        assert!(p.find(PartitionDesignator::Home).is_none());
    }

    #[test]
    fn test_flags_extended_equal() {
        let a = PartitionPolicyFlags::empty();
        let b = PartitionPolicyFlags::OPEN;
        // After extension both should be the same
        assert!(partition_policy_flags_extended_equal(a, b));
    }
}
