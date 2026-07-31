// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.image-policy; authority=src/shared/image-policy.c,src/shared/image-policy.h

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use crate::ffi::Errno;
use std::ffi::{CStr, CString};
use std::ptr;

const EBADRQC: i32 = 56;
const EBADSLT: i32 = 57;
const ENAVAIL: i32 = 119;

pub const PARTITION_POLICY_VERITY: i32 = 1 << 0;
pub const PARTITION_POLICY_SIGNED: i32 = 1 << 1;
pub const PARTITION_POLICY_ENCRYPTED: i32 = 1 << 2;
pub const PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY: i32 = 1 << 3;
pub const PARTITION_POLICY_UNPROTECTED: i32 = 1 << 4;
pub const PARTITION_POLICY_UNUSED: i32 = 1 << 5;
pub const PARTITION_POLICY_ABSENT: i32 = 1 << 6;
pub const PARTITION_POLICY_OPEN: i32 = PARTITION_POLICY_VERITY
    | PARTITION_POLICY_SIGNED
    | PARTITION_POLICY_ENCRYPTED
    | PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY
    | PARTITION_POLICY_UNPROTECTED
    | PARTITION_POLICY_UNUSED
    | PARTITION_POLICY_ABSENT;
pub const PARTITION_POLICY_IGNORE: i32 = PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT;

pub const PARTITION_POLICY_READ_ONLY_OFF: i32 = 1 << 7;
pub const PARTITION_POLICY_READ_ONLY_ON: i32 = 1 << 8;
pub const PARTITION_POLICY_GROWFS_OFF: i32 = 1 << 9;
pub const PARTITION_POLICY_GROWFS_ON: i32 = 1 << 10;
pub const PARTITION_POLICY_BTRFS: i32 = 1 << 11;
pub const PARTITION_POLICY_EROFS: i32 = 1 << 12;
pub const PARTITION_POLICY_EXT4: i32 = 1 << 13;
pub const PARTITION_POLICY_F2FS: i32 = 1 << 14;
pub const PARTITION_POLICY_SQUASHFS: i32 = 1 << 15;
pub const PARTITION_POLICY_VFAT: i32 = 1 << 16;
pub const PARTITION_POLICY_XFS: i32 = 1 << 17;

const USE_MASK: i32 = PARTITION_POLICY_OPEN;
const READ_ONLY_MASK: i32 = PARTITION_POLICY_READ_ONLY_OFF | PARTITION_POLICY_READ_ONLY_ON;
const GROWFS_MASK: i32 = PARTITION_POLICY_GROWFS_OFF | PARTITION_POLICY_GROWFS_ON;
const PFLAGS_MASK: i32 = READ_ONLY_MASK | GROWFS_MASK;
const FSTYPE_MASK: i32 = PARTITION_POLICY_BTRFS
    | PARTITION_POLICY_EROFS
    | PARTITION_POLICY_EXT4
    | PARTITION_POLICY_F2FS
    | PARTITION_POLICY_SQUASHFS
    | PARTITION_POLICY_VFAT
    | PARTITION_POLICY_XFS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum PartitionDesignator {
    Root = 0,
    Usr = 1,
    Home = 2,
    Srv = 3,
    Esp = 4,
    Xbootldr = 5,
    Swap = 6,
    RootVerity = 7,
    UsrVerity = 8,
    RootVeritySig = 9,
    UsrVeritySig = 10,
    Tmp = 11,
    Var = 12,
}

impl PartitionDesignator {
    pub const ALL: [Self; 13] = [
        Self::Root,
        Self::Usr,
        Self::Home,
        Self::Srv,
        Self::Esp,
        Self::Xbootldr,
        Self::Swap,
        Self::RootVerity,
        Self::UsrVerity,
        Self::RootVeritySig,
        Self::UsrVeritySig,
        Self::Tmp,
        Self::Var,
    ];

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "root" => Some(Self::Root),
            "usr" => Some(Self::Usr),
            "home" => Some(Self::Home),
            "srv" => Some(Self::Srv),
            "esp" => Some(Self::Esp),
            "xbootldr" => Some(Self::Xbootldr),
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

    fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Root,
            1 => Self::Usr,
            2 => Self::Home,
            3 => Self::Srv,
            4 => Self::Esp,
            5 => Self::Xbootldr,
            6 => Self::Swap,
            7 => Self::RootVerity,
            8 => Self::UsrVerity,
            9 => Self::RootVeritySig,
            10 => Self::UsrVeritySig,
            11 => Self::Tmp,
            12 => Self::Var,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Usr => "usr",
            Self::Home => "home",
            Self::Srv => "srv",
            Self::Esp => "esp",
            Self::Xbootldr => "xbootldr",
            Self::Swap => "swap",
            Self::RootVerity => "root-verity",
            Self::UsrVerity => "usr-verity",
            Self::RootVeritySig => "root-verity-sig",
            Self::UsrVeritySig => "usr-verity-sig",
            Self::Tmp => "tmp",
            Self::Var => "var",
        }
    }

    fn verity_hash_to_data(self) -> Option<Self> {
        match self {
            Self::RootVerity => Some(Self::Root),
            Self::UsrVerity => Some(Self::Usr),
            _ => None,
        }
    }

    fn verity_sig_to_data(self) -> Option<Self> {
        match self {
            Self::RootVeritySig => Some(Self::Root),
            Self::UsrVeritySig => Some(Self::Usr),
            _ => None,
        }
    }

    fn verity_hash_of(self) -> Option<Self> {
        match self {
            Self::Root => Some(Self::RootVerity),
            Self::Usr => Some(Self::UsrVerity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionPolicy {
    pub designator: PartitionDesignator,
    pub flags: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePolicy {
    pub default_flags: i32,
    pub policies: Vec<PartitionPolicy>,
}

/// ABI view of the fixed prefix of C's flexible-array `ImagePolicy`.
///
/// This is intentionally separate from the native, `Vec`-backed
/// [`ImagePolicy`] above. Its layout mirrors the authoritative declaration in
/// `src/shared/image-policy.h`; the `PartitionPolicy policies[]` array starts
/// immediately after this prefix.
#[repr(C)]
pub struct CImagePolicy {
    default_flags: i32,
    n_policies: usize,
}

/// ABI view of C's `PartitionPolicy`.
#[derive(Clone, Copy)]
#[repr(C)]
struct CPartitionPolicy {
    designator: i32,
    flags: i32,
}

impl Default for ImagePolicy {
    fn default() -> Self {
        Self {
            default_flags: PARTITION_POLICY_IGNORE,
            policies: Vec::new(),
        }
    }
}

fn extended_equal(a: i32, b: i32) -> bool {
    partition_policy_flags_extend(a) == partition_policy_flags_extend(b)
}

fn has_unspecified(flags: i32) -> bool {
    (flags & USE_MASK) == 0 || (flags & READ_ONLY_MASK) == 0 || (flags & GROWFS_MASK) == 0
}

fn normalize(policy: PartitionPolicy) -> i32 {
    let mut flags = partition_policy_flags_extend(policy.flags);

    if policy.designator.verity_hash_to_data().is_some()
        || policy.designator.verity_sig_to_data().is_some()
    {
        flags &= !(PARTITION_POLICY_VERITY
            | PARTITION_POLICY_SIGNED
            | PARTITION_POLICY_ENCRYPTED
            | PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY);
    }

    if policy.designator.verity_hash_of().is_none() {
        flags &= !(PARTITION_POLICY_VERITY | PARTITION_POLICY_SIGNED);
    }

    if (flags & USE_MASK) == PARTITION_POLICY_ABSENT {
        flags &= !(READ_ONLY_MASK | GROWFS_MASK);
    }

    flags
}

fn policy_flag_from_fstype(s: &str) -> Result<i32, i32> {
    match s {
        "btrfs" => Ok(PARTITION_POLICY_BTRFS),
        "erofs" => Ok(PARTITION_POLICY_EROFS),
        "ext4" => Ok(PARTITION_POLICY_EXT4),
        "f2fs" => Ok(PARTITION_POLICY_F2FS),
        "squashfs" => Ok(PARTITION_POLICY_SQUASHFS),
        "vfat" => Ok(PARTITION_POLICY_VFAT),
        "xfs" => Ok(PARTITION_POLICY_XFS),
        _ => Err(-56),
    }
}

fn policy_flag_from_string_one(s: &str) -> Result<i32, i32> {
    match s {
        "verity" => Ok(PARTITION_POLICY_VERITY),
        "signed" => Ok(PARTITION_POLICY_SIGNED),
        "encrypted" => Ok(PARTITION_POLICY_ENCRYPTED),
        "encryptedwithintegrity" => Ok(PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY),
        "unprotected" => Ok(PARTITION_POLICY_UNPROTECTED),
        "unused" => Ok(PARTITION_POLICY_UNUSED),
        "absent" => Ok(PARTITION_POLICY_ABSENT),
        "open" => Ok(PARTITION_POLICY_OPEN),
        "ignore" => Ok(PARTITION_POLICY_IGNORE),
        "read-only-on" => Ok(PARTITION_POLICY_READ_ONLY_ON),
        "read-only-off" => Ok(PARTITION_POLICY_READ_ONLY_OFF),
        "growfs-on" => Ok(PARTITION_POLICY_GROWFS_ON),
        "growfs-off" => Ok(PARTITION_POLICY_GROWFS_OFF),
        _ => policy_flag_from_fstype(s),
    }
}

pub fn partition_policy_flags_extend(mut flags: i32) -> i32 {
    if (flags & USE_MASK) == 0 {
        flags |= PARTITION_POLICY_OPEN;
    }
    if (flags & READ_ONLY_MASK) == 0 {
        flags |= PARTITION_POLICY_READ_ONLY_ON | PARTITION_POLICY_READ_ONLY_OFF;
    }
    if (flags & GROWFS_MASK) == 0 {
        flags |= PARTITION_POLICY_GROWFS_ON | PARTITION_POLICY_GROWFS_OFF;
    }
    flags
}

pub fn partition_policy_flags_reduce(mut flags: i32) -> i32 {
    if (flags & USE_MASK) == USE_MASK {
        flags &= !USE_MASK;
    }
    if (flags & READ_ONLY_MASK) == READ_ONLY_MASK {
        flags &= !READ_ONLY_MASK;
    }
    if (flags & GROWFS_MASK) == GROWFS_MASK {
        flags &= !GROWFS_MASK;
    }
    flags
}

pub fn partition_policy_flags_from_string(s: &str, graceful: bool) -> Result<i32, i32> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return Ok(0);
    }

    let mut flags = 0;
    for word in s.split('+').map(str::trim).filter(|word| !word.is_empty()) {
        match policy_flag_from_string_one(word) {
            Ok(value) => flags |= value,
            Err(_) if graceful => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(flags)
}

impl ImagePolicy {
    pub fn image_policy_get(&self, designator: PartitionDesignator) -> Result<i32, i32> {
        if let Some(policy) = self
            .policies
            .iter()
            .find(|policy| policy.designator == designator)
        {
            return Ok(normalize(*policy));
        }

        if let Some(data_designator) = designator.verity_hash_to_data() {
            let data_flags = self.image_policy_get(data_designator)?;
            if (data_flags & (PARTITION_POLICY_SIGNED | PARTITION_POLICY_VERITY)) == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }

            return Ok(normalize(PartitionPolicy {
                designator,
                flags: PARTITION_POLICY_UNPROTECTED
                    | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                    | (data_flags & PFLAGS_MASK),
            }));
        }

        if let Some(data_designator) = designator.verity_sig_to_data() {
            let data_flags = self.image_policy_get(data_designator)?;
            if (data_flags & PARTITION_POLICY_SIGNED) == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }

            return Ok(normalize(PartitionPolicy {
                designator,
                flags: PARTITION_POLICY_UNPROTECTED
                    | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                    | (data_flags & PFLAGS_MASK),
            }));
        }

        Err(Errno::EINVAL.to_neg_errno())
    }
    pub fn image_policy_get_exhaustively(
        &self,
        designator: PartitionDesignator,
    ) -> Result<i32, i32> {
        self.image_policy_get(designator).or_else(|_| {
            Ok(normalize(PartitionPolicy {
                designator,
                flags: self.default_flags,
            }))
        })
    }

    pub fn image_policy_equal(&self, other: &Self) -> bool {
        self == other
    }

    pub fn image_policy_equivalent(&self, other: &Self) -> Result<bool, i32> {
        if !extended_equal(self.default_flags, other.default_flags) {
            return Ok(false);
        }

        for designator in PartitionDesignator::ALL {
            if self.image_policy_get_exhaustively(designator)?
                != other.image_policy_get_exhaustively(designator)?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn image_policy_to_string(&self, simplify: bool) -> Result<String, i32> {
        if simplify {
            if self.image_policy_flags_all_match(PARTITION_POLICY_OPEN)? {
                return Ok("*".into());
            }
            if self.image_policy_flags_all_match(PARTITION_POLICY_IGNORE)? {
                return Ok("-".into());
            }
            if self.image_policy_flags_all_match(PARTITION_POLICY_ABSENT)? {
                return Ok("~".into());
            }
        }

        let mut parts = Vec::new();

        for policy in &self.policies {
            if simplify {
                let df = normalize(PartitionPolicy {
                    designator: policy.designator,
                    flags: self.default_flags,
                });
                if df == policy.flags {
                    continue;
                }
            }

            parts.push(format!(
                "{}={}",
                policy.designator.as_str(),
                partition_policy_flags_to_string(policy.flags, simplify)?
            ));
        }

        if !simplify || !extended_equal(self.default_flags, PARTITION_POLICY_IGNORE) {
            parts.push(format!(
                "={}",
                partition_policy_flags_to_string(self.default_flags, simplify)?
            ));
        }

        if parts.is_empty() {
            Ok("-".into())
        } else {
            Ok(parts.join(":"))
        }
    }

    pub fn image_policy_flags_all_match(&self, expected: i32) -> Result<bool, i32> {
        if !extended_equal(self.default_flags, expected) {
            return Ok(false);
        }

        for designator in PartitionDesignator::ALL {
            if self.image_policy_get_exhaustively(designator)?
                != normalize(PartitionPolicy {
                    designator,
                    flags: expected,
                })
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn image_policy_ignore_designators(&self, designators: &[PartitionDesignator]) -> Self {
        let mut policies = self.policies.clone();
        for designator in designators {
            if let Some(policy) = policies
                .iter_mut()
                .find(|policy| policy.designator == *designator)
            {
                policy.flags = PARTITION_POLICY_IGNORE;
            } else {
                policies.push(PartitionPolicy {
                    designator: *designator,
                    flags: PARTITION_POLICY_IGNORE,
                });
            }
        }
        policies.sort_by_key(|policy| policy.designator);

        Self {
            default_flags: self.default_flags,
            policies,
        }
    }

    pub fn image_policy_intersect(&self, other: &Self) -> Result<Self, i32> {
        policy_intersect_or_union(self, other, |a, b| a & b)
    }

    pub fn image_policy_union(&self, other: &Self) -> Result<Self, i32> {
        policy_intersect_or_union(self, other, |a, b| a | b)
    }
}

pub fn image_policy_from_string(s: &str, graceful: bool) -> Result<ImagePolicy, i32> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return Ok(ImagePolicy::default());
    }
    if s == "*" {
        return Ok(ImagePolicy {
            default_flags: PARTITION_POLICY_OPEN,
            policies: Vec::new(),
        });
    }
    if s == "~" {
        return Ok(ImagePolicy {
            default_flags: PARTITION_POLICY_ABSENT,
            policies: Vec::new(),
        });
    }

    let mut default_specified = false;
    let mut policies = Vec::new();
    let mut mask: u64 = 0;
    let mut default_flags = PARTITION_POLICY_IGNORE;

    for expression in s.split(':').filter(|item| !item.is_empty()) {
        let (designator_text, flag_text) = expression
            .split_once('=')
            .ok_or(Errno::EINVAL.to_neg_errno())?;

        let designator_text = designator_text.trim();
        let flag_text = flag_text.trim();
        let flags = partition_policy_flags_from_string(flag_text, graceful)?;

        if designator_text.is_empty() {
            if default_specified {
                return Err(-76);
            }
            default_specified = true;
            default_flags = flags;
            continue;
        }

        let Some(designator) = PartitionDesignator::from_str(designator_text) else {
            if graceful {
                continue;
            }
            return Err(-EBADSLT);
        };

        let bit = 1u64 << (designator as u64);
        if (mask & bit) != 0 {
            return Err(Errno::ENOTUNIQ.to_neg_errno());
        }
        mask |= bit;

        policies.push(PartitionPolicy { designator, flags });
    }

    policies.sort_by_key(|policy| policy.designator);
    Ok(ImagePolicy {
        default_flags,
        policies,
    })
}

pub fn partition_policy_flags_to_string(flags: i32, simplify: bool) -> Result<String, i32> {
    if flags < 0 {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let mut parts = Vec::new();

    if simplify && (flags & USE_MASK) == PARTITION_POLICY_OPEN {
        parts.push("open");
    } else if simplify && (flags & USE_MASK) == PARTITION_POLICY_IGNORE {
        parts.push("ignore");
    } else {
        if (flags & PARTITION_POLICY_VERITY) != 0 {
            parts.push("verity");
        }
        if (flags & PARTITION_POLICY_SIGNED) != 0 {
            parts.push("signed");
        }
        if (flags & PARTITION_POLICY_ENCRYPTED) != 0 {
            parts.push("encrypted");
        }
        if (flags & PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY) != 0 {
            parts.push("encryptedwithintegrity");
        }
        if (flags & PARTITION_POLICY_UNPROTECTED) != 0 {
            parts.push("unprotected");
        }
        if (flags & PARTITION_POLICY_UNUSED) != 0 {
            parts.push("unused");
        }
        if (flags & PARTITION_POLICY_ABSENT) != 0 {
            parts.push("absent");
        }
    }

    if !simplify
        || ((flags & PARTITION_POLICY_READ_ONLY_ON) == 0)
            != ((flags & PARTITION_POLICY_READ_ONLY_OFF) == 0)
    {
        if (flags & PARTITION_POLICY_READ_ONLY_ON) != 0 {
            parts.push("read-only-on");
        }
        if (flags & PARTITION_POLICY_READ_ONLY_OFF) != 0 {
            parts.push("read-only-off");
        }
    }

    if !simplify
        || ((flags & PARTITION_POLICY_GROWFS_ON) == 0)
            != ((flags & PARTITION_POLICY_GROWFS_OFF) == 0)
    {
        if (flags & PARTITION_POLICY_GROWFS_OFF) != 0 {
            parts.push("growfs-off");
        }
        if (flags & PARTITION_POLICY_GROWFS_ON) != 0 {
            parts.push("growfs-on");
        }
    }

    if (flags & PARTITION_POLICY_BTRFS) != 0 {
        parts.push("btrfs");
    }
    if (flags & PARTITION_POLICY_EROFS) != 0 {
        parts.push("erofs");
    }
    if (flags & PARTITION_POLICY_EXT4) != 0 {
        parts.push("ext4");
    }
    if (flags & PARTITION_POLICY_F2FS) != 0 {
        parts.push("f2fs");
    }
    if (flags & PARTITION_POLICY_SQUASHFS) != 0 {
        parts.push("squashfs");
    }
    if (flags & PARTITION_POLICY_VFAT) != 0 {
        parts.push("vfat");
    }
    if (flags & PARTITION_POLICY_XFS) != 0 {
        parts.push("xfs");
    }

    if parts.is_empty() {
        Ok("-".into())
    } else {
        Ok(parts.join("+"))
    }
}

// ── C ABI facades: standalone partition-policy flags ─────────────────────

#[inline]
fn ascii_strstrip(bytes: &[u8]) -> &[u8] {
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = bytes
        .iter()
        .position(|byte| !is_space(*byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !is_space(*byte))
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[inline]
fn policy_flag_from_bytes(bytes: &[u8]) -> Option<i32> {
    Some(match bytes {
        b"verity" => PARTITION_POLICY_VERITY,
        b"signed" => PARTITION_POLICY_SIGNED,
        b"encrypted" => PARTITION_POLICY_ENCRYPTED,
        b"encryptedwithintegrity" => PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY,
        b"unprotected" => PARTITION_POLICY_UNPROTECTED,
        b"unused" => PARTITION_POLICY_UNUSED,
        b"absent" => PARTITION_POLICY_ABSENT,
        b"open" => PARTITION_POLICY_OPEN,
        b"ignore" => PARTITION_POLICY_IGNORE,
        b"read-only-on" => PARTITION_POLICY_READ_ONLY_ON,
        b"read-only-off" => PARTITION_POLICY_READ_ONLY_OFF,
        b"growfs-on" => PARTITION_POLICY_GROWFS_ON,
        b"growfs-off" => PARTITION_POLICY_GROWFS_OFF,
        b"btrfs" => PARTITION_POLICY_BTRFS,
        b"erofs" => PARTITION_POLICY_EROFS,
        b"ext4" => PARTITION_POLICY_EXT4,
        b"f2fs" => PARTITION_POLICY_F2FS,
        b"squashfs" => PARTITION_POLICY_SQUASHFS,
        b"vfat" => PARTITION_POLICY_VFAT,
        b"xfs" => PARTITION_POLICY_XFS,
        _ => return None,
    })
}

/// Split one of image-policy's C tokenizer fields.
///
/// `extract_first_word(..., EXTRACT_DONT_COALESCE_SEPARATORS)` strips a
/// non-trailing backslash and treats the following byte literally, including
/// a separator. It also keeps empty fields. Model that behavior here instead
/// of treating every backslash as invalid.
fn split_c_policy_words(bytes: &[u8], separator: u8) -> Result<Vec<Vec<u8>>, i32> {
    let mut words = vec![Vec::new()];
    let mut escaped = false;

    for &byte in bytes {
        if escaped {
            words
                .last_mut()
                .expect("policy tokenizer always has a current field")
                .push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == separator {
            words.push(Vec::new());
        } else {
            words
                .last_mut()
                .expect("policy tokenizer always has a current field")
                .push(byte);
        }
    }

    if escaped {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    Ok(words)
}

/// # Safety
///
/// `policy` must be null or point to a complete, live C `ImagePolicy`
/// allocation for the returned borrow's lifetime.
#[inline]
unsafe fn c_image_policy_entries<'a>(policy: *const CImagePolicy) -> &'a [CPartitionPolicy] {
    if policy.is_null() {
        return &[];
    }

    // SAFETY: the caller guarantees a complete C allocation including all
    // flexible-array entries immediately after the repr(C) prefix.
    unsafe {
        let n_policies = (*policy).n_policies;
        let entries = policy
            .cast::<u8>()
            .add(std::mem::size_of::<CImagePolicy>())
            .cast::<CPartitionPolicy>();
        std::slice::from_raw_parts(entries, n_policies)
    }
}

/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`.
#[inline]
unsafe fn c_image_policy_default(policy: *const CImagePolicy) -> i32 {
    if policy.is_null() {
        PARTITION_POLICY_OPEN
    } else {
        // SAFETY: non-null policy pointers passed to the ABI facade must point
        // to a live C `ImagePolicy`.
        unsafe_ffi!((*policy).default_flags)
    }
}

/// Copy a valid C flexible-array policy into the native representation used by
/// the policy algorithms below.
///
/// # Safety
///
/// `policy` must be null or point to a complete, live C `ImagePolicy` for the
/// duration of this call. Non-null entries must use valid
/// `PartitionDesignator` values, as required by the C API.
unsafe fn c_image_policy_to_native(policy: *const CImagePolicy) -> Result<ImagePolicy, i32> {
    // SAFETY: forwarded from this helper's complete C flexible-array policy
    // contract for both the prefix and entries.
    let (default_flags, entries) = unsafe {
        (
            c_image_policy_default(policy),
            c_image_policy_entries(policy),
        )
    };
    let mut policies = Vec::new();
    for entry in entries {
        let designator = PartitionDesignator::from_i32(entry.designator)
            .ok_or_else(|| Errno::EINVAL.to_neg_errno())?;
        policies.push(PartitionPolicy {
            designator,
            flags: entry.flags,
        });
    }

    Ok(ImagePolicy {
        default_flags,
        policies,
    })
}

/// Allocate a C-layout flexible-array policy from the native representation.
/// The caller owns the returned `malloc(3)` allocation.
fn native_image_policy_to_c(policy: &ImagePolicy) -> Result<*mut CImagePolicy, i32> {
    let entries_bytes = policy
        .policies
        .len()
        .checked_mul(std::mem::size_of::<CPartitionPolicy>())
        .ok_or_else(|| Errno::ENOMEM.to_neg_errno())?;
    let allocation_size = std::mem::size_of::<CImagePolicy>()
        .checked_add(entries_bytes)
        .ok_or_else(|| Errno::ENOMEM.to_neg_errno())?;
    let result = crate::ffi::malloc(allocation_size).cast::<CImagePolicy>();
    if result.is_null() {
        return Err(Errno::ENOMEM.to_neg_errno());
    }

    // SAFETY: `result` is a fresh allocation large enough for the C prefix
    // and all flexible-array entries computed above.
    unsafe {
        ptr::write(
            result,
            CImagePolicy {
                default_flags: policy.default_flags,
                n_policies: policy.policies.len(),
            },
        );
        let entries = result
            .cast::<u8>()
            .add(std::mem::size_of::<CImagePolicy>())
            .cast::<CPartitionPolicy>();
        for (index, entry) in policy.policies.iter().enumerate() {
            ptr::write(
                entries.add(index),
                CPartitionPolicy {
                    designator: entry.designator as i32,
                    flags: entry.flags,
                },
            );
        }
    }
    Ok(result)
}

/// Duplicate a Rust string into a C-allocator-owned NUL-terminated buffer.
fn c_strdup(value: &str) -> Result<*mut libc::c_char, i32> {
    let value = CString::new(value).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    // SAFETY: value is a live NUL-terminated string and strdup returns memory
    // in the C allocator family required by these ABI exports.
    let output = unsafe_ffi!(crate::ffi::strdup(value.as_ptr()));
    if output.is_null() {
        Err(Errno::ENOMEM.to_neg_errno())
    } else {
        Ok(output)
    }
}

#[inline]
fn partition_policy_flags_from_bytes(bytes: &[u8], graceful: bool) -> Result<i32, i32> {
    if bytes.is_empty() || bytes == b"-" {
        return Ok(0);
    }

    let mut flags = 0;
    for raw_flag in split_c_policy_words(bytes, b'+')? {
        match policy_flag_from_bytes(ascii_strstrip(&raw_flag)) {
            Some(flag) => flags |= flag,
            None if graceful => {}
            None => return Err(-EBADRQC),
        }
    }
    Ok(flags)
}

/// Parse the C grammar without first converting it to UTF-8 or normalizing
/// separators. `extract_first_word(..., EXTRACT_DONT_COALESCE_SEPARATORS)` in
/// the C source deliberately treats empty `:` fields as malformed rules.
fn image_policy_from_bytes(bytes: &[u8], graceful: bool) -> Result<ImagePolicy, i32> {
    let symbolic_default = match bytes {
        b"" | b"-" => Some(PARTITION_POLICY_IGNORE),
        b"*" => Some(PARTITION_POLICY_OPEN),
        b"~" => Some(PARTITION_POLICY_ABSENT),
        _ => None,
    };
    if let Some(default_flags) = symbolic_default {
        return Ok(ImagePolicy {
            default_flags,
            policies: Vec::new(),
        });
    }

    let mut default_flags = PARTITION_POLICY_IGNORE;
    let mut default_specified = false;
    let mut seen_designators = 0_u64;
    let mut policies = Vec::new();

    for expression in split_c_policy_words(bytes, b':')? {
        let Some(separator) = expression.iter().position(|byte| *byte == b'=') else {
            return Err(Errno::EINVAL.to_neg_errno());
        };
        let designator_name = ascii_strstrip(&expression[..separator]);
        let flags_text = ascii_strstrip(&expression[separator + 1..]);

        if designator_name.is_empty() {
            if default_specified {
                return Err(Errno::ENOTUNIQ.to_neg_errno());
            }
            default_specified = true;
            default_flags = partition_policy_flags_from_bytes(flags_text, graceful)?;
            continue;
        }

        let Some(designator) = std::str::from_utf8(designator_name)
            .ok()
            .and_then(PartitionDesignator::from_str)
        else {
            if graceful {
                continue;
            }
            return Err(-EBADSLT);
        };
        let bit = 1_u64 << designator as u64;
        if seen_designators & bit != 0 {
            return Err(Errno::ENOTUNIQ.to_neg_errno());
        }
        seen_designators |= bit;

        policies.push(PartitionPolicy {
            designator,
            flags: partition_policy_flags_from_bytes(flags_text, graceful)?,
        });
    }

    policies.sort_by_key(|policy| policy.designator);
    Ok(ImagePolicy {
        default_flags,
        policies,
    })
}

/// C ABI facade for `partition_policy_flags_extend()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_policy_flags_extend(flags: i32) -> i32 {
    partition_policy_flags_extend(flags)
}

/// C ABI facade for `partition_policy_flags_reduce()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_policy_flags_reduce(flags: i32) -> i32 {
    partition_policy_flags_reduce(flags)
}

/// Parse an ASCII partition-policy flag list with C's exact empty-field and
/// ASCII-stripping rules. Unknown flags have C's recognizable `-EBADRQC`
/// result unless `graceful` is true.
///
/// # Safety
///
/// `s` must be a live NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_partition_policy_flags_from_string(
    s: *const libc::c_char,
    graceful: bool,
) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: upheld by this export's C-string contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    if bytes.is_empty() || bytes == b"-" {
        return 0;
    }

    match partition_policy_flags_from_bytes(bytes, graceful) {
        Ok(flags) => flags,
        Err(error) => error,
    }
}

/// Format flags into a C-allocator-owned policy string. The result pointer is
/// published only after the string has been allocated successfully.
///
/// # Safety
///
/// `ret` must be a writable pointer slot. On success it receives a fresh
/// `strdup(3)` allocation that the caller must release with `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_partition_policy_flags_to_string(
    flags: i32,
    simplify: bool,
    ret: *mut *mut libc::c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    let rendered = match partition_policy_flags_to_string(flags, simplify) {
        Ok(rendered) => rendered,
        Err(error) => return error,
    };
    let count = if rendered == "-" {
        0
    } else {
        (rendered.bytes().filter(|byte| *byte == b'+').count() + 1) as i32
    };
    let output = match c_strdup(&rendered) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` is writable by this export's contract and publication
    // happens only after a complete C-allocator string was obtained.
    unsafe_ffi!(ptr::write(ret, output));
    count
}

/// Release a C-allocator-owned `ImagePolicy` and return null, matching
/// `image_policy_free()`.
///
/// # Safety
///
/// `policy` must be null or an allocation that may be released with
/// `free(3)`. The pointer must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_free(policy: *mut CImagePolicy) -> *mut CImagePolicy {
    // SAFETY: the caller supplies a C-allocator-owned pointer or null.
    unsafe_ffi!(libc::free(policy.cast()));
    ptr::null_mut()
}

/// Look up the effective flags for one partition designator.
///
/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`, including its
/// complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_get(policy: *const CImagePolicy, designator: i32) -> i32 {
    let Some(designator) = PartitionDesignator::from_i32(designator) else {
        if policy.is_null() {
            // C's NULL-policy fast path normalizes even an out-of-range enum.
            // Every out-of-range value is non-verity, so `Home` is an exact
            // representative for that normalization class.
            return normalize(PartitionPolicy {
                designator: PartitionDesignator::Home,
                flags: PARTITION_POLICY_OPEN,
            });
        }
        return Errno::EINVAL.to_neg_errno();
    };
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    match unsafe_ffi!(c_image_policy_to_native(policy))
        .and_then(|policy| policy.image_policy_get(designator))
    {
        Ok(flags) => flags,
        Err(error) => error,
    }
}

/// Look up flags and fall back to the policy default when no explicit or
/// derived rule exists.
///
/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`, including its
/// complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_get_exhaustively(
    policy: *const CImagePolicy,
    designator: i32,
) -> i32 {
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    let policy = match unsafe_ffi!(c_image_policy_to_native(policy)) {
        Ok(policy) => policy,
        Err(error) => return error,
    };
    let Some(designator) = PartitionDesignator::from_i32(designator) else {
        // C's exhaustive accessor falls back even for an out-of-range enum.
        // Such a value has the same normalization rules as a generic,
        // non-verity designator, represented here by `Home`.
        return normalize(PartitionPolicy {
            designator: PartitionDesignator::Home,
            flags: policy.default_flags,
        });
    };
    policy
        .image_policy_get_exhaustively(designator)
        .unwrap_or_else(|error| error)
}

/// Compare two policies exactly as defined, including redundant entries.
///
/// # Safety
///
/// Each pointer must be null or point to a live C `ImagePolicy`, including
/// its complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_equal(
    a: *const CImagePolicy,
    b: *const CImagePolicy,
) -> bool {
    if a == b {
        return true;
    }

    // SAFETY: both pointers satisfy this export's flexible-array contract.
    match unsafe_ffi!((c_image_policy_to_native(a), c_image_policy_to_native(b))) {
        (Ok(a), Ok(b)) => a.image_policy_equal(&b),
        _ => false,
    }
}

/// Check whether every partition resolves to the same outcome in both
/// policies.
///
/// # Safety
///
/// Each pointer must be null or point to a live C `ImagePolicy`, including
/// its complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_equivalent(
    a: *const CImagePolicy,
    b: *const CImagePolicy,
) -> i32 {
    // SAFETY: both pointers satisfy this export's flexible-array contract.
    let (a, b) = match unsafe_ffi!((c_image_policy_to_native(a), c_image_policy_to_native(b))) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => return error,
    };
    match a.image_policy_equivalent(&b) {
        Ok(equivalent) => i32::from(equivalent),
        Err(error) => error,
    }
}

/// Check whether a policy is equivalent to the built-in ignore policy.
///
/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`, including its
/// complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_equiv_ignore(policy: *const CImagePolicy) -> bool {
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    unsafe_ffi!(c_image_policy_to_native(policy))
        .and_then(|policy| policy.image_policy_flags_all_match(PARTITION_POLICY_IGNORE))
        .unwrap_or(true)
}

/// Check whether a policy is equivalent to the built-in allow policy.
///
/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`, including its
/// complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_equiv_allow(policy: *const CImagePolicy) -> bool {
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    unsafe_ffi!(c_image_policy_to_native(policy))
        .and_then(|policy| policy.image_policy_flags_all_match(PARTITION_POLICY_OPEN))
        .unwrap_or(true)
}

/// Check whether a policy is equivalent to the built-in deny policy.
///
/// # Safety
///
/// `policy` must be null or point to a live C `ImagePolicy`, including its
/// complete flexible array, for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_equiv_deny(policy: *const CImagePolicy) -> bool {
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    unsafe_ffi!(c_image_policy_to_native(policy))
        .and_then(|policy| policy.image_policy_flags_all_match(PARTITION_POLICY_ABSENT))
        .unwrap_or(true)
}

/// Parse a C image-policy expression into a C-allocator-owned flexible-array
/// policy. A null `ret` performs C's validation-only parse.
///
/// # Safety
///
/// `s` must point to a live NUL-terminated C string. If non-null, `ret` must
/// be writable for one `ImagePolicy *`; on success it receives ownership of a
/// `malloc(3)` allocation released by `rs_image_policy_free()` or `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_from_string(
    s: *const libc::c_char,
    graceful: bool,
    ret: *mut *mut CImagePolicy,
) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: upheld by this export's C-string contract.
    let policy = match image_policy_from_bytes(unsafe_ffi!(CStr::from_ptr(s)).to_bytes(), graceful)
    {
        Ok(policy) => policy,
        Err(error) => return error,
    };
    if ret.is_null() {
        return 0;
    }
    let output = match native_image_policy_to_c(&policy) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` is writable by this export's contract and publication
    // occurs only after the complete C-layout allocation has succeeded.
    unsafe_ffi!(ptr::write(ret, output));
    0
}

/// Render a C-layout image policy to a fresh C-allocator-owned string.
///
/// # Safety
///
/// `policy` must be null or point to a complete, live C `ImagePolicy`. `ret`
/// must be writable and receives a `strdup(3)` allocation on success that the
/// caller must release with `free(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_to_string(
    policy: *const CImagePolicy,
    simplify: bool,
    ret: *mut *mut libc::c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: forwarded from this export's C `ImagePolicy` contract.
    let policy = match unsafe_ffi!(c_image_policy_to_native(policy)) {
        Ok(policy) => policy,
        Err(error) => return error,
    };
    let rendered = match policy.image_policy_to_string(simplify) {
        Ok(rendered) => rendered,
        Err(error) => return error,
    };
    let output = match c_strdup(&rendered) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` is writable by this export's contract.
    unsafe_ffi!(ptr::write(ret, output));
    0
}

/// Calculate the intersection of two C-layout policies. Null inputs retain
/// C's "allow everything" policy meaning; a null `ret` validates and
/// calculates without publishing the temporary policy.
///
/// # Safety
///
/// Each input must be null or point to a complete, live C `ImagePolicy`. If
/// non-null, `ret` must be writable for one `ImagePolicy *` and receives a
/// C-allocator-owned flexible-array allocation on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_intersect(
    a: *const CImagePolicy,
    b: *const CImagePolicy,
    ret: *mut *mut CImagePolicy,
) -> i32 {
    // SAFETY: forwarded from this export's two C `ImagePolicy` contracts.
    let (a, b) = match unsafe_ffi!((c_image_policy_to_native(a), c_image_policy_to_native(b))) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => return error,
    };
    let result = match a.image_policy_intersect(&b) {
        Ok(policy) => policy,
        Err(error) => return error,
    };
    if ret.is_null() {
        return 0;
    }
    let output = match native_image_policy_to_c(&result) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` is writable by this export's contract.
    unsafe_ffi!(ptr::write(ret, output));
    0
}

/// Calculate the union of two C-layout policies. See
/// `rs_image_policy_intersect()` for pointer and ownership requirements.
///
/// # Safety
/// Each input must be null or point to a complete, live C `ImagePolicy`. If
/// non-null, `ret` must be writable for one `ImagePolicy *` and receives a
/// C-allocator-owned flexible-array allocation on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_image_policy_union(
    a: *const CImagePolicy,
    b: *const CImagePolicy,
    ret: *mut *mut CImagePolicy,
) -> i32 {
    // SAFETY: forwarded from this export's two C `ImagePolicy` contracts.
    let (a, b) = match unsafe_ffi!((c_image_policy_to_native(a), c_image_policy_to_native(b))) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => return error,
    };
    let result = match a.image_policy_union(&b) {
        Ok(policy) => policy,
        Err(error) => return error,
    };
    if ret.is_null() {
        return 0;
    }
    let output = match native_image_policy_to_c(&result) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: `ret` is writable by this export's contract.
    unsafe_ffi!(ptr::write(ret, output));
    0
}

/// Determine the uniquely permitted filesystem type for a partition policy.
///
/// # Safety
///
/// `policy` must be null or point to a complete, live C `ImagePolicy`.
/// `ret_fstype` must be writable; on a successful result of `1` it receives a
/// `strdup(3)` allocation owned by the caller, and on a successful result of
/// `0` it is set to null. `ret_encrypted` is optional but, if non-null, must
/// be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_partition_policy_determine_fstype(
    policy: *const CImagePolicy,
    designator: i32,
    ret_encrypted: *mut bool,
    ret_fstype: *mut *mut libc::c_char,
) -> i32 {
    if ret_fstype.is_null() || PartitionDesignator::from_i32(designator).is_none() {
        return Errno::EINVAL.to_neg_errno();
    }
    let designator =
        PartitionDesignator::from_i32(designator).expect("designator was checked above");
    // SAFETY: the C ABI contract guarantees a complete flexible-array policy.
    let policy_flags = match unsafe_ffi!(c_image_policy_to_native(policy))
        .and_then(|policy| policy.image_policy_get_exhaustively(designator))
    {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if policy_flags < 0 {
        return policy_flags;
    }
    let fstype = match partition_policy_flags_to_string(policy_flags & FSTYPE_MASK, true) {
        Ok(fstype) => fstype,
        Err(error) => return error,
    };
    let count = if fstype == "-" {
        0
    } else {
        fstype.bytes().filter(|byte| *byte == b'+').count() + 1
    };
    if count != 1 {
        // SAFETY: the required output and, when supplied, the optional output
        // are writable by this export's contract.
        unsafe {
            if !ret_encrypted.is_null() {
                ptr::write(ret_encrypted, false);
            }
            ptr::write(ret_fstype, ptr::null_mut());
        }
        return 0;
    }

    let encrypted = (policy_flags
        & (PARTITION_POLICY_ENCRYPTED | PARTITION_POLICY_ENCRYPTEDWITHINTEGRITY))
        != 0
        && (policy_flags
            & (PARTITION_POLICY_VERITY | PARTITION_POLICY_SIGNED | PARTITION_POLICY_UNPROTECTED))
            == 0;
    let output = match c_strdup(&fstype) {
        Ok(output) => output,
        Err(error) => return error,
    };
    // SAFETY: the required output and, when supplied, the optional output
    // are writable by this export's contract.
    unsafe {
        if !ret_encrypted.is_null() {
            ptr::write(ret_encrypted, encrypted);
        }
        ptr::write(ret_fstype, output);
    }
    1
}

fn policy_intersect_or_union(
    a: &ImagePolicy,
    b: &ImagePolicy,
    op: fn(i32, i32) -> i32,
) -> Result<ImagePolicy, i32> {
    let mut policy = ImagePolicy {
        default_flags: op(
            partition_policy_flags_extend(a.default_flags),
            partition_policy_flags_extend(b.default_flags),
        ),
        policies: Vec::new(),
    };

    if has_unspecified(policy.default_flags) {
        return Err(-ENAVAIL);
    }

    policy.default_flags = partition_policy_flags_reduce(policy.default_flags);

    for designator in PartitionDesignator::ALL {
        let present_in_a = a
            .policies
            .iter()
            .any(|policy| policy.designator == designator);
        let present_in_b = b
            .policies
            .iter()
            .any(|policy| policy.designator == designator);
        if !present_in_a && !present_in_b {
            continue;
        }

        let z = op(
            a.image_policy_get_exhaustively(designator)?,
            b.image_policy_get_exhaustively(designator)?,
        );

        if z != PARTITION_POLICY_ABSENT && has_unspecified(z) {
            return Err(-ENAVAIL);
        }

        let df = normalize(PartitionPolicy {
            designator,
            flags: policy.default_flags,
        });

        if df != z {
            policy.policies.push(PartitionPolicy {
                designator,
                flags: partition_policy_flags_reduce(z),
            });
        }
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_fills_unspecified_fields() {
        let extended = partition_policy_flags_extend(PARTITION_POLICY_SIGNED);
        assert_eq!(extended & READ_ONLY_MASK, READ_ONLY_MASK);
        assert_eq!(extended & GROWFS_MASK, GROWFS_MASK);
    }

    #[test]
    fn reduce_removes_full_masks() {
        let reduced = partition_policy_flags_reduce(partition_policy_flags_extend(0));
        assert_eq!(reduced, 0);
    }

    #[test]
    fn parse_symbolic_allow_policy() {
        let policy = image_policy_from_string("*", false).unwrap();
        assert_eq!(policy.default_flags, PARTITION_POLICY_OPEN);
        assert!(policy.policies.is_empty());
    }

    #[test]
    fn parse_designator_and_default_rules() {
        let policy = image_policy_from_string("root=signed: =unused+absent", false).unwrap();
        assert_eq!(policy.default_flags, PARTITION_POLICY_IGNORE);
        assert_eq!(policy.policies.len(), 1);
        assert_eq!(policy.policies[0].designator, PartitionDesignator::Root);
    }

    #[test]
    fn reject_duplicate_designators() {
        assert_eq!(
            image_policy_from_string("root=signed:root=verity", false),
            Err(Errno::ENOTUNIQ.to_neg_errno())
        );
    }

    #[test]
    fn verity_partition_is_synthesized_from_data_partition() {
        let policy = image_policy_from_string("root=signed+read-only-on", false).unwrap();
        let flags = policy
            .image_policy_get(PartitionDesignator::RootVeritySig)
            .unwrap();
        assert!((flags & PARTITION_POLICY_UNPROTECTED) != 0);
        assert!((flags & PARTITION_POLICY_READ_ONLY_ON) != 0);
    }

    #[test]
    fn verity_synthesis_uses_normalized_data_flags() {
        // `-` is normalized to the permissive policy for a root data
        // partition. C performs that normalization before deciding whether
        // the corresponding verity partitions can be synthesized.
        let policy = image_policy_from_string("root=-", false).unwrap();
        assert!(
            policy
                .image_policy_get(PartitionDesignator::RootVerity)
                .is_ok()
        );
        assert!(
            policy
                .image_policy_get(PartitionDesignator::RootVeritySig)
                .is_ok()
        );
    }

    #[test]
    fn to_string_simplifies_ignore_policy() {
        let policy = image_policy_from_string("-", false).unwrap();
        assert_eq!(policy.image_policy_to_string(true).unwrap(), "-");
    }

    #[test]
    fn equivalent_ignores_redundant_per_partition_rule() {
        let a = image_policy_from_string("=signed:root=signed", false).unwrap();
        let b = image_policy_from_string("=signed", false).unwrap();
        assert!(a.image_policy_equivalent(&b).unwrap());
    }

    #[test]
    fn intersect_rejects_impossible_policy() {
        let a = image_policy_from_string("root=absent", false).unwrap();
        let b = image_policy_from_string("root=verity", false).unwrap();
        assert_eq!(a.image_policy_intersect(&b), Err(-ENAVAIL));
    }

    #[test]
    fn union_combines_flags() {
        let a = image_policy_from_string("root=signed", false).unwrap();
        let b = image_policy_from_string("root=verity", false).unwrap();
        let union = a.image_policy_union(&b).unwrap();
        let flags = union
            .image_policy_get_exhaustively(PartitionDesignator::Root)
            .unwrap();
        assert!((flags & PARTITION_POLICY_SIGNED) != 0);
        assert!((flags & PARTITION_POLICY_VERITY) != 0);
    }

    #[test]
    fn ignore_designators_overrides_selected_entries() {
        let policy = image_policy_from_string("root=signed:usr=verity", false).unwrap();
        let patched = policy.image_policy_ignore_designators(&[PartitionDesignator::Usr]);
        let usr = patched
            .image_policy_get_exhaustively(PartitionDesignator::Usr)
            .unwrap();
        assert_eq!(usr & USE_MASK, PARTITION_POLICY_IGNORE);
    }

    #[test]
    fn flags_to_string_handles_filesystem_flags() {
        let text = partition_policy_flags_to_string(
            PARTITION_POLICY_EXT4 | PARTITION_POLICY_UNPROTECTED,
            true,
        )
        .unwrap();
        assert_eq!(text, "unprotected+ext4");
    }
}
