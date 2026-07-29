// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.image-policy; authority=src/shared/image-policy.c,src/shared/image-policy.h

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
            let raw_flags = self.get_raw_flags(data_designator);
            if (raw_flags & (PARTITION_POLICY_SIGNED | PARTITION_POLICY_VERITY)) == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }

            let data_flags = self.image_policy_get(data_designator)?;
            return Ok(normalize(PartitionPolicy {
                designator,
                flags: PARTITION_POLICY_UNPROTECTED
                    | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                    | (data_flags & PFLAGS_MASK),
            }));
        }

        if let Some(data_designator) = designator.verity_sig_to_data() {
            let raw_flags = self.get_raw_flags(data_designator);
            if (raw_flags & PARTITION_POLICY_SIGNED) == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }

            let data_flags = self.image_policy_get(data_designator)?;
            return Ok(normalize(PartitionPolicy {
                designator,
                flags: PARTITION_POLICY_UNPROTECTED
                    | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                    | (data_flags & PFLAGS_MASK),
            }));
        }

        Err(Errno::EINVAL.to_neg_errno())
    }

    fn get_raw_flags(&self, designator: PartitionDesignator) -> i32 {
        if let Some(policy) = self
            .policies
            .iter()
            .find(|policy| policy.designator == designator)
        {
            return policy.flags;
        }
        self.default_flags
    }

    pub fn image_policy_get_exhaustively(
        &self,
        designator: PartitionDesignator,
    ) -> Result<i32, i32> {
        self.image_policy_get(designator).or_else(|_| {
            if let Some(data_designator) = designator.verity_hash_to_data() {
                let raw_flags = self.get_raw_flags(data_designator);
                if (raw_flags & (PARTITION_POLICY_SIGNED | PARTITION_POLICY_VERITY)) == 0 {
                    return Ok(normalize(PartitionPolicy {
                        designator,
                        flags: self.default_flags,
                    }));
                }
                let data_flags = normalize(PartitionPolicy {
                    designator: data_designator,
                    flags: raw_flags,
                });
                return Ok(normalize(PartitionPolicy {
                    designator,
                    flags: PARTITION_POLICY_UNPROTECTED
                        | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                        | (data_flags & PFLAGS_MASK),
                }));
            }
            if let Some(data_designator) = designator.verity_sig_to_data() {
                let raw_flags = self.get_raw_flags(data_designator);
                if (raw_flags & PARTITION_POLICY_SIGNED) == 0 {
                    return Ok(normalize(PartitionPolicy {
                        designator,
                        flags: self.default_flags,
                    }));
                }
                let data_flags = normalize(PartitionPolicy {
                    designator: data_designator,
                    flags: raw_flags,
                });
                return Ok(normalize(PartitionPolicy {
                    designator,
                    flags: PARTITION_POLICY_UNPROTECTED
                        | (data_flags & (PARTITION_POLICY_UNUSED | PARTITION_POLICY_ABSENT))
                        | (data_flags & PFLAGS_MASK),
                }));
            }
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
            return Err(-Errno::ENOTUNIQ.to_neg_errno());
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
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    if bytes.is_empty() || bytes == b"-" {
        return 0;
    }

    let mut flags = 0;
    for raw_flag in bytes.split(|byte| *byte == b'+') {
        match policy_flag_from_bytes(ascii_strstrip(raw_flag)) {
            Some(flag) => flags |= flag,
            None if graceful => {}
            None => return -EBADRQC,
        }
    }
    flags
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
    let rendered = match CString::new(rendered) {
        Ok(rendered) => rendered,
        Err(_) => return Errno::EINVAL.to_neg_errno(),
    };
    // SAFETY: `rendered` is live and NUL-terminated; strdup returns memory in
    // the C allocator family required by the public header.
    let output = unsafe { crate::ffi::strdup(rendered.as_ptr()) };
    if output.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: `ret` is writable by this export's contract and publication
    // happens only after a complete C-allocator string was obtained.
    unsafe { ptr::write(ret, output) };
    count
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
            Err(-Errno::ENOTUNIQ.to_neg_errno())
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
