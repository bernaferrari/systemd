// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dissect-image.c, src/shared/dissect-image.h
//
// Image dissection utilities.
//
// Provides types and pure-logic functions for parsing disk images,
// partition tables (GPT/MBR), mount point resolution, filesystem
// probing, verity integrity, and LUKS header inspection. System-call
// heavy operations (blkid probing, cryptsetup, loopback ioctls) remain
// in C; this module handles all domain logic that can be expressed in
// safe Rust.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default filesystem types allowed for automatic mounting.
use crate::ffi::*;
pub const DEFAULT_ALLOWED_FSTYPES: &[&str] =
    &["btrfs", "erofs", "ext4", "f2fs", "squashfs", "vfat", "xfs"];

/// Environment variable that overrides the allowed filesystem list.
pub const FSTYPES_ENV_VAR: &str = "SYSTEMD_DISSECT_FILE_SYSTEMS";

/// Traditional (and minimum) sector size in bytes.
pub const SECTOR_SIZE_DEFAULT: u32 = 512;

/// Maximum sector size we probe for.
pub const SECTOR_SIZE_MAX: u32 = 4096;

/// GPT header "EFI PART" signature bytes.
pub const GPT_HEADER_SIGNATURE: &[u8; 8] = b"EFI PART";

/// LUKS2 fixed header size.
pub const LUKS2_FIXED_HDR_SIZE: u64 = 0x1000;

/// LUKS2 magic bytes (without the trailing version field).
pub const LUKS2_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// Maximum verity signature partition size we accept (4 MiB).
pub const MAX_VERITY_SIG_PARTITION_SIZE: u64 = 4 * 1024 * 1024;

/// Bytes read from disk for sector-size probing (2 × max sector size).
pub const PROBE_READ_SIZE: usize = 2 * SECTOR_SIZE_MAX as usize;

/// GPT partition type UUIDs – well-known systemd designators.
pub const GPT_UUID_ROOT: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const GPT_UUID_USR: &str = "8484680c-9521-48c6-9c11-b0720656f69e";
pub const GPT_UUID_HOME: &str = "933ac7e1-2eb4-4f13-b844-0e14e2aef915";
pub const GPT_UUID_SRV: &str = "3b8f8425-20e0-4f3b-907f-1a25a76f98e8";
pub const GPT_UUID_VAR: &str = "4d21b016-b534-45c2-a9fb-5c16e091fd2d";
pub const GPT_UUID_TMP: &str = "7ec6f557-3bc5-4aca-b293-17ef5df6394e";
pub const GPT_UUID_SWAP: &str = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f";
pub const GPT_UUID_ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const GPT_UUID_XBOOTLDR: &str = "bc13c2ff-59e6-4262-a352-b275fd6f7172";
pub const GPT_UUID_ROOT_VERITY: &str = "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5";
pub const GPT_UUID_USR_VERITY: &str = "8da63339-7f94-4be2-8b68-4f4e3f2e6cfa";
pub const GPT_UUID_ROOT_VERITY_SIG: &str = "d13c5d3b-b5d1-422a-b29f-9758ab3cd8a5";
pub const GPT_UUID_USR_VERITY_SIG: &str = "e38b475f-858d-4574-bbf9-c01637da0f1a";
pub const GPT_UUID_LINUX_GENERIC: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

/// GPT partition attribute flags.
pub const GPT_FLAG_NO_AUTO: u64 = 1 << 63;
pub const GPT_FLAG_READ_ONLY: u64 = 1 << 60;
pub const GPT_FLAG_GROWFS: u64 = 1 << 59;
pub const GPT_FLAG_REQUIRED_PARTITION: u64 = 1 << 2;
pub const GPT_FLAG_NO_BLOCK_IO_PROTOCOL: u64 = 1 << 1;
pub const GPT_FLAG_LEGACY_BIOS_BOOTABLE: u64 = 1 << 0;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Partition table type detected in a disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableType {
    None,
    Gpt,
    Mbr,
}

/// Filesystem types recognised during dissection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemType {
    Btrfs,
    Erofs,
    Ext4,
    F2fs,
    Squashfs,
    Vfat,
    Xfs,
    CryptoLuks,
    VerityHash,
    VerityHashSignature,
    Swap,
    Unknown(String),
}

impl FilesystemType {
    /// Parse a filesystem type string (case-insensitive).
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "btrfs" => FilesystemType::Btrfs,
            "erofs" => FilesystemType::Erofs,
            "ext4" | "ext3" | "ext2" => FilesystemType::Ext4,
            "f2fs" => FilesystemType::F2fs,
            "squashfs" => FilesystemType::Squashfs,
            "vfat" | "fat32" | "fat16" => FilesystemType::Vfat,
            "xfs" => FilesystemType::Xfs,
            "crypto_luks" => FilesystemType::CryptoLuks,
            "dm_verity_hash" => FilesystemType::VerityHash,
            "verity_hash_signature" => FilesystemType::VerityHashSignature,
            "swap" => FilesystemType::Swap,
            other => FilesystemType::Unknown(other.to_owned()),
        }
    }

    /// The raw name used by the kernel / blkid.
    pub fn as_str(&self) -> &str {
        match self {
            FilesystemType::Btrfs => "btrfs",
            FilesystemType::Erofs => "erofs",
            FilesystemType::Ext4 => "ext4",
            FilesystemType::F2fs => "f2fs",
            FilesystemType::Squashfs => "squashfs",
            FilesystemType::Vfat => "vfat",
            FilesystemType::Xfs => "xfs",
            FilesystemType::CryptoLuks => "crypto_LUKS",
            FilesystemType::VerityHash => "DM_verity_hash",
            FilesystemType::VerityHashSignature => "verity_hash_signature",
            FilesystemType::Swap => "swap",
            FilesystemType::Unknown(s) => s.as_str(),
        }
    }

    /// True if this filesystem type is inherently read-only.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            FilesystemType::Squashfs | FilesystemType::Erofs | FilesystemType::VerityHash
        )
    }
}

impl std::fmt::Display for FilesystemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Well-known GPT partition designators (maps to `PartitionDesignator` in C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum PartitionDesignator {
    #[default]
    Invalid,
    Root,
    Usr,
    Home,
    Srv,
    Var,
    Tmp,
    Swap,
    Esp,
    Xbootldr,
    RootVerity,
    UsrVerity,
    RootVeritySig,
    UsrVeritySig,
}

impl PartitionDesignator {
    /// Resolve a GPT partition type UUID to a designator.
    pub fn from_gpt_type_uuid(uuid: &str) -> Option<Self> {
        // Normalise to lowercase for comparison.
        match uuid.to_lowercase().as_str() {
            GPT_UUID_ROOT => Some(PartitionDesignator::Root),
            GPT_UUID_USR => Some(PartitionDesignator::Usr),
            GPT_UUID_HOME => Some(PartitionDesignator::Home),
            GPT_UUID_SRV => Some(PartitionDesignator::Srv),
            GPT_UUID_VAR => Some(PartitionDesignator::Var),
            GPT_UUID_TMP => Some(PartitionDesignator::Tmp),
            GPT_UUID_SWAP => Some(PartitionDesignator::Swap),
            GPT_UUID_ESP => Some(PartitionDesignator::Esp),
            GPT_UUID_XBOOTLDR => Some(PartitionDesignator::Xbootldr),
            GPT_UUID_ROOT_VERITY => Some(PartitionDesignator::RootVerity),
            GPT_UUID_USR_VERITY => Some(PartitionDesignator::UsrVerity),
            GPT_UUID_ROOT_VERITY_SIG => Some(PartitionDesignator::RootVeritySig),
            GPT_UUID_USR_VERITY_SIG => Some(PartitionDesignator::UsrVeritySig),
            _ => None,
        }
    }

    /// Human-readable name (e.g. `"root"`, `"esp"`).
    pub fn as_str(self) -> &'static str {
        match self {
            PartitionDesignator::Root => "root",
            PartitionDesignator::Usr => "usr",
            PartitionDesignator::Home => "home",
            PartitionDesignator::Srv => "srv",
            PartitionDesignator::Var => "var",
            PartitionDesignator::Tmp => "tmp",
            PartitionDesignator::Swap => "swap",
            PartitionDesignator::Esp => "esp",
            PartitionDesignator::Xbootldr => "xbootldr",
            PartitionDesignator::RootVerity => "root-verity",
            PartitionDesignator::UsrVerity => "usr-verity",
            PartitionDesignator::RootVeritySig => "root-verity-sig",
            PartitionDesignator::UsrVeritySig => "usr-verity-sig",
            PartitionDesignator::Invalid => "invalid",
        }
    }

    /// True if this designator represents a verity hash partition.
    pub fn is_verity(self) -> bool {
        matches!(
            self,
            PartitionDesignator::RootVerity
                | PartitionDesignator::UsrVerity
                | PartitionDesignator::RootVeritySig
                | PartitionDesignator::UsrVeritySig
        )
    }

    /// True if this designator is a verity *hash* (not signature) partition.
    pub fn is_verity_hash(self) -> bool {
        matches!(
            self,
            PartitionDesignator::RootVerity | PartitionDesignator::UsrVerity
        )
    }

    /// True if this designator is a verity *signature* partition.
    pub fn is_verity_sig(self) -> bool {
        matches!(
            self,
            PartitionDesignator::RootVeritySig | PartitionDesignator::UsrVeritySig
        )
    }

    /// For a verity designator return the corresponding data partition.
    /// Returns `Invalid` if this is not a verity designator.
    pub fn verity_to_data(self) -> Self {
        match self {
            PartitionDesignator::RootVerity | PartitionDesignator::RootVeritySig => {
                PartitionDesignator::Root
            }
            PartitionDesignator::UsrVerity | PartitionDesignator::UsrVeritySig => {
                PartitionDesignator::Usr
            }
            other => other,
        }
    }

    /// For a data partition, return the corresponding verity hash designator.
    pub fn verity_hash_of(self) -> Self {
        match self {
            PartitionDesignator::Root => PartitionDesignator::RootVerity,
            PartitionDesignator::Usr => PartitionDesignator::UsrVerity,
            other => other,
        }
    }

    /// For a data partition, return the corresponding verity signature designator.
    pub fn verity_sig_of(self) -> Self {
        match self {
            PartitionDesignator::Root => PartitionDesignator::RootVeritySig,
            PartitionDesignator::Usr => PartitionDesignator::UsrVeritySig,
            other => other,
        }
    }

    /// True if this partition is versioned (root / usr – A/B versioning by label).
    pub fn is_versioned(self) -> bool {
        matches!(self, PartitionDesignator::Root | PartitionDesignator::Usr)
    }

    /// All valid designators (for iteration).
    pub fn all() -> &'static [PartitionDesignator] {
        &[
            PartitionDesignator::Root,
            PartitionDesignator::Usr,
            PartitionDesignator::Home,
            PartitionDesignator::Srv,
            PartitionDesignator::Var,
            PartitionDesignator::Tmp,
            PartitionDesignator::Swap,
            PartitionDesignator::Esp,
            PartitionDesignator::Xbootldr,
            PartitionDesignator::RootVerity,
            PartitionDesignator::UsrVerity,
            PartitionDesignator::RootVeritySig,
            PartitionDesignator::UsrVeritySig,
        ]
    }
}

impl std::fmt::Display for PartitionDesignator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

bitflags::bitflags! {
    /// Flags that control image dissection behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DissectImageFlags: u64 {
        const DEVICE_READ_ONLY       = 1 << 0;
        const DISCARD_ON_LOOP        = 1 << 1;
        const DISCARD                = 1 << 2;
        const DISCARD_ON_CRYPTO      = 1 << 3;
        const GPT_ONLY               = 1 << 4;
        const GENERIC_ROOT           = 1 << 5;
        const MOUNT_ROOT_ONLY        = 1 << 6;
        const MOUNT_NON_ROOT_ONLY    = 1 << 7;
        const VALIDATE_OS            = 1 << 8;
        const VALIDATE_OS_EXT        = 1 << 9;
        const RELAX_VAR_CHECK        = 1 << 10;
        const FSCK                   = 1 << 11;
        const NO_PARTITION_TABLE     = 1 << 12;
        const VERITY_SHARE           = 1 << 13;
        const MKDIR                  = 1 << 14;
        const USR_NO_ROOT            = 1 << 15;
        const REQUIRE_ROOT           = 1 << 16;
        const MOUNT_READ_ONLY        = 1 << 17;
        const GROWFS                 = 1 << 18;
        const MOUNT_IDMAPPED         = 1 << 19;
        const ADD_PARTITION_DEVICES  = 1 << 20;
        const PIN_PARTITION_DEVICES  = 1 << 21;
        const RELAX_EXTENSION_CHECK  = 1 << 22;
        const DISKSEQ_DEVNODE        = 1 << 23;
        const ALLOW_EMPTY            = 1 << 24;
        const TRY_ATOMIC_MOUNT_EXCHANGE = 1 << 25;
        const ALLOW_USERSPACE_VERITY = 1 << 26;
        const ALLOW_INTERACTIVE_AUTH = 1 << 27;
        const FOREIGN_UID            = 1 << 28;
        const IDENTITY_UID           = 1 << 29;
    }
}

impl DissectImageFlags {
    /// Convenience alias for read-only device + read-only mount.
    pub const READ_ONLY: DissectImageFlags =
        DissectImageFlags::DEVICE_READ_ONLY.union(DissectImageFlags::MOUNT_READ_ONLY);

    /// Convenience alias for any discard mode.
    pub const DISCARD_ANY: DissectImageFlags = DissectImageFlags::DISCARD_ON_LOOP
        .union(DissectImageFlags::DISCARD)
        .union(DissectImageFlags::DISCARD_ON_CRYPTO);
}

bitflags::bitflags! {
    /// Partition protection policy flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PartitionPolicyFlags: u32 {
        const ABSENT                 = 1 << 0;
        const UNUSED                 = 1 << 1;
        const UNPROTECTED            = 1 << 2;
        const ENCRYPTED              = 1 << 3;
        const ENCRYPTED_WITH_INTEGRITY = 1 << 4;
        const VERITY                 = 1 << 5;
        const SIGNED                 = 1 << 6;
        const READ_ONLY_ON           = 1 << 7;
        const READ_ONLY_OFF          = 1 << 8;
        const GROWFS_ON              = 1 << 9;
        const GROWFS_OFF             = 1 << 10;
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can arise during image dissection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DissectError {
    /// No suitable partition table or filesystem found.
    NoPackage,
    /// Root hash specified but no matching root/verity partition found.
    AddrNotAvail,
    /// No suitable root partition found.
    NoDevice,
    /// Multiple generic root partitions – ambiguous.
    NotUnique,
    /// Image does not match image policy.
    Refused,
    /// Partitioned image combined with external verity data.
    BadRequest,
    /// Block device lacks partition scanning.
    ProtocolNotSupported,
    /// No usable partitions found (and DISSECT_IMAGE_REFUSE_EMPTY set).
    NoMessage,
    /// Ambiguous filesystem superblock.
    NotClean,
    /// Image is not a block device.
    NotBlock,
    /// Dissecting images not supported (compiled without blkid).
    NotSupported,
    /// Image fails os-release / extension-release validation.
    NoMedium,
    /// Root and usr have different architectures.
    Remote,
    /// General I/O or OS error with an errno-like code.
    Io(i32),
    /// Filesystem probing returned an ambiguous result.
    AmbiguousFilesystem,
    /// Generic error with description.
    Other(String),
}

impl std::fmt::Display for DissectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DissectError::NoPackage => write!(f, "no suitable partition table or filesystem found"),
            DissectError::AddrNotAvail => {
                write!(f, "no root/usr partition for specified hash found")
            }
            DissectError::NoDevice => write!(f, "no suitable root partition found"),
            DissectError::NotUnique => write!(f, "multiple suitable root partitions found"),
            DissectError::Refused => write!(f, "image does not match image policy"),
            DissectError::BadRequest => {
                write!(f, "partitioned image combined with external verity data")
            }
            DissectError::ProtocolNotSupported => {
                write!(f, "block device lacks partition scanning support")
            }
            DissectError::NoMessage => write!(f, "no usable partitions found"),
            DissectError::NotClean => write!(f, "ambiguous filesystem superblock"),
            DissectError::NotBlock => write!(f, "image is not a block device"),
            DissectError::NotSupported => write!(f, "dissecting images not supported"),
            DissectError::NoMedium => write!(f, "image fails os-release validation"),
            DissectError::Remote => write!(f, "root and usr have different architectures"),
            DissectError::Io(code) => write!(f, "I/O error (errno={})", code),
            DissectError::AmbiguousFilesystem => write!(f, "ambiguous filesystem superblock"),
            DissectError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DissectError {}

// ── Data structures ───────────────────────────────────────────────────────

/// A single partition discovered inside a disk image.
#[derive(Debug, Clone)]
pub struct DissectedPartition {
    /// Whether this partition was found in the image.
    pub found: bool,
    /// Whether this partition was found but ignored by policy.
    pub ignored: bool,
    /// Whether the partition is writable.
    pub rw: bool,
    /// Whether to grow the filesystem to fill the partition after mount.
    pub growfs: bool,
    /// Partition number, or -1 for a bare filesystem image.
    pub partno: i32,
    /// Filesystem type (once probed).
    pub fstype: Option<String>,
    /// Device node path (e.g. `/dev/sda1`).
    pub node: Option<String>,
    /// GPT partition label.
    pub label: Option<String>,
    /// Filesystem type after decryption (if applicable).
    pub decrypted_fstype: Option<String>,
    /// Device node path after decryption.
    pub decrypted_node: Option<String>,
    /// Mount options string.
    pub mount_options: Option<String>,
    /// Byte offset of partition within the image.
    pub offset: u64,
    /// Byte size of the partition.
    pub size: u64,
    /// Raw GPT attribute flags.
    pub gpt_flags: u64,
}

impl Default for DissectedPartition {
    fn default() -> Self {
        Self {
            found: false,
            ignored: false,
            rw: false,
            growfs: false,
            partno: -1,
            fstype: None,
            node: None,
            label: None,
            decrypted_fstype: None,
            decrypted_node: None,
            mount_options: None,
            offset: 0,
            size: 0,
            gpt_flags: 0,
        }
    }
}

/// Verity settings for integrity-verified images.
#[derive(Debug, Clone, Default)]
pub struct VeritySettings {
    /// Binary root hash of the verity Merkle tree.
    pub root_hash: Option<Vec<u8>>,
    /// PKCS#7 signature of the root hash.
    pub root_hash_sig: Option<Vec<u8>>,
    /// Path to external verity data file.
    pub data_path: Option<String>,
    /// Which partition these settings apply to (Root or Usr).
    pub designator: PartitionDesignator,
}

impl VeritySettings {
    pub fn new() -> Self {
        Self {
            designator: PartitionDesignator::Invalid,
            ..Default::default()
        }
    }

    /// True if the root hash field is set (non-empty).
    pub fn has_root_hash(&self) -> bool {
        self.root_hash.as_ref().map_or(false, |h| !h.is_empty())
    }

    /// True if the root hash signature field is set.
    pub fn has_root_hash_sig(&self) -> bool {
        self.root_hash_sig.as_ref().map_or(false, |h| !h.is_empty())
    }

    /// True if any verity data has been configured.
    pub fn is_set(&self) -> bool {
        self.has_root_hash() || self.has_root_hash_sig() || self.data_path.is_some()
    }

    /// True if the settings provide sufficient information to cover the given partition.
    ///
    /// Mirrors the C helper `verity_settings_data_covers()`.
    pub fn data_covers(&self, d: PartitionDesignator) -> bool {
        if self.root_hash.is_none() || self.data_path.is_none() {
            return false;
        }
        let matches = match self.designator {
            PartitionDesignator::Invalid => d == PartitionDesignator::Root,
            other => d == other,
        };
        matches && self.has_root_hash() && self.data_path.is_some()
    }
}

/// Per-designator mount options (mirrors the C `MountOptions` struct).
#[derive(Debug, Clone, Default)]
pub struct MountOptions {
    options: std::collections::HashMap<PartitionDesignator, String>,
}

impl MountOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set (and consume) a mount option string for a designator.
    pub fn set(&mut self, d: PartitionDesignator, s: String) {
        self.options.insert(d, s);
    }

    /// Get the mount options for a designator, if any.
    pub fn get(&self, d: PartitionDesignator) -> Option<&str> {
        self.options.get(&d).map(|s| s.as_str())
    }
}

/// Per-designator glob filter for partition labels.
#[derive(Debug, Clone, Default)]
pub struct ImageFilter {
    patterns: std::collections::HashMap<PartitionDesignator, String>,
}

impl ImageFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a glob pattern for a designator.
    pub fn set(&mut self, d: PartitionDesignator, pattern: String) {
        self.patterns.insert(d, pattern);
    }

    /// Test whether a partition passes the filter.
    /// Returns `true` if no filter is configured for the designator, or if the
    /// label matches the glob pattern.
    pub fn test(&self, d: PartitionDesignator, label: Option<&str>) -> bool {
        if d == PartitionDesignator::Invalid {
            return true;
        }
        match self.patterns.get(&d) {
            None => true,
            Some(pattern) => simple_glob(pattern, label.unwrap_or("")),
        }
    }
}

/// The result of dissecting a disk image.
#[derive(Debug, Clone)]
pub struct DissectedImage {
    /// True if any partition is encrypted (crypto_LUKS).
    pub encrypted: bool,
    /// True if the image contains verity hash partitions.
    pub has_verity: bool,
    /// True if the image contains an embedded verity signature.
    pub has_verity_sig: bool,
    /// True if verity is fully specified and usable.
    pub verity_ready: bool,
    /// True if the verity signature is fully specified and usable.
    pub verity_sig_ready: bool,
    /// True if this is a single-filesystem image (no partition table).
    pub single_file_system: bool,
    /// Detected partition table type.
    pub table_type: PartitionTableType,
    /// Sector size used for offset calculations.
    pub sector_size: u32,
    /// Total image size in bytes.
    pub image_size: u64,
    /// Image name derived from the path.
    pub image_name: Option<String>,
    /// Image UUID (GPT disk GUID).
    pub image_uuid: Option<String>,
    /// Discovered partitions, keyed by designator.
    pub partitions: std::collections::HashMap<PartitionDesignator, DissectedPartition>,
}

impl Default for DissectedImage {
    fn default() -> Self {
        Self {
            encrypted: false,
            has_verity: false,
            has_verity_sig: false,
            verity_ready: false,
            verity_sig_ready: false,
            single_file_system: false,
            table_type: PartitionTableType::None,
            sector_size: SECTOR_SIZE_DEFAULT,
            image_size: 0,
            image_name: None,
            image_uuid: None,
            partitions: std::collections::HashMap::new(),
        }
    }
}

impl DissectedImage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: get a partition reference by designator.
    pub fn get(&self, d: PartitionDesignator) -> Option<&DissectedPartition> {
        self.partitions.get(&d)
    }

    /// True if the given designator was found in the image.
    pub fn has_partition(&self, d: PartitionDesignator) -> bool {
        self.partitions.get(&d).map_or(false, |p| p.found)
    }

    /// True if no partitions were found at all.
    pub fn is_empty(&self) -> bool {
        self.partitions.values().all(|p| !p.found)
    }
}

// ── Pure-logic functions ─────────────────────────────────────────────────

/// Determine the list of allowed filesystem types.
///
/// Checks the `SYSTEMD_DISSECT_FILE_SYSTEMS` environment variable first;
/// if unset, returns the built-in default list.
pub fn allowed_fstypes() -> Vec<String> {
    if let Ok(val) = std::env::var(FSTYPES_ENV_VAR) {
        val.split(':').map(String::from).collect()
    } else {
        DEFAULT_ALLOWED_FSTYPES
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }
}

/// Check whether a given filesystem type is allowed for automatic mounting.
///
/// Mirrors the C `dissect_fstype_ok()`.
pub fn dissect_fstype_ok(fstype: &str) -> bool {
    allowed_fstypes().iter().any(|allowed| allowed == fstype)
}

/// Build an auxiliary file path by appending a suffix to the base image path.
///
/// E.g. `("/foo/bar.raw", ".verity")` → `Some("/foo/bar.raw.verity")`.
pub fn build_auxiliary_path(image: &str, suffix: &str) -> Option<String> {
    let path = std::path::Path::new(image);
    let file_name = path.file_name()?.to_str()?;
    Some(
        path.with_file_name(format!("{}{}", file_name, suffix))
            .to_string_lossy()
            .into_owned(),
    )
}

/// Extract an image name from a file path.
///
/// Strips directory components and known suffixes (`.raw`, `.img`, etc.),
/// then validates the result as a sane image name (no path separators,
/// not empty, not "." or "..").
pub fn dissected_image_name_from_path(path: &str) -> Option<String> {
    if path.contains("/../") || path.contains("/./") {
        return None;
    }

    let file_name = std::path::Path::new(path).file_name()?.to_str()?.to_owned();

    let mut name = file_name.as_str();

    // Strip known suffixes, repeating until no more match.
    let suffixes = [".raw", ".img", ".qcow2", ".verity", ".roothash", ".sha256"];
    loop {
        let mut changed = false;
        for suffix in &suffixes {
            if let Some(stripped) = name.strip_suffix(suffix) {
                name = stripped;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Validate: must not be empty, no path separators, not "." or "..".
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return None;
    }

    Some(name.to_owned())
}

/// Probe sector size by scanning for a valid GPT header at multiple offsets.
///
/// Reads `PROBE_READ_SIZE` bytes from `data` and tries sector sizes
/// 512, 1024, 2048, 4096. Returns `Some(sector_size)` if a valid GPT
/// header was found, or `None` if no header could be detected (in which
/// case the caller should fall back to `SECTOR_SIZE_DEFAULT`).
///
/// Returns `Err` if the data is too short or multiple valid headers are
/// found at different offsets.
pub fn probe_sector_size(data: &[u8]) -> Result<Option<u32>, DissectError> {
    if data.len() < PROBE_READ_SIZE {
        return Ok(None);
    }

    let mut found: Option<u32> = None;

    let mut sz: u32 = SECTOR_SIZE_DEFAULT;
    while sz <= SECTOR_SIZE_MAX {
        let offset = sz as usize;
        if offset + 8 > data.len() {
            sz <<= 1;
            continue;
        }
        if &data[offset..offset + 8] == GPT_HEADER_SIGNATURE {
            if found.is_some() {
                return Err(DissectError::NotUnique);
            }
            found = Some(sz);
        }
        sz <<= 1;
    }

    Ok(found)
}

/// Check GPT partition flags for unexpected bits.
///
/// Masks away known-good flags (required partition, no-block-io, bios-bootable,
/// plus any caller-supplied `supported` bits) and returns a list of unexpected
/// flag values, if any.
pub fn check_partition_flags(_node: &str, pflags: u64, supported: u64) -> Vec<u64> {
    let mask = supported
        | GPT_FLAG_REQUIRED_PARTITION
        | GPT_FLAG_NO_BLOCK_IO_PROTOCOL
        | GPT_FLAG_LEGACY_BIOS_BOOTABLE;

    let unexpected = pflags & !mask;
    let mut result = Vec::new();
    if unexpected != 0 {
        for i in 0..64 {
            let bit = 1u64 << i;
            if (unexpected & bit != 0) {
                result.push(bit);
            }
        }
    }
    result
}

/// Compare two architecture preferences.
///
/// Returns:
/// - `0` if equal,
/// - positive if `a` is preferred,
/// - negative if `b` is preferred.
///
/// Native architecture is always preferred.
pub fn compare_arch(a: i32, b: i32, native: i32) -> i32 {
    if a == b {
        return 0;
    }
    if a == native {
        return 1;
    }
    if b == native {
        return -1;
    }
    0
}

/// Build a partition device node name from the whole-disk device name.
///
/// E.g. `/dev/sda` partition 7 → `/dev/sda7`; `/dev/loop0` partition 5 → `/dev/loop0p5`.
/// If `nr` is negative the whole-disk name is returned unchanged.
pub fn make_partition_devname(whole_devname: &str, nr: i32) -> String {
    if nr < 0 {
        return whole_devname.to_owned();
    }
    let last_char = whole_devname.chars().last().unwrap_or('\0');
    if last_char.is_ascii_digit() {
        format!("{}p{}", whole_devname, nr)
    } else {
        format!("{}{}", whole_devname, nr)
    }
}

/// Build a diskseq-based partition device node name.
///
/// E.g. diskseq=42, nr=7 → `/dev/disk/by-diskseq/42-part7`.
pub fn make_diskseq_devname(diskseq: u64, nr: i32) -> String {
    if nr < 0 {
        format!("/dev/disk/by-diskseq/{}", diskseq)
    } else {
        format!("/dev/disk/by-diskseq/{}-part{}", diskseq, nr)
    }
}

/// Parse a minimal LUKS2 header from a byte slice and check for integrity protection.
///
/// Returns:
/// - `Ok(true)` if the partition is a LUKS2 volume with integrity protection,
/// - `Ok(false)` if the partition is LUKS2 but without integrity (or header can't be fully parsed),
/// - `Ok(false)` when the partition is not LUKS2.
/// - `Err` for malformed LUKS2 metadata.
///
/// This is a safe, pure Rust reimplementation of the C `partition_is_luks2_integrity()`.
pub fn partition_is_luks2_integrity(data: &[u8]) -> Result<bool, DissectError> {
    if data.len() < 10 {
        return Err(DissectError::Other(
            "partition too small for LUKS header".into(),
        ));
    }

    // Check magic.
    if &data[..LUKS2_MAGIC.len()] != LUKS2_MAGIC {
        return Ok(false);
    }

    // Parse version (big-endian u16 at offset 6).
    let version = u16::from_be_bytes([data[6], data[7]]);
    if version != 2 {
        return Ok(false);
    }

    // Parse header length (big-endian u64 at offset 8).
    if data.len() < 16 {
        return Err(DissectError::Other("LUKS header truncated".into()));
    }
    let hdr_len = u64::from_be_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    if hdr_len <= LUKS2_FIXED_HDR_SIZE {
        return Err(DissectError::Other("invalid LUKS header length".into()));
    }

    const LUKS2_JSON_MAX: u64 = 16 * 1024 * 1024;
    if hdr_len - LUKS2_FIXED_HDR_SIZE > LUKS2_JSON_MAX {
        return Err(DissectError::Other("LUKS JSON header is too large".into()));
    }

    let json_len = (hdr_len - LUKS2_FIXED_HDR_SIZE) as usize;
    let json_start = LUKS2_FIXED_HDR_SIZE as usize;
    if data.len() < json_start + json_len {
        return Err(DissectError::Other("LUKS JSON header truncated".into()));
    }

    // Extract JSON portion.
    let json_bytes = &data[json_start..json_start + json_len];
    let json_str = std::str::from_utf8(json_bytes).unwrap_or("");

    // Minimal JSON parsing – look for "integrity" inside "segments".
    // We don't need a full JSON parser for this; just check for the key.
    if let Some(segments_start) = json_str.find("\"segments\"") {
        let rest = &json_str[segments_start..];
        // Count occurrences of "integrity" after "segments" in each segment object.
        // If every segment has an integrity section with a non-"none" type, return true.
        let has_segments_content = rest.find('{').is_some();
        if !has_segments_content {
            return Ok(false);
        }
        // Check if integrity is present.
        // A simplified heuristic: if the string contains "integrity" key after segments.
        let after_segments = &rest[rest.find('{').unwrap_or(0)..];
        if after_segments.contains("\"integrity\"") {
            // Check if the type is not "none".
            // Look for the pattern: "type": "none"
            if let Some(integrity_pos) = after_segments.find("\"integrity\"") {
                let after_integrity = &after_segments[integrity_pos..];
                // Check within the next ~200 chars for "type" followed by "none".
                let search_window = &after_integrity[..after_integrity.len().min(200)];
                if search_window.contains("\"type\"") && search_window.contains("\"none\"") {
                    return Ok(false);
                }
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Parse verity signature JSON data from a partition and extract the root hash.
///
/// The expected JSON format is:
/// ```json
/// { "rootHash": "<hex>", "signature": "<base64>" }
/// ```
///
/// Returns `(root_hash_bytes, signature_bytes)` on success.
pub fn acquire_sig_for_roothash(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DissectError> {
    if data.is_empty() {
        return Err(DissectError::Other("empty signature data".into()));
    }

    if data.len() > MAX_VERITY_SIG_PARTITION_SIZE as usize {
        return Err(DissectError::Other(
            "verity signature partition larger than 4 MiB".into(),
        ));
    }

    // Check for embedded NUL bytes (not allowed).
    if let Some(nul_pos) = data.iter().position(|&b| b == 0) {
        // Everything after the first NUL must also be NUL.
        if !data[nul_pos + 1..].iter().all(|&b| b == 0) {
            return Err(DissectError::Other(
                "signature data contains embedded NUL byte".into(),
            ));
        }
    }

    let json_str = std::str::from_utf8(data)
        .map_err(|_| DissectError::Other("verity signature data is not valid UTF-8".into()))?;

    // Minimal JSON parsing: extract "rootHash" and "signature" values.
    let root_hash_hex = extract_json_string(json_str, "rootHash")
        .ok_or_else(|| DissectError::Other("missing 'rootHash' field".into()))?;

    let signature_b64 = extract_json_string(json_str, "signature")
        .ok_or_else(|| DissectError::Other("missing 'signature' field".into()))?;

    // Decode hex root hash.
    let root_hash = hex_decode(&root_hash_hex)
        .map_err(|e| DissectError::Other(format!("invalid rootHash hex: {}", e)))?;

    // Decode base64 signature.
    let signature = base64_decode(&signature_b64)
        .map_err(|e| DissectError::Other(format!("invalid signature base64: {}", e)))?;

    Ok((root_hash, signature))
}

/// Generate a human-readable error message for a dissection result.
///
/// Mirrors the C `dissect_log_error()`.
pub fn dissect_log_error(r: &Result<(), DissectError>, name: &str) -> String {
    match r {
        Ok(()) => String::new(),
        Err(DissectError::NoPackage) => {
            format!(
                "{}: Couldn't identify a suitable partition table or file system.",
                name
            )
        }
        Err(DissectError::NoMedium) => {
            format!(
                "{}: The image does not pass os-release/extension-release validation.",
                name
            )
        }
        Err(DissectError::AddrNotAvail) => {
            format!(
                "{}: No root/usr partition for specified root/usr hash found.",
                name
            )
        }
        Err(DissectError::Remote) => {
            format!(
                "{}: Found root and usr partitions with different architectures.",
                name
            )
        }
        Err(DissectError::NotUnique) => {
            format!(
                "{}: Multiple suitable root partitions found in image.",
                name
            )
        }
        Err(DissectError::NoDevice) => {
            format!("{}: No suitable root partition found in image.", name)
        }
        Err(DissectError::ProtocolNotSupported) => {
            format!("{}: Block device has partition scanning turned off.", name)
        }
        Err(DissectError::NotBlock) => {
            format!("{}: Image is not a block device.", name)
        }
        Err(DissectError::Refused) => {
            format!("{}: Image does not match image policy.", name)
        }
        Err(DissectError::NoMessage) => {
            format!("{}: No suitable partitions found.", name)
        }
        Err(DissectError::NotClean) => {
            format!(
                "{}: Partition with ambiguous file system superblock signature found.",
                name
            )
        }
        Err(e) => format!("{}: Cannot dissect image: {}", name, e),
    }
}

/// Pick mount options for a partition based on its designator and filesystem type.
///
/// Returns `(options_string, ms_flags)`.
/// `ms_flags` uses Linux mount(2) flag values (MS_NODEV = 0x4, MS_NOSUID = 0x2, etc.).
pub fn partition_pick_mount_options(
    d: PartitionDesignator,
    fstype: Option<&str>,
    rw: bool,
    discard: bool,
) -> (String, u64) {
    const MS_NODEV: u64 = 0x4;
    const MS_RDONLY: u64 = 0x1;
    const MS_NOSUID: u64 = 0x2;
    const MS_NOEXEC: u64 = 0x8;
    const MS_NOSYMFOLLOW: u64 = 0x100;

    let mut flags = MS_NODEV;
    let mut options_parts: Vec<String> = Vec::new();

    if !rw {
        flags |= MS_RDONLY;
    }

    match d {
        PartitionDesignator::Esp | PartitionDesignator::Xbootldr => {
            flags |= MS_NOSUID | MS_NOEXEC | MS_NOSYMFOLLOW;
            // ESP/XBOOTLDR is almost certainly VFAT.
            if fstype.map_or(true, |f| f.eq_ignore_ascii_case("vfat")) {
                options_parts.push("fmask=0177,dmask=0077".to_owned());
            }
        }
        PartitionDesignator::Tmp => {
            flags |= MS_NOSUID;
        }
        _ => {}
    }

    // Read-only journaling filesystems need "norecovery" to truly stop writing.
    if !rw {
        if let Some(fs) = fstype {
            if matches!(
                fs.to_lowercase().as_str(),
                "ext4" | "ext3" | "ext2" | "xfs" | "btrfs"
            ) {
                options_parts.push("norecovery".to_owned());
            }
        }
    }

    if discard {
        if let Some(fs) = fstype {
            if matches!(
                fs.to_lowercase().as_str(),
                "ext4" | "xfs" | "btrfs" | "f2fs" | "vfat"
            ) {
                options_parts.push("discard".to_owned());
            }
        }
    }

    let options = if options_parts.is_empty() {
        String::new()
    } else {
        options_parts.join(",")
    };

    (options, flags)
}

/// Check whether a user-ID mapping is needed.
///
/// A mapping is needed when `uid_shift` is non-zero or `uid_range` does not
/// cover the full 32-bit UID space.
pub fn need_user_mapping(uid_shift: u32, uid_range: u32) -> bool {
    uid_shift != 0 || uid_range != u32::MAX
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Simple glob matching supporting `*`, `?`, and `[abc]`/`[!abc]`/`[a-z]`.
///
/// Mirrors fnmatch(3) with FNM_NOESCAPE semantics.
fn simple_glob(pattern: &str, string: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = string.chars().collect();
    glob_match_impl(&p, &s)
}

fn glob_match_impl(pattern: &[char], string: &[char]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < string.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '*' => {
                    star_pi = pi;
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                '[' => {
                    if let Some(result) = match_char_class(&pattern[pi..], string[si]) {
                        pi = result.0;
                        if result.1 {
                            si += 1;
                            continue;
                        }
                    } else if pattern[pi] == string[si] {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                c if c == string[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }

        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
            continue;
        }

        return false;
    }

    // Consume trailing stars.
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

fn match_char_class(pattern: &[char], c: char) -> Option<(usize, bool)> {
    if pattern.is_empty() || pattern[0] != '[' {
        return None;
    }

    let mut i = 1;
    let negate = if i < pattern.len() && pattern[i] == '!' {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    while i < pattern.len() && pattern[i] != ']' {
        if i + 2 < pattern.len() && pattern[i + 1] == '-' {
            if c >= pattern[i] && c <= pattern[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if pattern[i] == c {
                matched = true;
            }
            i += 1;
        }
    }

    if i < pattern.len() && pattern[i] == ']' {
        Some((i + 1, matched != negate))
    } else {
        None
    }
}

/// Extract a string value from a JSON object by key.
///
/// Very minimal JSON parser – only handles flat string values at the top level.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let key_pattern = format!("\"{}\"", key);
    let key_pos = json.find(&key_pattern)?;
    let after_key = &json[key_pos + key_pattern.len()..];

    // Skip whitespace and colon.
    let rest = after_key.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();

    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Decode a hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd length".into());
    }
    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at position {}: {}", i, e))?;
        result.push(byte);
    }
    Ok(result)
}

/// Decode a base64 string to bytes (standard alphabet, no padding).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // Use a simple base64 decoder via a lookup table.
    const DECODE_TABLE: &[i8; 128] = &[
        // 0–15
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16–31
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        // 32–47  ('+' = 62)
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        // 48–63  ('0'–'9' = 52–61)
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        // 64–79  ('A'–'O' = 0–14)
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        // 80–95  ('P'–'Z' = 15–25)
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        // 96–111 ('a'–'o' = 26–40)
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        // 112–127 ('p'–'z' = 41–51)
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();

    let mut result = Vec::with_capacity(cleaned.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;

    for &byte in &cleaned {
        let val = if (byte as usize) < DECODE_TABLE.len() {
            DECODE_TABLE[byte as usize]
        } else {
            -1
        };
        if val < 0 {
            return Err(format!("invalid base64 character: {}", byte as char));
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    Ok(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── allowed_fstypes / dissect_fstype_ok ────────────────────────────────

    #[test]
    fn test_default_allowed_fstypes() {
        // When the env var is not set (normal test env), we get the defaults.
        let list = allowed_fstypes();
        assert!(list.contains(&"ext4".to_owned()));
        assert!(list.contains(&"xfs".to_owned()));
        assert!(list.contains(&"btrfs".to_owned()));
        assert!(list.contains(&"vfat".to_owned()));
        assert!(list.contains(&"squashfs".to_owned()));
        assert!(list.contains(&"erofs".to_owned()));
        assert!(list.contains(&"f2fs".to_owned()));
        assert_eq!(list.len(), 7);
    }

    #[test]
    fn test_dissect_fstype_ok_known() {
        assert!(dissect_fstype_ok("ext4"));
        assert!(dissect_fstype_ok("xfs"));
        assert!(dissect_fstype_ok("vfat"));
        assert!(dissect_fstype_ok("btrfs"));
        assert!(dissect_fstype_ok("squashfs"));
        assert!(dissect_fstype_ok("erofs"));
        assert!(dissect_fstype_ok("f2fs"));
    }

    #[test]
    fn test_dissect_fstype_ok_unknown() {
        assert!(!dissect_fstype_ok("ntfs"));
        assert!(!dissect_fstype_ok("exfat"));
        assert!(!dissect_fstype_ok(""));
        assert!(!dissect_fstype_ok("ext4\n"));
    }

    // ── PartitionDesignator ────────────────────────────────────────────────

    #[test]
    fn test_designator_from_gpt_uuid() {
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid(GPT_UUID_ROOT),
            Some(PartitionDesignator::Root)
        );
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid(GPT_UUID_USR),
            Some(PartitionDesignator::Usr)
        );
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid(GPT_UUID_ESP),
            Some(PartitionDesignator::Esp)
        );
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid(GPT_UUID_SWAP),
            Some(PartitionDesignator::Swap)
        );
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid(GPT_UUID_ROOT_VERITY),
            Some(PartitionDesignator::RootVerity)
        );
        assert_eq!(
            PartitionDesignator::from_gpt_type_uuid("00000000-0000-0000-0000-000000000000"),
            None,
        );
    }

    #[test]
    fn test_designator_verity_relationships() {
        assert_eq!(
            PartitionDesignator::RootVerity.verity_to_data(),
            PartitionDesignator::Root
        );
        assert_eq!(
            PartitionDesignator::UsrVeritySig.verity_to_data(),
            PartitionDesignator::Usr
        );
        assert_eq!(
            PartitionDesignator::Root.verity_hash_of(),
            PartitionDesignator::RootVerity
        );
        assert_eq!(
            PartitionDesignator::Usr.verity_sig_of(),
            PartitionDesignator::UsrVeritySig
        );
    }

    #[test]
    fn test_designator_is_verity() {
        assert!(PartitionDesignator::RootVerity.is_verity());
        assert!(PartitionDesignator::UsrVerity.is_verity());
        assert!(PartitionDesignator::RootVeritySig.is_verity());
        assert!(PartitionDesignator::UsrVeritySig.is_verity());
        assert!(!PartitionDesignator::Root.is_verity());
        assert!(!PartitionDesignator::Esp.is_verity());
    }

    #[test]
    fn test_designator_is_versioned() {
        assert!(PartitionDesignator::Root.is_versioned());
        assert!(PartitionDesignator::Usr.is_versioned());
        assert!(!PartitionDesignator::Home.is_versioned());
        assert!(!PartitionDesignator::Esp.is_versioned());
    }

    // ── FilesystemType ─────────────────────────────────────────────────────

    #[test]
    fn test_filesystem_type_from_name() {
        assert_eq!(FilesystemType::from_name("ext4"), FilesystemType::Ext4);
        assert_eq!(FilesystemType::from_name("XFS"), FilesystemType::Xfs);
        assert_eq!(
            FilesystemType::from_name("crypto_LUKS"),
            FilesystemType::CryptoLuks
        );
        assert_eq!(
            FilesystemType::from_name("DM_verity_hash"),
            FilesystemType::VerityHash
        );
        assert_eq!(
            FilesystemType::from_name("verity_hash_signature"),
            FilesystemType::VerityHashSignature
        );
        assert_eq!(FilesystemType::from_name("swap"), FilesystemType::Swap);
        assert_eq!(FilesystemType::from_name("vfat"), FilesystemType::Vfat);
        assert_eq!(FilesystemType::from_name("fat32"), FilesystemType::Vfat);
        assert_eq!(
            FilesystemType::from_name("foobar"),
            FilesystemType::Unknown("foobar".into())
        );
    }

    #[test]
    fn test_filesystem_type_is_read_only() {
        assert!(FilesystemType::Squashfs.is_read_only());
        assert!(FilesystemType::Erofs.is_read_only());
        assert!(FilesystemType::VerityHash.is_read_only());
        assert!(!FilesystemType::Ext4.is_read_only());
        assert!(!FilesystemType::Vfat.is_read_only());
        assert!(!FilesystemType::CryptoLuks.is_read_only());
    }

    // ── build_auxiliary_path ───────────────────────────────────────────────

    #[test]
    fn test_build_auxiliary_path() {
        assert_eq!(
            build_auxiliary_path("/foo/bar.raw", ".verity"),
            Some("/foo/bar.raw.verity".into())
        );
        assert_eq!(
            build_auxiliary_path("/images/my.img", ".roothash"),
            Some("/images/my.img.roothash".into())
        );
        assert_eq!(
            build_auxiliary_path("file.raw", ".sig"),
            Some("file.raw.sig".into())
        );
        // Path without a filename component.
        assert_eq!(build_auxiliary_path("/", ".verity"), None);
    }

    // ── dissected_image_name_from_path ─────────────────────────────────────

    #[test]
    fn test_dissected_image_name_from_path() {
        assert_eq!(
            dissected_image_name_from_path("/foo/bar.raw"),
            Some("bar".into())
        );
        assert_eq!(
            dissected_image_name_from_path("/images/my.img"),
            Some("my".into())
        );
        assert_eq!(
            dissected_image_name_from_path("/tmp/fedora.raw.verity"),
            Some("fedora".into())
        );
        // Rejects path traversal.
        assert_eq!(dissected_image_name_from_path("/foo/../bar.raw"), None);
        assert_eq!(dissected_image_name_from_path("/foo/./bar.raw"), None);
    }

    // ── make_partition_devname ─────────────────────────────────────────────

    #[test]
    fn test_make_partition_devname() {
        assert_eq!(make_partition_devname("/dev/sda", 1), "/dev/sda1");
        assert_eq!(make_partition_devname("/dev/sda", 12), "/dev/sda12");
        assert_eq!(make_partition_devname("/dev/loop0", 5), "/dev/loop0p5");
        assert_eq!(
            make_partition_devname("/dev/nvme0n1", 12),
            "/dev/nvme0n1p12"
        );
        // Whole disk (negative nr).
        assert_eq!(make_partition_devname("/dev/sda", -1), "/dev/sda");
    }

    #[test]
    fn test_make_diskseq_devname() {
        assert_eq!(make_diskseq_devname(42, 1), "/dev/disk/by-diskseq/42-part1");
        assert_eq!(make_diskseq_devname(7, -1), "/dev/disk/by-diskseq/7");
    }

    // ── check_partition_flags ──────────────────────────────────────────────

    #[test]
    fn test_check_partition_flags_clean() {
        let result = check_partition_flags("/dev/sda1", GPT_FLAG_READ_ONLY, GPT_FLAG_READ_ONLY);
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_partition_flags_unexpected() {
        // Set a high bit that is not in the standard flags.
        let result = check_partition_flags("/dev/sda1", 1 << 50, 0);
        assert!(!result.is_empty());
        assert!(result.contains(&(1u64 << 50)));
    }

    // ── probe_sector_size ──────────────────────────────────────────────────

    #[test]
    fn test_probe_sector_size_empty() {
        // Data too short → None.
        assert_eq!(probe_sector_size(&[0u8; 100]).unwrap(), None);
    }

    #[test]
    fn test_probe_sector_size_no_gpt() {
        // Enough data but no GPT signature at any offset.
        let data = vec![0u8; PROBE_READ_SIZE];
        assert_eq!(probe_sector_size(&data).unwrap(), None);
    }

    #[test]
    fn test_probe_sector_size_512() {
        let mut data = vec![0u8; PROBE_READ_SIZE];
        // Place GPT signature at offset 512.
        data[512..520].copy_from_slice(GPT_HEADER_SIGNATURE);
        assert_eq!(probe_sector_size(&data).unwrap(), Some(512));
    }

    #[test]
    fn test_probe_sector_size_4096() {
        let mut data = vec![0u8; PROBE_READ_SIZE];
        // Place GPT signature at offset 4096.
        data[4096..4104].copy_from_slice(GPT_HEADER_SIGNATURE);
        assert_eq!(probe_sector_size(&data).unwrap(), Some(4096));
    }

    #[test]
    fn test_probe_sector_size_ambiguous() {
        let mut data = vec![0u8; PROBE_READ_SIZE];
        // Place GPT signature at both 512 and 4096 → ambiguous.
        data[512..520].copy_from_slice(GPT_HEADER_SIGNATURE);
        data[4096..4104].copy_from_slice(GPT_HEADER_SIGNATURE);
        assert!(matches!(
            probe_sector_size(&data),
            Err(DissectError::NotUnique)
        ));
    }

    // ── partition_is_luks2_integrity ───────────────────────────────────────

    #[test]
    fn test_luks2_not_luks() {
        let data = [0u8; 32];
        assert!(partition_is_luks2_integrity(&data).is_err());
    }

    #[test]
    fn test_luks2_bad_magic() {
        let mut data = vec![0u8; 32];
        data[..6].copy_from_slice(b"FOOBAR");
        assert!(partition_is_luks2_integrity(&data).is_err());
    }

    #[test]
    fn test_luks2_wrong_version() {
        let mut data = vec![0u8; 32];
        data[..6].copy_from_slice(LUKS2_MAGIC);
        data[6..8].copy_from_slice(&1u16.to_be_bytes()); // version 1
        assert!(partition_is_luks2_integrity(&data).is_err());
    }

    #[test]
    fn test_luks2_valid_v2_no_json() {
        let mut data = vec![0u8; 0x2000];
        data[..6].copy_from_slice(LUKS2_MAGIC);
        data[6..8].copy_from_slice(&2u16.to_be_bytes());
        data[8..16].copy_from_slice(&0x2000u64.to_be_bytes()); // hdr_len = 0x2000
        // No JSON with integrity → returns false (LUKS2 but no integrity).
        assert_eq!(partition_is_luks2_integrity(&data).unwrap(), false);
    }

    #[test]
    fn test_luks2_with_integrity() {
        let mut data = vec![0u8; 0x2000];
        data[..6].copy_from_slice(LUKS2_MAGIC);
        data[6..8].copy_from_slice(&2u16.to_be_bytes());
        data[8..16].copy_from_slice(&0x2000u64.to_be_bytes()); // hdr_len
        // Write JSON with integrity section.
        let json = r#"{"segments": {"0": {"integrity": {"type": "hmac"}}}}"#;
        let json_start = LUKS2_FIXED_HDR_SIZE as usize;
        let json_end = json_start + json.len().min(data.len() - json_start);
        data[json_start..json_end].copy_from_slice(&json.as_bytes()[..json_end - json_start]);
        assert_eq!(partition_is_luks2_integrity(&data).unwrap(), true);
    }

    // ── acquire_sig_for_roothash ───────────────────────────────────────────

    #[test]
    fn test_acquire_sig_for_roothash_valid() {
        // rootHash = "aabb" → bytes [0xaa, 0xbb]
        // signature = "AAAA" → base64 decode
        let json = r#"{"rootHash": "aabbccdd", "signature": "QUFBQQ=="}"#;
        let (root_hash, sig) = acquire_sig_for_roothash(json.as_bytes()).unwrap();
        assert_eq!(root_hash, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(sig, vec![0x41, 0x41, 0x41, 0x41]);
    }

    #[test]
    fn test_acquire_sig_for_roothash_missing_field() {
        let json = r#"{"rootHash": "aabb"}"#;
        assert!(acquire_sig_for_roothash(json.as_bytes()).is_err());
    }

    #[test]
    fn test_acquire_sig_for_roothash_empty() {
        assert!(acquire_sig_for_roothash(&[]).is_err());
    }

    #[test]
    fn test_acquire_sig_for_roothash_nul_embedded() {
        let mut data = b"{\"rootHash\": \"aa\"}".to_vec();
        data.push(0);
        data.extend_from_slice(b"garbage");
        assert!(acquire_sig_for_roothash(&data).is_err());
    }

    // ── compare_arch ───────────────────────────────────────────────────────

    #[test]
    fn test_compare_arch() {
        let native = 1; // x86-64 or whatever
        assert_eq!(compare_arch(1, 1, native), 0);
        assert_eq!(compare_arch(1, 2, native), 1); // a == native → preferred
        assert_eq!(compare_arch(2, 1, native), -1); // b == native → preferred
        assert_eq!(compare_arch(2, 3, native), 0); // neither native → equal
    }

    // ── partition_pick_mount_options ───────────────────────────────────────

    #[test]
    fn test_mount_options_esp_ro() {
        let (opts, flags) =
            partition_pick_mount_options(PartitionDesignator::Esp, Some("vfat"), false, false);
        assert!(flags & 0x1 != 0); // MS_RDONLY
        assert!(flags & 0x2 != 0); // MS_NOSUID
        assert!(flags & 0x8 != 0); // MS_NOEXEC
        assert!(opts.contains("fmask=0177"));
        assert!(opts.contains("dmask=0077"));
    }

    #[test]
    fn test_mount_options_root_rw() {
        let (opts, flags) =
            partition_pick_mount_options(PartitionDesignator::Root, Some("ext4"), true, false);
        assert!(flags & 0x1 == 0); // not MS_RDONLY
        assert!(!opts.contains("norecovery"));
    }

    #[test]
    fn test_mount_options_root_ro_norecovery() {
        let (opts, _flags) =
            partition_pick_mount_options(PartitionDesignator::Root, Some("ext4"), false, false);
        assert!(opts.contains("norecovery"));
    }

    #[test]
    fn test_mount_options_discard() {
        let (opts, _flags) =
            partition_pick_mount_options(PartitionDesignator::Root, Some("ext4"), true, true);
        assert!(opts.contains("discard"));
    }

    // ── need_user_mapping ──────────────────────────────────────────────────

    #[test]
    fn test_need_user_mapping() {
        assert!(need_user_mapping(1000, 65536));
        assert!(need_user_mapping(1, u32::MAX));
        assert!(!need_user_mapping(0, u32::MAX));
    }

    // ── simple_glob ────────────────────────────────────────────────────────

    #[test]
    fn test_simple_glob() {
        assert!(simple_glob("*.txt", "file.txt"));
        assert!(simple_glob("*.txt", ".txt"));
        assert!(!simple_glob("*.txt", "file.rs"));
        assert!(simple_glob("test", "test"));
        assert!(!simple_glob("test", "other"));
        assert!(simple_glob("?", "a"));
        assert!(!simple_glob("?", "ab"));
        assert!(simple_glob("[abc]", "a"));
        assert!(!simple_glob("[abc]", "d"));
        assert!(simple_glob("[!abc]", "d"));
        assert!(!simple_glob("[!abc]", "a"));
        assert!(simple_glob("*", "anything"));
    }

    // ── ImageFilter ────────────────────────────────────────────────────────

    #[test]
    fn test_image_filter_no_filter() {
        let f = ImageFilter::new();
        assert!(f.test(PartitionDesignator::Root, Some("label")));
        assert!(f.test(PartitionDesignator::Invalid, None));
    }

    #[test]
    fn test_image_filter_with_pattern() {
        let mut f = ImageFilter::new();
        f.set(PartitionDesignator::Root, "fedora*".into());
        assert!(f.test(PartitionDesignator::Root, Some("fedora-39")));
        assert!(!f.test(PartitionDesignator::Root, Some("ubuntu")));
    }

    // ── VeritySettings ─────────────────────────────────────────────────────

    #[test]
    fn test_verity_settings_data_covers() {
        let mut v = VeritySettings::new();
        assert!(!v.data_covers(PartitionDesignator::Root));

        v.root_hash = Some(vec![0u8; 32]);
        v.data_path = Some("/verity.data".into());
        assert!(v.data_covers(PartitionDesignator::Root));
        assert!(!v.data_covers(PartitionDesignator::Usr));

        v.designator = PartitionDesignator::Usr;
        assert!(v.data_covers(PartitionDesignator::Usr));
        assert!(!v.data_covers(PartitionDesignator::Root));
    }

    #[test]
    fn test_verity_settings_is_set() {
        let v = VeritySettings::default();
        assert!(!v.is_set());

        let mut v2 = VeritySettings::default();
        v2.root_hash = Some(vec![0u8; 32]);
        assert!(v2.is_set());

        let mut v3 = VeritySettings::default();
        v3.data_path = Some("/foo".into());
        assert!(v3.is_set());
    }

    // ── DissectImageFlags ──────────────────────────────────────────────────

    #[test]
    fn test_dissect_flags_constants() {
        assert!(DissectImageFlags::READ_ONLY.contains(DissectImageFlags::DEVICE_READ_ONLY));
        assert!(DissectImageFlags::READ_ONLY.contains(DissectImageFlags::MOUNT_READ_ONLY));
        assert!(DissectImageFlags::DISCARD_ANY.contains(DissectImageFlags::DISCARD));
        assert!(DissectImageFlags::DISCARD_ANY.contains(DissectImageFlags::DISCARD_ON_LOOP));
    }

    // ── DissectedImage ─────────────────────────────────────────────────────

    #[test]
    fn test_dissected_image_default() {
        let img = DissectedImage::new();
        assert!(!img.encrypted);
        assert!(!img.has_verity);
        assert!(img.is_empty());
        assert_eq!(img.sector_size, SECTOR_SIZE_DEFAULT);
    }

    #[test]
    fn test_dissected_image_has_partition() {
        let mut img = DissectedImage::new();
        assert!(!img.has_partition(PartitionDesignator::Root));
        img.partitions.insert(
            PartitionDesignator::Root,
            DissectedPartition {
                found: true,
                ..Default::default()
            },
        );
        assert!(img.has_partition(PartitionDesignator::Root));
        assert!(!img.is_empty());
    }

    // ── dissect_log_error ──────────────────────────────────────────────────

    #[test]
    fn test_dissect_log_error_success() {
        let msg = dissect_log_error(&Ok(()), "test.img");
        assert!(msg.is_empty());
    }

    #[test]
    fn test_dissect_log_error_no_package() {
        let msg = dissect_log_error(&Err(DissectError::NoPackage), "test.img");
        assert!(msg.contains("Couldn't identify"));
        assert!(msg.contains("test.img"));
    }

    #[test]
    fn test_dissect_log_error_refused() {
        let msg = dissect_log_error(&Err(DissectError::Refused), "test.img");
        assert!(msg.contains("image policy"));
    }

    // ── hex_decode / base64_decode ─────────────────────────────────────────

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("aabb").unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(hex_decode("AABB").unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("a").is_err());
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("QUFB").unwrap(), b"AAA");
        assert_eq!(base64_decode("QUFBQQ==").unwrap(), b"AAAA");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert!(base64_decode("!!!!").is_err());
    }
}
