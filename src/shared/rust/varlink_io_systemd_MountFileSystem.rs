// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.MountFileSystem.c
//
// Varlink interface definition for io.systemd.MountFileSystem.
//
// APIs for unprivileged mounting of disk images and directories,
// including partition enumeration, UID/GID mapping, and directory creation.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.MountFileSystem";

pub const METHOD_MOUNT_IMAGE: &str = "MountImage";
pub const METHOD_MOUNT_DIRECTORY: &str = "MountDirectory";
pub const METHOD_MAKE_DIRECTORY: &str = "MakeDirectory";

pub const METHODS: &[&str] = &[
    METHOD_MOUNT_IMAGE,
    METHOD_MOUNT_DIRECTORY,
    METHOD_MAKE_DIRECTORY,
];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Partition designator type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionDesignator {
    Root,
    Usr,
    Home,
    Srv,
    Esp,
    Xbootldr,
    Swap,
    RootVerity,
    UsrVerity,
    RootVeritySig,
    UsrVeritySig,
    Tmp,
    Var,
}

impl PartitionDesignator {
    pub const ALL: &[PartitionDesignator] = &[
        PartitionDesignator::Root,
        PartitionDesignator::Usr,
        PartitionDesignator::Home,
        PartitionDesignator::Srv,
        PartitionDesignator::Esp,
        PartitionDesignator::Xbootldr,
        PartitionDesignator::Swap,
        PartitionDesignator::RootVerity,
        PartitionDesignator::UsrVerity,
        PartitionDesignator::RootVeritySig,
        PartitionDesignator::UsrVeritySig,
        PartitionDesignator::Tmp,
        PartitionDesignator::Var,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            PartitionDesignator::Root => "root",
            PartitionDesignator::Usr => "usr",
            PartitionDesignator::Home => "home",
            PartitionDesignator::Srv => "srv",
            PartitionDesignator::Esp => "esp",
            PartitionDesignator::Xbootldr => "xbootldr",
            PartitionDesignator::Swap => "swap",
            PartitionDesignator::RootVerity => "root_verity",
            PartitionDesignator::UsrVerity => "usr_verity",
            PartitionDesignator::RootVeritySig => "root_verity_sig",
            PartitionDesignator::UsrVeritySig => "usr_verity_sig",
            PartitionDesignator::Tmp => "tmp",
            PartitionDesignator::Var => "var",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "root" => Some(PartitionDesignator::Root),
            "usr" => Some(PartitionDesignator::Usr),
            "home" => Some(PartitionDesignator::Home),
            "srv" => Some(PartitionDesignator::Srv),
            "esp" => Some(PartitionDesignator::Esp),
            "xbootldr" => Some(PartitionDesignator::Xbootldr),
            "swap" => Some(PartitionDesignator::Swap),
            "root_verity" => Some(PartitionDesignator::RootVerity),
            "usr_verity" => Some(PartitionDesignator::UsrVerity),
            "root_verity_sig" => Some(PartitionDesignator::RootVeritySig),
            "usr_verity_sig" => Some(PartitionDesignator::UsrVeritySig),
            "tmp" => Some(PartitionDesignator::Tmp),
            "var" => Some(PartitionDesignator::Var),
            _ => None,
        }
    }

    /// Whether this is a verity-related partition
    pub fn is_verity(&self) -> bool {
        matches!(
            self,
            PartitionDesignator::RootVerity
                | PartitionDesignator::UsrVerity
                | PartitionDesignator::RootVeritySig
                | PartitionDesignator::UsrVeritySig
        )
    }

    /// Whether this is a data partition (not verity/signature)
    pub fn is_data(&self) -> bool {
        !self.is_verity()
    }
}

/// UID/GID mapping mode for mount operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMapMode {
    /// Map caller's UID to root, nothing else
    Root,
    /// Map foreign UID range to base range (64K users)
    Foreign,
    /// Identity mapping (1:1), limited to 64K users
    Identity,
    /// Determine automatically
    Auto,
}

impl MountMapMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MountMapMode::Root => "root",
            MountMapMode::Foreign => "foreign",
            MountMapMode::Identity => "identity",
            MountMapMode::Auto => "auto",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "root" => Some(MountMapMode::Root),
            "foreign" => Some(MountMapMode::Foreign),
            "identity" => Some(MountMapMode::Identity),
            "auto" => Some(MountMapMode::Auto),
            _ => None,
        }
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Information about a specific partition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    /// Partition designator
    pub designator: PartitionDesignator,
    /// Whether the partition is writable
    pub writable: bool,
    /// Whether the partition can auto-grow
    pub grow_file_system: bool,
    /// Partition number (None if no partition table)
    pub partition_number: Option<i64>,
    /// Target CPU architecture
    pub architecture: Option<String>,
    /// Partition UUID
    pub partition_uuid: Option<String>,
    /// File system type
    pub file_system_type: String,
    /// Partition label
    pub partition_label: Option<String>,
    /// Partition size in bytes
    pub size: i64,
    /// Start offset in bytes
    pub offset: i64,
    /// Mount file descriptor
    pub mount_file_descriptor: i64,
    /// Intended mount points
    pub mount_point: Vec<String>,
}

impl PartitionInfo {
    /// Check if this partition has a mount point assigned
    pub fn has_mount_point(&self) -> bool {
        !self.mount_point.is_empty()
    }

    /// Check if this partition has a known UUID
    pub fn has_uuid(&self) -> bool {
        self.partition_uuid.is_some()
    }
}

/// Input for the MountImage method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountImageInput {
    /// Image file descriptor
    pub image_file_descriptor: i64,
    /// User namespace file descriptor
    pub user_namespace_file_descriptor: Option<i64>,
    /// Mount read-only
    pub read_only: Option<bool>,
    /// Grow file systems before mounting
    pub grow_file_systems: Option<bool>,
    /// Password for encrypted images
    pub password: Option<String>,
    /// Image policy string
    pub image_policy: Option<String>,
    /// Mount options keyed by partition designator
    pub mount_options: Vec<(String, String)>,
    /// Relax extension release checks
    pub relax_extension_release_checks: Option<bool>,
    /// Reuse dm-verity devices with same roothash
    pub verity_sharing: Option<bool>,
    /// dm-verity data file descriptor
    pub verity_data_file_descriptor: Option<i64>,
    /// Expected dm-verity root hash (hex)
    pub verity_root_hash: Option<String>,
    /// dm-verity root hash signature (Base64)
    pub verity_root_hash_signature: Option<String>,
}

impl MountImageInput {
    /// Validate mount image parameters
    pub fn validate(&self) -> Result<(), MountFileSystemError> {
        if self.image_file_descriptor < 0 {
            return Err(MountFileSystemError::BadFileDescriptorFlags {
                parameter: "imageFileDescriptor".into(),
            });
        }
        if let Some(fd) = self.user_namespace_file_descriptor {
            if fd < 0 {
                return Err(MountFileSystemError::BadFileDescriptorFlags {
                    parameter: "userNamespaceFileDescriptor".into(),
                });
            }
        }
        Ok(())
    }
}

/// Output from the MountImage method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountImageOutput {
    /// Prepared partition information
    pub partitions: Vec<PartitionInfo>,
    /// Whether image contains only a single filesystem
    pub single_file_system: bool,
    /// The image policy used
    pub image_policy: String,
    /// Image size in bytes
    pub image_size: i64,
    /// Sector size in bytes
    pub sector_size: i64,
    /// Image name
    pub image_name: Option<String>,
    /// Image UUID
    pub image_uuid: Option<String>,
}

/// Input for the MountDirectory method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountDirectoryInput {
    /// Directory file descriptor
    pub directory_file_descriptor: i64,
    /// User namespace file descriptor
    pub user_namespace_file_descriptor: Option<i64>,
    /// Mount read-only
    pub read_only: Option<bool>,
    /// UID/GID mapping mode
    pub mode: Option<MountMapMode>,
}

impl MountDirectoryInput {
    pub fn validate(&self) -> Result<(), MountFileSystemError> {
        if self.directory_file_descriptor < 0 {
            return Err(MountFileSystemError::BadFileDescriptorFlags {
                parameter: "directoryFileDescriptor".into(),
            });
        }
        Ok(())
    }
}

/// Input for the MakeDirectory method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeDirectoryInput {
    /// Parent directory file descriptor
    pub parent_file_descriptor: i64,
    /// Directory name to create
    pub name: String,
    /// Access mode (suid/sgid/sticky/world-writable masked off)
    pub mode: Option<i64>,
}

impl MakeDirectoryInput {
    pub fn validate(&self) -> Result<(), MountFileSystemError> {
        if self.parent_file_descriptor < 0 {
            return Err(MountFileSystemError::BadFileDescriptorFlags {
                parameter: "parentFileDescriptor".into(),
            });
        }
        if self.name.is_empty() || self.name.contains('/') {
            return Err(MountFileSystemError::RootPartitionNotFound);
        }
        Ok(())
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountFileSystemError {
    /// Disk image is not compatible
    IncompatibleImage,
    /// Multiple suitable root partitions found
    MultipleRootPartitionsFound,
    /// No suitable root partition found
    RootPartitionNotFound,
    /// Image policy disallows mounting
    DeniedByImagePolicy,
    /// Authentication key not available
    KeyNotFound,
    /// Verity setup failed
    VerityFailure,
    /// File descriptor has unexpected flags
    BadFileDescriptorFlags { parameter: String },
}

impl MountFileSystemError {
    pub fn error_id(&self) -> &'static str {
        match self {
            MountFileSystemError::IncompatibleImage => {
                "io.systemd.MountFileSystem.IncompatibleImage"
            }
            MountFileSystemError::MultipleRootPartitionsFound => {
                "io.systemd.MountFileSystem.MultipleRootPartitionsFound"
            }
            MountFileSystemError::RootPartitionNotFound => {
                "io.systemd.MountFileSystem.RootPartitionNotFound"
            }
            MountFileSystemError::DeniedByImagePolicy => {
                "io.systemd.MountFileSystem.DeniedByImagePolicy"
            }
            MountFileSystemError::KeyNotFound => "io.systemd.MountFileSystem.KeyNotFound",
            MountFileSystemError::VerityFailure => "io.systemd.MountFileSystem.VerityFailure",
            MountFileSystemError::BadFileDescriptorFlags { .. } => {
                "io.systemd.MountFileSystem.BadFileDescriptorFlags"
            }
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.MountFileSystem.IncompatibleImage",
    "io.systemd.MountFileSystem.MultipleRootPartitionsFound",
    "io.systemd.MountFileSystem.RootPartitionNotFound",
    "io.systemd.MountFileSystem.DeniedByImagePolicy",
    "io.systemd.MountFileSystem.KeyNotFound",
    "io.systemd.MountFileSystem.VerityFailure",
    "io.systemd.MountFileSystem.BadFileDescriptorFlags",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a hex-encoded verity root hash
pub fn is_valid_verity_root_hash(hash: &str) -> bool {
    !hash.is_empty() && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a Base64-encoded signature
pub fn is_valid_base64_signature(sig: &str) -> bool {
    !sig.is_empty()
}

/// Mask access mode bits (remove suid, sgid, sticky, world-writable)
pub fn mask_directory_mode(mode: i64) -> i64 {
    // Clear setuid (04000), setgid (02000), sticky (01000), other-write (00002)
    mode & !0o07002
}

/// Check if a file descriptor value looks valid (non-negative)
pub fn is_valid_fd(fd: i64) -> bool {
    fd >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.MountFileSystem");
        assert_eq!(METHODS.len(), 3);
    }

    #[test]
    fn test_partition_designator_roundtrip() {
        for pd in PartitionDesignator::ALL {
            assert_eq!(PartitionDesignator::from_str(pd.as_str()), Some(*pd));
        }
        assert_eq!(PartitionDesignator::ALL.len(), 13);
    }

    #[test]
    fn test_partition_designator_verity() {
        assert!(PartitionDesignator::RootVerity.is_verity());
        assert!(PartitionDesignator::UsrVerity.is_verity());
        assert!(PartitionDesignator::RootVeritySig.is_verity());
        assert!(PartitionDesignator::UsrVeritySig.is_verity());
        assert!(!PartitionDesignator::Root.is_verity());
    }

    #[test]
    fn test_partition_designator_data() {
        assert!(PartitionDesignator::Root.is_data());
        assert!(PartitionDesignator::Home.is_data());
        assert!(!PartitionDesignator::RootVerity.is_data());
    }

    #[test]
    fn test_mount_map_mode_roundtrip() {
        assert_eq!(MountMapMode::from_str("root"), Some(MountMapMode::Root));
        assert_eq!(
            MountMapMode::from_str("foreign"),
            Some(MountMapMode::Foreign)
        );
        assert_eq!(
            MountMapMode::from_str("identity"),
            Some(MountMapMode::Identity)
        );
        assert_eq!(MountMapMode::from_str("auto"), Some(MountMapMode::Auto));
        assert_eq!(MountMapMode::from_str("manual"), None);
    }

    #[test]
    fn test_partition_info_helpers() {
        let pi = PartitionInfo {
            designator: PartitionDesignator::Root,
            writable: true,
            grow_file_system: true,
            partition_number: Some(1),
            architecture: None,
            partition_uuid: Some("abcd-1234".into()),
            file_system_type: "ext4".into(),
            partition_label: None,
            size: 1024,
            offset: 0,
            mount_file_descriptor: 3,
            mount_point: vec!["/".into()],
        };
        assert!(pi.has_mount_point());
        assert!(pi.has_uuid());
    }

    #[test]
    fn test_mount_image_input_validate() {
        let input = MountImageInput {
            image_file_descriptor: 3,
            user_namespace_file_descriptor: Some(4),
            read_only: Some(false),
            grow_file_systems: None,
            password: None,
            image_policy: None,
            mount_options: vec![],
            relax_extension_release_checks: None,
            verity_sharing: None,
            verity_data_file_descriptor: None,
            verity_root_hash: None,
            verity_root_hash_signature: None,
        };
        assert!(input.validate().is_ok());

        let bad_input = MountImageInput {
            image_file_descriptor: -1,
            ..input.clone()
        };
        assert!(bad_input.validate().is_err());
    }

    #[test]
    fn test_mount_directory_input_validate() {
        let input = MountDirectoryInput {
            directory_file_descriptor: 3,
            user_namespace_file_descriptor: None,
            read_only: None,
            mode: Some(MountMapMode::Auto),
        };
        assert!(input.validate().is_ok());

        let bad = MountDirectoryInput {
            directory_file_descriptor: -1,
            ..input.clone()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_make_directory_input_validate() {
        let input = MakeDirectoryInput {
            parent_file_descriptor: 3,
            name: "testdir".into(),
            mode: Some(0o755),
        };
        assert!(input.validate().is_ok());

        let slash = MakeDirectoryInput {
            parent_file_descriptor: 3,
            name: "has/slash".into(),
            mode: None,
        };
        assert!(slash.validate().is_err());

        let empty = MakeDirectoryInput {
            parent_file_descriptor: 3,
            name: String::new(),
            mode: None,
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn test_is_valid_verity_root_hash() {
        assert!(is_valid_verity_root_hash("a1b2c3d4"));
        assert!(is_valid_verity_root_hash("ABCDEF0123456789"));
        assert!(!is_valid_verity_root_hash(""));
        assert!(!is_valid_verity_root_hash("not-hex!"));
    }

    #[test]
    fn test_mask_directory_mode() {
        assert_eq!(mask_directory_mode(0o7777), 0o0775);
        assert_eq!(mask_directory_mode(0o0755), 0o0755);
        assert_eq!(mask_directory_mode(0o4755), 0o0755);
        assert_eq!(mask_directory_mode(0o2755), 0o0755);
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 7);
        assert!(
            MountFileSystemError::IncompatibleImage
                .error_id()
                .contains("IncompatibleImage")
        );
        assert!(
            MountFileSystemError::VerityFailure
                .error_id()
                .contains("VerityFailure")
        );
    }
}
