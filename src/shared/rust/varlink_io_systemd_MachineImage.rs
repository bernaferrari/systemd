// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.MachineImage.c
//
// Varlink interface definition for io.systemd.MachineImage.
//
// APIs for listing, updating, cloning, removing, and managing
// machine images and their pool quotas.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.MachineImage";

pub const METHOD_LIST: &str = "List";
pub const METHOD_UPDATE: &str = "Update";
pub const METHOD_CLONE: &str = "Clone";
pub const METHOD_REMOVE: &str = "Remove";
pub const METHOD_SET_POOL_LIMIT: &str = "SetPoolLimit";
pub const METHOD_CLEAN_POOL: &str = "CleanPool";

pub const METHODS: &[&str] = &[
    METHOD_LIST,
    METHOD_UPDATE,
    METHOD_CLONE,
    METHOD_REMOVE,
    METHOD_SET_POOL_LIMIT,
    METHOD_CLEAN_POOL,
];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Controls metadata inclusion in image listing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireMetadata {
    No,
    Yes,
    Graceful,
}

impl AcquireMetadata {
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquireMetadata::No => "no",
            AcquireMetadata::Yes => "yes",
            AcquireMetadata::Graceful => "graceful",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no" => Some(AcquireMetadata::No),
            "yes" => Some(AcquireMetadata::Yes),
            "graceful" => Some(AcquireMetadata::Graceful),
            _ => None,
        }
    }

    pub fn should_include(&self) -> bool {
        !matches!(self, AcquireMetadata::No)
    }
}

/// Controls which images to clean
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanPoolMode {
    /// Remove all unused images
    All,
    /// Remove only hidden images
    Hidden,
}

impl CleanPoolMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CleanPoolMode::All => "all",
            CleanPoolMode::Hidden => "hidden",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "all" => Some(CleanPoolMode::All),
            "hidden" => Some(CleanPoolMode::Hidden),
            _ => None,
        }
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// Image information returned by the List method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    /// Name of the image
    pub name: String,
    /// File system path where image is stored
    pub path: Option<String>,
    /// Image type
    pub image_type: String,
    /// Image class
    pub class: String,
    /// Whether the image is read-only
    pub read_only: bool,
    /// Creation timestamp
    pub creation_timestamp: Option<i64>,
    /// Modification timestamp
    pub modification_timestamp: Option<i64>,
    /// Disk usage in bytes
    pub usage: Option<i64>,
    /// Exclusive disk usage
    pub usage_exclusive: Option<i64>,
    /// Usage limit
    pub limit: Option<i64>,
    /// Exclusive usage limit
    pub limit_exclusive: Option<i64>,
    /// Image hostname
    pub hostname: Option<String>,
    /// Image machine ID
    pub machine_id: Option<String>,
}

impl ImageInfo {
    /// Check if the image has size information
    pub fn has_usage_info(&self) -> bool {
        self.usage.is_some()
    }

    /// Check if the image has quota limits set
    pub fn has_limits(&self) -> bool {
        self.limit.is_some() || self.limit_exclusive.is_some()
    }
}

/// Input for the Update method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInput {
    /// Name of the image to update
    pub name: String,
    /// New name for the image
    pub new_name: Option<String>,
    /// Read-only flag
    pub read_only: Option<bool>,
    /// Quota limit
    pub limit: Option<i64>,
}

impl UpdateInput {
    /// Validate update parameters
    pub fn validate(&self) -> Result<(), MachineImageError> {
        if self.name.is_empty() {
            return Err(MachineImageError::NoSuchImage);
        }
        if let Some(ref new_name) = self.new_name {
            if new_name.is_empty() {
                return Err(MachineImageError::NoSuchImage);
            }
        }
        if let Some(lim) = self.limit {
            if lim < 0 {
                return Err(MachineImageError::NotSupported);
            }
        }
        Ok(())
    }
}

/// Input for the Clone method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneInput {
    /// Name of the source image
    pub name: String,
    /// Name for the cloned image
    pub new_name: String,
    /// Read-only flag for the clone
    pub read_only: Option<bool>,
}

impl CloneInput {
    pub fn validate(&self) -> Result<(), MachineImageError> {
        if self.name.is_empty() || self.new_name.is_empty() {
            return Err(MachineImageError::NoSuchImage);
        }
        if self.name == self.new_name {
            return Err(MachineImageError::NoSuchImage);
        }
        Ok(())
    }
}

/// Input for the SetPoolLimit method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPoolLimitInput {
    pub limit: i64,
}

impl SetPoolLimitInput {
    pub fn validate(&self) -> Result<(), MachineImageError> {
        if self.limit < 0 {
            return Err(MachineImageError::NotSupported);
        }
        Ok(())
    }
}

/// Input for the CleanPool method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanPoolInput {
    pub mode: CleanPoolMode,
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineImageError {
    NoSuchImage,
    TooManyOperations,
    NotSupported,
}

impl MachineImageError {
    pub fn error_id(&self) -> &'static str {
        match self {
            MachineImageError::NoSuchImage => "io.systemd.MachineImage.NoSuchImage",
            MachineImageError::TooManyOperations => "io.systemd.MachineImage.TooManyOperations",
            MachineImageError::NotSupported => "io.systemd.MachineImage.NotSupported",
        }
    }
}

pub const ERROR_IDS: &[&str] = &[
    "io.systemd.MachineImage.NoSuchImage",
    "io.systemd.MachineImage.TooManyOperations",
    "io.systemd.MachineImage.NotSupported",
];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate an image name
pub fn is_valid_image_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('\0') && !name.contains('/') && name.len() <= 255
}

/// Format byte count to human-readable size
pub fn format_size(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = 1024 * KB;
    const GB: i64 = 1024 * MB;
    const TB: i64 = 1024 * GB;

    if bytes < 0 {
        return format!("{} B", bytes);
    }

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.MachineImage");
        assert_eq!(METHODS.len(), 6);
    }

    #[test]
    fn test_acquire_metadata_roundtrip() {
        for s in &["no", "yes", "graceful"] {
            let am = AcquireMetadata::from_str(s).unwrap();
            assert_eq!(am.as_str(), *s);
        }
        assert_eq!(AcquireMetadata::from_str("maybe"), None);
    }

    #[test]
    fn test_clean_pool_mode_roundtrip() {
        assert_eq!(CleanPoolMode::from_str("all"), Some(CleanPoolMode::All));
        assert_eq!(
            CleanPoolMode::from_str("hidden"),
            Some(CleanPoolMode::Hidden)
        );
        assert_eq!(CleanPoolMode::from_str("visible"), None);
    }

    #[test]
    fn test_image_info_helpers() {
        let info = ImageInfo {
            name: "test".into(),
            path: Some("/var/lib/machines/test".into()),
            image_type: "raw".into(),
            class: "machine".into(),
            read_only: false,
            creation_timestamp: Some(1000),
            modification_timestamp: None,
            usage: Some(1024),
            usage_exclusive: None,
            limit: None,
            limit_exclusive: None,
            hostname: None,
            machine_id: None,
        };
        assert!(info.has_usage_info());
        assert!(!info.has_limits());
    }

    #[test]
    fn test_update_input_validate() {
        let input = UpdateInput {
            name: "test".into(),
            new_name: Some("new".into()),
            read_only: Some(true),
            limit: Some(1024),
        };
        assert!(input.validate().is_ok());

        let empty = UpdateInput {
            name: String::new(),
            new_name: None,
            read_only: None,
            limit: None,
        };
        assert_eq!(empty.validate(), Err(MachineImageError::NoSuchImage));
    }

    #[test]
    fn test_clone_input_validate() {
        let input = CloneInput {
            name: "src".into(),
            new_name: "dst".into(),
            read_only: None,
        };
        assert!(input.validate().is_ok());

        let same = CloneInput {
            name: "same".into(),
            new_name: "same".into(),
            read_only: None,
        };
        assert_eq!(same.validate(), Err(MachineImageError::NoSuchImage));
    }

    #[test]
    fn test_set_pool_limit_validate() {
        assert!(SetPoolLimitInput { limit: 0 }.validate().is_ok());
        assert!(SetPoolLimitInput { limit: 1024 }.validate().is_ok());
        assert_eq!(
            SetPoolLimitInput { limit: -1 }.validate(),
            Err(MachineImageError::NotSupported)
        );
    }

    #[test]
    fn test_is_valid_image_name() {
        assert!(is_valid_image_name("my-image"));
        assert!(is_valid_image_name("image.raw"));
        assert!(!is_valid_image_name(""));
        assert!(!is_valid_image_name("has/slash"));
        assert!(!is_valid_image_name("null\0byte"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert!(format_size(1024).contains("KB"));
        assert!(format_size(1048576).contains("MB"));
        assert!(format_size(1073741824).contains("GB"));
        assert!(format_size(1099511627776).contains("TB"));
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 3);
        assert!(
            MachineImageError::NoSuchImage
                .error_id()
                .contains("NoSuchImage")
        );
        assert!(
            MachineImageError::TooManyOperations
                .error_id()
                .contains("TooManyOperations")
        );
    }

    #[test]
    fn test_acquire_metadata_should_include() {
        assert!(!AcquireMetadata::No.should_include());
        assert!(AcquireMetadata::Yes.should_include());
        assert!(AcquireMetadata::Graceful.should_include());
    }

    #[test]
    fn test_update_input_negative_limit() {
        let input = UpdateInput {
            name: "test".into(),
            new_name: None,
            read_only: None,
            limit: Some(-100),
        };
        assert_eq!(input.validate(), Err(MachineImageError::NotSupported));
    }
}
