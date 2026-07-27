// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.sysext.c
//
// Varlink interface definition for io.systemd.sysext
// System extension image management APIs.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the sysext service
pub const INTERFACE_NAME: &str = "io.systemd.sysext";

/// Method: Merge system extensions
pub const METHOD_MERGE: &str = "io.systemd.sysext.Merge";

/// Method: Unmerge system extensions
pub const METHOD_UNMERGE: &str = "io.systemd.sysext.Unmerge";

/// Method: Refresh system extensions
pub const METHOD_REFRESH: &str = "io.systemd.sysext.Refresh";

/// Method: List system extensions
pub const METHOD_LIST: &str = "io.systemd.sysext.List";

/// Error: No images found
pub const ERROR_NO_IMAGES_FOUND: &str = "io.systemd.sysext.NoImagesFound";

/// Error: Already merged
pub const ERROR_ALREADY_MERGED: &str = "io.systemd.sysext.AlreadyMerged";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Image class (sysext or confext)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageClass {
    /// System extension
    Sysext,
    /// Configuration extension
    Confext,
}

impl ImageClass {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "sysext" => Ok(ImageClass::Sysext),
            "confext" => Ok(ImageClass::Confext),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageClass::Sysext => "sysext",
            ImageClass::Confext => "confext",
        }
    }
}

/// Image type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    /// Directory-based image
    Directory,
    /// Btrfs subvolume
    Subvolume,
    /// Raw disk image
    Raw,
    /// Block device
    Block,
    /// Mstack bundle
    Mstack,
}

impl ImageType {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "directory" => Ok(ImageType::Directory),
            "subvolume" => Ok(ImageType::Subvolume),
            "raw" => Ok(ImageType::Raw),
            "block" => Ok(ImageType::Block),
            "mstack" => Ok(ImageType::Mstack),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ImageType::Directory => "directory",
            ImageType::Subvolume => "subvolume",
            ImageType::Raw => "raw",
            ImageType::Block => "block",
            ImageType::Mstack => "mstack",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for Merge method
#[derive(Debug, Clone, Default)]
pub struct MergeParams {
    /// Image class to merge
    pub class: Option<ImageClass>,
    /// Force merge even if already merged
    pub force: Option<bool>,
    /// Skip daemon reload after merge
    pub no_reload: Option<bool>,
    /// Mark as noexec
    pub noexec: Option<bool>,
}

/// Parameters for Unmerge method
#[derive(Debug, Clone, Default)]
pub struct UnmergeParams {
    /// Image class to unmerge
    pub class: Option<ImageClass>,
    /// Skip daemon reload after unmerge
    pub no_reload: Option<bool>,
}

/// Parameters for Refresh method
#[derive(Debug, Clone, Default)]
pub struct RefreshParams {
    /// Image class to refresh
    pub class: Option<ImageClass>,
    /// Force refresh
    pub force: Option<bool>,
    /// Skip daemon reload after refresh
    pub no_reload: Option<bool>,
    /// Always refresh even if unchanged
    pub always_refresh: Option<bool>,
    /// Mark as noexec
    pub noexec: Option<bool>,
}

/// Parameters for List method
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    /// Filter by image class
    pub class: Option<ImageClass>,
}

/// Output row from List method
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Image class
    pub class: ImageClass,
    /// Image type
    pub image_type: ImageType,
    /// Image name
    pub name: String,
    /// File system path
    pub path: Option<String>,
    /// Whether image is read-only
    pub read_only: bool,
    /// Creation timestamp (usec)
    pub creation_timestamp: Option<i64>,
    /// Modification timestamp (usec)
    pub modification_timestamp: Option<i64>,
    /// Disk usage (bytes)
    pub usage: Option<i64>,
    /// Exclusive disk usage
    pub usage_exclusive: Option<i64>,
    /// Disk usage limit
    pub limit: Option<i64>,
    /// Exclusive disk usage limit
    pub limit_exclusive: Option<i64>,
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if an image class string is valid
pub fn is_valid_image_class(s: &str) -> bool {
    ImageClass::from_str(s).is_ok()
}

/// Check if an image type string is valid
pub fn is_valid_image_type(s: &str) -> bool {
    ImageType::from_str(s).is_ok()
}

/// Get all known method names
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_MERGE, METHOD_UNMERGE, METHOD_REFRESH, METHOD_LIST]
}

/// Get all known error names
pub fn error_names() -> &'static [&'static str] {
    &[ERROR_NO_IMAGES_FOUND, ERROR_ALREADY_MERGED]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.sysext");
    }

    #[test]
    fn test_method_names_const() {
        assert_eq!(METHOD_MERGE, "io.systemd.sysext.Merge");
        assert_eq!(METHOD_UNMERGE, "io.systemd.sysext.Unmerge");
        assert_eq!(METHOD_REFRESH, "io.systemd.sysext.Refresh");
        assert_eq!(METHOD_LIST, "io.systemd.sysext.List");
    }

    #[test]
    fn test_error_names() {
        assert_eq!(ERROR_NO_IMAGES_FOUND, "io.systemd.sysext.NoImagesFound");
        assert_eq!(ERROR_ALREADY_MERGED, "io.systemd.sysext.AlreadyMerged");
    }

    #[test]
    fn test_image_class_from_str() {
        assert_eq!(ImageClass::from_str("sysext"), Ok(ImageClass::Sysext));
        assert_eq!(ImageClass::from_str("confext"), Ok(ImageClass::Confext));
        assert!(ImageClass::from_str("invalid").is_err());
    }

    #[test]
    fn test_image_class_as_str() {
        assert_eq!(ImageClass::Sysext.as_str(), "sysext");
        assert_eq!(ImageClass::Confext.as_str(), "confext");
    }

    #[test]
    fn test_image_type_from_str() {
        assert_eq!(ImageType::from_str("directory"), Ok(ImageType::Directory));
        assert_eq!(ImageType::from_str("subvolume"), Ok(ImageType::Subvolume));
        assert_eq!(ImageType::from_str("raw"), Ok(ImageType::Raw));
        assert_eq!(ImageType::from_str("block"), Ok(ImageType::Block));
        assert_eq!(ImageType::from_str("mstack"), Ok(ImageType::Mstack));
        assert!(ImageType::from_str("invalid").is_err());
    }

    #[test]
    fn test_image_type_as_str() {
        assert_eq!(ImageType::Directory.as_str(), "directory");
        assert_eq!(ImageType::Subvolume.as_str(), "subvolume");
        assert_eq!(ImageType::Raw.as_str(), "raw");
        assert_eq!(ImageType::Block.as_str(), "block");
        assert_eq!(ImageType::Mstack.as_str(), "mstack");
    }

    #[test]
    fn test_merge_params_default() {
        let params = MergeParams::default();
        assert!(params.class.is_none());
        assert!(params.force.is_none());
        assert!(params.no_reload.is_none());
        assert!(params.noexec.is_none());
    }

    #[test]
    fn test_unmerge_params_default() {
        let params = UnmergeParams::default();
        assert!(params.class.is_none());
        assert!(params.no_reload.is_none());
    }

    #[test]
    fn test_refresh_params_default() {
        let params = RefreshParams::default();
        assert!(params.class.is_none());
        assert!(params.force.is_none());
        assert!(params.no_reload.is_none());
        assert!(params.always_refresh.is_none());
        assert!(params.noexec.is_none());
    }

    #[test]
    fn test_is_valid_image_class() {
        assert!(is_valid_image_class("sysext"));
        assert!(is_valid_image_class("confext"));
        assert!(!is_valid_image_class("unknown"));
    }

    #[test]
    fn test_is_valid_image_type() {
        assert!(is_valid_image_type("directory"));
        assert!(is_valid_image_type("raw"));
        assert!(!is_valid_image_type("unknown"));
    }

    #[test]
    fn test_method_names_list() {
        let methods = method_names();
        assert_eq!(methods.len(), 4);
        assert!(methods.contains(&METHOD_MERGE));
        assert!(methods.contains(&METHOD_LIST));
    }

    #[test]
    fn test_error_names_list() {
        let errors = error_names();
        assert_eq!(errors.len(), 2);
        assert!(errors.contains(&ERROR_NO_IMAGES_FOUND));
        assert!(errors.contains(&ERROR_ALREADY_MERGED));
    }

    #[test]
    fn test_image_info_construction() {
        let info = ImageInfo {
            class: ImageClass::Sysext,
            image_type: ImageType::Raw,
            name: "test.ext".to_string(),
            path: Some("/var/lib/extensions/test.ext".to_string()),
            read_only: false,
            creation_timestamp: Some(1000000),
            modification_timestamp: None,
            usage: Some(4096),
            usage_exclusive: Some(4096),
            limit: None,
            limit_exclusive: None,
        };
        assert_eq!(info.class, ImageClass::Sysext);
        assert_eq!(info.image_type, ImageType::Raw);
        assert_eq!(info.name, "test.ext");
        assert!(!info.read_only);
    }
}
