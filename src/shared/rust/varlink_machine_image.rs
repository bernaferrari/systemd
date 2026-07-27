// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.MachineImage.c
//
// Varlink interface definition for io.systemd.MachineImage
// APIs for managing machine images.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the MachineImage service
pub const INTERFACE_NAME: &str = "io.systemd.MachineImage";

/// Method name for List
pub const METHOD_LIST: &str = "io.systemd.MachineImage.List";

/// Method name for Update
pub const METHOD_UPDATE: &str = "io.systemd.MachineImage.Update";

/// Method name for Clone
pub const METHOD_CLONE: &str = "io.systemd.MachineImage.Clone";

/// Method name for Remove
pub const METHOD_REMOVE: &str = "io.systemd.MachineImage.Remove";

/// Method name for SetPoolLimit
pub const METHOD_SET_POOL_LIMIT: &str = "io.systemd.MachineImage.SetPoolLimit";

/// Method name for CleanPool
pub const METHOD_CLEAN_POOL: &str = "io.systemd.MachineImage.CleanPool";

/// Error name for NoSuchImage
pub const ERROR_NO_SUCH_IMAGE: &str = "io.systemd.MachineImage.NoSuchImage";

/// Error name for TooManyOperations
pub const ERROR_TOO_MANY_OPERATIONS: &str = "io.systemd.MachineImage.TooManyOperations";

/// Error name for NotSupported
pub const ERROR_NOT_SUPPORTED: &str = "io.systemd.MachineImage.NotSupported";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Metadata acquisition mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireMetadata {
    No,
    Yes,
    Graceful,
}

impl AcquireMetadata {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "no" => Ok(AcquireMetadata::No),
            "yes" => Ok(AcquireMetadata::Yes),
            "graceful" => Ok(AcquireMetadata::Graceful),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquireMetadata::No => "no",
            AcquireMetadata::Yes => "yes",
            AcquireMetadata::Graceful => "graceful",
        }
    }
}

/// Clean pool mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanPoolMode {
    /// Remove all unused images
    All,
    /// Remove only hidden images
    Hidden,
}

impl CleanPoolMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "all" => Ok(CleanPoolMode::All),
            "hidden" => Ok(CleanPoolMode::Hidden),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            CleanPoolMode::All => "all",
            CleanPoolMode::Hidden => "hidden",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parameters for List method
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub name: Option<String>,
    pub acquire_metadata: Option<AcquireMetadata>,
}

/// Image information returned from List
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub name: String,
    pub path: Option<String>,
    pub image_type: String,
    pub class: String,
    pub read_only: bool,
    pub creation_timestamp: Option<i64>,
    pub modification_timestamp: Option<i64>,
    pub usage: Option<i64>,
    pub usage_exclusive: Option<i64>,
    pub limit: Option<i64>,
    pub limit_exclusive: Option<i64>,
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub machine_info: Option<Vec<String>>,
    pub os_release: Option<Vec<String>>,
}

/// Parameters for Update method
#[derive(Debug, Clone)]
pub struct UpdateParams {
    pub name: String,
    pub new_name: Option<String>,
    pub read_only: Option<bool>,
    pub limit: Option<i64>,
}

impl UpdateParams {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            new_name: None,
            read_only: None,
            limit: None,
        }
    }
}

/// Parameters for Clone method
#[derive(Debug, Clone)]
pub struct CloneParams {
    pub name: String,
    pub new_name: String,
    pub read_only: Option<bool>,
}

impl CloneParams {
    pub fn new(name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            new_name: new_name.into(),
            read_only: None,
        }
    }
}

/// Parameters for Remove method
#[derive(Debug, Clone)]
pub struct RemoveParams {
    pub name: String,
}

impl RemoveParams {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Parameters for SetPoolLimit method
#[derive(Debug, Clone)]
pub struct SetPoolLimitParams {
    pub limit: i64,
}

impl SetPoolLimitParams {
    pub fn new(limit: i64) -> Self {
        Self { limit }
    }
}

/// Parameters for CleanPool method
#[derive(Debug, Clone)]
pub struct CleanPoolParams {
    pub mode: CleanPoolMode,
}

impl CleanPoolParams {
    pub fn new(mode: CleanPoolMode) -> Self {
        Self { mode }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Get all known method names
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_LIST,
        METHOD_UPDATE,
        METHOD_CLONE,
        METHOD_REMOVE,
        METHOD_SET_POOL_LIMIT,
        METHOD_CLEAN_POOL,
    ]
}

/// Get all known error names
pub fn error_names() -> &'static [&'static str] {
    &[
        ERROR_NO_SUCH_IMAGE,
        ERROR_TOO_MANY_OPERATIONS,
        ERROR_NOT_SUPPORTED,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.MachineImage");
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_LIST.contains("List"));
        assert!(METHOD_UPDATE.contains("Update"));
        assert!(METHOD_CLONE.contains("Clone"));
        assert!(METHOD_REMOVE.contains("Remove"));
        assert!(METHOD_SET_POOL_LIMIT.contains("SetPoolLimit"));
        assert!(METHOD_CLEAN_POOL.contains("CleanPool"));
    }

    #[test]
    fn test_error_names() {
        assert!(ERROR_NO_SUCH_IMAGE.contains("NoSuchImage"));
        assert!(ERROR_TOO_MANY_OPERATIONS.contains("TooManyOperations"));
        assert!(ERROR_NOT_SUPPORTED.contains("NotSupported"));
    }

    #[test]
    fn test_acquire_metadata() {
        assert_eq!(AcquireMetadata::from_str("no"), Ok(AcquireMetadata::No));
        assert_eq!(AcquireMetadata::from_str("yes"), Ok(AcquireMetadata::Yes));
        assert_eq!(
            AcquireMetadata::from_str("graceful"),
            Ok(AcquireMetadata::Graceful)
        );
        assert!(AcquireMetadata::from_str("maybe").is_err());
        assert_eq!(AcquireMetadata::Yes.as_str(), "yes");
    }

    #[test]
    fn test_clean_pool_mode() {
        assert_eq!(CleanPoolMode::from_str("all"), Ok(CleanPoolMode::All));
        assert_eq!(CleanPoolMode::from_str("hidden"), Ok(CleanPoolMode::Hidden));
        assert!(CleanPoolMode::from_str("none").is_err());
        assert_eq!(CleanPoolMode::Hidden.as_str(), "hidden");
    }

    #[test]
    fn test_list_params_default() {
        let params = ListParams::default();
        assert!(params.name.is_none());
        assert!(params.acquire_metadata.is_none());
    }

    #[test]
    fn test_update_params() {
        let params = UpdateParams::new("myimage");
        assert_eq!(params.name, "myimage");
        assert!(params.new_name.is_none());
        assert!(params.read_only.is_none());
        assert!(params.limit.is_none());
    }

    #[test]
    fn test_clone_params() {
        let params = CloneParams::new("source", "dest");
        assert_eq!(params.name, "source");
        assert_eq!(params.new_name, "dest");
    }

    #[test]
    fn test_remove_params() {
        let params = RemoveParams::new("myimage");
        assert_eq!(params.name, "myimage");
    }

    #[test]
    fn test_set_pool_limit_params() {
        let params = SetPoolLimitParams::new(1073741824);
        assert_eq!(params.limit, 1073741824);
    }

    #[test]
    fn test_clean_pool_params() {
        let params = CleanPoolParams::new(CleanPoolMode::All);
        assert_eq!(params.mode, CleanPoolMode::All);
    }

    #[test]
    fn test_method_names_list() {
        let names = method_names();
        assert_eq!(names.len(), 6);
        assert!(names.contains(&METHOD_LIST));
        assert!(names.contains(&METHOD_CLEAN_POOL));
    }

    #[test]
    fn test_error_names_list() {
        let errors = error_names();
        assert_eq!(errors.len(), 3);
        assert!(errors.contains(&ERROR_NO_SUCH_IMAGE));
    }
}
